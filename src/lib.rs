// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Implementation of Transfers in the SAFE Network.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]
// For explanation of lint checks, run `rustc -W help`.
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]

mod actor;
mod genesis;
mod replica;
mod wallet;
//mod test_file;

pub use self::{
    actor::Actor as TransferActor, genesis::get_genesis, replica::Replica as TransferReplica,
    wallet::Wallet,
};

use serde::{Deserialize, Serialize};
use sn_data_types::{
    CreditAgreementProof, CreditId, DebitId, Error, Money, PublicKey, Result, SignedCredit,
    SignedDebit, TransferAgreementProof, TransferValidated,
};
use std::collections::HashSet;

type Outcome<T> = Result<Option<T>>;

trait TernaryResult<T> {
    fn success(item: T) -> Self;
    fn no_change() -> Self;
    fn rejected(error: Error) -> Self;
}

impl<T> TernaryResult<T> for Outcome<T> {
    fn success(item: T) -> Self {
        Ok(Some(item))
    }
    fn no_change() -> Self {
        Ok(None)
    }
    fn rejected(error: Error) -> Self {
        Err(error)
    }
}

/// A received credit, contains the CreditAgreementProof from the sender Replicas,
/// as well as the public key of those Replicas, for us to verify that they are valid Replicas.
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Serialize, Deserialize, Debug)]
pub struct ReceivedCredit {
    /// The sender's aggregated Replica signatures of the credit.
    pub credit_proof: CreditAgreementProof,
    /// The public key of the signing Replicas.
    pub debiting_replicas: PublicKey,
}

impl ReceivedCredit {
    /// Get the transfer id
    pub fn id(&self) -> &CreditId {
        self.credit_proof.id()
    }

    /// Get the amount of this transfer
    pub fn amount(&self) -> Money {
        self.credit_proof.amount()
    }

    /// Get the recipient of this transfer
    pub fn recipient(&self) -> PublicKey {
        self.credit_proof.recipient()
    }
}

// ------------------------------------------------------------
//                      Actor
// ------------------------------------------------------------

/// An implementation of the ReplicaValidator, should contain the logic from upper layers
/// for determining if a remote group of Replicas, represented by a PublicKey, is indeed valid.
/// This is logic from the membership part of the system, and thus handled by the upper layers
/// membership implementation.
pub trait ReplicaValidator {
    /// Determines if a remote group of Replicas, represented by a PublicKey, is indeed valid.
    fn is_valid(&self, replica_group: PublicKey) -> bool;
}

/// Events raised by the Actor.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub enum ActorEvent {
    /// Raised when a request to create
    /// a transfer validation cmd for Replicas,
    /// has been successful (valid on local state).
    TransferInitiated(TransferInitiated),
    /// Raised when an Actor receives a Replica transfer validation.
    TransferValidationReceived(TransferValidationReceived),
    /// Raised when the Actor has accumulated a
    /// quorum of validations, and produced a RegisterTransfer cmd
    /// for sending to Replicas.
    TransferRegistrationSent(TransferRegistrationSent),
    /// Raised when the Actor has received
    /// unknown credits on querying Replicas.
    TransfersSynched(TransfersSynched),
}

/// Raised when the Actor has received
/// f.ex. credits that its Replicas were holding upon
/// the propagation of them from a remote group of Replicas,
/// or unknown debits that its Replicas were holding
/// upon the registration of them from another
/// instance of the same Actor.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct TransfersSynched {
    id: PublicKey,
    balance: Money,
    debit_version: u64,
    credit_ids: HashSet<CreditId>,
}

/// This event is raised by the Actor after having
/// successfully created a transfer cmd to send to the
/// Replicas for validation.
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Serialize, Deserialize, Debug)]
pub struct TransferInitiated {
    /// The debit signed by the initiating Actor.
    pub signed_debit: SignedDebit,
    /// The credit signed by the initiating Actor.
    pub signed_credit: SignedCredit,
}

impl TransferInitiated {
    /// Get the debit id
    pub fn id(&self) -> DebitId {
        self.signed_debit.id()
    }
}

/// Raised when a Replica responds with
/// a successful validation of a transfer.
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Serialize, Deserialize, Debug)]
pub struct TransferValidationReceived {
    /// The event raised by a Replica.
    validation: TransferValidated,
    /// Added when quorum of validations
    /// have been received from Replicas.
    pub proof: Option<TransferAgreementProof>,
}

/// Raised when the Actor has accumulated a
/// quorum of validations, and produced a RegisterTransfer cmd
/// for sending to Replicas.
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Serialize, Deserialize, Debug)]
pub struct TransferRegistrationSent {
    transfer_proof: TransferAgreementProof,
}

#[allow(unused)]
#[cfg(test)]
mod test {
    use crate::{
        actor::Actor, genesis, replica::Replica, wallet::WalletSnapshot, ActorEvent,
        ReplicaValidator, SignedCredit, SignedDebit, TransferInitiated, Wallet,
    };
    use crdts::{
        quickcheck::{quickcheck, TestResult},
        Dot,
    };
    use prop::test_runner::*;
    use proptest::prelude::*;
    use rand::RngCore;
    use rand::{CryptoRng, Rng, SeedableRng};
    use sn_data_types::{
        Credit, CreditAgreementProof, CreditId, Debit, Keypair, Money, PublicKey, ReplicaEvent,
        Result, Transfer, TransferAgreementProof,
    };
    use std::collections::{HashMap, HashSet};
    use std::time::{Duration, Instant};
    use threshold_crypto::{PublicKeySet, SecretKey, SecretKeySet, SecretKeyShare};

    macro_rules! hashmap {
        ($( $key: expr => $val: expr ),*) => {{
             let mut map = ::std::collections::HashMap::new();
             $( let _ = map.insert($key, $val); )*
             map
        }}
    }

    // ------------------------------------------------------------------------
    // ------------------------ Basic Transfer --------------------------------
    // ------------------------------------------------------------------------

    #[test]
    fn run_transfers_single_iter() {
        let seed = 3;
        let num_transfers = 10;
        let replica_count = 7;
        let mut wallet_configs = HashMap::new();
        for i in 0..2 {
            let actors = vec![(i as u64 + 1) * 500, (i as u64 + 1) * 400];
            let _ = wallet_configs.insert(i, actors);
        }
        let mut network = get_network(seed, replica_count, wallet_configs);
        run_transfers(num_transfers, &mut network);
        output(&mut network);
        verify(&mut network);
    }

    fn output(network: &mut Network) {
        println!("Printing results..");

        for group in &mut network.replica_groups {
            println!("Replica group: {}", group.index);
            for i in 0..group.replicas.len() {
                let replica = &group.replicas[i];
                for actor in &network.actors {
                    if let Some(balance) = replica.balance(&actor.id()) {
                        println!(
                            "Group: {}, replica: {}, balance of actor {}: {}",
                            group.index,
                            i,
                            actor.id(),
                            balance.as_nano()
                        );
                    }
                }
            }
        }

        for actor in &network.actors {
            println!(
                "Balance of actor {}: {}",
                actor.id(),
                actor.balance().as_nano()
            );
        }
    }

    // --------------------------------------------------------
    //   ----------------- Prop test ------------------------
    // --------------------------------------------------------

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 6,
            max_local_rejects: u32::MAX,
            max_global_rejects: u32::MAX,
            verbose: 0,
            fork: false,
            .. ProptestConfig::default()
        })]

        #[test]
        fn basic(seed: u64, system: Vec<Vec<u64>>) { // Vec<Vec<u64>> -> ReplicaGroups, Actors and their balances
            //return Err(TestCaseError::Fail("Reason".into()));
            //return Err(TestCaseError::Reject("Reason".into()));
            let max_sections = 4;
            let max_actors_in_section = 5;
            let min_actors_in_system = 2;
            prop_assume!(system.len() > 0);
            prop_assume!(max_sections >= system.len());
            prop_assume!(system.iter().map(|a| a.len()).sum::<usize>() >= min_actors_in_system);

            let replica_count = 7;
            let mut wallet_configs = HashMap::new();
            let mut system = system;
            for i in 0..system.len() {
                let actors = system.remove(0);
                prop_assume!(actors.len() > 0);
                prop_assume!(max_actors_in_section >= actors.len());
                let _ = wallet_configs.insert(i, actors);
            }
            let mut network = get_network(seed, replica_count, wallet_configs);
            let num_transfers = network.rng.gen_range(max_actors_in_section / 2, max_sections * max_actors_in_section);

            run_transfers(num_transfers as u32, &mut network);
            verify(&mut network);
        }
    }

    fn verify(network: &Network) {
        println!("Verifying..");
        for actor in &network.actors {
            let amount = actor.actor.balance();
            let group = &network.replica_groups[actor.replica_group];
            group
                .replicas
                .iter()
                .map(|replica| replica.balance(&actor.actor.id()).unwrap())
                .for_each(|balance| assert_eq!(balance, amount));
        }
    }

    fn run_transfers(num_transfers: u32, network: &mut Network) {
        println!("Setting up transfers..");
        for i in 0..num_transfers {
            let (sender_index, recipient_index) = gen_distinct(network);
            let recipient_key = network.actors[recipient_index].id();
            let mut sender = network.actors.remove(sender_index);
            let amount = network.rng.gen_range(
                1 + (sender.balance().as_nano() / 10),
                sender.balance().as_nano(),
            );
            sender.transfer(Money::from_nano(amount), recipient_key, network);
            let _ = network.actors.insert(sender_index, sender);
        }

        // process messages
        loop_msg_routing(network);

        // synch actors
        synch(network);
    }

    fn gen_distinct(network: &mut Network) -> (usize, usize) {
        let mut sender_index = 0;
        let mut recipient_index = 0;
        while sender_index == recipient_index {
            sender_index = network.rng.gen_range(0, network.actors.len());
            recipient_index = network.rng.gen_range(0, network.actors.len());
        }
        (sender_index, recipient_index)
    }

    fn synch(network: &mut Network) {
        println!("Synching..");
        for actor in &mut network.actors {
            let wallet =
                network.replica_groups[actor.replica_group].replicas[0].wallet(&actor.id());
            if let Some(wallet) = wallet {
                let result =
                    actor
                        .actor
                        .synch(wallet.balance, wallet.debit_version, wallet.credit_ids);
                match result {
                    Ok(Some(synched)) => {
                        actor
                            .actor
                            .apply(ActorEvent::TransfersSynched(synched.clone()));
                    }
                    Err(e) => println!("{}", 0),
                    _ => return,
                }
            }
        }
    }

    fn loop_msg_routing(network: &mut Network) {
        println!("Routing messages..");
        let timer = Instant::now();
        let mut msg_count = 0;
        let mut actor_index = HashMap::new();
        let mut replica_timings = vec![];
        let mut actor_timings = vec![];
        while !network.msg_queue.is_empty() {
            let popped = network.msg_queue.pop_front();
            if popped.is_none() {
                break;
            }
            if let Some(next) = popped {
                match next {
                    Msg::Cmd { cmd, from, to } => {
                        let mut group = network.replica_groups.remove(to);

                        let replica_timer = Instant::now();
                        for replica in &mut group.replicas {
                            replica.handle(cmd.clone(), from, network);
                        }
                        replica_timings.push(replica_timer.elapsed().as_millis() as usize);

                        msg_count += group.replicas.len();
                        let _ = network.replica_groups.insert(to, group);
                    }
                    Msg::Event { event, to } => {
                        if !actor_index.contains_key(&to) {
                            for i in 0..network.actors.len() {
                                if network.actors[i].id() == to {
                                    let _ = actor_index.insert(to, i);
                                    break;
                                }
                            }
                        }
                        if let Some(index) = actor_index.get(&to) {
                            let mut actor = network.actors.remove(*index);

                            let actor_timer = Instant::now();
                            actor.handle(event, network);
                            actor_timings.push(actor_timer.elapsed().as_millis() as usize);

                            let _ = network.actors.insert(*index, actor);
                            msg_count += 1;
                        }
                    }
                }
            }
            shuffle(&mut network.msg_queue, &mut network.rng);
        }

        println!(
            "Processed {} messages in {} s.",
            msg_count,
            timer.elapsed().as_secs()
        );
        println!(
            "Avg actor time per msg {} ms.",
            actor_timings.iter().sum::<usize>() / actor_timings.len()
        );
        println!(
            "Avg replica group time per msg {} ms.",
            replica_timings.iter().sum::<usize>() / replica_timings.len()
        );
        println!("Actors handled {} msgs.", actor_timings.len());
        println!("Replicas handled {} msgs.", replica_timings.len() * 7);
    }

    // ------------------------------------------------------------------------
    // ------------------------ Setup Helpers ---------------------------------
    // ------------------------------------------------------------------------

    fn get_genesis<R: Rng>(rng: &mut R) -> Result<CreditAgreementProof> {
        let balance = u32::MAX as u64 * 1_000_000_000;
        let threshold = 0;
        let bls_secret_key = SecretKeySet::random(threshold, rng);
        let peer_replicas = bls_secret_key.public_keys();
        let id = PublicKey::Bls(peer_replicas.public_key());
        genesis::get_genesis(balance, id)
    }

    use std::collections::VecDeque;
    struct Network {
        replica_groups: Vec<ReplicaGroup>,
        actors: Vec<TestActor>,
        msg_queue: VecDeque<Msg>,
        rng: rand::rngs::StdRng,
    }
    enum Msg {
        Cmd {
            cmd: Cmd,
            to: ReplicaIndex,
            from: PublicKey,
        },
        Event {
            event: ReplicaEvent,
            to: PublicKey,
            //from: ReplicaIndex,
        },
    }

    #[derive(Clone)]
    enum Cmd {
        ValidateDebit {
            signed_debit: SignedDebit,
            signed_credit: SignedCredit,
            // amount: Money,
            // recipient: PublicKey,
            // msg: String,
        },
        RegisterDebitAgreement(TransferAgreementProof),
        PropagateTransfer(CreditAgreementProof),
    }

    fn get_network(
        seed: u64,
        replica_count: u8,
        wallet_configs: HashMap<usize, Vec<u64>>,
    ) -> Network {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        let wallets: Vec<_> = wallet_configs
            .iter()
            .map(|(replica_group, balances)| {
                balances
                    .iter()
                    .map(|b| setup_wallet(*b, *replica_group, &mut rng))
                    .collect::<Vec<_>>()
            })
            .flatten()
            .collect();

        let group_count = wallet_configs.len();
        let group_keys = setup_replica_group_keys(group_count, replica_count, &mut rng);
        let mut replica_groups = setup_replica_groups(group_keys, wallets.clone());

        let actors: Vec<TestActor> = wallets
            .iter()
            .map(|wallet| setup_actor(wallet.clone(), &mut replica_groups))
            .collect();

        Network {
            replica_groups,
            actors,
            msg_queue: Default::default(),
            rng,
        }
    }

    fn find_group(
        index: ReplicaIndex,
        replica_groups: &mut Vec<ReplicaGroup>,
    ) -> Option<&mut ReplicaGroup> {
        for replica_group in replica_groups {
            if replica_group.index == index {
                return Some(replica_group);
            }
        }
        None
    }

    fn get_random_pk() -> PublicKey {
        PublicKey::from(SecretKey::random().public_key())
    }

    fn setup_wallet<R: Rng + CryptoRng>(
        balance: u64,
        replica_group: ReplicaIndex,
        rng: &mut R,
    ) -> TestWallet {
        let keypair = Keypair::new_ed25519(rng);
        let recipient = keypair.public_key();
        let mut wallet = Wallet::new(recipient);

        let amount = Money::from_nano(balance);
        let sender = Dot::new(get_random_pk(), 0);
        let debit = Debit { id: sender, amount };
        let credit = Credit {
            id: debit.credit_id(),
            recipient,
            amount,
            msg: "".to_string(),
        };
        let _ = wallet.apply_credit(credit);

        TestWallet {
            wallet,
            keypair,
            replica_group,
        }
    }

    fn setup_actor(wallet: TestWallet, replica_groups: &mut Vec<ReplicaGroup>) -> TestActor {
        let replica_group = find_group(wallet.replica_group, replica_groups).unwrap();

        let actor = Actor::from_snapshot(
            wallet.wallet,
            wallet.keypair,
            replica_group.id.clone(),
            Validator {},
        );

        TestActor {
            actor,
            replica_group: replica_group.index,
        }
    }

    // Create n replica groups, with k replicas in each
    fn setup_replica_group_keys<R: Rng>(
        group_count: usize,
        replica_count: u8,
        rng: &mut R,
    ) -> HashMap<usize, ReplicaGroupKeys> {
        let mut groups = HashMap::new();
        let threshold = 3; //(2 * replica_count / 3) - 1;
        for i in 0..group_count {
            let bls_secret_key = SecretKeySet::random(threshold as usize, rng);
            let peers = bls_secret_key.public_keys();
            let mut shares = vec![];
            for j in 0..replica_count {
                let share = bls_secret_key.secret_key_share(j as usize);
                shares.push((share, j as usize));
            }
            let _ = groups.insert(
                i,
                ReplicaGroupKeys {
                    index: i,
                    id: peers,
                    keys: shares,
                },
            );
        }
        groups
    }

    fn setup_replica_groups(
        group_keys: HashMap<usize, ReplicaGroupKeys>,
        wallets: Vec<TestWallet>,
    ) -> Vec<ReplicaGroup> {
        let mut group_index_and_other_keys = HashMap::new();
        for (this_group_index, _) in group_keys.clone() {
            let the_other_groups = group_keys
                .clone()
                .into_iter()
                .filter(|(index, _)| *index != this_group_index)
                .map(|(_, some_other_groups_keys)| some_other_groups_keys.id)
                .collect::<HashSet<PublicKeySet>>();
            let _ = group_index_and_other_keys.insert(this_group_index, the_other_groups);
        }

        let mut replica_groups = vec![];
        for (this_group_index, the_other_groups) in &group_index_and_other_keys {
            let group_wallets = wallets
                .clone()
                .into_iter()
                .filter(|c| c.replica_group == *this_group_index)
                .map(|c| (c.wallet.id(), c.wallet))
                .collect::<HashMap<PublicKey, Wallet>>();

            let mut replicas = vec![];
            let this_group = group_keys[this_group_index].clone();
            for (secret_key, index) in this_group.keys {
                let peer_replicas = this_group.id.clone();
                let other_groups = the_other_groups.clone();
                let wallets = group_wallets.clone();
                let pending_debits = Default::default();
                let replica = Replica::from_snapshot(
                    secret_key,
                    index,
                    peer_replicas,
                    other_groups,
                    wallets,
                    pending_debits,
                );
                replicas.push(TestReplica {
                    replica,
                    replica_group: *this_group_index,
                });
            }
            replica_groups.push(ReplicaGroup {
                index: *this_group_index,
                id: this_group.id,
                replicas,
            });
        }
        replica_groups
    }

    // ------------------------------------------------------------------------
    // ------------------------ Structs ---------------------------------------
    // ------------------------------------------------------------------------

    #[derive(Debug, Clone)]
    struct Validator {}

    impl ReplicaValidator for Validator {
        fn is_valid(&self, _replica_group: PublicKey) -> bool {
            true
        }
    }

    type ReplicaIndex = usize;

    #[derive(Debug, Clone)]
    struct TestWallet {
        wallet: Wallet,
        keypair: Keypair,
        replica_group: ReplicaIndex,
    }

    #[derive(Debug, Clone)]
    struct TestActor {
        actor: Actor<Validator>,
        replica_group: ReplicaIndex,
    }

    impl TestActor {
        pub fn id(&self) -> PublicKey {
            self.actor.id()
        }

        pub fn balance(&self) -> Money {
            self.actor.balance()
        }

        pub fn transfer(&mut self, amount: Money, recipient: PublicKey, network: &mut Network) {
            // -- Send the first cmd. --
            if let Ok(Some(e)) = self.actor.transfer(amount, recipient, "msg".into()) {
                self.actor.apply(ActorEvent::TransferInitiated(e.clone()));
                network.msg_queue.push_back(Msg::Cmd {
                    cmd: Cmd::ValidateDebit {
                        signed_debit: e.signed_debit,
                        signed_credit: e.signed_credit,
                    },
                    from: self.id(),
                    to: self.replica_group,
                });
            }
        }

        pub fn handle(&mut self, event: ReplicaEvent, network: &mut Network) {
            let result = match event {
                ReplicaEvent::TransferValidated(validation) => {
                    let result = self.actor.receive(validation);
                    if let Ok(Some(validation)) = result {
                        // println!(
                        //     "Sending agreement registration for debit {}",
                        //     agreed.debit.id
                        // );
                        self.actor
                            .apply(ActorEvent::TransferValidationReceived(validation.clone()));
                        // println!(
                        //     "[ACTOR]: Received validation {:?}.",
                        //     validation
                        // );
                        if let Some(proof) = validation.proof {
                            // -- Send the cmd to the router. --
                            network.msg_queue.push_back(Msg::Cmd {
                                cmd: Cmd::RegisterDebitAgreement(proof.clone()),
                                from: self.actor.id(),
                                to: self.replica_group,
                            });
                            // println!(
                            //     "[ACTOR]: Agreement reached {:?}. Happy!",
                            //     proof
                            // );
                        }
                    }
                }
                ReplicaEvent::TransferRegistered(registration) => {
                    // println!(
                    //     "[ACTOR]: Received registration {:?}",
                    //     registration
                    // );
                    return;
                }
                ReplicaEvent::TransferPropagated(propagation) => return,
                _ => return,
            };
        }
    }

    #[derive(Debug)]
    struct TestReplica {
        replica_group: ReplicaIndex,
        replica: Replica,
    }

    impl TestReplica {
        pub fn balance(&self, wallet_id: &PublicKey) -> Option<Money> {
            self.replica.balance(wallet_id)
        }

        pub fn wallet(&self, wallet_id: &PublicKey) -> Option<WalletSnapshot> {
            self.replica.wallet(wallet_id)
        }

        pub fn handle(&mut self, cmd: Cmd, from: PublicKey, network: &mut Network) {
            // -- Process the cmd. --
            let result = match cmd {
                Cmd::ValidateDebit {
                    signed_debit,
                    signed_credit,
                } => match self.replica.validate(signed_debit, signed_credit) {
                    Err(e) => {
                        println!(
                            "-- // -- // Replica {} REJECTED cmd, due to: {} // -- // -- ",
                            self.replica_group, e
                        );
                    }
                    Ok(Some(e)) => {
                        let event = ReplicaEvent::TransferValidated(e);
                        // -- Apply the event! --
                        self.replica.apply(event.clone());
                        //let id = e.id();
                        // --> // println!("-- Replica sending event {:?}", event);
                        network.msg_queue.push_back(Msg::Event {
                            event,
                            //from: self.id(),
                            to: from,
                        });
                        //println!("-- Replica SENT event {:?}", id);
                    }
                    _ => return,
                },
                Cmd::RegisterDebitAgreement(transfer_proof) => {
                    match self.replica.register(&transfer_proof, || true) {
                        Err(e) => {
                            //println!("-- // -- // Replica {} REJECTED cmd {}, due to: {} // -- // -- ", self.id(), cmd_id, e);
                        }
                        Ok(Some(e)) => {
                            let event = ReplicaEvent::TransferRegistered(e.clone());
                            // -- Apply the event! --
                            self.replica.apply(event.clone());
                            // let id = e.id();
                            // --> // println!("-- Replica sending event {:?}", event);
                            let wallet_id = e.transfer_proof.signed_credit.recipient();
                            network.msg_queue.push_back(Msg::Cmd {
                                cmd: Cmd::PropagateTransfer(e.transfer_proof.credit_proof()),
                                from: wallet_id, // not really, but doesn't matter here
                                to: index_of(wallet_id, self.replica_group, network),
                            });
                            // --> // println!("-- Replica SENT event {}", id);
                        }
                        _ => return,
                    }
                }
                Cmd::PropagateTransfer(proof) => {
                    match self.replica.receive_propagated(&proof, || None) {
                        Err(e) => {
                            //println!("-- // -- // Replica {} REJECTED cmd {}, due to: {} // -- // -- ", self.id(), cmd_id, e);
                        }
                        Ok(Some(e)) => {
                            let event = ReplicaEvent::TransferPropagated(e.clone());
                            // -- Apply the event! --
                            self.replica.apply(event.clone());
                            // let id = e.id();
                            // --> // println!("-- Replica sending event {:?}", event);
                            // network.msg_queue.push_back(Msg::Event {
                            //     event,
                            //     //from: self.replica_group,
                            //     to: e.credit_proof.recipient(),
                            // });
                            // --> // println!("-- Replica SENT event {}", id);
                        }
                        _ => return,
                    }
                }
            };
        }
    }

    fn index_of(wallet_id: PublicKey, current: ReplicaIndex, network: &Network) -> usize {
        for group in &network.replica_groups {
            if group
                .replicas
                .iter()
                .any(|r| r.wallet(&wallet_id).is_some())
            {
                return group.index;
            }
        }
        // since we remove from the vec in order to mut operate on it,
        // the group won't be found in there if the wallet belongs to current group
        current
    }

    #[derive(Debug)]
    struct ReplicaGroup {
        index: ReplicaIndex,
        id: PublicKeySet,
        replicas: Vec<TestReplica>,
    }

    #[derive(Debug, Clone)]
    struct ReplicaGroupKeys {
        index: ReplicaIndex,
        id: PublicKeySet,
        keys: Vec<(SecretKeyShare, usize)>,
    }

    // Real requirement for shuffle
    trait LenAndSwap {
        fn len(&self) -> usize;
        fn swap(&mut self, i: usize, j: usize);
    }

    // An exact copy of rand::Rng::shuffle, with the signature modified to
    // accept any type that implements LenAndSwap
    fn shuffle<T, R>(values: &mut T, mut rng: R)
    where
        T: LenAndSwap,
        R: Rng,
    {
        let mut i = values.len();
        while i >= 2 {
            // invariant: elements with index >= i have been locked in place.
            i -= 1;
            // lock element i in place.
            values.swap(i, rng.gen_range(0, i + 1));
        }
    }

    // VecDeque trivially fulfills the LenAndSwap requirement, but
    // we have to spell it out.
    impl<T> LenAndSwap for VecDeque<T> {
        fn len(&self) -> usize {
            self.len()
        }
        fn swap(&mut self, i: usize, j: usize) {
            self.swap(i, j)
        }
    }
}
