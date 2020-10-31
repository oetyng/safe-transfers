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
    CreditAgreementProof, CreditId, DebitId, Error, Money, PublicKey, ReplicaEvent, Result,
    SignedCredit, SignedDebit, TransferAgreementProof, TransferValidated,
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
/// upon the reginetworkion of them from another
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
mod test {
    use crate::{
        actor::Actor, genesis, replica::Replica, wallet::WalletSnapshot, ActorEvent, ReplicaEvent,
        ReplicaValidator, SignedCredit, SignedDebit, TransferInitiated, Wallet,
    };
    use crdts::{
        quickcheck::{quickcheck, TestResult},
        Dot,
    };
    use prop::test_runner::*;
    use proptest::prelude::*;
    use rand::RngCore;
    use rand::{Rng, SeedableRng};
    use sn_data_types::{
        Credit, CreditAgreementProof, CreditId, Debit, Keypair, Money, PublicKey, Result, Transfer,
        TransferAgreementProof,
    };
    use std::collections::{HashMap, HashSet};
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
    fn single_wallet_test() {
        let seed = 3;
        let num_transfers = 20;
        let replica_count = 7;
        let mut wallet_configs = HashMap::new();
        for i in 0..1 {
            let actors = vec![500, 400, 300, 200, 100];
            let _ = wallet_configs.insert(i, actors);
        }
        let mut network = get_network(seed, replica_count, wallet_configs);
        run_debit(num_transfers, &mut network);
        output(&mut network);
        verify(&mut network);
    }

    fn output(network: &mut Network) {
        for group in &mut network.replica_groups {
            println!("Replica group: {}", group.index);
            for replica in &group.replicas {
                for actor in &network.actors {
                    if let Some(balance) = replica.balance(&actor.id()) {
                        println!("Replica balance of actor {}: {}", actor.id(), balance.as_nano());
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

    // #[test]
    // fn basic_transfer() {
    //     let _ = transfer_between_actors(100, 10, 2, 3, 0, 1);
    // }

    // --------------------------------------------------------
    //   ----------------- Prop test ------------------------
    // --------------------------------------------------------

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 1,
            max_local_rejects: u32::MAX,
            verbose: 2,
            fork: false,
            .. ProptestConfig::default()
        })]

        #[test]
        fn basic(seed: u64, system: Vec<Vec<u64>>) { // Vec<Vec<u64>> -> ReplicaGroups, Actors and their balances
            //return Err(TestCaseError::Fail("Reason".into()));
            //return Err(TestCaseError::Reject("Reason".into()));
            let seed = 3;
            let max_sections = 1;
            let max_actors_in_section = 5;
            //prop_assume!(max_sections >= system.len());

            let replica_count = 7;
            let mut wallet_configs = HashMap::new();
            let mut system = system;
            for i in 0..1 { //system.len() {
                let actors = vec![500, 400, 300, 200, 100]; // system.remove(0);
                //prop_assume!(max_actors_in_section >= actors.len());
                let _ = wallet_configs.insert(i, actors);
            }
            let mut network = get_network(seed, replica_count, wallet_configs);
            let num_transfers = 20;//network.rng.gen_range(max_actors_in_section / 2, max_sections * max_actors_in_section);

            run_debit(num_transfers as u32, &mut network);
            verify(&mut network);
        }
    }

    fn verify(network: &Network) {
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

    fn run_debit(num_transfers: u32, network: &mut Network) {

        for i in 0..num_transfers {
            let sender_index = network.rng.gen_range(0, network.actors.len());
            let recipient_index = network.rng.gen_range(0, network.actors.len());
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

    fn synch(network: &mut Network) {
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
        while !network.msg_queue.is_empty() {
            let popped = network.msg_queue.pop_front();
            if popped.is_none() {
                break;
            }
            if let Some(next) = popped {
                match next {
                    Msg::Cmd { cmd, from, to } => {
                        let mut group = network.replica_groups.remove(to);
                        for replica in &mut group.replicas {
                            replica.handle(cmd.clone(), from, network);
                        }
                        let _ = network.replica_groups.insert(to, group);
                    }
                    Msg::Event { event, to } => {
                        for i in 0..network.actors.len() {
                            if network.actors[i].id() == to {
                                let mut actor = network.actors.remove(i);
                                actor.handle(event, network);
                                let _ = network.actors.insert(i, actor);
                                break;
                            }
                        }
                    }
                }
            }
            shuffle(&mut network.msg_queue, &mut network.rng);
        }
    }

    // ------------------------------------------------------------------------
    // ------------------------ Setup Helpers ---------------------------------
    // ------------------------------------------------------------------------

    fn get_genesis() -> Result<CreditAgreementProof> {
        let balance = u32::MAX as u64 * 1_000_000_000;
        let mut rng = rand::thread_rng();
        let threshold = 0;
        let bls_secret_key = SecretKeySet::random(threshold, &mut rng);
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
        let wallets: Vec<_> = wallet_configs
            .iter()
            .map(|(replica_group, balances)| {
                balances
                    .iter()
                    .map(|b| setup_wallet(*b, *replica_group))
                    .collect::<Vec<_>>()
            })
            .flatten()
            .collect();

        let group_count = wallet_configs.len();
        let group_keys = setup_replica_group_keys(group_count, replica_count);
        let mut replica_groups = setup_replica_groups(group_keys, wallets.clone());

        let actors = wallets
            .iter()
            .map(|wallet| setup_actor(wallet.clone(), &mut replica_groups))
            .collect();
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
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

    fn setup_wallet(balance: u64, replica_group: ReplicaIndex) -> TestWallet {
        let mut rng = rand::thread_rng();
        let keypair = Keypair::new_ed25519(&mut rng);
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
    fn setup_replica_group_keys(
        group_count: usize,
        replica_count: u8,
    ) -> HashMap<usize, ReplicaGroupKeys> {
        let mut rng = rand::thread_rng();
        let mut groups = HashMap::new();
        let threshold = (2 * replica_count / 3) - 1;
        for i in 0..group_count {
            let bls_secret_key = SecretKeySet::random(threshold as usize, &mut rng);
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
        let mut other_groups_keys = HashMap::new();
        for (i, _) in group_keys.clone() {
            let other = group_keys
                .clone()
                .into_iter()
                .filter(|(c, _)| *c != i)
                .map(|(_, group_keys)| group_keys.id)
                .collect::<HashSet<PublicKeySet>>();
            let _ = other_groups_keys.insert(i, other);
        }

        let mut replica_groups = vec![];
        for (i, other) in &other_groups_keys {
            let group_wallets = wallets
                .clone()
                .into_iter()
                .filter(|c| c.replica_group == *i)
                .map(|c| (c.wallet.id(), c.wallet))
                .collect::<HashMap<PublicKey, Wallet>>();

            let mut replicas = vec![];
            let group = group_keys[i].clone();
            for (secret_key, index) in group.keys {
                let peer_replicas = group.id.clone();
                let other_groups = other.clone();
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
                    replica_group: *i,
                });
            }
            replica_groups.push(ReplicaGroup {
                index: *i,
                id: group.id,
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
                        //     "Sending agreement reginetworkion for debit {}",
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
                ReplicaEvent::TransferRegistered(reginetworkion) => {
                    // println!(
                    //     "[ACTOR]: Received reginetworkion {:?}",
                    //     reginetworkion
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
            //let cmd_id = cmd.id();
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
                            network.msg_queue.push_back(Msg::Event {
                                event,
                                //from: self.id(),
                                to: from,
                            });
                            network.msg_queue.push_back(Msg::Cmd {
                                cmd: Cmd::PropagateTransfer(e.transfer_proof.credit_proof()),
                                from: e.transfer_proof.id().actor,
                                to: self.replica_group,
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
