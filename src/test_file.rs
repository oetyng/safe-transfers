use ed25519::{PublicKey, Signature};

pub fn verify_signature(data: &[u8], sig: &Signature, key: PublicKey) -> bool {
    key.verify_strict(data, sig).is_ok()
}

#[cfg(test)]
mod tests {
    use crate::{
        Outcome,
        actor::Actor, genesis, replica::Replica, ActorEvent, ReplicaEvent, ReplicaValidator,
        TransferInitiated, Wallet, SignedDebit, SignedCredit,
    };
    use crdts::{
        Dot,
    };
    use sn_data_types::{
        Credit, CreditAgreementProof, CreditId, Debit, Keypair, Money, PublicKey, Result, Transfer,
        TransferAgreementProof,
    };
    use std::collections::{HashMap, HashSet};
    use threshold_crypto::{PublicKeySet, SecretKey, SecretKeySet, SecretKeyShare};
    use anyhow::Result;
    use prop::test_runner::*;
    use proptest::prelude::*;
    use rand::{Rng, SeedableRng};
    use std::collections::VecDeque;
    

    type TestCaseResult = proptest::test_runner::TestCaseResult;

    #[test]
    fn single_wallet_test() {
        let replica_count = 7;
        let nr_debits = 5;
        let seed = 3;
        let mut strat = generate(replica_count, nr_debits, seed).unwrap();
        run_debit(&mut strat);
        output(&mut strat);
        sync(&mut strat);
        output(&mut strat);
        verify(&mut strat);
    }

    #[test]
    fn loop_through_args() {
        let replica_count = 7;
        let nr_debits = 5;
        let seed_max = 2555;

        let seeds: Vec<u64> = (0..seed_max).collect();
        //let debits: Vec<u8> = (1..nr_debits).collect();
        let mut converged = 0;
        let mut failed = 0;
        seeds.into_iter().for_each(|seed| {
            //debits.iter().for_each(|debits| {
            //println!("seed {}", seed);
            let mut strat = generate(replica_count, nr_debits, seed).unwrap();
            run_debit(&mut strat);
            //output(&mut strat);
            sync(&mut strat);
            //output(&mut strat);
            verify(&mut strat);
            if strat.converged {
                converged += 1;
            } else {
                failed += 1;
            }
            //});
        });
        println!("Converged {}, failed {}", converged, failed);
    }

    // --------------------------------------------------------
    //   ----------------- Prop test ------------------------
    // --------------------------------------------------------

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 20000,
            max_local_rejects: u32::MAX,
            verbose: 2,
            .. ProptestConfig::default()
        })]

        #[test]
        fn basic(seed: u64) { // nr_debits: u8,
            //return Err(TestCaseError::Fail("Reason".into()));
            //return Err(TestCaseError::Reject("Reason".into()));
            let nr_debits = 4;
            // prop_assume!(40 >= nr_debits);
            // prop_assume!(nr_debits > 0);

            let replica_count = 7;
            let mut strat = generate(replica_count, nr_debits, seed).unwrap();

            run_debit(&mut strat);
            output(&mut strat);
            sync(&mut strat);
            output(&mut strat);
            verify(&mut strat);
        }
    }

    // --------------------------------------------------------
    //   ----------------- Test logic ------------------------
    // --------------------------------------------------------

    fn run_debit(strat: &mut Strat) {
        // start debits
        for i in 0..strat.debit_instances.len() {
            let debit_instance = strat.debit_instances.remove(i);
            debit_instance.start(strat);
            strat.debit_instances.insert(i, debit_instance);
        }

        // process messages
        loop_msg_routing(strat);
    }

    fn generate(replica_count: u8, nr_debits: u8, seed: u64) -> Result<Strat> {
        let mut replicas = vec![];
        let mut debit_instances = vec![];

        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let nr_debits = nr_debits as u32;
        let balance = rng.gen_range(10 * nr_debits, 1000 * nr_debits);
        let debit_amounts: Vec<u64> = (0..nr_debits)
            .into_iter()
            .map(|_| rng.gen_range(1 + (balance / nr_debits / 10), 2 * balance / nr_debits) as u64)
            .collect();

        for i in 0..replica_count {
            let replica = Replica::from_snapshot(0, i as usize, (balance - 1) as u64);
            replicas.push(TestReplica::new(i as usize, replica));
        }
        for i in 0..debit_amounts.len() {
            let amount = debit_amounts[i];
            let debit_data = DebitData {
                id: i,
                amount,
                replica_count,
            };
            let debit_instance = DebitInstance::new(debit_data);
            debit_instances.push(debit_instance);
        }

        Ok(Strat {
            balance: balance as u64,
            replicas,
            debit_instances,
            rng,
            queue: Default::default(),
            converged: false,
        })
    }

    fn output(strat: &mut Strat) {
        // let mut metrics = vec![];
        // for replica in &mut strat.replicas {
        //     metrics.push(replica.metrics());
        // }

        // for metric in &metrics {
        //     println!(
        //         "END: Replica {}, balance {}, pending {}, available {}.",
        //         metric.id, metric.balance, metric.pending, metric.available
        //     );
        // }

        // println!(
        //     "Intended total debit amount: {}, wallet initial balance: {}",
        //     strat.balance,
        //     strat.balance - 1,
        // );
    }

    fn verify(strat: &mut Strat) {
        // let mut metrics = vec![];
        // for replica in &mut strat.replicas {
        //     metrics.push(replica.metrics());
        // }
        // let mut valid_count = 0;
        // let first = &metrics[0];
        // for i in 1..metrics.len() {
        //     let metric = &metrics[i];
        //     // assert_eq!(first.balance, metric.balance);
        //     // assert_eq!(first.pending, metric.pending);
        //     // assert_eq!(first.available, metric.available);
        //     let valid = first.balance == metric.balance
        //         && first.pending == metric.pending
        //         && first.available == metric.available;
        //     if valid {
        //         valid_count += 1;
        //     }
        // }
        // strat.converged = valid_count + 1 == metrics.len()
    }

    fn sync(strat: &mut Strat) {
        let all_agreed: Vec<(usize, HashMap<usize, AgreedDebit>)> = strat
            .replicas
            .iter()
            .map(|r| (r.id(), r.get_agreed()))
            .collect();
        for (id, agreed) in all_agreed {
            for replica in &mut strat.replicas {
                if id == replica.id() {
                    continue;
                }
                replica.sync(id, agreed.clone());
            }
        }
    }

    fn loop_msg_routing(strat: &mut Strat) {
        while !strat.queue.is_empty() {
            let popped = strat.queue.pop_front();
            if popped.is_none() {
                break;
            }
            if let Some(next) = popped {
                match next {
                    Msg::Cmd { cmd, from, to } => {
                        let mut replica = strat.replicas.remove(to);
                        replica.handle(cmd, from, strat);
                        strat.replicas.insert(to, replica);
                    }
                    Msg::Event { event, to, .. } => {
                        let mut debit_instance = strat.debit_instances.remove(to);
                        debit_instance.handle(event, strat);
                        strat.debit_instances.insert(to, debit_instance);
                    }
                }
            }
            shuffle(&mut strat.queue, &mut strat.rng);
        }
    }

    // --------------------------------------------------------
    //   ----------------- Models ------------------------
    // --------------------------------------------------------

    struct Metrics {
        id: usize,
        balance: u64,
        pending: u64,
        available: u64,
    }

    struct DebitData {
        id: usize,
        amount: u64,
        replica_count: u8,
    }

    struct Strat {
        balance: u64,
        replicas: Vec<TestReplica>,
        debit_instances: Vec<DebitInstance>,
        queue: VecDeque<Msg>,
        rng: rand::rngs::StdRng,
        converged: bool,
    }

    enum Msg {
        Cmd {
            cmd: Cmd,
            to: usize,
            from: usize,
        },
        Event {
            event: ReplicaEvent,
            to: usize,
            //from: usize,
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
    }

    impl Cmd {
        pub fn id(&self) -> String {
            match self {
                Cmd::ValidateDebit { signed_debit, signed_credit } => format!("ValidateDebit-{:?}", signed_debit.id()),
                Cmd::RegisterDebitAgreement(agreed) => {
                    format!("RegisterDebitAgreement-{:?}", agreed.id())
                }
            }
        }
    }

    // impl Event {
    //     pub fn id(&self) -> String {
    //         match self {
    //             Event::Validated(pending) => {
    //                 format!("Validated-{}-at-{}", pending.debit.id, pending.replica_id)
    //             }
    //             Event::Registered(registered) => format!(
    //                 "Registered-{}-at-{}",
    //                 registered.debit.debit.id, registered.replica_id
    //             ),
    //         }
    //     }
    // }

    struct TestReplica {
        id: usize,
        replica: Replica,
    }

    impl TestReplica {
        pub fn new(id: usize, replica: Replica) -> Self {
            Self { id, replica }
        }

        pub fn id(&self) -> usize {
            self.id
        }

        // pub fn metrics(&self) -> Metrics {
        //     Metrics {
        //         id: self.id(),
        //         balance: self.balance(),
        //         pending: self.pending(),
        //         available: self.available(),
        //     }
        // }

        pub fn balance(&self, id: &PublicKey) -> Option<Money> {
            self.replica.balance(id)
        }

        // pub fn pending(&self) -> u64 {
        //     self.replica.pending()
        // }

        // pub fn available(&self) -> u64 {
        //     self.replica.available()
        // }

        pub fn handle(&mut self, cmd: Cmd, from: usize, strat: &mut Strat) {
            let cmd_id = cmd.id();
            // -- Process the cmd. --
            let event = match cmd {
                Cmd::ValidateDebit { signed_debit, signed_credit } => self.validate(signed_debit, signed_credit),
                Cmd::RegisterDebitAgreement(agreed) => self.register(agreed),
            };
            match event {
                Err(e) => {
                    //println!("-- // -- // Replica {} REJECTED cmd {}, due to: {} // -- // -- ", self.id(), cmd_id, e);
                }
                Ok(e) => {
                    // -- Apply the event! --
                    self.apply(e.clone());

                    let id = e.id();
                    // --> // println!("-- Replica sending event {}", id);

                    strat.queue.push_back(Msg::Event {
                        event: e,
                        //from: self.id(),
                        to: from,
                    });

                    // --> // println!("-- Replica SENT event {}", id);
                }
            }
        }

        pub fn validate(&self, signed_debit: SignedDebit, signed_credit: SignedCredit ) -> Outcome<TransferValidated> {
            // println!(
            //     "Starting validation of debit nr {} (of $ {}) at replica nr {}",
            //     debit.id,
            //     debit.amount,
            //     self.replica.id()
            // );
            Ok(ReplicaEvent::TransferValidated(self.replica.validate(signed_debit, signed_credit)?))
        }

        pub fn register(&self, agreed: AgreedDebit) -> Result<Event> {
            // println!(
            //     "Starting registration of agreed debit nr {} (of $ {}) at replica nr {}",
            //     agreed.debit.id,
            //     agreed.debit.amount,
            //     self.replica.id()
            // );
            Ok(Event::Registered(self.replica.register(agreed)?))
        }

        pub fn apply(&mut self, event: Event) {
            self.replica.apply(event);
        }

        pub fn get_agreed(&self) -> HashMap<usize, AgreedDebit> {
            self.replica.applied()
        }

        pub fn sync(&mut self, from: usize, agreed: HashMap<usize, AgreedDebit>) {
            let existing = self.get_agreed();
            for (id, debit) in agreed {
                if existing.contains_key(&id) {
                    continue;
                }
                if self.replica.balance() >= debit.debit.amount {
                    self.replica.apply(Event::Registered(DebitRegistered {
                        debit,
                        replica_id: from,
                        removed_pending: vec![],
                    }));
                }
            }
            self.replica.clear_pending();
        }
    }

    struct DebitInstance {
        debit_data: DebitData,
        received: Vec<PendingDebit>,
        agreed: bool,
    }

    impl DebitInstance {
        pub fn new(debit_data: DebitData) -> Self {
            Self {
                debit_data,
                received: vec![],
                agreed: false,
            }
        }

        pub fn id(&self) -> usize {
            self.debit_data.id
        }

        pub fn start(&self, strat: &mut Strat) {
            // -- Send the first cmd. --
            for i in 0..strat.replicas.len() {
                strat.queue.push_back(Msg::Cmd {
                    cmd: Cmd::ValidateDebit(self.debit()),
                    from: self.debit_data.id,
                    to: i as usize,
                });
            }
        }

        pub fn handle(&mut self, event: Event, strat: &mut Strat) {
            let cmd = match event {
                Event::Validated(pending) => self.receive_validation(pending),
                Event::Registered(registration) => {
                    // println!(
                    //     "[ACTOR]: Received registration {} from {}. Happy!",
                    //     registration.debit.debit.id, registration.replica_id
                    // );
                    if !registration.removed_pending.is_empty() {
                        // --> // println!("[ACTOR]: Some pending were removed!!");
                    }
                    return;
                }
            };
            if let Some(agreed) = cmd {
                // println!(
                //     "Sending agreement registration for debit {}",
                //     agreed.debit.id
                // );
                // -- Send the cmd to the router. --
                for i in 0..strat.replicas.len() {
                    strat.queue.push_back(Msg::Cmd {
                        cmd: Cmd::RegisterDebitAgreement(agreed.clone()),
                        from: self.debit_data.id,
                        to: i as usize,
                    });
                }
            }
        }

        fn debit(&self) -> SolicitedDebit {
            // println!(
            //     "Starting debit nr {}, of $ {}",
            //     self.debit_data.id, self.debit_data.amount
            // );
            SolicitedDebit {
                id: self.debit_data.id,
                amount: self.debit_data.amount,
            }
        }

        fn receive_validation(&mut self, pending: PendingDebit) -> Option<AgreedDebit> {
            let debit_id = pending.debit.id;
            let replica_id = pending.replica_id;
            // println!(
            //     "Receiving validation.. Debit {} from replica {}",
            //     debit_id, replica_id
            // );
            let debit = pending.debit.clone();
            self.received.push(pending);
            if !self.agreed && 2 * self.received.len() > self.debit_data.replica_count as usize {
                self.agreed = true;
                // println!(
                //     "Agreement reached! Debit: {} from replica {}",
                //     debit_id, replica_id
                // );
                Some(AgreedDebit { debit })
            } else {
                None
            }
        }
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
        R: rand::Rng,
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

    fn get_network(
        group_count: u8,
        replica_count: u8,
        wallet_configs: HashMap<u8, u64>,
    ) -> (Vec<ReplicaGroup>, HashMap<u8, TestActor>) {
        let wallets: Vec<_> = wallet_configs
            .iter()
            .map(|(index, balance)| setup_wallet(*balance, *index))
            .collect();

        let group_keys = setup_replica_group_keys(group_count, replica_count);
        let mut replica_groups = setup_replica_groups(group_keys, wallets.clone());

        let actors: HashMap<_, _> = wallets
            .iter()
            .map(|a| (a.replica_group, setup_actor(a.clone(), &mut replica_groups)))
            .collect();

        (replica_groups, actors)
    }

    fn find_group(index: u8, replica_groups: &mut Vec<ReplicaGroup>) -> Option<&mut ReplicaGroup> {
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

    fn setup_wallet(balance: u64, replica_group: u8) -> TestWallet {
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
        let replica_group = find_group(wallet.replica_group, replica_groups)
            .unwrap()
            .clone();

        let actor = Actor::from_snapshot(
            wallet.wallet,
            wallet.keypair,
            replica_group.id.clone(),
            Validator {},
        );

        TestActor {
            actor,
            replica_group,
        }
    }

    // Create n replica groups, with k replicas in each
    fn setup_replica_group_keys(
        group_count: u8,
        replica_count: u8,
    ) -> HashMap<u8, ReplicaGroupKeys> {
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
        group_keys: HashMap<u8, ReplicaGroupKeys>,
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
                replicas.push(replica);
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

    #[derive(Debug, Clone)]
    struct TestWallet {
        wallet: Wallet,
        keypair: Keypair,
        replica_group: u8,
    }

    #[derive(Debug, Clone)]
    struct TestActor {
        actor: Actor<Validator>,
        replica_group: ReplicaGroup,
    }

    #[derive(Debug, Clone)]
    struct ReplicaGroup {
        index: u8,
        id: PublicKeySet,
        replicas: Vec<Replica>,
    }

    #[derive(Debug, Clone)]
    struct ReplicaGroupKeys {
        index: u8,
        id: PublicKeySet,
        keys: Vec<(SecretKeyShare, usize)>,
    }
}
