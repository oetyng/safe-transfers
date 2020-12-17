// // Copyright 2020 MaidSafe.net limited.
// //
// // This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// // Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// // under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// // KIND, either express or implied. Please review the Licences for the specific language governing
// // permissions and limitations relating to use of the SAFE Network Software.

// use super::{
//     wallet::{Wallet, WalletSnapshot},
//     Outcome, TernaryResult,
// };
// use log::debug;
// #[cfg(feature = "simulated-payouts")]
// use sn_data_types::Credit;
// use sn_data_types::{
//     CreditAgreementProof, Debit, Error, KnownGroupAdded, Money, PublicKey, ReplicaEvent, Result,
//     SignatureShare, SignedCredit, SignedDebit, TransferAgreementProof, TransferPropagated,
//     TransferRegistered, TransferValidated,
// };
// use std::collections::{HashMap, HashSet};
// use threshold_crypto::{PublicKeySet, PublicKeyShare, SecretKeyShare};

// /// The Replica is the part of an AT2 system
// /// that forms validating groups, and signs
// /// individual transfers between wallets.
// /// Replicas validate requests to debit an wallet, and
// /// apply operations that has a valid "debit agreement proof"
// /// from the group, i.e. signatures from a quorum of its peers.
// /// Replicas don't initiate transfers or drive the algo - only Actors do.
// #[derive(Debug, Clone, PartialEq, Eq)]
// pub struct Replica {
//     /// The public key share of this Replica.
//     id: PublicKeyShare,
//     /// Secret key share.
//     secret_key: SecretKeyShare,
//     /// The index of this Replica key share, in the group set.
//     key_index: usize,
//     /// The PK set of our peer Replicas.
//     peer_replicas: PublicKeySet,
//     /// PK sets of other known groups of Replicas.
//     other_groups: HashSet<PublicKeySet>,
//     /// All wallets that this Replica validates transfers for.
//     wallets: HashMap<PublicKey, Wallet>,
//     /// Ensures that invidual wallet's debit
//     /// initiations (ValidateTransfer cmd) are sequential.
//     pending_debits: HashMap<PublicKey, u64>,
// }

// impl Replica {
//     /// A new Replica instance from a history of events.
//     pub fn from_history(
//         secret_key: SecretKeyShare,
//         key_index: usize,
//         peer_replicas: PublicKeySet,
//         events: Vec<ReplicaEvent>,
//     ) -> Result<Replica> {
//         let mut instance = Replica::from_snapshot(
//             secret_key,
//             key_index,
//             peer_replicas,
//             Default::default(),
//             Default::default(),
//             Default::default(),
//         );
//         for e in events {
//             instance.apply(e)?;
//         }
//         Ok(instance)
//     }

//     /// A new Replica instance from current state.
//     pub fn from_snapshot(
//         secret_key: SecretKeyShare,
//         key_index: usize,
//         peer_replicas: PublicKeySet,
//         other_groups: HashSet<PublicKeySet>,
//         wallets: HashMap<PublicKey, Wallet>,
//         pending_debits: HashMap<PublicKey, u64>,
//     ) -> Replica {
//         let id = secret_key.public_key_share();
//         Replica {
//             secret_key,
//             id,
//             key_index,
//             peer_replicas,
//             other_groups,
//             wallets,
//             pending_debits,
//         }
//     }

//     /// -----------------------------------------------------------------
//     /// ---------------------- Queries ----------------------------------
//     /// -----------------------------------------------------------------

//     ///
//     pub fn balance(&self, wallet_id: &PublicKey) -> Option<Money> {
//         let result = self.wallets.get(wallet_id);
//         match result {
//             None => None,
//             Some(history) => Some(history.balance()),
//         }
//     }

//     /// Get the replica's PK set
//     pub fn replicas_pk_set(&self) -> Option<PublicKeySet> {
//         Some(self.peer_replicas.clone())
//     }

//     ///
//     pub fn wallet(&self, wallet_id: &PublicKey) -> Option<WalletSnapshot> {
//         let wallet = self.wallets.get(wallet_id)?.to_owned();
//         Some(wallet.into())
//     }

//     /// -----------------------------------------------------------------
//     /// ---------------------- Cmds -------------------------------------
//     /// -----------------------------------------------------------------

//     /// This is the one and only infusion of money to the system. Ever.
//     /// It is carried out by the first node in the network.
//     pub fn genesis<F: FnOnce() -> Option<PublicKey>>(
//         &self,
//         credit_proof: &CreditAgreementProof,
//         f: F,
//     ) -> Outcome<TransferPropagated> {
//         // Genesis must be the first wallet.
//         if !self.wallets.is_empty() {
//             return Err(Error::InvalidOperation);
//         }
//         self.receive_propagated(credit_proof, f)
//     }

//     /// Adds a PK set for a a new group that we learn of.
//     pub fn add_known_group(&self, group: PublicKeySet) -> Outcome<KnownGroupAdded> {
//         if self.other_groups.contains(&group) {
//             return Err(Error::DataExists);
//         }
//         Outcome::success(KnownGroupAdded { group })
//     }

//     /// For now, with test money there is no from wallet.., money is created from thin air.
//     pub fn test_validate_transfer(
//         &self,
//         signed_debit: SignedDebit,
//         signed_credit: SignedCredit,
//     ) -> Outcome<TransferValidated> {
//         if signed_debit.sender() == signed_credit.recipient() {
//             Err(Error::from("Sender and recipient are the same."))
//         } else if signed_credit.id() != &signed_debit.credit_id()? {
//             Err(Error::from("The credit does not correspond to the debit."))
//         } else if signed_credit.amount() != signed_debit.amount() {
//             Err(Error::from("Amounts must be equal."))
//         } else {
//             let replica_debit_sig = match self.sign_validated_debit(&signed_debit) {
//                 Err(_) => return Err(Error::InvalidSignature),
//                 Ok(replica_signature) => replica_signature,
//             };
//             let replica_credit_sig = match self.sign_validated_credit(&signed_credit) {
//                 Err(_) => return Err(Error::InvalidSignature),
//                 Ok(replica_signature) => replica_signature,
//             };
//             Outcome::success(TransferValidated {
//                 signed_debit,
//                 signed_credit,
//                 replica_debit_sig,
//                 replica_credit_sig,
//                 replicas: self.peer_replicas.clone(),
//             })
//         }
//     }

//     /// Step 1. Main business logic validation of a debit.
//     pub fn validate(
//         &self,
//         signed_debit: SignedDebit,
//         signed_credit: SignedCredit,
//     ) -> Outcome<TransferValidated> {
//         debug!("Checking TransferValidated");
//         let debit = &signed_debit.debit;
//         let credit = &signed_credit.credit;

//         // Always verify signature first! (as to not leak any information).
//         if self
//             .verify_actor_signature(&signed_debit, &signed_credit)
//             .is_err()
//         {
//             return Outcome::rejected(Error::InvalidSignature);
//         } else if debit.sender() == credit.recipient() {
//             return Outcome::rejected(Error::from("Sender and recipient are the same."));
//         } else if credit.id() != &debit.credit_id()? {
//             return Outcome::rejected(Error::from("The credit does not correspond to the debit."));
//         } else if credit.amount() != debit.amount() {
//             return Outcome::rejected(Error::from("Amounts must be equal."));
//         } else if debit.amount() == Money::zero() {
//             return Outcome::rejected(Error::Unexpected(
//                 "Transfer amount must be more than zero.".to_string(),
//             ));
//         } else if !self.wallets.contains_key(&debit.sender()) {
//             return Outcome::rejected(Error::NoSuchSender);
//         }
//         match self.pending_debits.get(&debit.sender()) {
//             None => {
//                 if debit.id.counter != 0 {
//                     return Outcome::rejected(Error::from(
//                         "out of order msg, actor's counter should be 0",
//                     ));
//                 }
//             }
//             Some(value) => {
//                 if debit.id.counter != (value + 1) {
//                     return Outcome::rejected(Error::from(format!(
//                         "out of order msg, previous count: {:?}",
//                         value
//                     )));
//                 }
//             }
//         }
//         match self.balance(&debit.sender()) {
//             Some(balance) => {
//                 if debit.amount() > balance {
//                     return Outcome::rejected(Error::InsufficientBalance);
//                 }
//             }
//             None => return Outcome::rejected(Error::NoSuchSender),
//         }

//         let replica_debit_sig = match self.sign_validated_debit(&signed_debit) {
//             Err(_) => return Outcome::rejected(Error::InvalidSignature),
//             Ok(replica_signature) => replica_signature,
//         };
//         let replica_credit_sig = match self.sign_validated_credit(&signed_credit) {
//             Err(_) => return Outcome::rejected(Error::InvalidSignature),
//             Ok(replica_signature) => replica_signature,
//         };

//         Outcome::success(TransferValidated {
//             signed_debit,
//             signed_credit,
//             replica_debit_sig,
//             replica_credit_sig,
//             replicas: self.peer_replicas.clone(),
//         })
//     }

//     /// Step 2. Validation of agreement, and order at debit source.
//     pub fn register<F: FnOnce() -> bool>(
//         &self,
//         transfer_proof: &TransferAgreementProof,
//         f: F,
//     ) -> Outcome<TransferRegistered> {
//         debug!("Checking registered transfer");

//         // Always verify signature first! (as to not leak any information).
//         if self.verify_registered_proof(transfer_proof, f).is_err() {
//             return Outcome::rejected(Error::InvalidSignature);
//         }

//         let debit = &transfer_proof.signed_debit.debit;
//         let sender = self.wallets.get(&transfer_proof.sender());
//         match sender {
//             None => Outcome::rejected(Error::NoSuchSender),
//             Some(history) => {
//                 if history.next_debit() == debit.id().counter {
//                     Outcome::success(TransferRegistered {
//                         transfer_proof: transfer_proof.clone(),
//                     })
//                 } else {
//                     Outcome::rejected(Error::InvalidOperation) // from this place this code won't happen, but history validates the transfer is actually debits from it's owner.
//                 }
//             }
//         }
//     }

//     /// Step 3. Validation of TransferAgreementProof, and credit idempotency at credit destination.
//     /// (Since this leads to a credit, there is no requirement on order.)
//     pub fn receive_propagated<F: FnOnce() -> Option<PublicKey>>(
//         &self,
//         credit_proof: &CreditAgreementProof,
//         f: F,
//     ) -> Outcome<TransferPropagated> {
//         // Always verify signature first! (as to not leak any information).
//         let _debiting_replicas = self.verify_propagated_proof(credit_proof, f)?;
//         let already_exists = match self.wallets.get(&credit_proof.recipient()) {
//             None => false,
//             Some(history) => history.contains(&credit_proof.id()),
//         };
//         if already_exists {
//             Outcome::no_change()
//         } else {
//             match self.sign_credit_proof(&credit_proof) {
//                 Err(_) => Outcome::rejected(Error::InvalidSignature),
//                 Ok(crediting_replica_sig) => Outcome::success(TransferPropagated {
//                     credit_proof: credit_proof.clone(),
//                     crediting_replica_sig,
//                     crediting_replica_keys: PublicKey::Bls(self.peer_replicas.public_key()),
//                 }),
//             }
//         }
//     }

//     /// -----------------------------------------------------------------
//     /// ---------------------- Mutation ---------------------------------
//     /// -----------------------------------------------------------------

//     /// Mutation of state.
//     /// There is no validation of an event, it (the cmd) is assumed to have
//     /// been properly validated before the fact is established (event raised),
//     /// and thus anything that breaks here, is a bug in the validation..
//     pub fn apply(&mut self, event: ReplicaEvent) -> Result<()> {
//         match event {
//             ReplicaEvent::KnownGroupAdded(e) => {
//                 let _ = self.other_groups.insert(e.group);
//                 Ok(())
//             }
//             ReplicaEvent::TransferValidated(e) => {
//                 let debit = e.signed_debit.debit;
//                 let _ = self.pending_debits.insert(debit.id.actor, debit.id.counter);
//                 Ok(())
//             }
//             ReplicaEvent::TransferRegistered(e) => {
//                 let debit = e.transfer_proof.signed_debit.debit;
//                 match self.wallets.get_mut(&debit.id.actor) {
//                     None => return Err(Error::from("")),
//                     Some(wallet) => wallet.apply_debit(Debit {
//                         id: debit.id(),
//                         amount: debit.amount(),
//                     })?,
//                 }
//                 Ok(())
//             }
//             ReplicaEvent::TransferPropagated(e) => {
//                 let credit = e.credit_proof.signed_credit.credit;
//                 match self.wallets.get_mut(&credit.recipient()) {
//                     Some(wallet) => wallet.apply_credit(credit)?,
//                     None => {
//                         // Creates if not exists.
//                         let mut wallet = Wallet::new(credit.recipient());
//                         wallet.apply_credit(credit.clone())?;
//                         let _ = self.wallets.insert(credit.recipient(), wallet);
//                     }
//                 };
//                 Ok(())
//             }
//         }
//     }

//     /// Test-helper API to simulate Client CREDIT Transfers.
//     #[cfg(feature = "simulated-payouts")]
//     pub fn credit_without_proof(&mut self, credit: Credit) -> Result<()> {
//         match self.wallets.get_mut(&credit.recipient()) {
//             Some(wallet) => wallet.simulated_credit(credit),
//             None => {
//                 // Creates if it doesn't exist.
//                 let mut wallet = Wallet::new(credit.recipient());
//                 wallet.simulated_credit(credit.clone())?;
//                 let _ = self.wallets.insert(credit.recipient(), wallet);
//                 Ok(())
//             }
//         }
//     }

//     /// Test-helper API to simulate Client DEBIT Transfers.
//     #[cfg(feature = "simulated-payouts")]
//     pub fn debit_without_proof(&mut self, debit: Debit) -> Result<()> {
//         match self.wallets.get_mut(&debit.id.actor) {
//             Some(wallet) => wallet.simulated_debit(debit),
//             None => Err(Error::Unexpected(format!(
//                 "Cannot debit from a non-existing wallet. this transfer caused the problem: {:?}",
//                 debit
//             ))),
//         }
//     }

//     /// -----------------------------------------------------------------
//     /// ---------------------- Private methods --------------------------
//     /// -----------------------------------------------------------------

//     ///
//     fn sign_validated_debit(&self, debit: &SignedDebit) -> Result<SignatureShare> {
//         match bincode::serialize(debit) {
//             Err(_) => Err(Error::NetworkOther("Could not serialise debit".into())),
//             Ok(data) => Ok(SignatureShare {
//                 index: self.key_index,
//                 share: self.secret_key.sign(data),
//             }),
//         }
//     }

//     ///
//     fn sign_validated_credit(&self, credit: &SignedCredit) -> Result<SignatureShare> {
//         match bincode::serialize(credit) {
//             Err(_) => Err(Error::NetworkOther("Could not serialise credit".into())),
//             Ok(data) => Ok(SignatureShare {
//                 index: self.key_index,
//                 share: self.secret_key.sign(data),
//             }),
//         }
//     }

//     fn sign_credit_proof(&self, proof: &CreditAgreementProof) -> Result<SignatureShare> {
//         match bincode::serialize(proof) {
//             Err(_) => Err(Error::NetworkOther("Could not serialise proof".into())),
//             Ok(data) => Ok(SignatureShare {
//                 index: self.key_index,
//                 share: self.secret_key.sign(data),
//             }),
//         }
//     }

//     ///
//     fn verify_actor_signature(
//         &self,
//         signed_debit: &SignedDebit,
//         signed_credit: &SignedCredit,
//     ) -> Result<()> {
//         let debit = &signed_debit.debit;
//         let credit = &signed_credit.credit;
//         let debit_bytes = match bincode::serialize(&debit) {
//             Err(_) => return Err(Error::NetworkOther("Could not serialise debit".into())),
//             Ok(bytes) => bytes,
//         };
//         let credit_bytes = match bincode::serialize(&credit) {
//             Err(_) => return Err(Error::NetworkOther("Could not serialise credit".into())),
//             Ok(bytes) => bytes,
//         };
//         let valid_debit = signed_debit
//             .sender()
//             .verify(&signed_debit.actor_signature, debit_bytes)
//             .is_ok();
//         let valid_credit = signed_debit
//             .sender()
//             .verify(&signed_credit.actor_signature, credit_bytes)
//             .is_ok();

//         if valid_debit && valid_credit && credit.id() == &debit.credit_id()? {
//             Ok(())
//         } else {
//             Err(Error::InvalidSignature)
//         }
//     }

//     /// Verify that this is a valid _registered_
//     /// TransferAgreementProof, i.e. signed by our peers.
//     fn verify_registered_proof<F: FnOnce() -> bool>(
//         &self,
//         proof: &TransferAgreementProof,
//         f: F,
//     ) -> Result<()> {
//         if proof.signed_credit.id() != &proof.signed_debit.credit_id()? {
//             return Err(Error::NetworkOther(
//                 "Credit does not correspond with the debit.".into(),
//             ));
//         }
//         // Check that the proof corresponds to a public key set of our peers.
//         let debit_bytes = match bincode::serialize(&proof.signed_debit) {
//             Ok(bytes) => bytes,
//             Err(_) => return Err(Error::NetworkOther("Could not serialise transfer".into())),
//         };
//         let credit_bytes = match bincode::serialize(&proof.signed_credit) {
//             Ok(bytes) => bytes,
//             Err(_) => return Err(Error::NetworkOther("Could not serialise transfer".into())),
//         };
//         // Check if proof is signed by our peers.
//         let public_key = sn_data_types::PublicKey::Bls(self.peer_replicas.public_key());
//         let valid_debit = public_key.verify(&proof.debit_sig, &debit_bytes).is_ok();
//         let valid_credit = public_key.verify(&proof.credit_sig, &credit_bytes).is_ok();
//         if valid_debit && valid_credit {
//             return Ok(());
//         }
//         // Check if proof is signed with an older key
//         if f() {
//             return Ok(());
//         }

//         // If it's not signed with our peers' public key, we won't consider it valid.
//         Err(Error::InvalidSignature)
//     }

//     /// Verify that this is a valid _propagated_
//     /// TransferAgreementProof, i.e. signed by a group that we know of.
//     fn verify_propagated_proof<F: FnOnce() -> Option<PublicKey>>(
//         &self,
//         proof: &CreditAgreementProof,
//         f: F,
//     ) -> Result<PublicKey> {
//         // Check that the proof corresponds to a public key set of some Replicas.
//         match bincode::serialize(&proof.signed_credit) {
//             Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
//             Ok(data) => {
//                 // Check if it is from our group.
//                 let our_key = sn_data_types::PublicKey::Bls(self.peer_replicas.public_key());
//                 if our_key.verify(&proof.debiting_replicas_sig, &data).is_ok() {
//                     return Ok(our_key);
//                 }

//                 // Check if it was previously a part of our group
//                 if let Some(our_past_key) = f() {
//                     return Ok(our_past_key);
//                 }

//                 // TODO: Check retrospectively(using SectionProofChain) for known groups also
//                 // Check all known groups of Replicas.
//                 for set in &self.other_groups {
//                     let debiting_replicas = sn_data_types::PublicKey::Bls(set.public_key());
//                     let result = debiting_replicas.verify(&proof.debiting_replicas_sig, &data);
//                     if result.is_ok() {
//                         return Ok(debiting_replicas);
//                     }
//                 }
//                 // If we don't know the public key this was signed with, we won't consider it valid.
//                 Err(Error::InvalidSignature)
//             }
//         }
//     }
// }
