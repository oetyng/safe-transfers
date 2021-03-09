// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod signing_actor;

use super::{
    wallet::Wallet, ActorEvent, Error, ReplicaValidator, Result, TransferRegistrationSent,
    TransferValidated, TransferValidationReceived, TransfersSynched,
};
use crate::StateSynched;
use crdts::Dot;
use itertools::Itertools;
use log::debug;
use sn_data_types::{
    ActorHistory, Credit, CreditAgreementProof, CreditId, Debit, DebitId, OwnerType, PublicKey,
    SignatureShare, SignedCredit, SignedDebit, Token, TransferAgreementProof, WalletInfo,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use threshold_crypto::PublicKeySet;

/// The Actor is the part of an AT2 system
/// that initiates transfers, by requesting Replicas
/// to validate them, and then receive the proof of agreement.
/// It also syncs transfers from the Replicas.
#[derive(Clone)]
pub struct ReadOnlyActor<V: ReplicaValidator> {
    ///
    id: OwnerType,
    /// Set of all transfers impacting a given identity
    wallet: Wallet,
    /// Ensures that the actor's transfer
    /// initiations (ValidateTransfer cmd) are sequential.
    next_expected_debit: u64,
    /// When a transfer is initiated, validations are accumulated here.
    /// After quorum is reached and proof produced, the set is cleared.
    accumulating_validations: HashMap<DebitId, HashMap<usize, TransferValidated>>,
    /// The PK Set of the Replicas
    replicas: PublicKeySet,
    /// The passed in replica_validator, contains the logic from upper layers
    /// for determining if a remote group of Replicas, represented by a PublicKey, is indeed valid.
    replica_validator: V,
    /// A log of applied events.
    history: ActorHistory,
}

impl<V: ReplicaValidator> ReadOnlyActor<V> {
    /// Use this ctor for a new instance,
    /// or to rehydrate from events ([see the synch method](Actor::synch)).
    /// Pass in the key set of the replicas of this actor, i.e. our replicas.
    /// Credits to our wallet are most likely debited at other replicas than our own (the sender's replicas),
    /// The replica_validator lets upper layer decide how to validate those remote replicas (i.e. not our replicas).
    /// If upper layer trusts them, the validator might do nothing but return "true".
    /// If it wants to execute some logic for verifying that the remote replicas are in fact part of the system,
    /// before accepting credits, it then implements that in the replica_validator.
    pub fn new(id: OwnerType, replicas: PublicKeySet, replica_validator: V) -> ReadOnlyActor<V> {
        let wallet = Wallet::new(id.clone());
        ReadOnlyActor {
            id,
            replicas,
            replica_validator,
            wallet,
            next_expected_debit: 0,
            accumulating_validations: Default::default(),
            history: ActorHistory::empty(),
        }
    }

    ///
    pub fn from_info(
        id: OwnerType,
        info: WalletInfo,
        replica_validator: V,
    ) -> Result<ReadOnlyActor<V>> {
        let mut actor = Self::new(id, info.replicas, replica_validator);
        match actor.from_history(info.history) {
            Ok(event) => actor.apply(ActorEvent::TransfersSynched(event))?,
            Err(error) => {
                match error {
                    Error::InvalidActorHistory => {
                        // do nothing
                    }
                    _ => return Err(error),
                }
            }
        }

        Ok(actor)
    }

    /// Temp, for test purposes
    pub fn from_snapshot(
        wallet: Wallet,
        replicas: PublicKeySet,
        replica_validator: V,
    ) -> ReadOnlyActor<V> {
        let id = wallet.id().clone();
        ReadOnlyActor {
            id,
            replicas,
            replica_validator,
            wallet,
            next_expected_debit: 0,
            accumulating_validations: Default::default(),
            history: ActorHistory::empty(),
        }
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Queries ----------------------------------
    /// -----------------------------------------------------------------

    /// Query for the id of the Actor.
    pub fn id(&self) -> PublicKey {
        self.id.public_key()
    }

    /// Query for the id of the Actor.
    pub fn owner(&self) -> &OwnerType {
        &self.id
    }

    /// Query for the balance of the Actor.
    pub fn balance(&self) -> Token {
        self.wallet.balance()
    }

    ///
    pub fn replicas_public_key(&self) -> PublicKey {
        PublicKey::Bls(self.replicas.public_key())
    }

    ///
    pub fn replicas_key_set(&self) -> PublicKeySet {
        self.replicas.clone()
    }

    /// History of credits and debits
    pub fn history(&self) -> ActorHistory {
        self.history.clone()
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Cmds -------------------------------------
    /// -----------------------------------------------------------------

    /// Step 1. Build a valid cmd for validation of a debit.
    pub fn transfer(
        &self,
        amount: Token,
        recipient: PublicKey,
        msg: String,
    ) -> Result<(Debit, Credit)> {
        if recipient == self.id() {
            return Err(Error::SameSenderAndRecipient);
        }

        let id = Dot::new(self.id(), self.wallet.next_debit());

        // ensures one debit is completed at a time
        if self.next_expected_debit != self.wallet.next_debit() {
            return Err(Error::DebitPending);
        }
        if self.next_expected_debit != id.counter {
            return Err(Error::DebitProposed);
        }
        if amount > self.balance() {
            return Err(Error::InsufficientBalance);
        }

        if amount == Token::from_nano(0) {
            return Err(Error::ZeroValueTransfer);
        }

        let debit = Debit { id, amount };
        let credit = Credit {
            id: debit.credit_id()?,
            recipient,
            amount,
            msg,
        };

        Ok((debit, credit))
    }

    /// Step 2. Receive validations from Replicas, aggregate the signatures.
    pub fn receive(&self, validation: TransferValidated) -> Result<TransferValidationReceived> {
        // Always verify signature first! (as to not leak any information).
        if self.verify(&validation).is_err() {
            debug!(">>>>SIG NOT VALID");
            return Err(Error::InvalidSignature);
        }
        debug!(">>>>Actor: Verified validation.");

        let signed_debit = &validation.signed_debit;
        let signed_credit = &validation.signed_credit;

        // check if credit and debit correspond
        if signed_credit.id() != &signed_debit.credit_id()? {
            return Err(Error::CreditDebitIdMismatch);
        }
        // check if validation was initiated by this actor
        if self.id() != signed_debit.sender() {
            return Err(Error::WrongValidationActor);
        }
        // check if expected this validation
        if self.next_expected_debit != signed_debit.id().counter + 1 {
            return Err(Error::OperationOutOfOrder(
                signed_debit.id().counter,
                self.next_expected_debit,
            ));
        }
        // check if already received
        if let Some(map) = self.accumulating_validations.get(&validation.id()) {
            if map.contains_key(&validation.replica_debit_sig.index) {
                return Err(Error::ValidatedAlready);
            }
        } else {
            return Err(Error::NoSetForDebitId(validation.id()));
        }

        debug!(">>>>>>AFTER THE CHECKS");

        // TODO: Cover scenario where replica keys might have changed during an ongoing transfer.
        let map = self
            .accumulating_validations
            .get(&validation.id())
            .ok_or_else(|| Error::NoSetForTransferId(validation.id()))?;

        let mut proof = None;

        // If the previous count of accumulated + current validation coming in here,
        // is greater than the threshold, then we have reached the quorum needed
        // to build the proof. (Quorum = threshold + 1)
        let majority =
            map.len() + 1 > self.replicas.threshold() && self.replicas == validation.replicas;
        if majority {
            let debit_bytes = match bincode::serialize(&signed_debit) {
                Err(_) => return Err(Error::Serialisation("Serialization Error".to_string())),
                Ok(data) => data,
            };
            let credit_bytes = match bincode::serialize(&signed_credit) {
                Err(_) => return Err(Error::Serialisation("Serialization Error".to_string())),
                Ok(data) => data,
            };

            // collect sig shares
            let debit_sig_shares: BTreeMap<_, _> = map
                .values()
                .chain(vec![&validation])
                .map(|v| v.replica_debit_sig.clone())
                .map(|s| (s.index, s.share))
                .collect();
            // collect sig shares
            let credit_sig_shares: BTreeMap<_, _> = map
                .values()
                .chain(vec![&validation])
                .map(|v| v.replica_credit_sig.clone())
                .map(|s| (s.index, s.share))
                .collect();

            // Combine shares to produce the main signature.
            let debit_sig = self
                .replicas
                .combine_signatures(&debit_sig_shares)
                .map_err(|_| Error::CannotAggregate)?;
            // Combine shares to produce the main signature.
            let credit_sig = self
                .replicas
                .combine_signatures(&credit_sig_shares)
                .map_err(|_| Error::CannotAggregate)?;

            let valid_debit = self.replicas.public_key().verify(&debit_sig, debit_bytes);
            let valid_credit = self.replicas.public_key().verify(&credit_sig, credit_bytes);

            // Validate the combined signatures. If the shares were valid, this can't fail.
            if valid_debit && valid_credit {
                proof = Some(TransferAgreementProof {
                    signed_debit: signed_debit.clone(),
                    debit_sig: sn_data_types::Signature::Bls(debit_sig),
                    signed_credit: signed_credit.clone(),
                    credit_sig: sn_data_types::Signature::Bls(credit_sig),
                    debiting_replicas_keys: self.replicas.clone(),
                });
            } // else, we have some corrupt data. (todo: Do we need to act on that fact?)
        }

        Ok(TransferValidationReceived { validation, proof })
    }

    /// Step 3. Registration of an agreed transfer.
    /// (The actual sending of the registration over the wire is done by upper layer,
    /// only after that, the event is applied to the actor instance.)
    pub fn register(
        &self,
        transfer_proof: TransferAgreementProof,
    ) -> Result<TransferRegistrationSent> {
        // Always verify signature first! (as to not leak any information).
        if self.verify_transfer_proof(&transfer_proof).is_err() {
            return Err(Error::InvalidSignature);
        }
        if self.wallet.next_debit() == transfer_proof.id().counter {
            Ok(TransferRegistrationSent { transfer_proof })
        } else {
            Err(Error::OperationOutOfOrder(
                transfer_proof.id().counter,
                self.wallet.next_debit(),
            ))
        }
    }

    ///
    pub fn synch(
        &self,
        balance: Token,
        debit_version: u64,
        credit_ids: HashSet<CreditId>,
    ) -> Result<StateSynched> {
        // todo: use WalletSnapshot, aggregate sigs
        Ok(StateSynched {
            id: self.id(),
            balance,
            debit_version,
            credit_ids,
        })
    }

    /// Step xx. Continuously receiving credits from Replicas via push or pull model, decided by upper layer.
    /// The credits are most likely originating at an Actor whose Replicas are not the same as our Replicas.
    /// That means that the signature on the DebitAgreementProof, is that of some Replicas we don't know.
    /// What we do here is to use the passed in replica_validator, that injects the logic from upper layers
    /// for determining if this remote group of Replicas is indeed valid.
    /// It should consider our Replicas valid as well, for the rare cases when sender replicate to the same group.
    ///
    /// This also ensures that we receive transfers initiated at other Actor instances (same id or other,
    /// i.e. with multiple instances of same Actor we can also sync debits made on other isntances).
    /// Todo: This looks to be handling the case when there is a transfer in flight from this client
    /// (i.e. self.next_expected_debit has been incremented, but transfer not yet accumulated).
    /// Just make sure this is 100% the case as well.
    ///
    /// NB: If a non-complete* set of debits has been provided, this Actor instance
    /// will still apply any credits, and thus be out of synch with its Replicas,
    /// as it will have a balance that is higher than at the Replicas.
    /// (*Non-complete means non-contiguous set or not starting immediately
    /// after current debit version.)
    pub fn from_history(&self, history: ActorHistory) -> Result<TransfersSynched> {
        if history.is_empty() {
            return Err(Error::InvalidActorHistory);
        }
        // filter out any credits and debits already existing in current wallet
        let credits = self.validate_credits(&history.credits);
        let debits = self.validate_debits(&history.debits);
        if !credits.is_empty() || !debits.is_empty() {
            Ok(TransfersSynched(ActorHistory { credits, debits }))
        } else {
            Err(Error::InvalidActorHistory) // TODO: the error is actually that credits and/or debits failed validation..
        }
    }

    fn validate_credits(&self, credits: &[CreditAgreementProof]) -> Vec<CreditAgreementProof> {
        let valid_credits: Vec<_> = credits
            .iter()
            .cloned()
            .unique_by(|e| *e.id())
            .filter(|_credit_proof| {
                #[cfg(feature = "simulated-payouts")]
                return true;

                #[cfg(not(feature = "simulated-payouts"))]
                self.verify_credit_proof(_credit_proof).is_ok()
            })
            .filter(|credit| self.id() == credit.recipient())
            .filter(|credit| !self.wallet.contains(&credit.id()))
            .collect();

        valid_credits
    }

    /// Filters out any debits already applied,
    /// and makes sure the returned set is a contiguous
    /// set of debits beginning immediately after current debit version.
    #[allow(clippy::explicit_counter_loop)]
    fn validate_debits(&self, debits: &[TransferAgreementProof]) -> Vec<TransferAgreementProof> {
        let mut debits: Vec<_> = debits
            .iter()
            .unique_by(|e| e.id())
            .filter(|transfer| self.id() == transfer.sender())
            .filter(|transfer| transfer.id().counter >= self.wallet.next_debit())
            .filter(|transfer| self.verify_transfer_proof(transfer).is_ok())
            .collect();

        debits.sort_by_key(|t| t.id().counter);

        let mut iter = 0;
        let mut valid_debits = vec![];
        for out in debits {
            let version = out.id().counter;
            let expected_version = iter + self.wallet.next_debit();
            if version != expected_version {
                break; // since it's sorted, if first is not matching, then no point continuing
            }
            valid_debits.push(out.clone());
            iter += 1;
        }

        valid_debits
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Mutation ---------------------------------
    /// -----------------------------------------------------------------

    /// Mutation of state.
    /// There is no validation of an event, it is assumed to have
    /// been properly validated before raised, and thus anything that breaks is a bug.
    pub fn apply(&mut self, event: ActorEvent) -> Result<()> {
        debug!(
            ">>>>> ********* Transfer Actor {}: applying event {:?}",
            self.id(),
            event
        );
        match event {
            ActorEvent::TransferInitiated(e) => {
                self.next_expected_debit = e.id().counter + 1;
                let _ = self.accumulating_validations.insert(e.id(), HashMap::new());
                Ok(())
            }
            ActorEvent::TransferValidationReceived(e) => {
                if e.proof.is_some() {
                    // if we have a proof, then we have a valid set of replicas (potentially new) to update with
                    self.replicas = e.validation.replicas.clone();
                }
                match self.accumulating_validations.get_mut(&e.validation.id()) {
                    Some(map) => {
                        let _ = map.insert(e.validation.replica_debit_sig.index, e.validation);
                    }
                    None => return Err(Error::PendingTransferNotFound),
                }
                Ok(())
            }
            ActorEvent::TransferRegistrationSent(e) => {
                self.wallet
                    .apply_debit(e.transfer_proof.signed_debit.debit.clone())?;
                self.accumulating_validations.clear();
                self.history.debits.push(e.transfer_proof);
                Ok(())
            }
            ActorEvent::TransfersSynched(e) => {
                for credit in e.0.credits {
                    // append credits _before_ debits
                    self.wallet
                        .apply_credit(credit.signed_credit.credit.clone())?;
                    self.history.credits.push(credit);
                }
                for debit in e.0.debits {
                    // append debits _after_ credits
                    self.wallet.apply_debit(debit.signed_debit.debit.clone())?;
                    self.history.debits.push(debit);
                }
                self.next_expected_debit = self.wallet.next_debit();
                Ok(())
            }
            ActorEvent::StateSynched(e) => {
                self.wallet = Wallet::from(
                    self.owner().clone(),
                    e.balance,
                    e.debit_version,
                    e.credit_ids,
                );
                self.next_expected_debit = self.wallet.next_debit();
                Ok(())
            }
        }
        // consider event log, to properly be able to reconstruct state from restart
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Private methods --------------------------
    /// -----------------------------------------------------------------

    /// We verify that we signed the underlying cmd,
    /// and the replica signature against the pk set included in the event.
    /// Note that we use the provided pk set to verify the event.
    /// This might not be the way we want to do it.
    fn verify(&self, event: &TransferValidated) -> Result<()> {
        let signed_debit = &event.signed_debit;
        let signed_credit = &event.signed_credit;

        // Check that we signed this.
        if let error @ Err(_) = self.verify_is_our_transfer(signed_debit, signed_credit) {
            return error;
        }

        let valid_debit = self
            .verify_share(signed_debit, &event.replica_debit_sig, &event.replicas)
            .is_ok();
        let valid_credit = self
            .verify_share(signed_credit, &event.replica_credit_sig, &event.replicas)
            .is_ok();

        if valid_debit && valid_credit {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    // Check that the replica signature is valid per the provided public key set.
    // (if we only use this in one place we can move the content to that method)
    fn verify_share<T: serde::Serialize>(
        &self,
        item: T,
        replica_signature: &SignatureShare,
        replicas: &PublicKeySet,
    ) -> Result<()> {
        let sig_share = &replica_signature.share;
        let share_index = replica_signature.index;
        match bincode::serialize(&item) {
            Err(_) => Err(Error::Serialisation("Could not serialise item".into())),
            Ok(data) => {
                let verified = replicas
                    .public_key_share(share_index)
                    .verify(sig_share, data);
                if verified {
                    Ok(())
                } else {
                    Err(Error::InvalidSignature)
                }
            }
        }
    }

    /// Verify that this is a valid TransferAgreementProof over our cmd.
    fn verify_transfer_proof(&self, proof: &TransferAgreementProof) -> Result<()> {
        let signed_debit = &proof.signed_debit;
        let signed_credit = &proof.signed_credit;
        // Check that we signed this.
        if let error @ Err(_) = self.verify_is_our_transfer(signed_debit, signed_credit) {
            return error;
        }

        // Check that the proof corresponds to a/the public key set of our Replicas.
        let valid_debit = match bincode::serialize(&proof.signed_debit) {
            Err(_) => return Err(Error::Serialisation("Could not serialise debit".into())),
            Ok(data) => {
                let public_key = sn_data_types::PublicKey::Bls(self.replicas.public_key());
                public_key.verify(&proof.debit_sig, &data).is_ok()
            }
        };

        let valid_credit = match bincode::serialize(&proof.signed_credit) {
            Err(_) => return Err(Error::Serialisation("Could not serialise credit".into())),
            Ok(data) => {
                let public_key = sn_data_types::PublicKey::Bls(self.replicas.public_key());
                public_key.verify(&proof.credit_sig, &data).is_ok()
            }
        };

        if valid_debit && valid_credit {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// Verify that this is a valid ReceivedCredit.
    #[cfg(not(feature = "simulated-payouts"))]
    fn verify_credit_proof(&self, proof: &CreditAgreementProof) -> Result<()> {
        let debiting_replicas_keys = PublicKey::Bls(proof.debiting_replicas_keys.public_key());

        if !self.replica_validator.is_valid(debiting_replicas_keys) {
            return Err(Error::Unknown(format!(
                "Unknown debiting replica keys: {}",
                debiting_replicas_keys
            )));
        }

        // TODO: verify crediting replica sig??

        debug!("Verfying debiting_replicas_sig..!");
        // Check that the proof corresponds to a/the public key set of our Replicas.
        match bincode::serialize(&proof.signed_credit) {
            Err(_) => Err(Error::Serialisation("Could not serialise credit".into())),
            Ok(data) => debiting_replicas_keys
                .verify(&proof.debiting_replicas_sig, &data)
                .map_err(Error::NetworkDataError),
        }
    }

    /// Check that we signed this.
    fn verify_is_our_transfer(
        &self,
        signed_debit: &SignedDebit,
        signed_credit: &SignedCredit,
    ) -> Result<()> {
        debug!("ReadOnlyActor: Verifying is this our transfer?!");
        let valid_debit = self
            .id
            .verify(&signed_debit.actor_signature, &signed_debit.debit);
        let valid_credit = self
            .id
            .verify(&signed_credit.actor_signature, &signed_credit.credit);

        if !(valid_debit && valid_credit) {
            debug!(
                "ReadOnlyActor: Valid debit sig? {}, Valid credit sig? {}",
                valid_debit, valid_credit
            );
            Err(Error::InvalidSignature)
        } else if signed_credit.id() != &signed_debit.credit_id()? {
            Err(Error::CreditDebitIdMismatch)
        } else {
            Ok(())
        }
    }
}

impl<V: ReplicaValidator + fmt::Debug> fmt::Debug for ReadOnlyActor<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ReadOnlyActor {{ id: {:?}, wallet: {:?}, next_expected_debit: {:?}, accumulating_validations: {:?}, replicas: PkSet {{ public_key: {:?} }}, replica_validator: {:?} }}",
            self.id,
            self.wallet,
            self.next_expected_debit,
            self.accumulating_validations,
            self.replicas.public_key(),
            self.replica_validator
        )
    }
}
