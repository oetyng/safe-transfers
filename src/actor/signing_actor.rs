// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    super::{
        ActorEvent, ReplicaValidator, Result, TransferInitiated, TransferRegistrationSent,
        TransferValidated, TransferValidationReceived, TransfersSynched,
    },
    ReadOnlyActor as Actor,
};
use crate::StateSynched;
use sn_data_types::{
    ActorHistory, CreditId, OwnerType, PublicKey, SignedCredit, SignedDebit, Signing, Token,
    TransferAgreementProof,
};
use std::collections::HashSet;
use std::fmt;
use threshold_crypto::PublicKeySet;

/// The Actor is the part of an AT2 system
/// that initiates transfers, by requesting Replicas
/// to validate them, and then receive the proof of agreement.
/// It also syncs transfers from the Replicas.
#[derive(Clone)]
pub struct SigningActor<V: ReplicaValidator, S: Signing> {
    ///
    signing: S,
    ///
    actor: Actor<V>,
}

impl<V: ReplicaValidator, S: Signing> SigningActor<V, S> {
    /// Use this ctor for a new instance,
    /// or to rehydrate from events ([see the synch method](Actor::synch)).
    /// Pass in the key set of the replicas of this actor, i.e. our replicas.
    /// Credits to our wallet are most likely debited at other replicas than our own (the sender's replicas),
    /// The replica_validator lets upper layer decide how to validate those remote replicas (i.e. not our replicas).
    /// If upper layer trusts them, the validator might do nothing but return "true".
    /// If it wants to execute some logic for verifying that the remote replicas are in fact part of the system,
    /// before accepting credits, it then implements that in the replica_validator.
    pub fn new(signing: S, actor: Actor<V>) -> SigningActor<V, S> {
        SigningActor { signing, actor }
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Queries ----------------------------------
    /// -----------------------------------------------------------------

    /// Query for the id of the Actor.
    pub fn id(&self) -> PublicKey {
        self.actor.id()
    }

    /// Query for the id of the Actor.
    pub fn owner(&self) -> &OwnerType {
        &self.actor.owner()
    }

    /// Query for the balance of the Actor.
    pub fn balance(&self) -> Token {
        self.actor.balance()
    }

    ///
    pub fn replicas_public_key(&self) -> PublicKey {
        self.actor.replicas_public_key()
    }

    ///
    pub fn replicas_key_set(&self) -> PublicKeySet {
        self.actor.replicas_key_set()
    }

    /// History of credits and debits
    pub fn history(&self) -> ActorHistory {
        self.actor.history()
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
    ) -> Result<TransferInitiated> {
        let (debit, credit) = self.actor.transfer(amount, recipient, msg)?;

        let actor_signature = self.signing.sign(&debit)?;
        let signed_debit = SignedDebit {
            debit,
            actor_signature,
        };
        let actor_signature = self.signing.sign(&credit)?;
        let signed_credit = SignedCredit {
            credit,
            actor_signature,
        };

        Ok(TransferInitiated {
            signed_debit,
            signed_credit,
        })
    }

    /// Step 2. Receive validations from Replicas, aggregate the signatures.
    pub fn receive(&self, validation: TransferValidated) -> Result<TransferValidationReceived> {
        self.actor.receive(validation)
    }

    /// Step 3. Registration of an agreed transfer.
    /// (The actual sending of the registration over the wire is done by upper layer,
    /// only after that, the event is applied to the actor instance.)
    pub fn register(
        &self,
        transfer_proof: TransferAgreementProof,
    ) -> Result<TransferRegistrationSent> {
        self.actor.register(transfer_proof)
    }

    ///
    pub fn synch(
        &self,
        balance: Token,
        debit_version: u64,
        credit_ids: HashSet<CreditId>,
    ) -> Result<StateSynched> {
        self.actor.synch(balance, debit_version, credit_ids)
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
        self.actor.from_history(history)
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Mutation ---------------------------------
    /// -----------------------------------------------------------------

    /// Mutation of state.
    /// There is no validation of an event, it is assumed to have
    /// been properly validated before raised, and thus anything that breaks is a bug.
    pub fn apply(&mut self, event: ActorEvent) -> Result<()> {
        self.actor.apply(event)
    }
}

impl<V: ReplicaValidator + fmt::Debug, S: Signing + fmt::Debug> fmt::Debug for SigningActor<V, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Actor {{ actor: {:?}, signing: {:?},",
            self.actor, self.signing,
        )
    }
}

#[cfg(test)]
mod test {
    use super::{
        super::{Error, Wallet},
        Actor, ActorEvent, OwnerType, ReplicaValidator, Result, SigningActor, TransferInitiated,
        TransferRegistrationSent,
    };
    use crdts::Dot;
    use serde::Serialize;
    use sn_data_types::{
        Credit, Debit, Keypair, PublicKey, Signature, SignatureShare, Token,
        TransferAgreementProof, TransferValidated,
    };
    use std::collections::BTreeMap;
    use threshold_crypto::{SecretKey, SecretKeySet};
    struct Validator {}

    impl ReplicaValidator for Validator {
        fn is_valid(&self, _replica_group: PublicKey) -> bool {
            true
        }
    }

    #[test]
    fn creates_actor() -> Result<()> {
        // Act
        let (_actor, _sk_set) = get_actor_and_replicas_sk_set(10)?;
        Ok(())
    }

    #[test]
    fn initial_state_is_applied() -> Result<()> {
        // Act
        let initial_amount = 10;
        let (actor, _sk_set) = get_actor_and_replicas_sk_set(initial_amount)?;
        assert_eq!(actor.balance(), Token::from_nano(initial_amount));
        Ok(())
    }

    #[test]
    fn initiates_transfers() -> Result<()> {
        // Act
        let (actor, _sk_set) = get_actor_and_replicas_sk_set(10)?;
        let debit = get_debit(&actor)?;
        let mut actor = actor;
        actor.apply(ActorEvent::TransferInitiated(debit))?;
        Ok(())
    }

    #[test]
    fn cannot_initiate_0_value_transfers() -> anyhow::Result<()> {
        let (actor, _sk_set) = get_actor_and_replicas_sk_set(10)?;

        match actor.transfer(Token::from_nano(0), get_random_pk(), "asfd".to_string()) {
            Ok(_) => Err(anyhow::anyhow!(
                "Should not be able to send 0 value transfers",
            )),
            Err(error) => {
                assert!(error
                    .to_string()
                    .contains("Transfer amount must be greater than zero"));
                Ok(())
            }
        }
    }

    #[test]
    fn can_apply_completed_transfer() -> Result<()> {
        // Act
        let (actor, sk_set) = get_actor_and_replicas_sk_set(15)?;
        let debit = get_debit(&actor)?;
        let mut actor = actor;
        actor.apply(ActorEvent::TransferInitiated(debit.clone()))?;
        let transfer_event = get_transfer_registration_sent(debit, &sk_set)?;
        actor.apply(ActorEvent::TransferRegistrationSent(transfer_event))?;
        assert_eq!(Token::from_nano(5), actor.balance());
        Ok(())
    }

    #[test]
    fn can_apply_completed_transfers_in_succession() -> Result<()> {
        // Act
        let (actor, sk_set) = get_actor_and_replicas_sk_set(22)?;
        let debit = get_debit(&actor)?;
        let mut actor = actor;
        actor.apply(ActorEvent::TransferInitiated(debit.clone()))?;
        let transfer_event = get_transfer_registration_sent(debit, &sk_set)?;
        actor.apply(ActorEvent::TransferRegistrationSent(transfer_event))?;

        assert_eq!(Token::from_nano(12), actor.balance()); // 22 - 10

        let debit2 = get_debit(&actor)?;
        actor.apply(ActorEvent::TransferInitiated(debit2.clone()))?;
        let transfer_event = get_transfer_registration_sent(debit2, &sk_set)?;
        actor.apply(ActorEvent::TransferRegistrationSent(transfer_event))?;

        assert_eq!(Token::from_nano(2), actor.balance()); // 22 - 10 - 10
        Ok(())
    }

    #[allow(clippy::needless_range_loop)]
    #[test]
    fn can_return_proof_for_validated_transfers() -> Result<()> {
        let (actor, sk_set) = get_actor_and_replicas_sk_set(22)?;
        let debit = get_debit(&actor)?;
        let mut actor = actor;
        actor.apply(ActorEvent::TransferInitiated(debit.clone()))?;
        let validations = get_transfer_validation_vec(debit, &sk_set)?;

        // 7 elders and validations
        for i in 0..7 {
            let transfer_validation = actor.receive(validations[i].clone())?;

            if i < 1
            // threshold is 1
            {
                assert_eq!(transfer_validation.clone().proof, None);
            } else {
                assert_ne!(transfer_validation.proof, None);
            }

            actor.apply(ActorEvent::TransferValidationReceived(
                transfer_validation.clone(),
            ))?;
        }
        Ok(())
    }

    fn get_debit(actor: &SigningActor<Validator, Keypair>) -> Result<TransferInitiated> {
        actor.transfer(Token::from_nano(10), get_random_pk(), "asdf".to_string())
    }

    fn try_serialize<T: Serialize>(value: T) -> Result<Vec<u8>> {
        match bincode::serialize(&value) {
            Ok(res) => Ok(res),
            _ => Err(Error::Serialisation("Serialisation error".to_string())),
        }
    }

    /// returns a vec of validated transfers from the sk_set 'replicas'
    fn get_transfer_validation_vec(
        transfer: TransferInitiated,
        sk_set: &SecretKeySet,
    ) -> Result<Vec<TransferValidated>> {
        let signed_debit = transfer.signed_debit;
        let signed_credit = transfer.signed_credit;
        let serialized_signed_debit = try_serialize(&signed_debit)?;
        let serialized_signed_credit = try_serialize(&signed_credit)?;

        let sk_shares: Vec<_> = (0..7).map(|i| sk_set.secret_key_share(i)).collect();
        let pk_set = sk_set.public_keys();

        let debit_sig_shares: BTreeMap<_, _> = (0..7)
            .map(|i| (i, sk_shares[i].sign(serialized_signed_debit.clone())))
            .collect();
        let credit_sig_shares: BTreeMap<_, _> = (0..7)
            .map(|i| (i, sk_shares[i].sign(serialized_signed_credit.clone())))
            .collect();

        let mut validated_transfers = vec![];

        for i in 0..7 {
            let debit_sig_share = &debit_sig_shares[&i];
            let credit_sig_share = &credit_sig_shares[&i];
            assert!(pk_set
                .public_key_share(i)
                .verify(debit_sig_share, serialized_signed_debit.clone()));
            assert!(pk_set
                .public_key_share(i)
                .verify(credit_sig_share, serialized_signed_credit.clone()));
            validated_transfers.push(TransferValidated {
                signed_debit: signed_debit.clone(),
                signed_credit: signed_credit.clone(),
                replica_debit_sig: SignatureShare {
                    index: i,
                    share: debit_sig_share.clone(),
                },
                replica_credit_sig: SignatureShare {
                    index: i,
                    share: credit_sig_share.clone(),
                },
                replicas: pk_set.clone(),
            })
        }

        Ok(validated_transfers)
    }

    fn get_transfer_registration_sent(
        transfer: TransferInitiated,
        sk_set: &SecretKeySet,
    ) -> Result<TransferRegistrationSent> {
        let signed_debit = transfer.signed_debit;
        let signed_credit = transfer.signed_credit;
        let serialized_signed_debit = try_serialize(&signed_debit)?;
        let serialized_signed_credit = try_serialize(&signed_credit)?;

        let sk_shares: Vec<_> = (0..7).map(|i| sk_set.secret_key_share(i)).collect();
        let pk_set = sk_set.public_keys();

        let debit_sig_shares: BTreeMap<_, _> = (0..7)
            .map(|i| (i, sk_shares[i].sign(serialized_signed_debit.clone())))
            .collect();
        let credit_sig_shares: BTreeMap<_, _> = (0..7)
            .map(|i| (i, sk_shares[i].sign(serialized_signed_credit.clone())))
            .collect();

        // Combine them to produce the main signature.
        let debit_sig = match pk_set.combine_signatures(&debit_sig_shares) {
            Ok(s) => s,
            _ => return Err(Error::InvalidSignature),
        };
        let credit_sig = match pk_set.combine_signatures(&credit_sig_shares) {
            Ok(s) => s,
            _ => return Err(Error::InvalidSignature),
        };

        // Validate the main signature. If the shares were valid, this can't fail.
        assert!(pk_set
            .public_key()
            .verify(&debit_sig, serialized_signed_debit));
        assert!(pk_set
            .public_key()
            .verify(&credit_sig, serialized_signed_credit));

        let debit_sig = Signature::Bls(debit_sig);
        let credit_sig = Signature::Bls(credit_sig);
        let transfer_agreement_proof = TransferAgreementProof {
            signed_debit,
            signed_credit,
            debit_sig,
            credit_sig,
            debiting_replicas_keys: pk_set,
        };

        Ok(TransferRegistrationSent {
            transfer_proof: transfer_agreement_proof,
        })
    }

    fn get_actor_and_replicas_sk_set(
        amount: u64,
    ) -> Result<(SigningActor<Validator, Keypair>, SecretKeySet)> {
        let mut rng = rand::thread_rng();
        let keypair = Keypair::new_ed25519(&mut rng);
        let client_pubkey = keypair.public_key();
        let bls_secret_key = SecretKeySet::random(1, &mut rng);
        let replicas_id = bls_secret_key.public_keys();
        let balance = Token::from_nano(amount);
        let sender = Dot::new(get_random_pk(), 0);
        let credit = get_credit(sender, client_pubkey, balance)?;
        let replica_validator = Validator {};
        let mut wallet = Wallet::new(OwnerType::Single(credit.recipient()));
        wallet.apply_credit(credit)?;

        let actor = Actor::from_snapshot(wallet, replicas_id, replica_validator);
        let signing_actor = SigningActor::new(keypair, actor);
        Ok((signing_actor, bls_secret_key))
    }

    fn get_credit(from: Dot<PublicKey>, recipient: PublicKey, amount: Token) -> Result<Credit> {
        let debit = Debit { id: from, amount };
        Ok(Credit {
            id: debit.credit_id()?,
            recipient,
            amount,
            msg: "asdf".to_string(),
        })
    }

    #[allow(unused)]
    fn get_random_dot() -> Dot<PublicKey> {
        Dot::new(get_random_pk(), 0)
    }

    fn get_random_pk() -> PublicKey {
        PublicKey::from(SecretKey::random().public_key())
    }
}
