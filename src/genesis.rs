// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use sn_data_types::{Credit, CreditAgreementProof, Error, Money, PublicKey, Result, SignedCredit};
use std::collections::BTreeMap;
use threshold_crypto::{SecretKey, SecretKeySet};

/// Produces a genesis balance for a new network.
pub fn get_genesis(balance: u64, id: PublicKey) -> Result<CreditAgreementProof> {
    let index = 0;
    let threshold = 0;
    // Nothing comes before genesis, it is a paradox
    // that it comes from somewhere. In other words, it is
    // signed over from a "ghost", the keys generated are "ghost" keys,
    // they come from nothing and can't be verified.
    // They are unimportant and will be thrown away,
    // thus the source of random is also unimportant.
    let mut rng = rand::thread_rng();
    let bls_secret_key = SecretKeySet::random(threshold, &mut rng);
    let peer_replicas = bls_secret_key.public_keys();
    let secret_key = bls_secret_key.secret_key_share(index);

    let credit = Credit {
        id: Default::default(),
        amount: Money::from_nano(balance),
        recipient: id,
        msg: "genesis".to_string(),
    };

    let serialised_credit =
        bincode::serialize(&credit).map_err(|e| Error::NetworkOther(e.to_string()))?;
    let credit_sig_share = secret_key.sign(serialised_credit);
    let mut credit_sig_shares = BTreeMap::new();
    let _ = credit_sig_shares.insert(0, credit_sig_share);
    // Combine shares to produce the main signature.
    let actor_signature = sn_data_types::Signature::Bls(
        peer_replicas
            .combine_signatures(&credit_sig_shares)
            .map_err(|e| Error::NetworkOther(e.to_string()))?,
    );

    let signed_credit = SignedCredit {
        credit,
        actor_signature,
    };
    let debiting_replicas_sig = sn_data_types::Signature::Bls(
        peer_replicas
            .combine_signatures(&credit_sig_shares)
            .map_err(|e| Error::NetworkOther(e.to_string()))?,
    );

    Ok(CreditAgreementProof {
        signed_credit,
        debiting_replicas_sig,
        debiting_replicas_keys: peer_replicas,
    })
}

fn get_random_pk() -> PublicKey {
    PublicKey::from(SecretKey::random().public_key())
}
