// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use sn_data_types::{Credit, CreditId, Debit, Error, Money, PublicKey, Result};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct WalletSnapshot {
    pub balance: Money,
    pub debit_version: u64,
    pub credit_ids: HashSet<CreditId>,
}

impl Into<WalletSnapshot> for Wallet {
    fn into(self) -> WalletSnapshot {
        WalletSnapshot {
            balance: self.balance,
            debit_version: self.debit_version,
            credit_ids: self.credit_ids.clone(),
        }
    }
}

/// The balance and history of transfers for a wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wallet {
    id: PublicKey,
    balance: Money,
    debit_version: u64,
    credit_ids: HashSet<CreditId>,
}

impl Wallet {
    /// Creates a new wallet.
    pub fn new(id: PublicKey) -> Self {
        Self {
            id,
            balance: Money::zero(),
            debit_version: 0,
            credit_ids: Default::default(),
        }
    }

    /// Creates a wallet from existing state.
    pub fn from(
        id: PublicKey,
        balance: Money,
        debit_version: u64,
        credit_ids: HashSet<CreditId>,
    ) -> Self {
        Self {
            id,
            balance,
            debit_version,
            credit_ids,
        }
    }

    /// Get the id of the wallet.
    pub fn id(&self) -> PublicKey {
        self.id
    }

    /// Query for next version.
    pub fn next_debit(&self) -> u64 {
        self.debit_version
    }

    /// Query for balance.
    pub fn balance(&self) -> Money {
        self.balance
    }

    /// Query for already received credit.
    pub fn contains(&self, id: &CreditId) -> bool {
        self.credit_ids.contains(id)
    }

    /// Mutates state.
    pub fn apply_debit(&mut self, debit: Debit) -> Result<()> {
        if self.id == debit.id.actor {
            match self.balance.checked_sub(debit.amount) {
                Some(amount) => self.balance = amount,
                None => return Err(Error::from("overflow when subtracting!")),
            }
            self.debit_version += 1;
            Ok(())
        } else {
            Err(Error::from(format!(
                "Debit does not belong to this wallet({:?}): debit: {:?}",
                self.id, debit
            )))
        }
    }

    /// Mutates state.
    pub fn apply_credit(&mut self, credit: Credit) -> Result<()> {
        if self.id == credit.recipient() {
            match self.balance.checked_add(credit.amount) {
                Some(amount) => self.balance = amount,
                None => return Err(Error::from("overflow when adding!")),
            }
            let _ = self.credit_ids.insert(credit.id);
            Ok(())
        } else {
            Err(Error::from(format!(
                "Credit does not belong to this wallet({:?}): credit: {:?}",
                self.id, credit
            )))
        }
    }

    /// Test-helper API to simulate Client Transfers.
    #[cfg(feature = "simulated-payouts")]
    pub fn simulated_credit(&mut self, credit: Credit) {
        if self.id == credit.recipient() {
            match self.balance.checked_add(credit.amount) {
                Some(amount) => self.balance = amount,
                None => panic!("overflow when adding!"),
            }
        } else {
            panic!(
                "Credit does not belong to this wallet({:?}): credit: {:?}",
                self.id, credit
            )
        }
    }

    /// Test-helper API to simulate section payments.
    #[cfg(feature = "simulated-payouts")]
    pub fn simulated_debit(&mut self, debit: Debit) {
        if self.id == debit.id.actor {
            match self.balance.checked_sub(debit.amount) {
                Some(amount) => self.balance = amount,
                None => panic!("overflow when subtracting!"),
            }
            self.debit_version += 1;
        } else {
            panic!(
                "Debit does not belong to this wallet({:?}): debit: {:?}",
                self.id, debit
            )
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crdts::Dot;
    use sn_data_types::PublicKey;
    use threshold_crypto::SecretKey;
    use xor_name::XorName;

    #[test]
    fn applies_credits() -> Result<()> {
        // Arrange
        let balance = Money::from_nano(10);
        let first_credit = Credit {
            id: Default::default(),
            recipient: get_random_pk(),
            amount: balance,
            msg: "asdf".to_string(),
        };
        let mut wallet = Wallet::new(first_credit.recipient);
        wallet.apply_credit(first_credit.clone())?;
        let second_credit = Credit {
            id: Default::default(),
            recipient: first_credit.recipient,
            amount: balance,
            msg: "asdf".to_string(),
        };

        // Act
        wallet.apply_credit(second_credit.clone())?;

        // Assert
        assert_eq!(wallet.balance(), balance.checked_add(balance).unwrap());
        assert_eq!(wallet.next_debit(), 0);
        Ok(())
    }

    #[test]
    fn applies_debits() -> Result<()> {
        // Arrange
        let balance = Money::from_nano(10);
        let first_credit = Credit {
            id: Default::default(),
            recipient: get_random_pk(),
            amount: balance,
            msg: "asdf".to_string(),
        };
        let mut wallet = Wallet::new(first_credit.recipient);
        wallet.apply_credit(first_credit.clone())?;
        let first_debit = Debit {
            id: Dot::new(first_credit.recipient, 0),
            amount: balance,
        };

        // Act
        wallet.apply_debit(first_debit.clone())?;

        // Assert
        assert_eq!(wallet.balance(), Money::zero());
        assert_eq!(wallet.next_debit(), 1);
        Ok(())
    }

    #[allow(unused)]
    fn get_random_xor() -> XorName {
        XorName::random()
    }

    fn get_random_pk() -> PublicKey {
        PublicKey::from(SecretKey::random().public_key())
    }
}
