use std::{
    collections::{BinaryHeap, HashMap},
    ops::Deref,
    str::FromStr,
};
use thiserror::Error;

use bigdecimal::{BigDecimal, Zero};

use crate::algorithm::currency::Currency;

use super::{debt::Debt, expense::Expense, transaction::Transaction};

/// Represents possible errors that can occur when creating an expense.
#[derive(Error, Debug, PartialEq, uniffi::Error)]
pub enum GroupError {
    /// The amount is malformed.
    #[error("The amount is malformed.")]
    MalformedAmount,
    /// The expense to add does not have the same currency as the group.
    #[error("The expense to add does not have the same currency as the group.")]
    WrongCurrency,
    /// The creditor of the expense is not part of the group.
    #[error("The creditor of the expense is not part of the group.")]
    CreditorUnknown,
    /// At least one of the beneficiary of the expense is not part of the group.
    #[error("At least one of the beneficiary of the expense is not part of the group.")]
    BeneficiaryUnknown,
}

/// Represents a group of users and their shared expenses.
///
/// The [Group] struct is used to manage a collection of users and their associated expenses.
/// It provides functionality to add users and expenses, calculate net debts per user,
/// and determine the transactions needed to equilibrate debts among users.
#[derive(Debug, Clone, uniffi::Object)]
pub struct Group {
    /// The currency used by the group.
    pub currency: Currency,
    /// A list of user IDs in the group.
    pub users_id: Vec<String>,
    /// A list of expenses associated with the group.
    pub expenses: Vec<Expense>,
}

#[uniffi::export]
impl Group {
    /// Creates a new [Group].
    ///
    /// # Arguments
    ///
    /// * `currency` - A reference to a [Currency] object, which defines the currency used for all expenses within the group.
    /// * `users_id` - A reference to a list of string representing the unique identifier of the users that are part of the group.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```rust
    /// # use lib_duckcount::algorithm::currency::Currency;
    /// # use lib_duckcount::algorithm::group::Group;
    /// # use uuid::Uuid;
    ///
    /// let alice_id = Uuid::new_v4().to_string();
    /// let bob_id = Uuid::new_v4().to_string();
    ///
    /// let currency = Currency::new("Euro", "€", true).unwrap();
    /// let users_id = vec![alice_id, bob_id];
    /// let mut group = Group::new(&currency, &users_id);
    /// ```
    #[uniffi::constructor]
    pub fn new(currency: &Currency, users_id: &Vec<String>) -> Self {
        Self {
            currency: currency.to_owned(),
            users_id: users_id.to_owned(),
            expenses: Vec::new(),
        }
    }

    /// Adds a user to the group and returns a new `Group` instance with the user added.
    ///
    /// This method creates a copy of the current group, appends the provided `user_id` to the list of users,
    /// and returns the new group. The original group remains unchanged.
    ///
    /// # Arguments
    ///
    /// * `user_id` - A string slice representing the unique identifier of the user to add.
    ///
    /// # Returns
    ///
    /// A new `Group` instance containing all existing users plus the newly added user.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use lib_duckcount::algorithm::currency::Currency;
    /// # use lib_duckcount::algorithm::group::Group;
    /// # use uuid::Uuid;
    ///
    /// let currency = Currency::new("Euro", "€", true).unwrap();
    /// let mut group = Group::new(&currency, &vec![]);
    ///
    /// let user_id = Uuid::new_v4().to_string();
    /// group.with_added_user(&user_id);
    /// ```
    pub fn with_added_user(&self, user_id: &str) -> Group {
        let mut new_group = self.clone();

        new_group.users_id.push(user_id.to_string());

        new_group
    }

    /// Adds an expense to the group and returns a new `Group` instance with the expense included.
    ///
    /// This method creates a copy of the current group, appends the provided `expense` to the list of expenses,
    /// and returns the new group. The original group remains unchanged.
    ///
    /// # Arguments
    ///
    /// * `expense` - A reference to the `Expense` to add to the group.
    ///
    /// # Returns
    ///
    /// A new `Group` instance containing all existing expenses plus the newly added expense.
    ///
    /// ```rust
    /// # use lib_duckcount::algorithm::{beneficiary::Beneficiary, currency::Currency, expense::Expense, group::Group};
    /// # use uuid::Uuid;
    ///
    /// let currency = Currency::new("Euro", "€", true).unwrap();
    /// let mut group = Group::new(&currency, &vec![]);
    ///
    /// let creditor_id = Uuid::new_v4().to_string();
    /// let alice_id = Uuid::new_v4().to_string();
    ///
    /// let beneficiaries = vec![
    ///     Beneficiary::new(&alice_id, None),
    /// ];
    ///
    /// let expense = Expense::new(&creditor_id, "100.0", &currency, beneficiaries).unwrap();
    /// group.with_added_expense(&expense);
    /// ```
    pub fn with_added_expense(&self, expense: &Expense) -> Result<Group, GroupError> {
        if !self.users_id.contains(&expense.creditor_id) {
            return Err(GroupError::CreditorUnknown);
        }

        if !expense
            .beneficiaries
            .iter()
            .all(|beneficiary| self.users_id.contains(&beneficiary.user_id))
        {
            return Err(GroupError::BeneficiaryUnknown);
        }

        if expense.currency != self.currency {
            return Err(GroupError::WrongCurrency);
        }

        let mut new_group = self.clone();

        new_group.expenses.push(expense.clone());

        Ok(new_group)
    }

    /// Calculates the net debt for each user based on their expenses.
    ///
    /// This function computes the net debt for each user by iterating over all expenses
    /// and adjusting each user's balance according to their role in each expense (either
    /// as a creditor or a beneficiary).
    ///
    /// # Returns
    ///
    /// A `HashMap` where the keys are `Uuid` representing user IDs and the values are `f64`
    /// representing the net debt for each user. A positive value indicates that the user is
    /// owed money, while a negative value indicates that the user owes money.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```rust
    /// # use lib_duckcount::algorithm::{currency::Currency, group::Group};
    ///
    /// let currency = Currency::new("Euro", "€", true).unwrap();
    /// let mut group = Group::new(&currency, &vec![]);
    ///
    /// let net_debts = group.calculate_net_debts_per_user().unwrap();
    /// for (user_id, debt) in net_debts {
    ///     println!("User {} has a net debt of {:.2}", user_id, debt);
    /// }
    /// ```
    ///
    /// Example with specific users and expenses:
    ///
    /// Suppose we have the following users and expenses:
    /// - Alice: Creditor for an expense of 100.0
    /// - Bob: Beneficiary for the same expense with an equal share
    /// - Charlie: Beneficiary for the same expense with an equal share
    ///
    /// The function will return a HashMap containing net debts such as:
    /// - Alice: 100.0 (owed this amount)
    /// - Bob: -50.0 (owes this amount)
    /// - Charlie: -50.0 (owes this amount)
    ///
    /// This ensures that the net debts are calculated correctly and reflect each user's financial standing.
    pub fn calculate_net_debts_per_user(&self) -> Result<HashMap<String, String>, GroupError> {
        let mut net_debts = HashMap::new();

        for user_id in self.users_id.deref() {
            net_debts.insert(user_id.clone(), BigDecimal::zero().to_plain_string());
        }

        for expense in self.expenses.deref() {
            let net_debt = net_debts
                .entry(expense.creditor_id.clone())
                .or_insert(BigDecimal::zero().to_plain_string());

            let mut net_debt =
                BigDecimal::from_str(&net_debt).map_err(|_| GroupError::MalformedAmount)?;

            net_debt +=
                BigDecimal::from_str(&expense.amount).map_err(|_| GroupError::MalformedAmount)?;

            net_debts.insert(expense.creditor_id.clone(), net_debt.to_plain_string());

            let equal_shares = expense
                .calculate_equal_shares()
                .map_err(|_| GroupError::MalformedAmount)?;

            for beneficiary in &expense.beneficiaries {
                // TODO:
                let beneficiary_share = if let Some(share) = beneficiary.share.clone() {
                    share
                } else if let Some(share) = equal_shares.get(&beneficiary.user_id) {
                    share.to_owned()
                } else {
                    expense
                        .calculate_equal_share()
                        .map_err(|_| GroupError::MalformedAmount)?
                };

                let beneficiary_net_debt = net_debts
                    .entry(beneficiary.user_id.clone())
                    .or_insert(BigDecimal::zero().to_plain_string());

                let mut beneficiary_net_debt = BigDecimal::from_str(&beneficiary_net_debt)
                    .map_err(|_| GroupError::MalformedAmount)?;

                beneficiary_net_debt -= BigDecimal::from_str(&beneficiary_share)
                    .map_err(|_| GroupError::MalformedAmount)?;

                net_debts.insert(
                    beneficiary.user_id.clone(),
                    beneficiary_net_debt.to_plain_string(),
                );
            }
        }

        Ok(net_debts)
    }

    /// Calculates the necessary transactions to equilibrate debts among users.
    ///
    /// This function determines the optimal set of transactions required to settle debts
    /// among a group of users. It uses a two-heap approach to efficiently match debtors
    /// (users with negative balances) with creditors (users with positive balances) and
    /// computes the transactions needed to equilibrate the system.
    ///
    /// # Returns
    ///
    /// A vector of [Transaction]. Each transaction includes the debtor's user ID, the creditor's
    /// user ID, and the amount to be transferred.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```rust
    /// # use lib_duckcount::algorithm::{currency::Currency, group::Group};
    ///
    /// let currency = Currency::new("Euro", "€", true).unwrap();
    /// let mut group = Group::new(&currency, &vec![]);
    ///
    /// let transactions = group.calculate_transactions_to_equilibrate().unwrap();
    /// for transaction in transactions {
    ///     println!("{} owes {} to {}", transaction.debtor_id, transaction.amount, transaction.creditor_id);
    /// }
    /// ```
    ///
    /// Example with specific debts:
    ///
    /// Suppose we have the following debts:
    /// - Alice owes 100.0
    /// - Bob is owed 50.0
    /// - Charlie is owed 50.0
    ///
    /// The function will return a vector containing transactions such as:
    /// - Alice owes 50.0 to Bob
    /// - Alice owes 50.0 to Charlie
    ///
    /// This ensures that all debts are settled.
    pub fn calculate_transactions_to_equilibrate(&self) -> Result<Vec<Transaction>, GroupError> {
        let debts = self
            .calculate_net_debts_per_user()
            .map_err(|_| GroupError::MalformedAmount)?;

        let mut debtors = BinaryHeap::new();
        let mut creditors = BinaryHeap::new();

        for (user_id, debt) in debts {
            let debt = BigDecimal::from_str(&debt).map_err(|_| GroupError::MalformedAmount)?;

            if debt < BigDecimal::zero() {
                debtors.push(Debt::new(&-debt, &user_id));
            } else if debt > BigDecimal::zero() {
                creditors.push(Debt::new(&debt, &user_id));
            }
        }

        let mut result = Vec::new();

        while let (Some(debtor), Some(creditor)) = (debtors.pop(), creditors.pop()) {
            let transfer_amount = debtor.amount.clone().min(creditor.amount.clone());

            result.push(Transaction::new(
                &debtor.user_id,
                &creditor.user_id,
                &transfer_amount.to_plain_string(),
            ));

            let remaining_debt = debtor.amount - transfer_amount.clone();
            let remaining_credit = creditor.amount - transfer_amount;

            if remaining_debt > BigDecimal::zero() {
                debtors.push(Debt::new(&remaining_debt, &debtor.user_id));
            }

            if remaining_credit > BigDecimal::zero() {
                creditors.push(Debt::new(&remaining_credit, &creditor.user_id));
            }
        }

        Ok(result)
    }
}
