use std::{
    collections::{BinaryHeap, HashMap},
    ops::Deref,
    str::FromStr,
    sync::Arc,
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
    pub users_uuid: Vec<String>,
    /// A list of expenses associated with the group.
    pub expenses: Vec<Arc<Expense>>,
}

#[uniffi::export]
impl Group {
    /// Creates a new [Group].
    ///
    /// # Arguments
    ///
    /// * `currency` - A reference to a [Currency] object, which defines the currency used for all expenses within the group.
    /// * `users_uuid` - A reference to a list of string representing the unique identifier of the users that are part of the group.
    /// * `expenses` - A reference to a list of [Expense] that should be added to the group.
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
    /// let alice_uuid = Uuid::new_v4().to_string();
    /// let bob_uuid = Uuid::new_v4().to_string();
    ///
    /// let currency = Currency::new("Euro", "€", true).unwrap();
    /// let users_uuid = vec![alice_uuid, bob_uuid];
    /// let mut group = Group::new(&currency, &users_uuid, &vec![]);
    /// ```
    #[uniffi::constructor]
    pub fn new(
        currency: &Currency,
        users_uuid: &Vec<String>,
        expenses: &Vec<Arc<Expense>>,
    ) -> Result<Self, GroupError> {
        for expense in expenses {
            Group::check_expense(users_uuid, currency, expense)?;
        }

        Ok(Self {
            currency: currency.to_owned(),
            users_uuid: users_uuid.to_owned(),
            expenses: expenses.to_owned(),
        })
    }

    /// Adds a user to the group and returns a new `Group` instance with the user added.
    ///
    /// This method creates a copy of the current group, appends the provided `user_uuid` to the list of users,
    /// and returns the new group. The original group remains unchanged.
    ///
    /// # Arguments
    ///
    /// * `user_uuid` - A string slice representing the unique identifier of the user to add.
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
    /// let mut group = Group::new(&currency, &vec![], &vec![]).unwrap();
    ///
    /// let user_uuid = Uuid::new_v4().to_string();
    /// group.with_added_user(&user_uuid);
    /// ```
    pub fn with_added_user(&self, user_uuid: &str) -> Group {
        let mut new_group = self.clone();

        new_group.users_uuid.push(user_uuid.to_string());

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
    /// # use lib_duckcount::algorithm::{beneficiary::Beneficiary, currency::Currency, expense::{Expense, compute_beneficiaries}, group::Group};
    /// # use std::{collections::HashMap, sync::Arc};
    /// # use uuid::Uuid;
    ///
    /// let currency = Currency::new("Euro", "€", true).unwrap();
    /// let mut group = Group::new(&currency, &vec![], &vec![]).unwrap();
    ///
    /// let creditor_uuid = Uuid::new_v4().to_string();
    /// let alice_uuid = Uuid::new_v4().to_string();
    ///
    /// let amount = "100.00";
    ///
    /// let beneficiary_uuids = vec![alice_uuid.clone()];
    ///
    /// let mut fixed_shares = HashMap::new();
    /// fixed_shares.insert(alice_uuid.clone(), String::from("100.00"));
    ///
    /// let beneficiaries =
    ///     compute_beneficiaries(amount, &currency, &beneficiary_uuids, &fixed_shares, &HashMap::new())
    ///         .unwrap();
    ///
    /// let expense = Expense::new(&creditor_uuid, amount, &currency, &beneficiaries).unwrap();
    /// group.with_added_expense(Arc::new(expense));
    /// ```
    pub fn with_added_expense(&self, expense: Arc<Expense>) -> Result<Group, GroupError> {
        Group::check_expense(&self.users_uuid, &self.currency, &expense)?;

        let mut new_group = self.clone();

        new_group.expenses.push(expense);

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
    /// let mut group = Group::new(&currency, &vec![], &vec![]).unwrap();
    ///
    /// let net_debts = group.calculate_net_debts_per_user().unwrap();
    /// for (user_uuid, debt) in net_debts {
    ///     println!("User {} has a net debt of {:.2}", user_uuid, debt);
    /// }
    /// ```
    ///
    /// Example with specific users and expenses:
    ///
    /// Suppose we have the following users and expenses:
    /// - Alice: Creditor for an expense of 100.00
    /// - Bob: Beneficiary for the same expense with an equal share
    /// - Charlie: Beneficiary for the same expense with an equal share
    ///
    /// The function will return a HashMap containing net debts such as:
    /// - Alice: 100.00 (owed this amount)
    /// - Bob: -50.00 (owes this amount)
    /// - Charlie: -50.00 (owes this amount)
    ///
    /// This ensures that the net debts are calculated correctly and reflect each user's financial standing.
    pub fn calculate_net_debts_per_user(&self) -> Result<HashMap<String, String>, GroupError> {
        let mut net_debts = HashMap::new();

        for user_uuid in self.users_uuid.deref() {
            net_debts.insert(user_uuid.clone(), BigDecimal::zero().to_plain_string());
        }

        for expense in self.expenses.deref() {
            let net_debt = net_debts
                .entry(expense.creditor_uuid.clone())
                .or_insert(BigDecimal::zero().to_plain_string());

            let mut net_debt =
                BigDecimal::from_str(&net_debt).map_err(|_| GroupError::MalformedAmount)?;

            net_debt +=
                BigDecimal::from_str(&expense.amount).map_err(|_| GroupError::MalformedAmount)?;

            net_debts.insert(expense.creditor_uuid.clone(), net_debt.to_plain_string());

            for beneficiary in &expense.beneficiaries {
                let beneficiary_net_debt = net_debts
                    .entry(beneficiary.user_uuid.clone())
                    .or_insert(BigDecimal::zero().to_plain_string());

                let mut beneficiary_net_debt = BigDecimal::from_str(&beneficiary_net_debt)
                    .map_err(|_| GroupError::MalformedAmount)?;

                beneficiary_net_debt -= BigDecimal::from_str(&beneficiary.share)
                    .map_err(|_| GroupError::MalformedAmount)?;

                net_debts.insert(
                    beneficiary.user_uuid.clone(),
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
    /// let mut group = Group::new(&currency, &vec![], &vec![]).unwrap();
    ///
    /// let transactions = group.calculate_transactions_to_equilibrate().unwrap();
    /// for transaction in transactions {
    ///     println!("{} owes {} to {}", transaction.debtor_uuid, transaction.amount, transaction.creditor_uuid);
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

        for (user_uuid, debt) in debts {
            let debt = BigDecimal::from_str(&debt).map_err(|_| GroupError::MalformedAmount)?;

            if debt < BigDecimal::zero() {
                debtors.push(Debt::new(&-debt, &user_uuid));
            } else if debt > BigDecimal::zero() {
                creditors.push(Debt::new(&debt, &user_uuid));
            }
        }

        let mut result = Vec::new();

        while let (Some(debtor), Some(creditor)) = (debtors.pop(), creditors.pop()) {
            let transfer_amount = debtor.amount.clone().min(creditor.amount.clone());

            result.push(Transaction::new(
                &debtor.user_uuid,
                &creditor.user_uuid,
                &transfer_amount.to_plain_string(),
            ));

            let remaining_debt = debtor.amount - transfer_amount.clone();
            let remaining_credit = creditor.amount - transfer_amount;

            if remaining_debt > BigDecimal::zero() {
                debtors.push(Debt::new(&remaining_debt, &debtor.user_uuid));
            }

            if remaining_credit > BigDecimal::zero() {
                creditors.push(Debt::new(&remaining_credit, &creditor.user_uuid));
            }
        }

        Ok(result)
    }
}

impl Group {
    /// Checks whether an [Expense] is compatible with a group.
    ///
    /// This function validates that the given expense can be added to a group composed of `users_uuid`
    /// and using `currency`. It ensures that the creditor and every beneficiary of the expense are
    /// part of the group, and that the expense uses the same currency as the group.
    ///
    /// # Arguments
    ///
    /// * `users_uuid` - A reference to a list of string representing the unique identifier of the users that are part of the group.
    /// * `currency` - A reference to the [Currency] used by the group.
    /// * `expense` - A reference to the [Expense] to validate.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The creditor of the expense is not part of the group.
    /// - At least one of the beneficiaries of the expense is not part of the group.
    /// - The expense does not use the same currency as the group.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```rust
    /// # use lib_duckcount::algorithm::{beneficiary::Beneficiary, currency::Currency, expense::{Expense, compute_beneficiaries}, group::Group};
    /// # use uuid::Uuid;
    /// # use std::collections::HashMap;
    ///
    /// let creditor_uuid = Uuid::new_v4().to_string();
    /// let alice_uuid = Uuid::new_v4().to_string();
    ///
    /// let currency = Currency::new("Euro", "€", true).unwrap();
    /// let users_uuid = vec![creditor_uuid.clone(), alice_uuid.clone()];
    ///
    /// let amount = "100.00";
    ///
    /// let beneficiary_uuids = vec![alice_uuid.clone()];
    ///
    /// let beneficiaries =
    ///     compute_beneficiaries(amount, &currency, &beneficiary_uuids, &HashMap::new(), &HashMap::new())
    ///         .unwrap();
    ///
    /// let expense = Expense::new(&creditor_uuid, amount, &currency, &beneficiaries).unwrap();
    ///
    /// Group::check_expense(&users_uuid, &currency, &expense).unwrap();
    /// ```
    pub fn check_expense(
        users_uuid: &Vec<String>,
        currency: &Currency,
        expense: &Expense,
    ) -> Result<(), GroupError> {
        if !users_uuid.contains(&expense.creditor_uuid) {
            return Err(GroupError::CreditorUnknown);
        }

        if !expense
            .beneficiaries
            .iter()
            .all(|beneficiary| users_uuid.contains(&beneficiary.user_uuid))
        {
            return Err(GroupError::BeneficiaryUnknown);
        }

        if expense.currency != *currency {
            return Err(GroupError::WrongCurrency);
        }

        Ok(())
    }
}
