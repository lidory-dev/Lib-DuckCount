use std::{collections::HashMap, str::FromStr};

use bigdecimal::num_bigint::BigInt;
use bigdecimal::num_bigint::ToBigInt;
use bigdecimal::{BigDecimal, RoundingMode, Zero};
use thiserror::Error;

use super::beneficiary::Beneficiary;

/// Represents possible errors that can occur when creating an expense.
#[derive(Error, Debug, PartialEq, uniffi::Error)]
pub enum ExpenseError {
    /// The expense amount must be greater than zero.
    #[error("The expense amount must be greater than zero.")]
    NonPositiveAmount,
    /// Shares must be greater than zero. Use `None` for non-explicit shares.
    #[error("Shares must be greater than zero. Use `None` for non-explicit shares.")]
    NonPositiveShare,
    /// The sum of shares cannot exceed the total amount of the expense.
    #[error("The sum of shares cannot exceed the total amount of the expense.")]
    SharesExceedTotalAmount,
    /// If each beneficiary has a share, then the sum of the shares cannot be less than the total amount of the expense.
    #[error(
        "If each beneficiary has a share, then the sum of the shares cannot be less than the total amount of the expense."
    )]
    SharesBelowTotalAmount,
    /// There must be at least one beneficiary for an expense.
    #[error("There must be at least one beneficiary for an expense.")]
    NoBeneficiaries,
    /// The amount is malformed.
    #[error("The amount is malformed.")]
    MalformedAmount,
    /// A division by zerro occured.
    #[error("A division by zerro occured.")]
    DivisionByZero,
    /// A type could not be converted.
    #[error("A type could not be converted.")]
    InternalTypeConversionFailed,
}

/// Represents an expense made by a creditor, distributed among multiple beneficiaries.
///
/// The [Expense] struct captures details about a financial expense, including the creditor's ID,
/// the total amount of the expense, and how this amount is shared among beneficiaries. It also
/// keeps track of the total share amount and the number of beneficiaries without a specified share.
#[derive(Debug, uniffi::Object)]
pub struct Expense {
    /// The ID of the creditor who made the expense.
    pub creditor_id: String,
    /// The total amount of the expense.
    pub amount: String,
    /// The total amount that has been explicitly shared among beneficiaries.
    pub total_share_amount: String,
    /// The number of beneficiaries without an explicitly specified share.
    pub number_of_beneficiaries_without_share: String,
    /// A list of beneficiaries who share this expense.
    pub beneficiaries: Vec<Beneficiary>,
}

#[uniffi::export]
impl Expense {
    /// Attempts to create a new [Expense].
    ///
    /// This constructor initializes an [Expense] with the given creditor ID, total amount, and list of beneficiaries.
    /// It validates the inputs and calculates the total share amount and the number of beneficiaries without a specified share by iterating
    /// through the beneficiaries.
    ///
    /// # Arguments
    ///
    /// * `creditor_id` - The ID of the creditor who made the expense.
    /// * `amount` - The total amount of the expense.
    /// * `beneficiaries` - A list of beneficiaries who share this expense.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The expense amount is not greater than zero.
    /// - There are no beneficiaries.
    /// - The sum of the shares exceeds the total expense amount.
    /// - Each beneficiary has a share, and the sum of the shares is less than the total amount of the expense.
    /// - Any share amount is not positive.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```rust
    /// use duckcount_algorithm::{beneficiary::Beneficiary, expense::Expense};
    /// use uuid::Uuid;
    ///
    /// let alice_id = Uuid::new_v4().to_string();
    /// let bob_id = Uuid::new_v4().to_string();
    /// let creditor_id = Uuid::new_v4().to_string();
    ///
    /// let amount = "100.0";
    ///
    /// let beneficiaries = vec![
    ///     Beneficiary::new(&alice_id, Some(String::from("50.0"))),
    ///     Beneficiary::new(&bob_id, None),
    /// ];
    ///
    /// let expense = Expense::new(&creditor_id, amount, beneficiaries);
    /// ```
    #[uniffi::constructor]
    pub fn new(
        creditor_id: &str,
        amount: &str,
        beneficiaries: Vec<Beneficiary>,
    ) -> Result<Self, ExpenseError> {
        let amount = BigDecimal::from_str(&amount).map_err(|_| ExpenseError::MalformedAmount)?;

        if amount <= BigDecimal::zero() {
            return Err(ExpenseError::NonPositiveAmount);
        }

        if beneficiaries.is_empty() {
            return Err(ExpenseError::NoBeneficiaries);
        }

        let mut total_share_amount = BigDecimal::zero();
        let mut number_of_beneficiaries_without_share = BigDecimal::zero();

        for beneficiary in &beneficiaries {
            if let Some(share_amount) = &beneficiary.share {
                let share_amount = BigDecimal::from_str(&share_amount)
                    .map_err(|_| ExpenseError::MalformedAmount)?;

                if share_amount <= BigDecimal::zero() {
                    return Err(ExpenseError::NonPositiveShare);
                }

                total_share_amount += share_amount;
            } else {
                number_of_beneficiaries_without_share += 1;
            }
        }

        if total_share_amount > amount {
            return Err(ExpenseError::SharesExceedTotalAmount);
        }

        if number_of_beneficiaries_without_share == BigDecimal::zero()
            && total_share_amount < amount
        {
            return Err(ExpenseError::SharesBelowTotalAmount);
        }

        Ok(Expense {
            creditor_id: creditor_id.to_string(),
            amount: amount.to_plain_string(),
            total_share_amount: total_share_amount.to_plain_string(),
            number_of_beneficiaries_without_share: number_of_beneficiaries_without_share
                .to_plain_string(),
            beneficiaries,
        })
    }

    /// Calculates the equal shares of all beneficiaries without a share.
    ///
    /// It handles rounding discrepancies by making small
    /// adjustments to ensure that the total amounts are balanced correctly.
    ///
    /// # Rounding Adjustments
    ///
    /// The function makes small adjustments to handle rounding discrepancies:
    /// - It checks if a number has more than two decimal places.
    /// - If a rounding discrepancy is found, each share is rounded down to two decimal places to ensure standard financial formatting.
    /// - It adds one penny (0.01) to the share of the first beneficiary that triggers this condition to ensure the total amount is balanced.
    pub fn calculate_equal_shares(&self) -> Result<HashMap<String, String>, ExpenseError> {
        let mut shares = HashMap::new();

        let amount =
            BigDecimal::from_str(&self.amount).map_err(|_| ExpenseError::MalformedAmount)?;

        let total_share_amount = BigDecimal::from_str(&self.total_share_amount)
            .map_err(|_| ExpenseError::MalformedAmount)?;

        let remaining_amount = amount - total_share_amount;
        let remaining_amount_str = remaining_amount.to_plain_string();

        let number_of_beneficiaries_without_share =
            usize::from_str(&self.number_of_beneficiaries_without_share)
                .map_err(|_| ExpenseError::MalformedAmount)?;

        if number_of_beneficiaries_without_share == 0 {
            return Ok(shares);
        }

        let divided_amount = Expense::divide_amount(
            &remaining_amount_str,
            number_of_beneficiaries_without_share,
            100, // 100 to convert to cents, 1 to keep as is.
        )?;

        let mut divided_amount_iter = divided_amount.into_iter();
        for beneficiary in &self.beneficiaries {
            if beneficiary.share.is_none() {
                if let Some(share) = divided_amount_iter.next() {
                    shares.insert(beneficiary.user_id.to_owned(), share.to_plain_string());
                }
            }
        }

        Ok(shares)
    }

    pub fn copy(&self) -> Self {
        Expense {
            creditor_id: self.creditor_id.clone(),
            amount: self.amount.clone(),
            total_share_amount: self.total_share_amount.clone(),
            number_of_beneficiaries_without_share: self
                .number_of_beneficiaries_without_share
                .clone(),
            beneficiaries: self.beneficiaries.clone(),
        }
    }
}

impl Expense {
    fn divide_amount(
        amount_str: &str,
        parts: usize,
        scale: usize,
    ) -> Result<Vec<BigDecimal>, ExpenseError> {
        if parts == 0 {
            return Err(ExpenseError::DivisionByZero);
        }

        let amount_bd = match BigDecimal::from_str(amount_str) {
            Ok(bd) => bd,
            Err(_) => return Err(ExpenseError::MalformedAmount),
        };

        let scale = BigInt::from(scale);
        let total_cents_bd = &amount_bd * &scale;
        let total_cents_bi = match total_cents_bd.to_bigint() {
            Some(bi) => bi,
            None => return Err(ExpenseError::InternalTypeConversionFailed),
        };

        let base_part = total_cents_bi.clone() / parts;
        let remainder = total_cents_bi % parts;

        let mut result = Vec::new();
        for i in 0..parts {
            let mut part_cents = base_part.clone();
            if BigInt::from(i) < remainder {
                part_cents += 1;
            }
            let part_amount =
                BigDecimal::from(part_cents) / BigDecimal::from_bigint(scale.clone(), 0);
            result.push(part_amount);
        }

        Ok(result)
    }

    /// Calculates the equal share of any beneficiary without a share.
    ///
    /// This function should only be used internally as a fallback to `calculate_equal_shares`.
    ///
    /// DO NOT use it as a replacement for `calculate_equal_shares`.
    pub fn calculate_equal_share(&self) -> Result<String, ExpenseError> {
        let number_of_beneficiaries_without_share =
            BigDecimal::from_str(&self.number_of_beneficiaries_without_share)
                .map_err(|_| ExpenseError::MalformedAmount)?;

        let amount =
            BigDecimal::from_str(&self.amount).map_err(|_| ExpenseError::MalformedAmount)?;

        let total_share_amount = BigDecimal::from_str(&self.total_share_amount)
            .map_err(|_| ExpenseError::MalformedAmount)?;

        let mut share: BigDecimal =
            (1 / number_of_beneficiaries_without_share) * (amount - total_share_amount);

        share = share.with_scale_round(2, RoundingMode::Down);

        Ok(share.to_plain_string())
    }
}
