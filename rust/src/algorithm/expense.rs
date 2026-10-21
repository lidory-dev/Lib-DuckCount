use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use bigdecimal::num_bigint::BigInt;
use bigdecimal::num_bigint::ToBigInt;
use bigdecimal::{BigDecimal, Zero};
use thiserror::Error;

use crate::algorithm::currency::Currency;

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
    /// A fixed share was assigned to a UUID that is not among the beneficiaries.
    #[error("A fixed share was assigned to a UUID that is not among the beneficiaries.")]
    FixedShareForUnknownBeneficiary,
    /// The amount is malformed.
    #[error("The amount is malformed.")]
    MalformedAmount,
    /// A division by zerro occured.
    #[error("A division by zero occured.")]
    DivisionByZero,
    /// A type could not be converted.
    #[error("A type could not be converted.")]
    InternalTypeConversionFailed,
    /// The amount of the expense or the share of a beneficiary uses subunits, but the currency does not support fractional amounts (e.g., ¥12.50 for a currency that only allows whole units).
    #[error(
        "The amount or the share of a beneficiary uses subunits, but the currency does not support fractional amounts."
    )]
    UnsupportedSubunits,
    /// The same user is listed as a beneficiary more than once.
    #[error("The same user is listed as a beneficiary more than once.")]
    DuplicateBeneficiary,
    /// An expense cannot list more than [MAX_BENEFICIARIES] beneficiaries.
    #[error("An expense cannot list more than {MAX_BENEFICIARIES} beneficiaries.")]
    TooManyBeneficiaries,
}

/// The most beneficiaries an expense may list, its creditor included when they are
/// listed, whether it is a one-time expense or a group's.
///
/// Creating a one-time expense sends its key right away to every beneficiary but the
/// creditor, one direct message each, and no beneficiary can open the expense before
/// theirs arrives. The server's allowance of direct messages per sender is sized for two
/// expenses this large a minute, so that a user writing expenses one after the other
/// is never held back, and the server refuses a longer list of either kind anyway:
/// checking here lets the app say so before anything is sent.
pub const MAX_BENEFICIARIES: usize = 100;

/// Exposes [`MAX_BENEFICIARIES`] to the foreign bindings so clients can show the
/// limit and keep a selection within it instead of hardcoding it.
///
/// UniFFI has no `usize` support, so the value is narrowed to `u16`.
#[uniffi::export]
pub fn max_beneficiaries() -> u16 {
    MAX_BENEFICIARIES as u16
}

/// The most digits an amount or a share may have before its decimal point: a thousand
/// trillion, far past any real expense, and few enough to keep adding them up cheap.
const MAX_WHOLE_DIGITS: usize = 15;

/// The most digits an amount or a share may have after its decimal point, in a currency
/// with a subunit: its cents.
const MAX_SUBUNIT_DIGITS: usize = 2;

/// Represents an expense made by a creditor, distributed among multiple beneficiaries.
///
/// The [Expense] struct captures details about a financial expense, including the creditor's ID,
/// the total amount of the expense, the currency it is expressed in, and how this amount is
/// shared among its beneficiaries.
#[derive(Debug, Clone, uniffi::Object)]
pub struct Expense {
    /// The ID of the creditor who made the expense.
    pub creditor_uuid: String,
    /// The total amount of the expense.
    pub amount: String,
    /// The currency in which the expense is made.
    pub currency: Currency,
    /// A list of beneficiaries who share this expense.
    pub beneficiaries: Vec<Beneficiary>,
}

#[uniffi::export]
impl Expense {
    /// Attempts to create a new [Expense].
    ///
    /// This constructor initializes an [Expense] with the given creditor ID, total amount, currency, and list of beneficiaries.
    /// It validates the inputs and calculates the total share amount and the number of beneficiaries without a specified share by iterating
    /// through the beneficiaries.
    ///
    /// # Arguments
    ///
    /// * `creditor_uuid` - The ID of the creditor who made the expense.
    /// * `amount` - The total amount of the expense.
    /// * `currency` - The currency in which the expense is made.
    /// * `beneficiaries` - A list of beneficiaries who share this expense.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The amount or any share is malformed and cannot be parsed.
    /// - The expense amount is not greater than zero.
    /// - There are no beneficiaries.
    /// - The sum of the shares exceeds the total expense amount.
    /// - Each beneficiary has a share, and the sum of the shares is less than the total amount of the expense.
    /// - Any share amount is not positive.
    /// - The expense amount or any share uses subunits, but the currency does not support fractional amounts.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```rust
    /// # use lib_duckcount::algorithm::{beneficiary::Beneficiary, currency::Currency, expense::{Expense, compute_beneficiaries}};
    /// # use uuid::Uuid;
    /// # use std::collections::HashMap;
    ///
    /// let alice_uuid = Uuid::new_v4().to_string();
    /// let bob_uuid = Uuid::new_v4().to_string();
    /// let creditor_uuid = Uuid::new_v4().to_string();
    ///
    /// let amount = "100.00";
    ///
    /// let beneficiary_uuids = vec![alice_uuid.clone(), bob_uuid.clone()];
    ///
    /// let mut fixed_shares = HashMap::new();
    /// fixed_shares.insert(alice_uuid.clone(), String::from("50.00"));
    ///
    /// let currency = Currency::new("Euro", "€", true).unwrap();
    /// let beneficiaries =
    ///     compute_beneficiaries(amount, &currency, &beneficiary_uuids, &fixed_shares)
    ///         .unwrap();
    ///
    /// let currency = Currency::new("Euro", "€", true).unwrap();
    /// let expense = Expense::new(&creditor_uuid, amount, &currency, &beneficiaries);
    /// ```
    #[uniffi::constructor]
    pub fn new(
        creditor_uuid: &str,
        amount: &str,
        currency: &Currency,
        beneficiaries: &Vec<Beneficiary>,
    ) -> Result<Self, ExpenseError> {
        let amount = BigDecimal::from_str(&amount).map_err(|_| ExpenseError::MalformedAmount)?;

        if amount <= BigDecimal::zero() {
            return Err(ExpenseError::NonPositiveAmount);
        }

        if !currency.has_sub_unit && amount.fractional_digit_count() > 0 {
            return Err(ExpenseError::UnsupportedSubunits);
        }

        if beneficiaries.is_empty() {
            return Err(ExpenseError::NoBeneficiaries);
        }

        let mut total_share_amount = BigDecimal::zero();

        for beneficiary in beneficiaries {
            let share_amount = BigDecimal::from_str(&beneficiary.share)
                .map_err(|_| ExpenseError::MalformedAmount)?;

            if share_amount <= BigDecimal::zero() {
                return Err(ExpenseError::NonPositiveShare);
            }

            if !currency.has_sub_unit && share_amount.fractional_digit_count() > 0 {
                return Err(ExpenseError::UnsupportedSubunits);
            }

            total_share_amount += share_amount;
        }

        if total_share_amount > amount {
            return Err(ExpenseError::SharesExceedTotalAmount);
        }

        if total_share_amount < amount {
            return Err(ExpenseError::SharesBelowTotalAmount);
        }

        Ok(Expense {
            creditor_uuid: creditor_uuid.to_string(),
            amount: amount.to_plain_string(),
            currency: currency.to_owned(),
            beneficiaries: beneficiaries.to_owned(),
        })
    }

    pub fn copy(&self) -> Self {
        Expense {
            creditor_uuid: self.creditor_uuid.clone(),
            amount: self.amount.clone(),
            currency: self.currency.clone(),
            beneficiaries: self.beneficiaries.clone(),
        }
    }
}

impl Expense {
    /// Divides an amount into a given number of parts, distributing any remainder as evenly as possible.
    ///
    /// The amount is first converted into integer subunits using `scale` (e.g. `100` to work in cents),
    /// so the division avoids floating-point rounding errors. Every part receives the integer quotient,
    /// and the leftover subunits are handed out one at a time to the first parts. As a result the parts
    /// differ by at most one subunit and their sum equals the original amount exactly.
    ///
    /// # Arguments
    ///
    /// * `amount_str` - The amount to divide, as a decimal string.
    /// * `parts` - The number of parts to divide the amount into.
    /// * `scale` - The number of subunits per whole unit (e.g. `100` for cents, `1` for whole units).
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - `parts` is zero (division by zero).
    /// - The amount is malformed and cannot be parsed.
    /// - The amount cannot be converted into an integer number of subunits.
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
}

/// Computes the share of every beneficiary, splitting the not-yet-assigned part of the amount
/// equally among the beneficiaries that do not have an explicit share.
///
/// Beneficiaries listed in `fixed_shares` keep their explicit share. The remaining amount
/// (the total minus the sum of the explicit shares) is divided equally among the beneficiaries
/// without a share. The split is computed in the currency's subunits (cents when the currency has a
/// subunit, whole units otherwise) so that the shares sum exactly to the remaining amount; any
/// indivisible remainder is distributed one subunit at a time across the first of those
/// beneficiaries. If every beneficiary already has an explicit share, those shares are returned
/// unchanged.
///
/// # Arguments
///
/// * `amount` - The total amount of the expense.
/// * `currency` - The currency in which the expense is made.
/// * `beneficiary_user_uuids` - The UUIDs of all beneficiaries sharing the expense.
/// * `fixed_shares` - A map from beneficiary UUID to an explicitly assigned share.
///
/// # Errors
///
/// This function will return an error if:
/// - A fixed share was assigned to a UUID that is not among the beneficiaries.
/// - The amount or any explicitly set share is malformed and cannot be parsed.
/// - Any fixed share is not positive.
/// - The sum of the shares exceeds the total expense amount.
/// - Each beneficiary has a share, and the sum of the shares is less than the total amount of the expense.
/// - A division by zero occurs while splitting the remaining amount.
/// - An internal type conversion fails while splitting the remaining amount.
///
/// # Examples
///
/// Basic usage:
///
/// ```rust
/// # use lib_duckcount::algorithm::{beneficiary::Beneficiary, currency::Currency, expense::compute_beneficiaries};
/// # use uuid::Uuid;
/// # use std::collections::HashMap;
///
/// let alice_uuid = Uuid::new_v4().to_string();
/// let bob_uuid = Uuid::new_v4().to_string();
///
/// let amount = "100.00";
/// let currency = Currency::new("Euro", "€", true).unwrap();
///
/// let beneficiary_uuids = vec![alice_uuid.clone(), bob_uuid.clone()];
///
/// let mut fixed_shares = HashMap::new();
/// fixed_shares.insert(alice_uuid.clone(), String::from("50.00"));
///
/// // Alice keeps her 50.00 share; Bob receives the remaining 50.00.
/// let beneficiaries =
///     compute_beneficiaries(amount, &currency, &beneficiary_uuids, &fixed_shares)
///         .unwrap();
/// ```
#[uniffi::export]
pub fn compute_beneficiaries(
    amount: &str,
    currency: &Currency,
    beneficiary_user_uuids: &Vec<String>,
    fixed_shares: &HashMap<String, String>,
) -> Result<Vec<Beneficiary>, ExpenseError> {
    let amount = BigDecimal::from_str(amount).map_err(|_| ExpenseError::MalformedAmount)?;

    let mut total_share_amount = BigDecimal::from(0);
    for (uuid, share) in fixed_shares {
        if !beneficiary_user_uuids.contains(uuid) {
            return Err(ExpenseError::FixedShareForUnknownBeneficiary);
        }

        let share_amount =
            BigDecimal::from_str(share).map_err(|_| ExpenseError::MalformedAmount)?;

        if share_amount <= BigDecimal::from(0) {
            return Err(ExpenseError::NonPositiveShare);
        }

        total_share_amount += share_amount;
    }

    if total_share_amount > amount {
        return Err(ExpenseError::SharesExceedTotalAmount);
    }

    let number_of_beneficiaries_without_share: usize =
        beneficiary_user_uuids.len() - fixed_shares.len();

    if number_of_beneficiaries_without_share == 0 {
        if total_share_amount > amount {
            return Err(ExpenseError::SharesExceedTotalAmount);
        }

        if total_share_amount < amount {
            return Err(ExpenseError::SharesBelowTotalAmount);
        }

        return Ok(fixed_shares
            .iter()
            .map(|(user_uuid, share)| Beneficiary::new(user_uuid, share))
            .collect());
    }

    // For now, if the currency has a subunit, we consider it to be cents.
    let scale = match currency.has_sub_unit {
        true => 100,
        false => 1,
    };

    let remaining_amount = (amount - total_share_amount).to_plain_string();

    let divided_amount = Expense::divide_amount(
        &remaining_amount,
        number_of_beneficiaries_without_share,
        scale,
    )?;

    let mut beneficiaries = Vec::with_capacity(beneficiary_user_uuids.len());

    let mut divided_amount_iter = divided_amount.into_iter();
    for beneficiary_user_uuid in beneficiary_user_uuids {
        if !fixed_shares.contains_key(beneficiary_user_uuid) {
            if let Some(share) = divided_amount_iter.next() {
                let beneficiary = Beneficiary::new(beneficiary_user_uuid, &share.to_plain_string());
                beneficiaries.push(beneficiary);
            }
        } else {
            let share = fixed_shares
                .get(beneficiary_user_uuid)
                .ok_or_else(|| ExpenseError::MalformedAmount)?;

            let beneficiary = Beneficiary::new(beneficiary_user_uuid, share);

            beneficiaries.push(beneficiary);
        }
    }

    Ok(beneficiaries)
}

/// Checks if an expense is valid.
///
/// This function tries to validate an expense with the given total amount, currency, and list of beneficiaries.
/// It validates the inputs and calculates the total share amount and the number of beneficiaries without a specified share by iterating
/// through the beneficiaries.
///
/// # Arguments
///
/// * `amount` - The total amount of the expense.
/// * `currency` - The currency in which the expense is made.
/// * `beneficiaries` - A list of beneficiaries who share this expense.
///
/// # Errors
///
/// This function will return an error if:
/// - The expense amount is not greater than zero.
/// - There are no beneficiaries.
/// - There are more than [MAX_BENEFICIARIES] beneficiaries. The count is checked before
///   any beneficiary is, so a list that is too long is refused for its length alone.
/// - The sum of the shares exceeds the total expense amount.
/// - Each beneficiary has a share, and the sum of the shares is less than the total amount of the expense.
/// - Any share amount is not positive.
/// - The expense amount or any share uses subunits, but the currency does not support fractional amounts.
/// - The expense amount or any share is not 1 to 15 ASCII digits, followed, only in a currency with a
///   subunit, by an optional point and 1 or 2 digits.
/// - The same user is listed as a beneficiary more than once.
///
/// # Examples
///
/// Basic usage:
///
/// ```rust
/// # use lib_duckcount::algorithm::{beneficiary::Beneficiary, currency::Currency, expense::{compute_beneficiaries, validate_expense}};
/// # use uuid::Uuid;
/// # use std::collections::HashMap;
///
/// let alice_uuid = Uuid::new_v4().to_string();
/// let bob_uuid = Uuid::new_v4().to_string();
/// let creditor_uuid = Uuid::new_v4().to_string();
///
/// let amount = "100.00";
/// let currency = Currency::new("Euro", "€", true).unwrap();
///
/// let beneficiary_uuids = vec![alice_uuid.clone(), bob_uuid.clone()];
///
/// let mut fixed_shares = HashMap::new();
/// fixed_shares.insert(alice_uuid.clone(), String::from("50.00"));
///
/// let beneficiaries =
///     compute_beneficiaries(amount, &currency, &beneficiary_uuids, &fixed_shares)
///         .unwrap();
///
/// let expense = validate_expense(amount, &currency, &beneficiaries);
/// ```
#[uniffi::export]
pub fn validate_expense(
    amount: &str,
    currency: &Currency,
    beneficiaries: &Vec<Beneficiary>,
) -> Result<(), ExpenseError> {
    let amount = parse_amount(amount, currency)?;

    if amount <= BigDecimal::zero() {
        return Err(ExpenseError::NonPositiveAmount);
    }

    if beneficiaries.is_empty() {
        return Err(ExpenseError::NoBeneficiaries);
    }

    if beneficiaries.len() > MAX_BENEFICIARIES {
        return Err(ExpenseError::TooManyBeneficiaries);
    }

    let mut user_uuids = HashSet::with_capacity(beneficiaries.len());
    let mut total_share_amount = BigDecimal::zero();

    for beneficiary in beneficiaries {
        if !user_uuids.insert(&beneficiary.user_uuid) {
            return Err(ExpenseError::DuplicateBeneficiary);
        }

        let share = parse_amount(&beneficiary.share, currency)?;

        if share <= BigDecimal::zero() {
            return Err(ExpenseError::NonPositiveShare);
        }

        total_share_amount += share;
    }

    if total_share_amount > amount {
        return Err(ExpenseError::SharesExceedTotalAmount);
    }

    if total_share_amount < amount {
        return Err(ExpenseError::SharesBelowTotalAmount);
    }

    Ok(())
}

/// Parses `amount` in the only form the app writes one: one to [MAX_WHOLE_DIGITS] ASCII
/// digits, then, in a currency with a subunit, optionally a point and one to
/// [MAX_SUBUNIT_DIGITS] more digits.
///
/// [BigDecimal] alone also reads a sign, an exponent and underscores, which other parsers
/// do not all read the same way, if at all. An exponent also lets two amounts differ in
/// scale by billions, which adding them up then pays for in time and memory.
///
/// # Errors
///
/// * `ExpenseError::UnsupportedSubunits` - If `amount` is digits then a point, and
///   `currency` has no subunit.
/// * `ExpenseError::MalformedAmount` - If `amount` is written any other way.
fn parse_amount(amount: &str, currency: &Currency) -> Result<BigDecimal, ExpenseError> {
    let (whole, subunits) = match amount.split_once('.') {
        Some((whole, subunits)) => (whole, Some(subunits)),
        None => (amount, None),
    };

    if !is_digits(whole, MAX_WHOLE_DIGITS) {
        return Err(ExpenseError::MalformedAmount);
    }

    if let Some(subunits) = subunits {
        if !currency.has_sub_unit {
            return Err(ExpenseError::UnsupportedSubunits);
        }

        if !is_digits(subunits, MAX_SUBUNIT_DIGITS) {
            return Err(ExpenseError::MalformedAmount);
        }
    }

    BigDecimal::from_str(amount).map_err(|_| ExpenseError::MalformedAmount)
}

/// Whether `part` is one to `max_length` ASCII digits.
fn is_digits(part: &str, max_length: usize) -> bool {
    (1..=max_length).contains(&part.len()) && part.bytes().all(|byte| byte.is_ascii_digit())
}
