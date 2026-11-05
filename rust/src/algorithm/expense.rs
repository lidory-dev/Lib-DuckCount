use std::{
    cmp::Reverse,
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
    /// A fixed share, a percentage or a weight was assigned to a UUID that is not among the beneficiaries.
    #[error(
        "A fixed share, a percentage or a weight was assigned to a UUID that is not among the beneficiaries."
    )]
    FixedShareForUnknownBeneficiary,
    /// A beneficiary's share was set more than one way: as a fixed share, a percentage or a weight.
    #[error(
        "A beneficiary's share was set more than one way: as a fixed share, a percentage or a weight."
    )]
    ShareSetMoreThanOneWay,
    /// The amount is malformed.
    #[error("The amount is malformed.")]
    MalformedAmount,
    /// A percentage is malformed.
    #[error("The percentage is malformed.")]
    MalformedPercentage,
    /// A share is not what the percentage it was set as comes to.
    #[error("A share is not what the percentage it was set as comes to.")]
    ShareDiffersFromPercentage,
    /// A weight is malformed.
    #[error("The weight is malformed.")]
    MalformedWeight,
    /// A share is not what the weight it was set as comes to.
    #[error("A share is not what the weight it was set as comes to.")]
    ShareDiffersFromWeight,
    /// A type could not be converted.
    #[error("A type could not be converted.")]
    InternalTypeConversionFailed,
    /// The amount of the expense or the share of a beneficiary uses subunits the currency does not have (e.g., ¥12.50 for a currency that only allows whole units, or €12.345).
    #[error("The amount or the share of a beneficiary uses subunits the currency does not have.")]
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

/// The most edits a group expense may have, as many as a one-time expense: it is
/// created at revision 1, and each edit is one more, up to `1 + MAX_GROUP_EXPENSE_EDITS`.
///
/// The server keeps every version of a group expense, none pruned, for its history to
/// be whole, and this is what bounds them. The DuckCount API refuses an edit past it,
/// holding its own copy of the cap: the two change together. A version past it is
/// refused whoever stored it, see
/// [`verify_group_expense`](crate::cryptography::mls::group_expense::verify_group_expense).
/// Deleting an expense and restoring it are no edit, and use up none, see
/// [`GroupExpenseDeletion`](crate::cryptography::mls::group_expense::GroupExpenseDeletion).
pub const MAX_GROUP_EXPENSE_EDITS: u64 = 10;

/// Exposes [`MAX_GROUP_EXPENSE_EDITS`] to the foreign bindings so clients can stop
/// offering an edit past it instead of hardcoding it.
///
/// The value is narrowed to `u16`, as [`max_beneficiaries`] is.
#[uniffi::export]
pub fn max_group_expense_edits() -> u16 {
    MAX_GROUP_EXPENSE_EDITS as u16
}

/// The most digits an amount or a share may have before its decimal point: a thousand
/// trillion, far past any real expense, and few enough to keep adding them up cheap.
const MAX_WHOLE_DIGITS: usize = 15;

/// The most digits an amount or a share may have after its decimal point, in a currency
/// with a subunit: its cents.
const MAX_SUBUNIT_DIGITS: usize = 2;

/// The most digits a percentage or a weight may have before its decimal point: as many as 100,
/// the most that shares can add up to, which is more parts than anybody counts in too.
const MAX_SHARE_SETTING_WHOLE_DIGITS: usize = 3;

/// The most digits a percentage or a weight may have after its decimal point. A client seals
/// each at one length whatever it says, which is what keeps it from telling the server by its
/// length who pays one, so the longest one written must stay short.
const MAX_SHARE_SETTING_SUBUNIT_DIGITS: usize = 2;

/// Hundredths of a percent in a whole amount, which percentages are counted in so that nothing
/// is rounded before it has to be.
const HUNDREDTHS_IN_WHOLE: i32 = 10_000;

/// The weight of a beneficiary sharing what is left who was given none, in the hundredths weights
/// are counted in: one part, so that an even split is what no weight at all comes to.
const DEFAULT_WEIGHT_HUNDREDTHS: i32 = 100;

/// The weight a beneficiary given none is said to have once anybody else has one.
const DEFAULT_WEIGHT: &str = "1";

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
    /// - The expense amount or any share uses subunits the currency does not have.
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
    /// let beneficiaries = compute_beneficiaries(
    ///     amount,
    ///     &currency,
    ///     &beneficiary_uuids,
    ///     &fixed_shares,
    ///     &HashMap::new(),
    ///     &HashMap::new(),
    /// )
    /// .unwrap();
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

        if amount.fractional_digit_count() > currency.subunit_digits() {
            return Err(ExpenseError::UnsupportedSubunits);
        }

        if beneficiaries.is_empty() {
            return Err(ExpenseError::NoBeneficiaries);
        }

        let mut total_share_amount = BigDecimal::zero();
        let mut written_beneficiaries = Vec::with_capacity(beneficiaries.len());

        for beneficiary in beneficiaries {
            let share_amount = BigDecimal::from_str(&beneficiary.share)
                .map_err(|_| ExpenseError::MalformedAmount)?;

            if share_amount <= BigDecimal::zero() {
                return Err(ExpenseError::NonPositiveShare);
            }

            if share_amount.fractional_digit_count() > currency.subunit_digits() {
                return Err(ExpenseError::UnsupportedSubunits);
            }

            written_beneficiaries.push(Beneficiary {
                share: currency.write_amount(&share_amount),
                ..beneficiary.clone()
            });

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
            amount: currency.write_amount(&amount),
            currency: currency.to_owned(),
            beneficiaries: written_beneficiaries,
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

/// Writes `amount` the one way the library hands an amount out, and the only way
/// [validate_expense] takes one, as every amount has to be before it is sealed: `12` in a currency
/// without a subunit, and `12.00` in a currency with one.
///
/// # Arguments
///
/// * `amount` - The amount, as anything from `12` to `12.50` in a currency with a subunit, and in
///   whole units otherwise.
/// * `currency` - The currency it is in.
///
/// # Errors
///
/// * `ExpenseError::UnsupportedSubunits` - If `amount` is digits then a point, and `currency` has no
///   subunit.
/// * `ExpenseError::MalformedAmount` - If `amount` is written any other way.
///
/// # Examples
///
/// ```rust
/// # use lib_duckcount::algorithm::{currency::Currency, expense::canonical_amount};
///
/// let euro = Currency::new("Euro", "€", true).unwrap();
/// let yen = Currency::new("Yen", "¥", false).unwrap();
///
/// assert_eq!(canonical_amount("12", &euro).unwrap(), "12.00");
/// assert_eq!(canonical_amount("12.5", &euro).unwrap(), "12.50");
/// assert_eq!(canonical_amount("12", &yen).unwrap(), "12");
/// ```
#[uniffi::export]
pub fn canonical_amount(amount: &str, currency: &Currency) -> Result<String, ExpenseError> {
    Ok(currency.write_amount(&parse_amount(amount, currency)?))
}

/// Computes the share of every beneficiary, splitting the not-yet-assigned part of the amount
/// among the beneficiaries that do not have an explicit share, by their weights: 2, 1 and 1 of 100
/// makes four parts of 25, so 50, 25 and 25, and no weights at all make an even split.
///
/// Beneficiaries listed in `fixed_shares` keep their explicit share, and those listed in
/// `share_percentages` get that percentage of the whole amount, whatever the others take: each
/// rounded to one of the two subunits around it, so that together they come to what the
/// percentages come to, the subunits rounding leaves going to whoever lost the most to it, then to
/// whoever comes first. The remaining amount (the total minus the sum of those shares) is
/// divided among the beneficiaries without a share, those not listed in `share_weights` counting
/// for one part. The split is computed in the currency's subunits (cents when the currency has a
/// subunit, whole units otherwise) so that the shares sum exactly to the remaining amount, any
/// indivisible remainder going one subunit at a time to whoever lost the most to rounding, then to
/// whoever comes first. If every beneficiary already has an explicit share or a percentage, those
/// shares must come to the amount.
///
/// The beneficiaries come back in the order of `beneficiary_user_uuids`, every share written as
/// [canonical_amount] writes an amount, a fixed one too. When `share_weights` lists anybody, those
/// splitting the remaining amount all come back with a weight, one for those it does not list, a
/// weight meaning nothing but next to the others.
///
/// # Arguments
///
/// * `amount` - The total amount of the expense.
/// * `currency` - The currency in which the expense is made.
/// * `beneficiary_user_uuids` - The UUIDs of all beneficiaries sharing the expense.
/// * `fixed_shares` - A map from beneficiary UUID to an explicitly assigned share.
/// * `share_percentages` - A map from beneficiary UUID to the percentage of the amount their share
///   is set as: `25` or `33.33`, up to two decimals.
/// * `share_weights` - A map from beneficiary UUID to how many parts of the remaining amount their
///   share is set as: `2` or `0.5`, up to two decimals.
///
/// # Errors
///
/// This function will return an error if:
/// - A fixed share, a percentage or a weight was assigned to a UUID that is not among the
///   beneficiaries.
/// - A beneficiary's share was set more than one way, as a fixed share, a percentage or a weight.
/// - The amount, any explicitly set share, any percentage or any weight is malformed and cannot be
///   parsed.
/// - The amount or any explicitly set share uses subunits the currency does not have.
/// - Any fixed share, percentage or weight is not positive.
/// - The sum of the shares, with each percentage taken before it is rounded, exceeds the total
///   expense amount.
/// - Each beneficiary has a share or a percentage, and that sum is less than the total amount of
///   the expense. Three times `33.33` is therefore refused, on any amount: what it leaves is no
///   rounding, and is for a beneficiary without a share to pay, or for the percentages to say.
/// - An internal type conversion fails while working out or splitting the shares.
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
/// let beneficiaries = compute_beneficiaries(
///     amount,
///     &currency,
///     &beneficiary_uuids,
///     &fixed_shares,
///     &HashMap::new(),
///     &HashMap::new(),
/// )
/// .unwrap();
/// ```
///
/// With a percentage:
///
/// ```rust
/// # use lib_duckcount::algorithm::{currency::Currency, expense::compute_beneficiaries};
/// # use uuid::Uuid;
/// # use std::collections::HashMap;
///
/// let alice_uuid = Uuid::new_v4().to_string();
/// let bob_uuid = Uuid::new_v4().to_string();
///
/// let currency = Currency::new("Euro", "€", true).unwrap();
///
/// let beneficiary_uuids = vec![alice_uuid.clone(), bob_uuid.clone()];
///
/// let mut share_percentages = HashMap::new();
/// share_percentages.insert(alice_uuid.clone(), String::from("25"));
///
/// // Alice pays 25% of it, 20.00; Bob receives the remaining 60.00.
/// let beneficiaries = compute_beneficiaries(
///     "80.00",
///     &currency,
///     &beneficiary_uuids,
///     &HashMap::new(),
///     &share_percentages,
///     &HashMap::new(),
/// )
/// .unwrap();
/// ```
///
/// With a weight:
///
/// ```rust
/// # use lib_duckcount::algorithm::{currency::Currency, expense::compute_beneficiaries};
/// # use uuid::Uuid;
/// # use std::collections::HashMap;
///
/// let alice_uuid = Uuid::new_v4().to_string();
/// let bob_uuid = Uuid::new_v4().to_string();
/// let charlie_uuid = Uuid::new_v4().to_string();
///
/// let currency = Currency::new("Euro", "€", true).unwrap();
///
/// let beneficiary_uuids = vec![alice_uuid.clone(), bob_uuid.clone(), charlie_uuid.clone()];
///
/// let mut share_weights = HashMap::new();
/// share_weights.insert(alice_uuid.clone(), String::from("2"));
///
/// // Four parts of 25.00: Alice pays two of them, 50.00, and Bob and Charlie 25.00 each.
/// let beneficiaries = compute_beneficiaries(
///     "100.00",
///     &currency,
///     &beneficiary_uuids,
///     &HashMap::new(),
///     &HashMap::new(),
///     &share_weights,
/// )
/// .unwrap();
/// ```
#[uniffi::export]
pub fn compute_beneficiaries(
    amount: &str,
    currency: &Currency,
    beneficiary_user_uuids: &Vec<String>,
    fixed_shares: &HashMap<String, String>,
    share_percentages: &HashMap<String, String>,
    share_weights: &HashMap<String, String>,
) -> Result<Vec<Beneficiary>, ExpenseError> {
    let amount = parse_amount(amount, currency)?;

    let mut total_fixed_amount = BigDecimal::from(0);
    let mut written_fixed_shares = HashMap::with_capacity(fixed_shares.len());
    for (uuid, share) in fixed_shares {
        if !beneficiary_user_uuids.contains(uuid) {
            return Err(ExpenseError::FixedShareForUnknownBeneficiary);
        }

        let share_amount = parse_amount(share, currency)?;

        if share_amount <= BigDecimal::from(0) {
            return Err(ExpenseError::NonPositiveShare);
        }

        written_fixed_shares.insert(uuid, currency.write_amount(&share_amount));

        total_fixed_amount += share_amount;
    }

    for uuid in share_percentages.keys() {
        if !beneficiary_user_uuids.contains(uuid) {
            return Err(ExpenseError::FixedShareForUnknownBeneficiary);
        }

        if fixed_shares.contains_key(uuid) {
            return Err(ExpenseError::ShareSetMoreThanOneWay);
        }
    }

    for uuid in share_weights.keys() {
        if !beneficiary_user_uuids.contains(uuid) {
            return Err(ExpenseError::FixedShareForUnknownBeneficiary);
        }

        if fixed_shares.contains_key(uuid) || share_percentages.contains_key(uuid) {
            return Err(ExpenseError::ShareSetMoreThanOneWay);
        }
    }

    // In the beneficiaries' order, which decides who gets a subunit when two have an equal claim.
    let percentage_uuids: Vec<&String> = beneficiary_user_uuids
        .iter()
        .filter(|uuid| share_percentages.contains_key(*uuid))
        .collect();

    let hundredths = percentage_uuids
        .iter()
        .map(|uuid| parse_percentage(&share_percentages[*uuid]))
        .collect::<Result<Vec<BigInt>, ExpenseError>>()?;

    // What the percentages say, not what they round to, so that whether they add up does not
    // depend on the amount they are of.
    let exact_percentage_amount = &amount * BigDecimal::new(hundredths.iter().sum::<BigInt>(), 4);
    let total_share_amount = &total_fixed_amount + &exact_percentage_amount;

    if total_share_amount > amount {
        return Err(ExpenseError::SharesExceedTotalAmount);
    }

    // Who shares what the others leave, in the beneficiaries' order, as for the percentages.
    let weighted_uuids: Vec<&String> = beneficiary_user_uuids
        .iter()
        .filter(|uuid| !fixed_shares.contains_key(*uuid) && !share_percentages.contains_key(*uuid))
        .collect();

    if weighted_uuids.is_empty() && total_share_amount < amount {
        return Err(ExpenseError::SharesBelowTotalAmount);
    }

    let weights = weighted_uuids
        .iter()
        .map(|uuid| match share_weights.get(*uuid) {
            Some(weight) => parse_weight(weight),
            None => Ok(BigInt::from(DEFAULT_WEIGHT_HUNDREDTHS)),
        })
        .collect::<Result<Vec<BigInt>, ExpenseError>>()?;

    let scale = subunit_scale(currency);

    let percentage_shares: HashMap<&String, BigDecimal> = percentage_uuids
        .into_iter()
        .zip(
            shares_of_percentages(&to_subunits(&amount, scale)?, &hundredths)
                .into_iter()
                .map(|share| from_subunits(share, scale)),
        )
        .collect();

    let remaining_amount =
        &amount - &total_fixed_amount - percentage_shares.values().sum::<BigDecimal>();

    let mut divided_amount_iter =
        shares_of_weights(&to_subunits(&remaining_amount, scale)?, &weights)
            .into_iter()
            .map(|share| from_subunits(share, scale));

    let mut beneficiaries = Vec::with_capacity(beneficiary_user_uuids.len());

    for beneficiary_user_uuid in beneficiary_user_uuids {
        if let Some(share) = written_fixed_shares.get(beneficiary_user_uuid) {
            beneficiaries.push(Beneficiary::new(beneficiary_user_uuid, share));
        } else if let Some(share) = percentage_shares.get(beneficiary_user_uuid) {
            beneficiaries.push(Beneficiary::with_percentage(
                beneficiary_user_uuid,
                &currency.write_amount(share),
                &share_percentages[beneficiary_user_uuid],
            ));
        } else if let Some(share) = divided_amount_iter.next() {
            let share = currency.write_amount(&share);

            beneficiaries.push(if share_weights.is_empty() {
                Beneficiary::new(beneficiary_user_uuid, &share)
            } else {
                let weight = share_weights
                    .get(beneficiary_user_uuid)
                    .map_or(DEFAULT_WEIGHT, String::as_str);

                Beneficiary::with_weight(beneficiary_user_uuid, &share, weight)
            });
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
/// - The expense amount or any share is not written as [canonical_amount] writes one: 1 to 15 ASCII
///   digits with no zero in front that does nothing, followed, only in a currency with a subunit
///   and always in one, by a point and 2 digits.
/// - The same user is listed as a beneficiary more than once.
/// - Any percentage or weight is malformed or not positive, or a share set as one is neither of the
///   two subunits around what it comes to, or that exact amount when it falls on a subunit. What a
///   weight comes to is its part of the shares that have one.
/// - A beneficiary's share was set as both a percentage and a weight.
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
/// let beneficiaries = compute_beneficiaries(
///     amount,
///     &currency,
///     &beneficiary_uuids,
///     &fixed_shares,
///     &HashMap::new(),
///     &HashMap::new(),
/// )
/// .unwrap();
///
/// let expense = validate_expense(amount, &currency, &beneficiaries);
/// ```
#[uniffi::export]
pub fn validate_expense(
    amount: &str,
    currency: &Currency,
    beneficiaries: &Vec<Beneficiary>,
) -> Result<(), ExpenseError> {
    let amount = parse_canonical_amount(amount, currency)?;

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
    let mut weighted_shares = Vec::new();

    for beneficiary in beneficiaries {
        if !user_uuids.insert(&beneficiary.user_uuid) {
            return Err(ExpenseError::DuplicateBeneficiary);
        }

        let share = parse_canonical_amount(&beneficiary.share, currency)?;

        if share <= BigDecimal::zero() {
            return Err(ExpenseError::NonPositiveShare);
        }

        if beneficiary.share_percentage.is_some() && beneficiary.share_weight.is_some() {
            return Err(ExpenseError::ShareSetMoreThanOneWay);
        }

        if let Some(percentage) = &beneficiary.share_percentage {
            check_share_of_percentage(&share, percentage, &amount, currency)?;
        }

        if let Some(weight) = &beneficiary.share_weight {
            weighted_shares.push((
                to_subunits(&share, subunit_scale(currency))?,
                parse_weight(weight)?,
            ));
        }

        total_share_amount += share;
    }

    if total_share_amount > amount {
        return Err(ExpenseError::SharesExceedTotalAmount);
    }

    if total_share_amount < amount {
        return Err(ExpenseError::SharesBelowTotalAmount);
    }

    check_shares_of_weights(&weighted_shares)
}

/// Checks that `share`, set as `percentage` of `amount`, is what that percentage comes to: the
/// amount in subunits on either side of it, or that exact amount when it falls on a subunit.
///
/// A share is all that sums read, and the percentage is what an edit works it out again from, so
/// the two saying different things would show one thing and charge another. Either side is taken,
/// since which way a share rounds depends on the other shares, see [largest_remainders], and on
/// their order, which reaches a receiver in no particular way.
///
/// # Errors
///
/// * `ExpenseError::MalformedPercentage` - If `percentage` is not written as [parse_share_setting] reads one.
/// * `ExpenseError::NonPositiveShare` - If `percentage` is zero.
/// * `ExpenseError::ShareDiffersFromPercentage` - If `share` is any other amount.
fn check_share_of_percentage(
    share: &BigDecimal,
    percentage: &str,
    amount: &BigDecimal,
    currency: &Currency,
) -> Result<(), ExpenseError> {
    let scale = subunit_scale(currency);
    let whole = BigInt::from(HUNDREDTHS_IN_WHOLE);

    let exact = to_subunits(amount, scale)? * parse_percentage(percentage)?;

    if !rounds_to(&to_subunits(share, scale)?, &exact, &whole) {
        return Err(ExpenseError::ShareDiffersFromPercentage);
    }

    Ok(())
}

/// Checks that each of `weighted_shares`, a share in subunits with the weight it was set as, is what
/// that weight comes to, its part of all of them, as [check_share_of_percentage] checks a percentage
/// and for the same reasons.
///
/// All of them, since nothing says which of the other shares were fixed amounts: an expense using
/// any weight states one for everybody sharing what is left, see [compute_beneficiaries], so those
/// with one are all there is to share it.
///
/// # Errors
///
/// * `ExpenseError::ShareDiffersFromWeight` - If a share is any other amount.
fn check_shares_of_weights(weighted_shares: &[(BigInt, BigInt)]) -> Result<(), ExpenseError> {
    let total = weighted_shares
        .iter()
        .map(|(share, _)| share)
        .sum::<BigInt>();
    let total_weight = weighted_shares
        .iter()
        .map(|(_, weight)| weight)
        .sum::<BigInt>();

    for (share, weight) in weighted_shares {
        if !rounds_to(share, &(&total * weight), &total_weight) {
            return Err(ExpenseError::ShareDiffersFromWeight);
        }
    }

    Ok(())
}

/// Whether `share` is `numerator` divided by `denominator` rounded either way, or that exact amount
/// when it falls on a whole number.
fn rounds_to(share: &BigInt, numerator: &BigInt, denominator: &BigInt) -> bool {
    let lowest = numerator / denominator;
    let highest = match (numerator % denominator).is_zero() {
        true => lowest.clone(),
        false => &lowest + 1,
    };

    *share >= lowest && *share <= highest
}

/// Works out the share each of `hundredths`, percentages in hundredths of a percent, comes to of
/// `amount`, all in subunits, in the same order: together, what the percentages come to together,
/// rounded to the nearest subunit, each one of the two subunits around what it says.
fn shares_of_percentages(amount: &BigInt, hundredths: &[BigInt]) -> Vec<BigInt> {
    let whole = BigInt::from(HUNDREDTHS_IN_WHOLE);

    let exact: Vec<BigInt> = hundredths.iter().map(|part| amount * part).collect();
    let total = (exact.iter().sum::<BigInt>() + &whole / 2) / &whole;

    largest_remainders(&exact, &whole, &total)
}

/// Works out the share each of `weights` comes to of `amount`, all in subunits, in the same order:
/// together, the whole of `amount`, each one of the two subunits around its part of it.
fn shares_of_weights(amount: &BigInt, weights: &[BigInt]) -> Vec<BigInt> {
    let exact: Vec<BigInt> = weights.iter().map(|weight| amount * weight).collect();

    largest_remainders(&exact, &weights.iter().sum::<BigInt>(), amount)
}

/// Divides each of `numerators` by `denominator` so that the results come to `total`, in the same
/// order: each rounds down, and then the subunits needed for them to add up go one each to those
/// that lost the most, the first of them when two lost as much.
///
/// Rounding each to the nearest on its own would not add up: `33.33`, `33.33` and `33.34` percent of
/// 10.00 would come to 9.99, and `50` percent twice of 0.01 to 0.02. This way each result is still
/// one of the two subunits around what it says, as long as `total` is the sum of the exact results,
/// rounded to the nearest subunit at most.
fn largest_remainders(numerators: &[BigInt], denominator: &BigInt, total: &BigInt) -> Vec<BigInt> {
    let mut shares: Vec<BigInt> = numerators
        .iter()
        .map(|numerator| numerator / denominator)
        .collect();

    let subunits_left = total - shares.iter().sum::<BigInt>();

    // A stable sort, so that an equal claim goes to whoever comes first.
    let mut by_largest_loss: Vec<usize> = (0..numerators.len()).collect();
    by_largest_loss.sort_by_key(|&index| Reverse(&numerators[index] % denominator));

    for (given, &index) in by_largest_loss.iter().enumerate() {
        if BigInt::from(given) < subunits_left {
            shares[index] += 1;
        }
    }

    shares
}

/// How many subunits a unit of `currency` is worth. For now, if the currency has a subunit, we
/// consider it to be cents.
fn subunit_scale(currency: &Currency) -> usize {
    match currency.has_sub_unit {
        true => 100,
        false => 1,
    }
}

/// `amount` in subunits, `scale` to the unit, dropping anything smaller than one.
fn to_subunits(amount: &BigDecimal, scale: usize) -> Result<BigInt, ExpenseError> {
    (amount * BigInt::from(scale))
        .to_bigint()
        .ok_or(ExpenseError::InternalTypeConversionFailed)
}

/// The amount `subunits` make up, `scale` to the unit.
fn from_subunits(subunits: BigInt, scale: usize) -> BigDecimal {
    BigDecimal::from(subunits) / BigDecimal::from_bigint(BigInt::from(scale), 0)
}

/// Parses `percentage`, in the only form the app writes one, see [parse_share_setting], into
/// hundredths of a percent.
///
/// One over 100 is no malformed percentage: it is shares that exceed the amount, which is what
/// checking the sum of the shares says of it.
///
/// # Errors
///
/// * `ExpenseError::MalformedPercentage` - If `percentage` is written any other way.
/// * `ExpenseError::NonPositiveShare` - If `percentage` is zero.
fn parse_percentage(percentage: &str) -> Result<BigInt, ExpenseError> {
    parse_share_setting(percentage, ExpenseError::MalformedPercentage)
}

/// Parses `weight`, in the only form the app writes one, see [parse_share_setting], into hundredths
/// of a part.
///
/// # Errors
///
/// * `ExpenseError::MalformedWeight` - If `weight` is written any other way.
/// * `ExpenseError::NonPositiveShare` - If `weight` is zero: somebody with no part of an expense is
///   no beneficiary of it.
fn parse_weight(weight: &str) -> Result<BigInt, ExpenseError> {
    parse_share_setting(weight, ExpenseError::MalformedWeight)
}

/// Parses `setting`, a percentage or a weight, into hundredths of it: one to
/// [MAX_SHARE_SETTING_WHOLE_DIGITS] ASCII digits, then optionally a point and one to
/// [MAX_SHARE_SETTING_SUBUNIT_DIGITS] more digits.
///
/// # Errors
///
/// * `malformed` - If `setting` is written any other way.
/// * `ExpenseError::NonPositiveShare` - If `setting` is zero.
fn parse_share_setting(setting: &str, malformed: ExpenseError) -> Result<BigInt, ExpenseError> {
    let (whole, subunits) = match setting.split_once('.') {
        Some((whole, subunits)) => (whole, Some(subunits)),
        None => (setting, None),
    };

    if !is_digits(whole, MAX_SHARE_SETTING_WHOLE_DIGITS)
        || subunits.is_some_and(|subunits| !is_digits(subunits, MAX_SHARE_SETTING_SUBUNIT_DIGITS))
    {
        return Err(malformed);
    }

    let setting = match BigDecimal::from_str(setting) {
        Ok(setting) => setting,
        Err(_) => return Err(malformed),
    };

    if setting.is_zero() {
        return Err(ExpenseError::NonPositiveShare);
    }

    to_subunits(&setting, 100)
}

/// Parses `amount`, written as [canonical_amount] writes one and no other way, which is all that
/// anybody should seal: two versions of an expense saying the same thing are then the same, and the
/// length of what is sealed says no more than how large the amount is.
///
/// # Errors
///
/// * `ExpenseError::UnsupportedSubunits` - If `amount` is digits then a point, and `currency` has no
///   subunit.
/// * `ExpenseError::MalformedAmount` - If `amount` is written any other way.
fn parse_canonical_amount(amount: &str, currency: &Currency) -> Result<BigDecimal, ExpenseError> {
    let parsed = parse_amount(amount, currency)?;

    if currency.write_amount(&parsed) != amount {
        return Err(ExpenseError::MalformedAmount);
    }

    Ok(parsed)
}

/// Parses `amount` in the forms the library reads one to work with: one to [MAX_WHOLE_DIGITS] ASCII
/// digits, then, in a currency with a subunit, optionally a point and one to [MAX_SUBUNIT_DIGITS]
/// more digits.
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
