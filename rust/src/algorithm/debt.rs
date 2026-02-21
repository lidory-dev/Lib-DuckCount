use std::cmp::Ordering;

use bigdecimal::BigDecimal;

/// Represents a debt associated with a user.
///
/// The [Debt] struct captures information about a financial debt, including the amount
/// and the ID of the user associated with the debt.
///
/// Debts are ordered, and therefore calculations based on debts can be deterministic.
/// The `user_id` (which is a [Uuid]) is used as a tie-breaker in the case where two debts are of equal amount.
/// Because of the uniqueness of a UUID, no two debts will ever be equal,
/// even if their respective amounts are equal.
#[derive(Debug, Eq)]
pub struct Debt {
    /// The amount of debt.
    pub amount: BigDecimal,
    /// The ID of the user associated with the debt.
    pub user_id: String,
}

impl Debt {
    /// Creates a new [Debt].
    ///
    /// This constructor initializes a [Debt] with the given amount and user ID.
    ///
    /// # Arguments
    ///
    /// * `amount` - The amount of debt.
    /// * `user_id` - The ID of the user associated with the debt.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```rust
    /// use std::str::FromStr;
    ///
    /// use bigdecimal::BigDecimal;
    /// use lib_duckcount::algorithm::debt::Debt;
    /// use uuid::Uuid;
    ///
    /// let amount = BigDecimal::from_str("100.0").unwrap();
    /// let user_id = Uuid::new_v4().to_string();
    ///
    /// let debt = Debt::new(&amount, &user_id);
    /// ```
    pub fn new(amount: &BigDecimal, user_id: &str) -> Self {
        Self {
            amount: amount.to_owned(),
            user_id: user_id.to_string(),
        }
    }
}

/// Implements the [PartialEq] trait for [Debt].
///
/// This allows for equality comparisons between two [Debt] instances based on both the amount and user ID.
impl PartialEq for Debt {
    fn eq(&self, other: &Self) -> bool {
        self.amount == other.amount && self.user_id == other.user_id
    }
}

/// Implements the [PartialOrd] trait for [Debt].
///
/// This allows for partial ordering comparisons between two [Debt] instances.
impl PartialOrd for Debt {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Implements the [Ord] trait for [Debt].
///
/// This defines a total order for [Debt] instances, primarily based on the amount of debt.
/// If the amounts are equal, the user IDs are used to determine the order.
impl Ord for Debt {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.amount.cmp(&other.amount) {
            Ordering::Equal => self.user_id.cmp(&other.user_id),
            ord => ord,
        }
    }
}
