/// Represents a beneficiary of an expense.
///
/// The [Beneficiary] struct captures information about a user who benefits from an expense.
/// It includes the user's ID and an optional share amount, which represents the portion of the expense
/// that the beneficiary is responsible for.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Beneficiary {
    /// The ID of the user who is a beneficiary.
    pub user_uuid: String,
    /// The share of the expense attributed to the beneficiary.
    pub share: String,
}

impl Beneficiary {
    /// Creates a new [Beneficiary].
    ///
    /// This constructor initializes a [Beneficiary] with the given user ID and share amount.
    ///
    /// # Arguments
    ///
    /// * `user_uuid` - The ID of the user who is a beneficiary.
    /// * `share` - A string representing the share of the expense attributed to the beneficiary.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```rust
    /// # use lib_duckcount::algorithm::beneficiary::Beneficiary;
    /// # use uuid::Uuid;
    ///
    /// let user_uuid = Uuid::new_v4().to_string();
    /// let beneficiary = Beneficiary::new(&user_uuid, "50.00");
    /// ```
    pub fn new(user_uuid: &str, share: &str) -> Self {
        Self {
            user_uuid: user_uuid.to_string(),
            share: share.to_string(),
        }
    }
}
