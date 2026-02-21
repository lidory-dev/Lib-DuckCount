/// Represents a beneficiary of an expense.
///
/// The [Beneficiary] struct captures information about a user who benefits from an expense.
/// It includes the user's ID and an optional share amount, which represents the portion of the expense
/// that the beneficiary is responsible for.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Beneficiary {
    /// The ID of the user who is a beneficiary.
    pub user_id: String,
    /// An optional field representing the share of the expense attributed to the beneficiary.
    /// If `None`, the share is calculated equally among all beneficiaries without an explicit share.
    #[uniffi(default = None)]
    pub share: Option<String>,
}

impl Beneficiary {
    /// Creates a new [Beneficiary].
    ///
    /// This constructor initializes a [Beneficiary] with the given user ID and share amount.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The ID of the user who is a beneficiary.
    /// * `share` - An optional field representing the share of the expense attributed to the beneficiary.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```rust
    /// use lib_duckcount::algorithm::beneficiary::Beneficiary;
    /// use uuid::Uuid;
    ///
    /// let user_id = Uuid::new_v4().to_string();
    /// let share = Some(String::from("50.0"));
    /// let beneficiary = Beneficiary::new(&user_id, share);
    /// ```
    ///
    /// Example with no specified share:
    ///
    /// ```rust
    /// use lib_duckcount::algorithm::beneficiary::Beneficiary;
    /// use uuid::Uuid;
    ///
    /// let user_id = Uuid::new_v4().to_string();
    /// let beneficiary = Beneficiary::new(&user_id, None);
    /// ```
    pub fn new(user_id: &str, share: Option<String>) -> Self {
        Self {
            user_id: user_id.to_string(),
            share,
        }
    }
}
