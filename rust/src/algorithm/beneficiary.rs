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
    /// The percentage of the expense's amount the share was set as, `None` for a share named as
    /// an amount or split from what the others leave.
    ///
    /// [share](Self::share) is what the beneficiary owes, here too, and all that any sum reads:
    /// this says how it came about, so that it follows the amount when that is edited.
    /// [validate_expense](crate::algorithm::expense::validate_expense) holds the two together.
    #[uniffi(default = None)]
    pub share_percentage: Option<String>,
    /// How many parts of what the fixed shares and percentages leave the share was set as,
    /// next to the parts of the others who have one, `None` for a share set otherwise.
    ///
    /// Like [share_percentage](Self::share_percentage), it says how
    /// [share](Self::share) came about, so that it follows the amount when that is edited.
    /// [validate_expense](crate::algorithm::expense::validate_expense) holds the two together.
    /// An expense using any weight states one for everybody sharing what is left, a weight being
    /// worth nothing but next to the others.
    #[uniffi(default = None)]
    pub share_weight: Option<String>,
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
            share_percentage: None,
            share_weight: None,
        }
    }

    /// Creates a new [Beneficiary] whose share was set as a percentage of the expense's amount.
    ///
    /// # Arguments
    ///
    /// * `user_uuid` - The ID of the user who is a beneficiary.
    /// * `share` - A string representing what `share_percentage` comes to.
    /// * `share_percentage` - The percentage of the expense's amount the share was set as.
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
    /// let beneficiary = Beneficiary::with_percentage(&user_uuid, "25.00", "25");
    /// ```
    pub fn with_percentage(user_uuid: &str, share: &str, share_percentage: &str) -> Self {
        Self {
            user_uuid: user_uuid.to_string(),
            share: share.to_string(),
            share_percentage: Some(share_percentage.to_string()),
            share_weight: None,
        }
    }

    /// Creates a new [Beneficiary] whose share was set as a weight.
    ///
    /// # Arguments
    ///
    /// * `user_uuid` - The ID of the user who is a beneficiary.
    /// * `share` - A string representing what `share_weight` comes to.
    /// * `share_weight` - How many parts of what is left the share was set as.
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
    /// let beneficiary = Beneficiary::with_weight(&user_uuid, "50.00", "2");
    /// ```
    pub fn with_weight(user_uuid: &str, share: &str, share_weight: &str) -> Self {
        Self {
            user_uuid: user_uuid.to_string(),
            share: share.to_string(),
            share_percentage: None,
            share_weight: Some(share_weight.to_string()),
        }
    }
}
