/// Represents a financial transaction between a debtor and a creditor.
///
/// The [Transaction] struct captures the details of a financial transaction, including the IDs of the debtor and creditor,
/// and the amount of money involved in the transaction.
#[derive(Debug, uniffi::Record)]
pub struct Transaction {
    /// The ID of the debtor who owes money.
    pub debtor_uuid: String,
    /// The ID of the creditor who is owed money.
    pub creditor_uuid: String,
    /// The amount of money involved in the transaction.
    pub amount: String,
}

impl Transaction {
    /// Creates a new [Transaction].
    ///
    /// This constructor initializes a [Transaction] with the given debtor ID, creditor ID, and amount.
    ///
    /// # Arguments
    ///
    /// * `debtor_uuid` - The ID of the debtor who owes money.
    /// * `creditor_uuid` - The ID of the creditor who is owed money.
    /// * `amount` - The amount of money involved in the transaction.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```rust
    /// use lib_duckcount::algorithm::transaction::Transaction;
    /// use uuid::Uuid;
    ///
    /// let debtor_uuid = Uuid::new_v4().to_string();
    /// let creditor_uuid = Uuid::new_v4().to_string();
    /// let amount = "50.00";
    ///
    /// let transaction = Transaction::new(&debtor_uuid, &creditor_uuid, amount);
    /// ```
    pub fn new(debtor_uuid: &str, creditor_uuid: &str, amount: &str) -> Self {
        Self {
            debtor_uuid: debtor_uuid.to_owned(),
            creditor_uuid: creditor_uuid.to_owned(),
            amount: amount.to_owned(),
        }
    }
}
