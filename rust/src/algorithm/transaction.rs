/// Represents a financial transaction between a debtor and a creditor.
///
/// The [Transaction] struct captures the details of a financial transaction, including the IDs of the debtor and creditor,
/// and the amount of money involved in the transaction.
#[derive(Debug, uniffi::Record)]
pub struct Transaction {
    /// The ID of the debtor who owes money.
    pub debtor_id: String,
    /// The ID of the creditor who is owed money.
    pub creditor_id: String,
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
    /// * `debtor_id` - The ID of the debtor who owes money.
    /// * `creditor_id` - The ID of the creditor who is owed money.
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
    /// let debtor_id = Uuid::new_v4().to_string();
    /// let creditor_id = Uuid::new_v4().to_string();
    /// let amount = "50.0";
    ///
    /// let transaction = Transaction::new(&debtor_id, &creditor_id, amount);
    /// ```
    pub fn new(debtor_id: &str, creditor_id: &str, amount: &str) -> Self {
        Self {
            debtor_id: debtor_id.to_string(),
            creditor_id: creditor_id.to_string(),
            amount: amount.to_owned(),
        }
    }
}
