#[cfg(test)]
mod tests {
    use crate::algorithm::transaction::Transaction;
    use uuid::Uuid;

    #[test]
    fn test_transaction_new() {
        let debtor_id = Uuid::new_v4().to_string();
        let creditor_id = Uuid::new_v4().to_string();
        let amount = "50.00";
        let transaction = Transaction::new(&debtor_id, &creditor_id, amount);

        assert_eq!(transaction.debtor_id, debtor_id);
        assert_eq!(transaction.creditor_id, creditor_id);
        assert_eq!(transaction.amount, amount);
    }
}
