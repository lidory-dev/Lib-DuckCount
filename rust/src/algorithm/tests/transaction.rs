#[cfg(test)]
mod tests {
    use crate::algorithm::transaction::Transaction;
    use uuid::Uuid;

    #[test]
    fn test_transaction_new() {
        let debtor_uuid = Uuid::new_v4().to_string();
        let creditor_uuid = Uuid::new_v4().to_string();
        let amount = "50.00";
        let transaction = Transaction::new(&debtor_uuid, &creditor_uuid, amount);

        assert_eq!(transaction.debtor_uuid, debtor_uuid);
        assert_eq!(transaction.creditor_uuid, creditor_uuid);
        assert_eq!(transaction.amount, amount);
    }
}
