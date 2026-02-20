#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::algorithm::{beneficiary::Beneficiary, expense::Expense, group::Group};
    use bigdecimal::BigDecimal;
    use uuid::Uuid;

    #[test]
    fn test_group_new() {
        let group = Group::new();
        assert!(group.users_id.lock().unwrap().is_empty());
        assert!(group.expenses.lock().unwrap().is_empty());
    }

    #[test]
    fn test_add_user() {
        let group = Group::new();
        let user_id = Uuid::new_v4().to_string();
        group.add_user(&user_id);

        assert_eq!(group.users_id.lock().unwrap().len(), 1);
        assert_eq!(group.users_id.lock().unwrap()[0], user_id);
    }

    #[test]
    fn test_add_expense() {
        let group = Group::new();
        let creditor_id = Uuid::new_v4().to_string();
        let amount = "100.00";
        let beneficiaries = vec![Beneficiary::new(
            &Uuid::new_v4().to_string(),
            Some(String::from("100.00")),
        )];
        let expense = Expense::new(&creditor_id, amount, beneficiaries).unwrap();

        group.add_expense(&expense);

        assert_eq!(group.expenses.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_calculate_net_debts_per_user() {
        let group = Group::new();
        let alice_id = Uuid::new_v4().to_string();
        let bob_id = Uuid::new_v4().to_string();
        let charlie_id = Uuid::new_v4().to_string();

        group.add_user(&alice_id);
        group.add_user(&bob_id);
        group.add_user(&charlie_id);

        let beneficiaries = vec![
            Beneficiary::new(&bob_id, Some(String::from("50.00"))),
            Beneficiary::new(&charlie_id, None),
        ];

        let expense = Expense::new(&alice_id, "100.00", beneficiaries).unwrap();
        group.add_expense(&expense);

        let net_debts = group.calculate_net_debts_per_user().unwrap();

        assert_eq!(
            BigDecimal::from_str(net_debts.get(&alice_id).unwrap()).unwrap(),
            BigDecimal::from_str("100.00").unwrap()
        );
        assert_eq!(
            BigDecimal::from_str(net_debts.get(&bob_id).unwrap()).unwrap(),
            BigDecimal::from_str("-50.00").unwrap()
        );
        assert_eq!(
            BigDecimal::from_str(net_debts.get(&charlie_id).unwrap()).unwrap(),
            BigDecimal::from_str("-50.00").unwrap()
        );
    }

    #[test]
    fn test_calculate_transactions_to_equilibrate() {
        let group = Group::new();
        let alice_id = Uuid::new_v4().to_string();
        let bob_id = Uuid::new_v4().to_string();
        let charlie_id = Uuid::new_v4().to_string();

        group.add_user(&alice_id);
        group.add_user(&bob_id);
        group.add_user(&charlie_id);

        let beneficiaries = vec![
            Beneficiary::new(&bob_id, Some(String::from("50.00"))),
            Beneficiary::new(&charlie_id, None),
        ];

        let expense = Expense::new(&alice_id, "100.00", beneficiaries).unwrap();
        group.add_expense(&expense);

        let transactions = group.calculate_transactions_to_equilibrate().unwrap();

        assert_eq!(transactions.len(), 2);
    }
}
