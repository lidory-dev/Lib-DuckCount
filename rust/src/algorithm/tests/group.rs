#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::algorithm::{
        beneficiary::Beneficiary,
        currency::Currency,
        expense::Expense,
        group::{Group, GroupError},
    };
    use bigdecimal::BigDecimal;
    use uuid::Uuid;

    #[test]
    fn test_group_new() {
        let alice_id = Uuid::new_v4().to_string();
        let bob_id = Uuid::new_v4().to_string();

        let currency = Currency::new("Euro", "€", true).unwrap();
        let users_id = vec![alice_id.clone(), bob_id.clone()];
        let group = Group::new(&currency, &users_id);

        assert_eq!(group.users_id.len(), 2);
        assert!(group.expenses.is_empty());
    }

    #[test]
    fn test_add_user() {
        let currency = Currency::new("Euro", "€", true).unwrap();
        let group = Group::new(&currency, &vec![]);
        let user_id = Uuid::new_v4().to_string();

        let group = group.with_added_user(&user_id);

        assert_eq!(group.users_id.len(), 1);
        assert_eq!(group.users_id[0], user_id);
    }

    #[test]
    fn test_add_expense() {
        let alice_id = Uuid::new_v4().to_string();
        let bob_id = Uuid::new_v4().to_string();

        let currency = Currency::new("Euro", "€", true).unwrap();
        let users_id = vec![alice_id.clone(), bob_id.clone()];
        let group = Group::new(&currency, &users_id);

        let amount = "100.00";
        let beneficiaries = vec![Beneficiary::new(&bob_id, Some(String::from("100.00")))];
        let expense = Expense::new(&alice_id, amount, &currency, beneficiaries).unwrap();

        let group = group.with_added_expense(&expense).unwrap();

        assert_eq!(group.expenses.len(), 1);
    }

    #[test]
    fn test_add_expense_creditor_unknown() {
        let alice_id = Uuid::new_v4().to_string();
        let bob_id = Uuid::new_v4().to_string();

        let currency = Currency::new("Euro", "€", true).unwrap();
        let users_id = vec![bob_id.clone()];
        let group = Group::new(&currency, &users_id);

        let group = group.with_added_user(&bob_id);

        let amount = "100.00";
        let beneficiaries = vec![Beneficiary::new(&bob_id, Some(String::from("100.00")))];
        let expense = Expense::new(&alice_id, amount, &currency, beneficiaries).unwrap();

        let group_result = group.with_added_expense(&expense).unwrap_err();

        assert_eq!(group_result, GroupError::CreditorUnknown);
    }

    #[test]
    fn test_add_expense_beneficiary_unknown() {
        let alice_id = Uuid::new_v4().to_string();
        let bob_id = Uuid::new_v4().to_string();

        let currency = Currency::new("Euro", "€", true).unwrap();
        let users_id = vec![alice_id.clone()];
        let group = Group::new(&currency, &users_id);

        let amount = "100.00";
        let beneficiaries = vec![Beneficiary::new(&bob_id, Some(String::from("100.00")))];
        let expense = Expense::new(&alice_id, amount, &currency, beneficiaries).unwrap();

        let group_result = group.with_added_expense(&expense).unwrap_err();

        assert_eq!(group_result, GroupError::BeneficiaryUnknown);
    }

    #[test]
    fn test_add_expense_wrong_currency() {
        let alice_id = Uuid::new_v4().to_string();
        let bob_id = Uuid::new_v4().to_string();

        let group_currency = Currency::new("Euro", "€", true).unwrap();
        let users_id = vec![alice_id.clone(), bob_id.clone()];
        let group = Group::new(&group_currency, &users_id);

        let amount = "100.00";
        let beneficiaries = vec![Beneficiary::new(&bob_id, Some(String::from("100.00")))];

        let expense_currency = Currency::new("Dollar", "$", true).unwrap();
        let expense = Expense::new(&alice_id, amount, &expense_currency, beneficiaries).unwrap();

        let group_error = group.with_added_expense(&expense).unwrap_err();

        assert_eq!(group_error, GroupError::WrongCurrency);
    }

    #[test]
    fn test_calculate_net_debts_per_user() {
        let alice_id = Uuid::new_v4().to_string();
        let bob_id = Uuid::new_v4().to_string();
        let charlie_id = Uuid::new_v4().to_string();

        let currency = Currency::new("Euro", "€", true).unwrap();
        let users_id = vec![alice_id.clone(), bob_id.clone(), charlie_id.clone()];
        let group = Group::new(&currency, &users_id);

        let beneficiaries = vec![
            Beneficiary::new(&bob_id, Some(String::from("50.00"))),
            Beneficiary::new(&charlie_id, None),
        ];

        let expense = Expense::new(&alice_id, "100.00", &currency, beneficiaries).unwrap();
        let group = group.with_added_expense(&expense).unwrap();

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
        let alice_id = Uuid::new_v4().to_string();
        let bob_id = Uuid::new_v4().to_string();
        let charlie_id = Uuid::new_v4().to_string();

        let currency = Currency::new("Euro", "€", true).unwrap();
        let users_id = vec![alice_id.clone(), bob_id.clone(), charlie_id.clone()];
        let group = Group::new(&currency, &users_id);

        let beneficiaries = vec![
            Beneficiary::new(&bob_id, Some(String::from("50.00"))),
            Beneficiary::new(&charlie_id, None),
        ];

        let expense = Expense::new(&alice_id, "100.00", &currency, beneficiaries).unwrap();
        let group = group.with_added_expense(&expense).unwrap();

        let transactions = group.calculate_transactions_to_equilibrate().unwrap();

        assert_eq!(transactions.len(), 2);
    }
}
