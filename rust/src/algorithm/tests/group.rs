#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr, sync::Arc};

    use crate::algorithm::{
        beneficiary::Beneficiary,
        currency::Currency,
        expense::{Expense, compute_beneficiaries},
        group::{Group, GroupError},
    };
    use bigdecimal::BigDecimal;
    use uuid::Uuid;

    #[test]
    fn test_group_new() {
        let alice_uuid = Uuid::new_v4().to_string();
        let bob_uuid = Uuid::new_v4().to_string();

        let currency = Currency::new("Euro", "€", true).unwrap();
        let users_uuid = vec![alice_uuid.clone(), bob_uuid.clone()];
        let group = Group::new(&currency, &users_uuid, &vec![]).unwrap();

        assert_eq!(group.users_uuid.len(), 2);
        assert!(group.expenses.is_empty());
    }

    #[test]
    fn test_add_user() {
        let currency = Currency::new("Euro", "€", true).unwrap();
        let group = Group::new(&currency, &vec![], &vec![]).unwrap();
        let user_uuid = Uuid::new_v4().to_string();

        let group = group.with_added_user(&user_uuid);

        assert_eq!(group.users_uuid.len(), 1);
        assert_eq!(group.users_uuid[0], user_uuid);
    }

    #[test]
    fn test_add_expense() {
        let alice_uuid = Uuid::new_v4().to_string();
        let bob_uuid = Uuid::new_v4().to_string();

        let currency = Currency::new("Euro", "€", true).unwrap();
        let users_uuid = vec![alice_uuid.clone(), bob_uuid.clone()];
        let group = Group::new(&currency, &users_uuid, &vec![]).unwrap();

        let amount = "100.00";
        let beneficiaries = vec![Beneficiary::new(&bob_uuid, "100.00")];
        let expense = Expense::new(&alice_uuid, amount, &currency, &beneficiaries).unwrap();

        let group = group.with_added_expense(Arc::new(expense)).unwrap();

        assert_eq!(group.expenses.len(), 1);
    }

    #[test]
    fn test_add_expense_creditor_unknown() {
        let alice_uuid = Uuid::new_v4().to_string();
        let bob_uuid = Uuid::new_v4().to_string();

        let currency = Currency::new("Euro", "€", true).unwrap();
        let users_uuid = vec![bob_uuid.clone()];
        let group = Group::new(&currency, &users_uuid, &vec![]).unwrap();

        let group = group.with_added_user(&bob_uuid);

        let amount = "100.00";
        let beneficiaries = vec![Beneficiary::new(&bob_uuid, "100.00")];
        let expense = Expense::new(&alice_uuid, amount, &currency, &beneficiaries).unwrap();

        let group_result = group.with_added_expense(Arc::new(expense)).unwrap_err();

        assert_eq!(group_result, GroupError::CreditorUnknown);
    }

    #[test]
    fn test_add_expense_beneficiary_unknown() {
        let alice_uuid = Uuid::new_v4().to_string();
        let bob_uuid = Uuid::new_v4().to_string();

        let currency = Currency::new("Euro", "€", true).unwrap();
        let users_uuid = vec![alice_uuid.clone()];
        let group = Group::new(&currency, &users_uuid, &vec![]).unwrap();

        let amount = "100.00";
        let beneficiaries = vec![Beneficiary::new(&bob_uuid, "100.00")];
        let expense = Expense::new(&alice_uuid, amount, &currency, &beneficiaries).unwrap();

        let group_result = group.with_added_expense(Arc::new(expense)).unwrap_err();

        assert_eq!(group_result, GroupError::BeneficiaryUnknown);
    }

    #[test]
    fn test_add_expense_wrong_currency() {
        let alice_uuid = Uuid::new_v4().to_string();
        let bob_uuid = Uuid::new_v4().to_string();

        let group_currency = Currency::new("Euro", "€", true).unwrap();
        let users_uuid = vec![alice_uuid.clone(), bob_uuid.clone()];
        let group = Group::new(&group_currency, &users_uuid, &vec![]).unwrap();

        let amount = "100.00";
        let beneficiaries = vec![Beneficiary::new(&bob_uuid, "100.00")];

        let expense_currency = Currency::new("Dollar", "$", true).unwrap();
        let expense = Expense::new(&alice_uuid, amount, &expense_currency, &beneficiaries).unwrap();

        let group_error = group.with_added_expense(Arc::new(expense)).unwrap_err();

        assert_eq!(group_error, GroupError::WrongCurrency);
    }

    #[test]
    fn test_calculate_net_debts_per_user() {
        let alice_uuid = Uuid::new_v4().to_string();
        let bob_uuid = Uuid::new_v4().to_string();
        let charlie_uuid = Uuid::new_v4().to_string();

        let currency = Currency::new("Euro", "€", true).unwrap();
        let users_uuid = vec![alice_uuid.clone(), bob_uuid.clone(), charlie_uuid.clone()];
        let group = Group::new(&currency, &users_uuid, &vec![]).unwrap();

        let amount = "100.00";

        let beneficiary_uuids = vec![bob_uuid.clone(), charlie_uuid.clone()];

        let mut fixed_shares = HashMap::new();
        fixed_shares.insert(bob_uuid.clone(), String::from("50.00"));

        let beneficiaries =
            compute_beneficiaries(amount, &currency, &beneficiary_uuids, &fixed_shares, &HashMap::new()).unwrap();

        let expense = Expense::new(&alice_uuid, amount, &currency, &beneficiaries).unwrap();
        let group = group.with_added_expense(Arc::new(expense)).unwrap();

        let net_debts = group.calculate_net_debts_per_user().unwrap();

        assert_eq!(
            BigDecimal::from_str(net_debts.get(&alice_uuid).unwrap()).unwrap(),
            BigDecimal::from_str("100.00").unwrap()
        );
        assert_eq!(
            BigDecimal::from_str(net_debts.get(&bob_uuid).unwrap()).unwrap(),
            BigDecimal::from_str("-50.00").unwrap()
        );
        assert_eq!(
            BigDecimal::from_str(net_debts.get(&charlie_uuid).unwrap()).unwrap(),
            BigDecimal::from_str("-50.00").unwrap()
        );
    }

    #[test]
    fn test_calculate_transactions_to_equilibrate() {
        let alice_uuid = Uuid::new_v4().to_string();
        let bob_uuid = Uuid::new_v4().to_string();
        let charlie_uuid = Uuid::new_v4().to_string();

        let currency = Currency::new("Euro", "€", true).unwrap();
        let users_uuid = vec![alice_uuid.clone(), bob_uuid.clone(), charlie_uuid.clone()];
        let group = Group::new(&currency, &users_uuid, &vec![]).unwrap();

        let amount = "100.00";

        let beneficiary_uuids = vec![bob_uuid.clone(), charlie_uuid.clone()];

        let mut fixed_shares = HashMap::new();
        fixed_shares.insert(bob_uuid.clone(), String::from("50.00"));

        let beneficiaries =
            compute_beneficiaries(amount, &currency, &beneficiary_uuids, &fixed_shares, &HashMap::new()).unwrap();

        let expense = Expense::new(&alice_uuid, amount, &currency, &beneficiaries).unwrap();
        let group = group.with_added_expense(Arc::new(expense)).unwrap();

        let transactions = group.calculate_transactions_to_equilibrate().unwrap();

        assert_eq!(transactions.len(), 2);
    }
}
