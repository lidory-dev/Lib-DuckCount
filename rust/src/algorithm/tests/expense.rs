#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use crate::algorithm::{
        beneficiary::Beneficiary,
        currency::Currency,
        expense::{Expense, ExpenseError, compute_beneficiaries},
    };
    use bigdecimal::{BigDecimal, Zero};
    use uuid::Uuid;

    #[test]
    fn test_expense_new_success() {
        let creditor_uuid = Uuid::new_v4().to_string();

        let amount = "100.00";

        let beneficiaries = vec![
            Beneficiary::new(&Uuid::new_v4().to_string(), "50.00"),
            Beneficiary::new(&Uuid::new_v4().to_string(), "50.00"),
        ];

        let currency = Currency::new("Euro", "€", true).unwrap();
        let expense = Expense::new(&creditor_uuid, amount, &currency, &beneficiaries).unwrap();

        assert_eq!(expense.creditor_id, creditor_uuid);
        assert_eq!(expense.amount, amount);
    }

    #[test]
    fn test_expense_new_non_positive_amount() {
        let creditor_id = Uuid::new_v4().to_string();
        let amount = "-100.00";
        let beneficiaries = vec![Beneficiary::new(&Uuid::new_v4().to_string(), "50.00")];

        let currency = Currency::new("Euro", "€", true).unwrap();
        let expense_result = Expense::new(&creditor_id, amount, &currency, &beneficiaries);

        assert!(expense_result.is_err());
        assert_eq!(expense_result.unwrap_err(), ExpenseError::NonPositiveAmount);
    }

    #[test]
    fn test_expense_new_no_beneficiaries() {
        let creditor_id = Uuid::new_v4().to_string();
        let amount = "100.00";
        let beneficiaries = vec![];

        let currency = Currency::new("Euro", "€", true).unwrap();
        let expense_result = Expense::new(&creditor_id, amount, &currency, &beneficiaries);

        assert!(expense_result.is_err());
        assert_eq!(expense_result.unwrap_err(), ExpenseError::NoBeneficiaries);
    }

    #[test]
    fn test_expense_new_shares_exceed_total_amount() {
        let creditor_id = Uuid::new_v4().to_string();
        let amount = "100.00";
        let beneficiaries = vec![
            Beneficiary::new(&Uuid::new_v4().to_string(), "60.00"),
            Beneficiary::new(&Uuid::new_v4().to_string(), "50.00"),
        ];

        let currency = Currency::new("Euro", "€", true).unwrap();
        let expense_result = Expense::new(&creditor_id, amount, &currency, &beneficiaries);

        assert!(expense_result.is_err());
        assert_eq!(
            expense_result.unwrap_err(),
            ExpenseError::SharesExceedTotalAmount
        );
    }

    #[test]
    fn test_expense_new_shares_below_total_amount() {
        let creditor_id = Uuid::new_v4().to_string();
        let amount = "100.00";
        let beneficiaries = vec![
            Beneficiary::new(&Uuid::new_v4().to_string(), "60.00"),
            Beneficiary::new(&Uuid::new_v4().to_string(), "30.00"),
        ];

        let currency = Currency::new("Euro", "€", true).unwrap();
        let expense_result = Expense::new(&creditor_id, amount, &currency, &beneficiaries);

        assert!(expense_result.is_err());
        assert_eq!(
            expense_result.unwrap_err(),
            ExpenseError::SharesBelowTotalAmount
        );
    }

    #[test]
    fn test_expense_new_non_positive_share() {
        let creditor_id = Uuid::new_v4().to_string();
        let amount = "100.00";
        let beneficiaries = vec![Beneficiary::new(&Uuid::new_v4().to_string(), "-10.00")];

        let currency = Currency::new("Euro", "€", true).unwrap();
        let expense_result = Expense::new(&creditor_id, amount, &currency, &beneficiaries);

        assert!(expense_result.is_err());
        assert_eq!(expense_result.unwrap_err(), ExpenseError::NonPositiveShare);
    }

    #[test]
    fn test_expense_new_currency_does_not_support_subunits_on_amount() {
        let creditor_id = Uuid::new_v4().to_string();
        let amount = "100.50";
        let beneficiaries = vec![Beneficiary::new(&Uuid::new_v4().to_string(), "50")];

        let currency = Currency::new("Yen", "¥", false).unwrap();
        let expense_result = Expense::new(&creditor_id, amount, &currency, &beneficiaries);

        assert!(expense_result.is_err());
        assert_eq!(
            expense_result.unwrap_err(),
            ExpenseError::UnsupportedSubunits
        );
    }

    #[test]
    fn test_expense_new_currency_does_not_support_subunits_on_share() {
        let creditor_id = Uuid::new_v4().to_string();
        let amount = "100";
        let beneficiaries = vec![Beneficiary::new(&Uuid::new_v4().to_string(), "50.50")];

        let currency = Currency::new("Yen", "¥", false).unwrap();
        let expense_result = Expense::new(&creditor_id, amount, &currency, &beneficiaries);

        assert!(expense_result.is_err());
        assert_eq!(
            expense_result.unwrap_err(),
            ExpenseError::UnsupportedSubunits
        );
    }

    #[test]
    fn test_simple_rounding_needed() {
        let creditor_id = Uuid::new_v4().to_string();
        let alice_id = Uuid::new_v4().to_string();
        let bob_id = Uuid::new_v4().to_string();
        let charlie_id = Uuid::new_v4().to_string();

        let beneficiary_uuids = vec![alice_id, bob_id, charlie_id];

        let amount = "100.00";
        let currency = Currency::new("Euro", "€", true).unwrap();
        let beneficiaries =
            compute_beneficiaries(amount, &currency, &beneficiary_uuids, &HashMap::new()).unwrap();
        let _ = Expense::new(&creditor_id, amount, &currency, &beneficiaries).unwrap();

        // One share should be 33.34 and the others 33.33
        let mut count_33_34 = 0;
        let mut count_33_33 = 0;

        for beneficiary in &beneficiaries {
            if beneficiary.share == "33.34" {
                count_33_34 += 1;
            } else if beneficiary.share == "33.33" {
                count_33_33 += 1;
            }
        }

        assert_eq!(count_33_34, 1);
        assert_eq!(count_33_33, 2);

        // Also check that the total is correct (100.00)
        let sum = beneficiaries
            .iter()
            .map(|beneficiary| {
                BigDecimal::from_str(&beneficiary.share)
                    .expect("Failed to parse string as BigDecimal")
            })
            .fold(BigDecimal::zero(), |acc, x| acc + x);

        assert!(sum == BigDecimal::from_str("100.00").unwrap());
    }

    #[test]
    fn test_no_rounding_needed() {
        let creditor_id = Uuid::new_v4().to_string();
        let alice_id = Uuid::new_v4().to_string();
        let bob_id = Uuid::new_v4().to_string();
        let charlie_id = Uuid::new_v4().to_string();

        let beneficiary_uuids = vec![alice_id, bob_id, charlie_id];

        let amount = "99999.00";
        let currency = Currency::new("Euro", "€", true).unwrap();
        let beneficiaries =
            compute_beneficiaries(amount, &currency, &beneficiary_uuids, &HashMap::new()).unwrap();
        let _ = Expense::new(&creditor_id, amount, &currency, &beneficiaries).unwrap();

        let mut count_33333 = 0;

        for beneficiary in &beneficiaries {
            if beneficiary.share == "33333" {
                count_33333 += 1;
            }
        }

        assert_eq!(count_33333, beneficiaries.len());

        // Also check that the total is correct (99999.00)
        let sum = beneficiaries
            .iter()
            .map(|beneficiary| {
                BigDecimal::from_str(&beneficiary.share)
                    .expect("Failed to parse string as BigDecimal")
            })
            .fold(BigDecimal::zero(), |acc, x| acc + x);

        assert!(sum == BigDecimal::from_str("99999").unwrap());
    }

    #[test]
    fn test_simple_rounding_needed_no_subunit() {
        let creditor_id = Uuid::new_v4().to_string();
        let alice_id = Uuid::new_v4().to_string();
        let bob_id = Uuid::new_v4().to_string();
        let charlie_id = Uuid::new_v4().to_string();

        let beneficiary_uuids = vec![alice_id, bob_id, charlie_id];

        let amount = "1000";
        let currency = Currency::new("Yen", "¥", false).unwrap();
        let beneficiaries =
            compute_beneficiaries(amount, &currency, &beneficiary_uuids, &HashMap::new()).unwrap();
        let _ = Expense::new(&creditor_id, amount, &currency, &beneficiaries).unwrap();

        // One share should be 334 and the others 333.
        let mut count_334 = 0;
        let mut count_333 = 0;

        for beneficiary in &beneficiaries {
            if beneficiary.share == "334" {
                count_334 += 1;
            } else if beneficiary.share == "333" {
                count_333 += 1;
            }
        }

        assert_eq!(count_334, 1);
        assert_eq!(count_333, 2);

        // Also check that the total is correct (1000).
        let sum = beneficiaries
            .iter()
            .map(|beneficiary| {
                BigDecimal::from_str(&beneficiary.share)
                    .expect("Failed to parse string as BigDecimal")
            })
            .fold(BigDecimal::zero(), |acc, x| acc + x);

        assert!(sum == BigDecimal::from_str("1000").unwrap());
    }
}
