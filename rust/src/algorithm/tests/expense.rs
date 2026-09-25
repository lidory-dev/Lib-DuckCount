#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use crate::algorithm::{
        beneficiary::Beneficiary,
        currency::Currency,
        expense::{Expense, ExpenseError, compute_beneficiaries, validate_expense},
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

        assert_eq!(expense.creditor_uuid, creditor_uuid);
        assert_eq!(expense.amount, amount);
    }

    #[test]
    fn test_expense_new_non_positive_amount() {
        let creditor_uuid = Uuid::new_v4().to_string();
        let amount = "-100.00";
        let beneficiaries = vec![Beneficiary::new(&Uuid::new_v4().to_string(), "50.00")];

        let currency = Currency::new("Euro", "€", true).unwrap();
        let expense_result = Expense::new(&creditor_uuid, amount, &currency, &beneficiaries);

        assert!(expense_result.is_err());
        assert_eq!(expense_result.unwrap_err(), ExpenseError::NonPositiveAmount);
    }

    #[test]
    fn test_expense_new_no_beneficiaries() {
        let creditor_uuid = Uuid::new_v4().to_string();
        let amount = "100.00";
        let beneficiaries = vec![];

        let currency = Currency::new("Euro", "€", true).unwrap();
        let expense_result = Expense::new(&creditor_uuid, amount, &currency, &beneficiaries);

        assert!(expense_result.is_err());
        assert_eq!(expense_result.unwrap_err(), ExpenseError::NoBeneficiaries);
    }

    #[test]
    fn test_expense_new_shares_exceed_total_amount() {
        let creditor_uuid = Uuid::new_v4().to_string();
        let amount = "100.00";
        let beneficiaries = vec![
            Beneficiary::new(&Uuid::new_v4().to_string(), "60.00"),
            Beneficiary::new(&Uuid::new_v4().to_string(), "50.00"),
        ];

        let currency = Currency::new("Euro", "€", true).unwrap();
        let expense_result = Expense::new(&creditor_uuid, amount, &currency, &beneficiaries);

        assert!(expense_result.is_err());
        assert_eq!(
            expense_result.unwrap_err(),
            ExpenseError::SharesExceedTotalAmount
        );
    }

    #[test]
    fn test_expense_new_shares_below_total_amount() {
        let creditor_uuid = Uuid::new_v4().to_string();
        let amount = "100.00";
        let beneficiaries = vec![
            Beneficiary::new(&Uuid::new_v4().to_string(), "60.00"),
            Beneficiary::new(&Uuid::new_v4().to_string(), "30.00"),
        ];

        let currency = Currency::new("Euro", "€", true).unwrap();
        let expense_result = Expense::new(&creditor_uuid, amount, &currency, &beneficiaries);

        assert!(expense_result.is_err());
        assert_eq!(
            expense_result.unwrap_err(),
            ExpenseError::SharesBelowTotalAmount
        );
    }

    #[test]
    fn test_expense_new_non_positive_share() {
        let creditor_uuid = Uuid::new_v4().to_string();
        let amount = "100.00";
        let beneficiaries = vec![Beneficiary::new(&Uuid::new_v4().to_string(), "-10.00")];

        let currency = Currency::new("Euro", "€", true).unwrap();
        let expense_result = Expense::new(&creditor_uuid, amount, &currency, &beneficiaries);

        assert!(expense_result.is_err());
        assert_eq!(expense_result.unwrap_err(), ExpenseError::NonPositiveShare);
    }

    #[test]
    fn test_expense_new_currency_does_not_support_subunits_on_amount() {
        let creditor_uuid = Uuid::new_v4().to_string();
        let amount = "100.50";
        let beneficiaries = vec![Beneficiary::new(&Uuid::new_v4().to_string(), "50")];

        let currency = Currency::new("Yen", "¥", false).unwrap();
        let expense_result = Expense::new(&creditor_uuid, amount, &currency, &beneficiaries);

        assert!(expense_result.is_err());
        assert_eq!(
            expense_result.unwrap_err(),
            ExpenseError::UnsupportedSubunits
        );
    }

    #[test]
    fn test_expense_new_currency_does_not_support_subunits_on_share() {
        let creditor_uuid = Uuid::new_v4().to_string();
        let amount = "100";
        let beneficiaries = vec![Beneficiary::new(&Uuid::new_v4().to_string(), "50.50")];

        let currency = Currency::new("Yen", "¥", false).unwrap();
        let expense_result = Expense::new(&creditor_uuid, amount, &currency, &beneficiaries);

        assert!(expense_result.is_err());
        assert_eq!(
            expense_result.unwrap_err(),
            ExpenseError::UnsupportedSubunits
        );
    }

    #[test]
    fn test_simple_rounding_needed() {
        let creditor_uuid = Uuid::new_v4().to_string();
        let alice_uuid = Uuid::new_v4().to_string();
        let bob_uuid = Uuid::new_v4().to_string();
        let charlie_uuid = Uuid::new_v4().to_string();

        let beneficiary_uuids = vec![alice_uuid, bob_uuid, charlie_uuid];

        let amount = "100.00";
        let currency = Currency::new("Euro", "€", true).unwrap();
        let beneficiaries =
            compute_beneficiaries(amount, &currency, &beneficiary_uuids, &HashMap::new()).unwrap();
        let _ = Expense::new(&creditor_uuid, amount, &currency, &beneficiaries).unwrap();

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
        let creditor_uuid = Uuid::new_v4().to_string();
        let alice_uuid = Uuid::new_v4().to_string();
        let bob_uuid = Uuid::new_v4().to_string();
        let charlie_uuid = Uuid::new_v4().to_string();

        let beneficiary_uuids = vec![alice_uuid, bob_uuid, charlie_uuid];

        let amount = "99999.00";
        let currency = Currency::new("Euro", "€", true).unwrap();
        let beneficiaries =
            compute_beneficiaries(amount, &currency, &beneficiary_uuids, &HashMap::new()).unwrap();
        let _ = Expense::new(&creditor_uuid, amount, &currency, &beneficiaries).unwrap();

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
        let creditor_uuid = Uuid::new_v4().to_string();
        let alice_uuid = Uuid::new_v4().to_string();
        let bob_uuid = Uuid::new_v4().to_string();
        let charlie_uuid = Uuid::new_v4().to_string();

        let beneficiary_uuids = vec![alice_uuid, bob_uuid, charlie_uuid];

        let amount = "1000";
        let currency = Currency::new("Yen", "¥", false).unwrap();
        let beneficiaries =
            compute_beneficiaries(amount, &currency, &beneficiary_uuids, &HashMap::new()).unwrap();
        let _ = Expense::new(&creditor_uuid, amount, &currency, &beneficiaries).unwrap();

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

    fn euro() -> Currency {
        Currency::new("Euro", "€", true).unwrap()
    }

    fn yen() -> Currency {
        Currency::new("Yen", "¥", false).unwrap()
    }

    fn one_beneficiary(share: &str) -> Vec<Beneficiary> {
        vec![Beneficiary::new(&Uuid::new_v4().to_string(), share)]
    }

    #[test]
    fn test_validate_expense_accepts_what_the_app_writes() {
        let beneficiary_uuids = vec![
            Uuid::new_v4().to_string(),
            Uuid::new_v4().to_string(),
            Uuid::new_v4().to_string(),
        ];

        for (amount, currency) in [
            ("100.00", euro()),
            ("0.50", euro()),
            ("12.5", euro()),
            ("1000", yen()),
        ] {
            let beneficiaries =
                compute_beneficiaries(amount, &currency, &beneficiary_uuids, &HashMap::new())
                    .unwrap();

            assert_eq!(
                validate_expense(amount, &currency, &beneficiaries),
                Ok(()),
                "{amount}"
            );
        }

        assert_eq!(
            validate_expense(
                "999999999999999.99",
                &euro(),
                &one_beneficiary("999999999999999.99")
            ),
            Ok(())
        );
    }

    #[test]
    fn test_validate_expense_refuses_amounts_written_any_other_way() {
        for amount in [
            "",
            ".",
            "5.",
            ".5",
            "+5",
            "-5",
            "1e2",
            "1E2",
            "1_000",
            "5.001",
            "0x10",
            " 5",
            "5 ",
            "1,5",
            "١٢",
            "1000000000000000",
        ] {
            assert_eq!(
                validate_expense(amount, &euro(), &one_beneficiary(amount)),
                Err(ExpenseError::MalformedAmount),
                "{amount:?}"
            );
        }
    }

    #[test]
    fn test_validate_expense_refuses_a_share_written_any_other_way() {
        let beneficiaries = vec![
            Beneficiary::new(&Uuid::new_v4().to_string(), "1e-3000000000"),
            Beneficiary::new(&Uuid::new_v4().to_string(), "100"),
        ];

        assert_eq!(
            validate_expense("100", &euro(), &beneficiaries),
            Err(ExpenseError::MalformedAmount)
        );
    }

    #[test]
    fn test_validate_expense_refuses_subunits_the_currency_does_not_have() {
        assert_eq!(
            validate_expense("100.00", &yen(), &one_beneficiary("100.00")),
            Err(ExpenseError::UnsupportedSubunits)
        );
    }

    #[test]
    fn test_validate_expense_refuses_a_zero_amount() {
        assert_eq!(
            validate_expense("0.00", &euro(), &one_beneficiary("0.00")),
            Err(ExpenseError::NonPositiveAmount)
        );
    }

    #[test]
    fn test_validate_expense_refuses_no_beneficiaries() {
        assert_eq!(
            validate_expense("100", &euro(), &vec![]),
            Err(ExpenseError::NoBeneficiaries)
        );
    }

    #[test]
    fn test_validate_expense_refuses_a_beneficiary_listed_twice() {
        let user_uuid = Uuid::new_v4().to_string();
        let beneficiaries = vec![
            Beneficiary::new(&user_uuid, "50"),
            Beneficiary::new(&user_uuid, "50"),
        ];

        assert_eq!(
            validate_expense("100", &euro(), &beneficiaries),
            Err(ExpenseError::DuplicateBeneficiary)
        );
    }

    #[test]
    fn test_validate_expense_refuses_shares_that_do_not_add_up() {
        let beneficiaries = vec![
            Beneficiary::new(&Uuid::new_v4().to_string(), "50"),
            Beneficiary::new(&Uuid::new_v4().to_string(), "49.99"),
        ];

        assert_eq!(
            validate_expense("100", &euro(), &beneficiaries),
            Err(ExpenseError::SharesBelowTotalAmount)
        );
        assert_eq!(
            validate_expense("99", &euro(), &beneficiaries),
            Err(ExpenseError::SharesExceedTotalAmount)
        );
    }
}
