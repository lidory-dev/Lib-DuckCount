#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use crate::algorithm::{
        beneficiary::Beneficiary,
        currency::Currency,
        expense::{
            Expense, ExpenseError, canonical_amount, compute_beneficiaries, max_beneficiaries,
            max_group_expense_edits, validate_expense,
        },
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
        let beneficiaries = compute_beneficiaries(
            amount,
            &currency,
            &beneficiary_uuids,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();
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
        let beneficiaries = compute_beneficiaries(
            amount,
            &currency,
            &beneficiary_uuids,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();
        let _ = Expense::new(&creditor_uuid, amount, &currency, &beneficiaries).unwrap();

        let mut count_33333 = 0;

        for beneficiary in &beneficiaries {
            if beneficiary.share == "33333.00" {
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
        let beneficiaries = compute_beneficiaries(
            amount,
            &currency,
            &beneficiary_uuids,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();
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

    /// `count` distinct beneficiaries splitting €100 equally.
    fn beneficiaries_sharing_100(count: usize) -> Vec<Beneficiary> {
        let beneficiary_uuids: Vec<String> =
            (0..count).map(|_| Uuid::new_v4().to_string()).collect();

        compute_beneficiaries(
            "100",
            &euro(),
            &beneficiary_uuids,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap()
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
            ("12.50", euro()),
            ("1000", yen()),
        ] {
            let beneficiaries = compute_beneficiaries(
                amount,
                &currency,
                &beneficiary_uuids,
                &HashMap::new(),
                &HashMap::new(),
                &HashMap::new(),
            )
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
            Beneficiary::new(&Uuid::new_v4().to_string(), "100.00"),
        ];

        assert_eq!(
            validate_expense("100.00", &euro(), &beneficiaries),
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
            validate_expense("100.00", &euro(), &vec![]),
            Err(ExpenseError::NoBeneficiaries)
        );
    }

    #[test]
    fn test_max_beneficiaries_is_the_cap_the_api_enforces() {
        // The API holds its own copy of the cap: the two must move together.
        assert_eq!(max_beneficiaries(), 100);
    }

    #[test]
    fn test_max_group_expense_edits_is_the_cap_the_api_enforces() {
        // The API holds its own copy of the cap: the two must move together.
        assert_eq!(max_group_expense_edits(), 10);
    }

    #[test]
    fn test_validate_expense_accepts_as_many_beneficiaries_as_the_cap() {
        assert_eq!(
            validate_expense("100.00", &euro(), &beneficiaries_sharing_100(100)),
            Ok(())
        );
    }

    #[test]
    fn test_validate_expense_refuses_one_beneficiary_over_the_cap() {
        assert_eq!(
            validate_expense("100.00", &euro(), &beneficiaries_sharing_100(101)),
            Err(ExpenseError::TooManyBeneficiaries)
        );
    }

    #[test]
    fn test_validate_expense_checks_the_amount_before_counting_beneficiaries() {
        let beneficiaries = beneficiaries_sharing_100(101);

        assert_eq!(
            validate_expense("1e2", &euro(), &beneficiaries),
            Err(ExpenseError::MalformedAmount)
        );
        assert_eq!(
            validate_expense("100.00", &yen(), &beneficiaries),
            Err(ExpenseError::UnsupportedSubunits)
        );
        assert_eq!(
            validate_expense("0.00", &euro(), &beneficiaries),
            Err(ExpenseError::NonPositiveAmount)
        );
    }

    #[test]
    fn test_validate_expense_counts_beneficiaries_before_checking_any_of_them() {
        let mut listed_twice = beneficiaries_sharing_100(101);
        listed_twice[100].user_uuid = listed_twice[0].user_uuid.clone();

        let mut malformed_share = beneficiaries_sharing_100(101);
        malformed_share[100].share = String::from("1e-2");

        let mut non_positive_share = beneficiaries_sharing_100(101);
        non_positive_share[100].share = String::from("0");

        for beneficiaries in [listed_twice, malformed_share, non_positive_share] {
            assert_eq!(
                validate_expense("100.00", &euro(), &beneficiaries),
                Err(ExpenseError::TooManyBeneficiaries)
            );
        }

        assert_eq!(
            validate_expense("99.00", &euro(), &beneficiaries_sharing_100(101)),
            Err(ExpenseError::TooManyBeneficiaries)
        );
    }

    #[test]
    fn test_validate_expense_refuses_a_beneficiary_listed_twice() {
        let user_uuid = Uuid::new_v4().to_string();
        let beneficiaries = vec![
            Beneficiary::new(&user_uuid, "50.00"),
            Beneficiary::new(&user_uuid, "50.00"),
        ];

        assert_eq!(
            validate_expense("100.00", &euro(), &beneficiaries),
            Err(ExpenseError::DuplicateBeneficiary)
        );
    }

    #[test]
    fn test_validate_expense_refuses_shares_that_do_not_add_up() {
        let beneficiaries = vec![
            Beneficiary::new(&Uuid::new_v4().to_string(), "50.00"),
            Beneficiary::new(&Uuid::new_v4().to_string(), "49.99"),
        ];

        assert_eq!(
            validate_expense("100.00", &euro(), &beneficiaries),
            Err(ExpenseError::SharesBelowTotalAmount)
        );
        assert_eq!(
            validate_expense("99.00", &euro(), &beneficiaries),
            Err(ExpenseError::SharesExceedTotalAmount)
        );
    }

    /// Fresh UUIDs for `count` beneficiaries.
    fn uuids(count: usize) -> Vec<String> {
        (0..count).map(|_| Uuid::new_v4().to_string()).collect()
    }

    /// Each of `uuids` with the percentage or weight at the same place in `settings`, a blank one having none.
    fn settings_of(uuids: &[String], settings: &[&str]) -> HashMap<String, String> {
        uuids
            .iter()
            .zip(settings)
            .filter(|(_, setting)| !setting.is_empty())
            .map(|(uuid, setting)| (uuid.clone(), setting.to_string()))
            .collect()
    }

    /// The shares `percentages` of `amount` come to, in order, written as numbers so that a test
    /// does not depend on how many zeros they end in.
    fn shares_for_percentages(
        amount: &str,
        currency: &Currency,
        percentages: &[&str],
    ) -> Vec<BigDecimal> {
        let uuids = uuids(percentages.len());

        compute_beneficiaries(
            amount,
            currency,
            &uuids,
            &HashMap::new(),
            &settings_of(&uuids, percentages),
            &HashMap::new(),
        )
        .unwrap()
        .iter()
        .map(|beneficiary| BigDecimal::from_str(&beneficiary.share).unwrap())
        .collect()
    }

    fn numbers(values: &[&str]) -> Vec<BigDecimal> {
        values
            .iter()
            .map(|value| BigDecimal::from_str(value).unwrap())
            .collect()
    }

    #[test]
    fn test_compute_beneficiaries_works_percentages_out() {
        assert_eq!(
            shares_for_percentages("80.00", &euro(), &["25", "75"]),
            numbers(&["20", "60"])
        );
        assert_eq!(
            shares_for_percentages("10.00", &euro(), &["12.5", "87.5"]),
            numbers(&["1.25", "8.75"])
        );
        assert_eq!(
            shares_for_percentages("1000", &yen(), &["10", "90"]),
            numbers(&["100", "900"])
        );
    }

    #[test]
    fn test_compute_beneficiaries_keeps_the_percentage_on_who_set_one_alone() {
        let uuids = uuids(3);
        let mut fixed_shares = HashMap::new();
        fixed_shares.insert(uuids[1].clone(), "10.00".to_string());

        let beneficiaries = compute_beneficiaries(
            "100.00",
            &euro(),
            &uuids,
            &fixed_shares,
            &settings_of(&uuids, &["25"]),
            &HashMap::new(),
        )
        .unwrap();

        // In the order they were given in, each with what it was set as.
        let found: Vec<(&str, Option<&str>)> = beneficiaries
            .iter()
            .map(|beneficiary| {
                (
                    beneficiary.user_uuid.as_str(),
                    beneficiary.share_percentage.as_deref(),
                )
            })
            .collect();

        assert_eq!(
            found,
            vec![
                (uuids[0].as_str(), Some("25")),
                (uuids[1].as_str(), None),
                (uuids[2].as_str(), None),
            ]
        );
    }

    #[test]
    fn test_a_percentage_is_of_the_whole_amount_and_the_rest_is_split() {
        let uuids = uuids(4);
        let mut fixed_shares = HashMap::new();
        fixed_shares.insert(uuids[1].clone(), "10.00".to_string());

        let beneficiaries = compute_beneficiaries(
            "100.00",
            &euro(),
            &uuids,
            &fixed_shares,
            &settings_of(&uuids, &["25"]),
            &HashMap::new(),
        )
        .unwrap();

        let shares: Vec<BigDecimal> = beneficiaries
            .iter()
            .map(|beneficiary| BigDecimal::from_str(&beneficiary.share).unwrap())
            .collect();

        // 25% of 100, whatever the 10 fixed takes; the 65 left, split between the other two.
        assert_eq!(shares, numbers(&["25", "10", "32.5", "32.5"]));
        assert_eq!(validate_expense("100.00", &euro(), &beneficiaries), Ok(()));
    }

    #[test]
    fn test_subunits_left_by_rounding_go_to_who_lost_the_most() {
        // 3.333, 3.333 and 3.334: all round down to 9.99 and the last lost the most.
        assert_eq!(
            shares_for_percentages("10.00", &euro(), &["33.33", "33.33", "33.34"]),
            numbers(&["3.33", "3.33", "3.34"])
        );
        // Wherever it is listed.
        assert_eq!(
            shares_for_percentages("10.00", &euro(), &["33.34", "33.33", "33.33"]),
            numbers(&["3.34", "3.33", "3.33"])
        );
        assert_eq!(
            shares_for_percentages("100", &yen(), &["33.33", "33.33", "33.34"]),
            numbers(&["33", "33", "34"])
        );
    }

    #[test]
    fn test_subunits_left_by_rounding_go_to_the_first_when_they_lost_as_much() {
        assert_eq!(
            shares_for_percentages("0.03", &euro(), &["50", "50"]),
            numbers(&["0.02", "0.01"])
        );
    }

    #[test]
    fn test_a_percentage_rounds_to_the_nearest_subunit_when_others_pay_the_rest() {
        let uuids = uuids(2);

        let shares_of = |percentage: &str| {
            compute_beneficiaries(
                "0.10",
                &euro(),
                &uuids,
                &HashMap::new(),
                &settings_of(&uuids, &[percentage]),
                &HashMap::new(),
            )
            .unwrap()
            .iter()
            .map(|beneficiary| BigDecimal::from_str(&beneficiary.share).unwrap())
            .collect::<Vec<BigDecimal>>()
        };

        assert_eq!(shares_of("14"), numbers(&["0.01", "0.09"]));
        assert_eq!(shares_of("15"), numbers(&["0.02", "0.08"]));
    }

    #[test]
    fn test_compute_beneficiaries_refuses_percentages_that_do_not_make_up_the_amount() {
        let compute = |amount: &str, percentages: &[&str]| {
            let uuids = uuids(percentages.len());

            compute_beneficiaries(
                amount,
                &euro(),
                &uuids,
                &HashMap::new(),
                &settings_of(&uuids, percentages),
                &HashMap::new(),
            )
            .map(|_| ())
        };

        assert_eq!(
            compute("100.00", &["60", "50"]),
            Err(ExpenseError::SharesExceedTotalAmount)
        );
        assert_eq!(
            compute("100.00", &["150"]),
            Err(ExpenseError::SharesExceedTotalAmount)
        );
        assert_eq!(
            compute("100.00", &["60", "30"]),
            Err(ExpenseError::SharesBelowTotalAmount)
        );
        // Not even when rounding would have made them add up, on an amount this small: whether
        // they do depends on what they say and not on what they are of.
        assert_eq!(
            compute("1.00", &["33.33", "33.33", "33.33"]),
            Err(ExpenseError::SharesBelowTotalAmount)
        );
    }

    #[test]
    fn test_a_fixed_share_and_percentages_have_to_make_up_the_amount_together() {
        let uuids = uuids(2);
        let compute = |percentage: &str| {
            let mut fixed_shares = HashMap::new();
            fixed_shares.insert(uuids[0].clone(), "40.00".to_string());

            compute_beneficiaries(
                "100.00",
                &euro(),
                &uuids,
                &fixed_shares,
                &settings_of(&uuids, &["", percentage]),
                &HashMap::new(),
            )
            .map(|beneficiaries| beneficiaries[1].share.clone())
        };

        assert_eq!(
            compute("60").map(|share| BigDecimal::from_str(&share).unwrap()),
            Ok(BigDecimal::from(60))
        );
        assert_eq!(compute("59"), Err(ExpenseError::SharesBelowTotalAmount));
        assert_eq!(compute("61"), Err(ExpenseError::SharesExceedTotalAmount));
    }

    #[test]
    fn test_compute_beneficiaries_refuses_a_percentage_it_cannot_take() {
        let uuids = uuids(2);
        let compute = |percentage: &str| {
            compute_beneficiaries(
                "100.00",
                &euro(),
                &uuids,
                &HashMap::new(),
                &settings_of(&uuids, &[percentage]),
                &HashMap::new(),
            )
            .map(|_| ())
        };

        for malformed in [
            "abc", "-5", "+5", "5.", ".5", "5.123", "1e1", "5_0", "1000", "٥", "5%", " 5",
        ] {
            assert_eq!(
                compute(malformed),
                Err(ExpenseError::MalformedPercentage),
                "{malformed}"
            );
        }

        for zero in ["0", "0.0", "0.00", "000"] {
            assert_eq!(compute(zero), Err(ExpenseError::NonPositiveShare), "{zero}");
        }
    }

    #[test]
    fn test_compute_beneficiaries_refuses_a_percentage_of_nobody_on_the_expense() {
        let uuids = uuids(1);

        assert_eq!(
            compute_beneficiaries(
                "100.00",
                &euro(),
                &uuids,
                &HashMap::new(),
                &settings_of(&[Uuid::new_v4().to_string()], &["100"]),
                &HashMap::new(),
            )
            .map(|_| ()),
            Err(ExpenseError::FixedShareForUnknownBeneficiary)
        );
    }

    #[test]
    fn test_compute_beneficiaries_refuses_a_share_both_fixed_and_a_percentage() {
        let uuids = uuids(2);
        let mut fixed_shares = HashMap::new();
        fixed_shares.insert(uuids[0].clone(), "50.00".to_string());

        assert_eq!(
            compute_beneficiaries(
                "100.00",
                &euro(),
                &uuids,
                &fixed_shares,
                &settings_of(&uuids, &["50"]),
                &HashMap::new(),
            )
            .map(|_| ()),
            Err(ExpenseError::ShareSetMoreThanOneWay)
        );
    }

    #[test]
    fn test_validate_expense_accepts_every_share_a_percentage_is_worked_out_to() {
        let percentages = [
            vec!["100"],
            vec!["50", "50"],
            vec!["33.33", "33.33", "33.34"],
            vec!["1", "99"],
            vec!["12.34", "23.45", "34.56", "29.65"],
            vec!["7", "13", "80"],
        ];

        for percentages in &percentages {
            for amount in ["100.00", "10.00", "99.99", "1234.56", "7.77", "1000000.01"] {
                let uuids = uuids(percentages.len());

                let beneficiaries = compute_beneficiaries(
                    amount,
                    &euro(),
                    &uuids,
                    &HashMap::new(),
                    &settings_of(&uuids, percentages),
                    &HashMap::new(),
                )
                .unwrap();

                assert_eq!(
                    validate_expense(amount, &euro(), &beneficiaries),
                    Ok(()),
                    "{percentages:?} of {amount}: {beneficiaries:?}"
                );

                // Whichever order a receiver is served them in.
                let reversed: Vec<Beneficiary> = beneficiaries.iter().rev().cloned().collect();
                assert_eq!(validate_expense(amount, &euro(), &reversed), Ok(()));
            }
        }
    }

    #[test]
    fn test_validate_expense_takes_a_percentage_rounded_either_way() {
        for shares in [["3.34", "6.66"], ["3.33", "6.67"]] {
            let beneficiaries = vec![
                Beneficiary::with_percentage(&Uuid::new_v4().to_string(), shares[0], "33.33"),
                Beneficiary::with_percentage(&Uuid::new_v4().to_string(), shares[1], "66.67"),
            ];

            assert_eq!(validate_expense("10.00", &euro(), &beneficiaries), Ok(()));
        }
    }

    #[test]
    fn test_validate_expense_refuses_a_share_its_percentage_does_not_come_to() {
        let refused = |amount: &str, first: (&str, &str), second: (&str, &str)| {
            validate_expense(
                amount,
                &euro(),
                &vec![
                    Beneficiary::with_percentage(&Uuid::new_v4().to_string(), first.0, first.1),
                    Beneficiary::with_percentage(&Uuid::new_v4().to_string(), second.0, second.1),
                ],
            )
        };

        // Adds up, and says something else.
        assert_eq!(
            refused("100.00", ("40.00", "25"), ("60.00", "75")),
            Err(ExpenseError::ShareDiffersFromPercentage)
        );
        // By a subunit, on a percentage that falls exactly on one.
        assert_eq!(
            refused("100.00", ("25.01", "25"), ("74.99", "75")),
            Err(ExpenseError::ShareDiffersFromPercentage)
        );
        // Two subunits from what it comes to, 3.333.
        assert_eq!(
            refused("10.00", ("3.35", "33.33"), ("6.65", "66.67")),
            Err(ExpenseError::ShareDiffersFromPercentage)
        );
    }

    #[test]
    fn test_validate_expense_refuses_a_percentage_it_cannot_read() {
        let one_with = |percentage: &str| {
            vec![Beneficiary::with_percentage(
                &Uuid::new_v4().to_string(),
                "100.00",
                percentage,
            )]
        };

        assert_eq!(
            validate_expense("100.00", &euro(), &one_with("all of it")),
            Err(ExpenseError::MalformedPercentage)
        );
        assert_eq!(
            validate_expense("100.00", &euro(), &one_with("")),
            Err(ExpenseError::MalformedPercentage)
        );
        assert_eq!(
            validate_expense("100.00", &euro(), &one_with("0")),
            Err(ExpenseError::NonPositiveShare)
        );
    }

    #[test]
    fn test_validate_expense_refuses_a_percentage_too_small_to_come_to_anything() {
        let uuids = uuids(2);

        // 1% of 0.10 rounds to nothing, which no beneficiary can owe.
        let beneficiaries = compute_beneficiaries(
            "0.10",
            &euro(),
            &uuids,
            &HashMap::new(),
            &settings_of(&uuids, &["1"]),
            &HashMap::new(),
        )
        .unwrap();

        assert_eq!(
            validate_expense("0.10", &euro(), &beneficiaries),
            Err(ExpenseError::NonPositiveShare)
        );
    }

    #[test]
    fn test_validate_expense_holds_a_currency_without_subunits_to_whole_shares() {
        let beneficiaries = vec![Beneficiary::with_percentage(
            &Uuid::new_v4().to_string(),
            "100.5",
            "100",
        )];

        assert_eq!(
            validate_expense("100", &yen(), &beneficiaries),
            Err(ExpenseError::UnsupportedSubunits)
        );
    }

    /// The shares `weights` of `amount` come to, in order, a blank weight having none, written as
    /// numbers so that a test does not depend on how many zeros they end in.
    fn shares_for_weights(amount: &str, currency: &Currency, weights: &[&str]) -> Vec<BigDecimal> {
        let uuids = uuids(weights.len());

        compute_beneficiaries(
            amount,
            currency,
            &uuids,
            &HashMap::new(),
            &HashMap::new(),
            &settings_of(&uuids, weights),
        )
        .unwrap()
        .iter()
        .map(|beneficiary| BigDecimal::from_str(&beneficiary.share).unwrap())
        .collect()
    }

    #[test]
    fn test_weights_divide_the_amount_into_parts() {
        // Four parts of 25.
        assert_eq!(
            shares_for_weights("100", &euro(), &["2", "1", "1"]),
            numbers(&["50", "25", "25"])
        );
        assert_eq!(
            shares_for_weights("1000", &yen(), &["3", "1"]),
            numbers(&["750", "250"])
        );
    }

    #[test]
    fn test_somebody_with_no_weight_counts_for_one_part() {
        assert_eq!(
            shares_for_weights("100", &euro(), &["2", "", ""]),
            numbers(&["50", "25", "25"])
        );
    }

    #[test]
    fn test_a_weight_may_be_part_of_a_part() {
        assert_eq!(
            shares_for_weights("30.00", &euro(), &["1", "0.5"]),
            numbers(&["20", "10"])
        );
        assert_eq!(
            shares_for_weights("100.00", &euro(), &["1.25", "3.75"]),
            numbers(&["25", "75"])
        );
    }

    #[test]
    fn test_only_how_weights_compare_counts() {
        assert_eq!(
            shares_for_weights("100", &euro(), &["4", "2", "2"]),
            shares_for_weights("100", &euro(), &["2", "1", "1"])
        );
    }

    #[test]
    fn test_equal_weights_divide_as_no_weights_do() {
        assert_eq!(
            shares_for_weights("100.00", &euro(), &["1", "1", "1"]),
            numbers(&["33.34", "33.33", "33.33"])
        );
        assert_eq!(
            shares_for_weights("100.00", &euro(), &["", "", ""]),
            numbers(&["33.34", "33.33", "33.33"])
        );
    }

    #[test]
    fn test_subunits_left_by_rounding_go_to_who_lost_the_most_of_their_weight() {
        // 3.33 and 6.67, of which the second lost the most rounding down.
        assert_eq!(
            shares_for_weights("0.10", &euro(), &["1", "2"]),
            numbers(&["0.03", "0.07"])
        );
        // 666.67 and 333.33, whole units here.
        assert_eq!(
            shares_for_weights("1000", &yen(), &["2", "1"]),
            numbers(&["667", "333"])
        );
    }

    #[test]
    fn test_weights_share_what_fixed_shares_and_percentages_leave() {
        let uuids = uuids(4);
        let mut fixed_shares = HashMap::new();
        fixed_shares.insert(uuids[0].clone(), "10.00".to_string());

        let beneficiaries = compute_beneficiaries(
            "100.00",
            &euro(),
            &uuids,
            &fixed_shares,
            &settings_of(&uuids, &["", "25"]),
            &settings_of(&uuids, &["", "", "2"]),
        )
        .unwrap();

        let shares: Vec<BigDecimal> = beneficiaries
            .iter()
            .map(|beneficiary| BigDecimal::from_str(&beneficiary.share).unwrap())
            .collect();

        // 10 fixed and 25% of 100 leave 65, two parts of three for the third, one for the last.
        assert_eq!(shares, numbers(&["10", "25", "43.33", "21.67"]));
        assert_eq!(validate_expense("100.00", &euro(), &beneficiaries), Ok(()));
    }

    #[test]
    fn test_a_weight_is_stated_for_everybody_sharing_what_is_left_once_anybody_has_one() {
        let uuids = uuids(4);
        let mut fixed_shares = HashMap::new();
        fixed_shares.insert(uuids[0].clone(), "10.00".to_string());

        let beneficiaries = compute_beneficiaries(
            "100.00",
            &euro(),
            &uuids,
            &fixed_shares,
            &HashMap::new(),
            &settings_of(&uuids, &["", "", "2"]),
        )
        .unwrap();

        let weights: Vec<Option<&str>> = beneficiaries
            .iter()
            .map(|beneficiary| beneficiary.share_weight.as_deref())
            .collect();

        assert_eq!(weights, vec![None, Some("1"), Some("2"), Some("1")]);
    }

    #[test]
    fn test_no_weight_is_stated_when_nobody_has_one() {
        let uuids = uuids(2);

        let beneficiaries = compute_beneficiaries(
            "100.00",
            &euro(),
            &uuids,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();

        assert!(beneficiaries.iter().all(|b| b.share_weight.is_none()));
    }

    #[test]
    fn test_compute_beneficiaries_refuses_a_weight_it_cannot_take() {
        let uuids = uuids(2);
        let compute = |weight: &str| {
            compute_beneficiaries(
                "100.00",
                &euro(),
                &uuids,
                &HashMap::new(),
                &HashMap::new(),
                &settings_of(&uuids, &[weight]),
            )
            .map(|_| ())
        };

        for malformed in [
            "abc", "-1", "+1", "1.", ".5", "1.123", "1e1", "1_0", "1000", "٥", " 1",
        ] {
            assert_eq!(
                compute(malformed),
                Err(ExpenseError::MalformedWeight),
                "{malformed}"
            );
        }

        for zero in ["0", "0.0", "0.00", "000"] {
            assert_eq!(compute(zero), Err(ExpenseError::NonPositiveShare), "{zero}");
        }
    }

    #[test]
    fn test_compute_beneficiaries_refuses_a_weight_of_nobody_on_the_expense() {
        let uuids = uuids(1);

        assert_eq!(
            compute_beneficiaries(
                "100.00",
                &euro(),
                &uuids,
                &HashMap::new(),
                &HashMap::new(),
                &settings_of(&[Uuid::new_v4().to_string()], &["2"]),
            )
            .map(|_| ()),
            Err(ExpenseError::FixedShareForUnknownBeneficiary)
        );
    }

    #[test]
    fn test_compute_beneficiaries_refuses_a_share_set_as_a_weight_and_anything_else() {
        let uuids = uuids(2);
        let mut fixed_shares = HashMap::new();
        fixed_shares.insert(uuids[0].clone(), "50.00".to_string());

        assert_eq!(
            compute_beneficiaries(
                "100.00",
                &euro(),
                &uuids,
                &fixed_shares,
                &HashMap::new(),
                &settings_of(&uuids, &["2"]),
            )
            .map(|_| ()),
            Err(ExpenseError::ShareSetMoreThanOneWay)
        );
        assert_eq!(
            compute_beneficiaries(
                "100.00",
                &euro(),
                &uuids,
                &HashMap::new(),
                &settings_of(&uuids, &["50"]),
                &settings_of(&uuids, &["2"]),
            )
            .map(|_| ()),
            Err(ExpenseError::ShareSetMoreThanOneWay)
        );
    }

    #[test]
    fn test_compute_beneficiaries_refuses_fixed_shares_past_the_amount_before_weights() {
        let uuids = uuids(2);
        let mut fixed_shares = HashMap::new();
        fixed_shares.insert(uuids[0].clone(), "150.00".to_string());

        assert_eq!(
            compute_beneficiaries(
                "100.00",
                &euro(),
                &uuids,
                &fixed_shares,
                &HashMap::new(),
                &settings_of(&uuids, &["", "2"]),
            )
            .map(|_| ()),
            Err(ExpenseError::SharesExceedTotalAmount)
        );
    }

    #[test]
    fn test_validate_expense_accepts_every_share_a_weight_is_worked_out_to() {
        let weights = [
            vec!["1"],
            vec!["2", "1", "1"],
            vec!["1", "1", "1"],
            vec!["1", "99"],
            vec!["0.5", "1", "1.5", "2.25"],
            vec!["7", "13", "80", "3", "11", "2"],
            vec!["2", "", ""],
        ];

        for weights in &weights {
            for amount in ["100.00", "10.00", "99.99", "1234.56", "7.77", "1000000.01"] {
                let uuids = uuids(weights.len());

                let beneficiaries = compute_beneficiaries(
                    amount,
                    &euro(),
                    &uuids,
                    &HashMap::new(),
                    &HashMap::new(),
                    &settings_of(&uuids, weights),
                )
                .unwrap();

                assert_eq!(
                    validate_expense(amount, &euro(), &beneficiaries),
                    Ok(()),
                    "{weights:?} of {amount}: {beneficiaries:?}"
                );

                // Whichever order a receiver is served them in.
                let reversed: Vec<Beneficiary> = beneficiaries.iter().rev().cloned().collect();
                assert_eq!(validate_expense(amount, &euro(), &reversed), Ok(()));
            }
        }
    }

    #[test]
    fn test_validate_expense_holds_many_small_weights_to_a_large_one_next_to_a_fixed_share() {
        let uuids = uuids(22);
        let mut fixed_shares = HashMap::new();
        fixed_shares.insert(uuids[0].clone(), "3.33".to_string());

        let mut weights = vec!["", "100"];
        weights.extend(vec!["1"; 20]);

        let beneficiaries = compute_beneficiaries(
            "153.33",
            &euro(),
            &uuids,
            &fixed_shares,
            &HashMap::new(),
            &settings_of(&uuids, &weights),
        )
        .unwrap();

        assert_eq!(validate_expense("153.33", &euro(), &beneficiaries), Ok(()));
    }

    #[test]
    fn test_validate_expense_refuses_a_share_its_weight_does_not_come_to() {
        let validated = |amount: &str, first: (&str, &str), second: (&str, &str)| {
            validate_expense(
                amount,
                &euro(),
                &vec![
                    Beneficiary::with_weight(&Uuid::new_v4().to_string(), first.0, first.1),
                    Beneficiary::with_weight(&Uuid::new_v4().to_string(), second.0, second.1),
                ],
            )
        };

        assert_eq!(validated("100.00", ("66.67", "2"), ("33.33", "1")), Ok(()));
        assert_eq!(validated("100.00", ("66.66", "2"), ("33.34", "1")), Ok(()));
        // Adds up, and says something else.
        assert_eq!(
            validated("100.00", ("80.00", "2"), ("20.00", "1")),
            Err(ExpenseError::ShareDiffersFromWeight)
        );
        // By a subunit, on weights that fall exactly on one.
        assert_eq!(
            validated("100.00", ("50.01", "1"), ("49.99", "1")),
            Err(ExpenseError::ShareDiffersFromWeight)
        );
    }

    #[test]
    fn test_validate_expense_takes_weights_next_to_a_fixed_share_and_a_percentage() {
        let beneficiaries = vec![
            Beneficiary::new(&Uuid::new_v4().to_string(), "40.00"),
            Beneficiary::with_percentage(&Uuid::new_v4().to_string(), "20.00", "20"),
            Beneficiary::with_weight(&Uuid::new_v4().to_string(), "30.00", "3"),
            Beneficiary::with_weight(&Uuid::new_v4().to_string(), "10.00", "1"),
        ];

        assert_eq!(validate_expense("100.00", &euro(), &beneficiaries), Ok(()));
    }

    #[test]
    fn test_validate_expense_refuses_a_share_set_as_a_percentage_and_a_weight() {
        let mut beneficiary =
            Beneficiary::with_percentage(&Uuid::new_v4().to_string(), "100.00", "100");
        beneficiary.share_weight = Some("1".to_string());

        assert_eq!(
            validate_expense("100.00", &euro(), &vec![beneficiary]),
            Err(ExpenseError::ShareSetMoreThanOneWay)
        );
    }

    #[test]
    fn test_validate_expense_refuses_a_weight_it_cannot_read() {
        let one_with = |weight: &str| {
            vec![Beneficiary::with_weight(
                &Uuid::new_v4().to_string(),
                "100.00",
                weight,
            )]
        };

        assert_eq!(
            validate_expense("100.00", &euro(), &one_with("two")),
            Err(ExpenseError::MalformedWeight)
        );
        assert_eq!(
            validate_expense("100.00", &euro(), &one_with("")),
            Err(ExpenseError::MalformedWeight)
        );
        assert_eq!(
            validate_expense("100.00", &euro(), &one_with("0")),
            Err(ExpenseError::NonPositiveShare)
        );
    }

    #[test]
    fn test_validate_expense_refuses_a_weight_too_small_to_come_to_anything() {
        let uuids = uuids(2);

        // 0.1 and 9.9 of 0.10, the first rounding to nothing, which no beneficiary can owe.
        let beneficiaries = compute_beneficiaries(
            "0.10",
            &euro(),
            &uuids,
            &HashMap::new(),
            &HashMap::new(),
            &settings_of(&uuids, &["1", "99"]),
        )
        .unwrap();

        assert_eq!(
            validate_expense("0.10", &euro(), &beneficiaries),
            Err(ExpenseError::NonPositiveShare)
        );
    }

    #[test]
    fn test_canonical_amount_writes_an_amount_the_one_way() {
        for (amount, written) in [
            ("12", "12.00"),
            ("12.5", "12.50"),
            ("12.50", "12.50"),
            ("007", "7.00"),
            ("0", "0.00"),
            ("0.5", "0.50"),
            ("999999999999999.99", "999999999999999.99"),
        ] {
            assert_eq!(
                canonical_amount(amount, &euro()).as_deref(),
                Ok(written),
                "{amount}"
            );
        }

        for (amount, written) in [("12", "12"), ("007", "7"), ("0", "0")] {
            assert_eq!(
                canonical_amount(amount, &yen()).as_deref(),
                Ok(written),
                "{amount}"
            );
        }
    }

    #[test]
    fn test_canonical_amount_refuses_what_it_cannot_write_exactly() {
        for amount in [
            "", "12.", ".5", "12.345", "-12", "+12", "1e2", "12,5", " 12", "abc",
        ] {
            assert_eq!(
                canonical_amount(amount, &euro()),
                Err(ExpenseError::MalformedAmount),
                "{amount:?}"
            );
        }

        assert_eq!(
            canonical_amount("12.50", &yen()),
            Err(ExpenseError::UnsupportedSubunits)
        );
        assert_eq!(
            canonical_amount("12.00", &yen()),
            Err(ExpenseError::UnsupportedSubunits)
        );
    }

    #[test]
    fn test_validate_expense_takes_only_what_canonical_amount_writes() {
        for amount in ["12", "12.5", "012.00", "0012.50"] {
            assert_eq!(
                validate_expense(amount, &euro(), &one_beneficiary(amount)),
                Err(ExpenseError::MalformedAmount),
                "{amount}"
            );
        }

        assert_eq!(
            validate_expense("012", &yen(), &one_beneficiary("012")),
            Err(ExpenseError::MalformedAmount)
        );

        // A share too, under an amount written as it should be.
        assert_eq!(
            validate_expense("12.00", &euro(), &one_beneficiary("12")),
            Err(ExpenseError::MalformedAmount)
        );

        for (amount, currency) in [("12.00", euro()), ("12.50", euro()), ("12", yen())] {
            assert_eq!(
                validate_expense(amount, &currency, &one_beneficiary(amount)),
                Ok(()),
                "{amount}"
            );
        }
    }

    /// The shares of `uuids` as written, whatever way each was set.
    fn written_shares(
        amount: &str,
        currency: &Currency,
        fixed: &[&str],
        percentages: &[&str],
        weights: &[&str],
    ) -> Vec<String> {
        let uuids = uuids(fixed.len().max(percentages.len()).max(weights.len()).max(2));

        compute_beneficiaries(
            amount,
            currency,
            &uuids,
            &settings_of(&uuids, fixed),
            &settings_of(&uuids, percentages),
            &settings_of(&uuids, weights),
        )
        .unwrap()
        .into_iter()
        .map(|beneficiary| beneficiary.share)
        .collect()
    }

    #[test]
    fn test_shares_are_written_with_their_subunits_however_they_come_about() {
        // Split.
        assert_eq!(
            written_shares("100.00", &euro(), &[], &[], &[]),
            vec!["50.00", "50.00"]
        );
        // Split, of an amount given in whole units.
        assert_eq!(
            written_shares("100", &euro(), &[], &[], &[]),
            vec!["50.00", "50.00"]
        );
        // Fixed, however they are given, and what they leave.
        assert_eq!(
            written_shares("22.50", &euro(), &["10", "12.5"], &[], &[]),
            vec!["10.00", "12.50"]
        );
        assert_eq!(
            written_shares("100", &euro(), &["10"], &[], &[]),
            vec!["10.00", "90.00"]
        );
        // A percentage.
        assert_eq!(
            written_shares("80", &euro(), &[], &["25", "75"], &[]),
            vec!["20.00", "60.00"]
        );
        // A weight.
        assert_eq!(
            written_shares("100", &euro(), &[], &[], &["2", "1", "1"]),
            vec!["50.00", "25.00", "25.00"]
        );
        // Nothing yet, as a form asks before an amount is typed.
        assert_eq!(
            written_shares("0", &euro(), &[], &[], &[]),
            vec!["0.00", "0.00"]
        );
    }

    #[test]
    fn test_shares_are_written_in_whole_units_in_a_currency_without_a_subunit() {
        assert_eq!(
            written_shares("100", &yen(), &[], &[], &[]),
            vec!["50", "50"]
        );
        assert_eq!(
            written_shares("100", &yen(), &["10"], &[], &[]),
            vec!["10", "90"]
        );
        assert_eq!(
            written_shares("80", &yen(), &[], &["25", "75"], &[]),
            vec!["20", "60"]
        );
        assert_eq!(
            written_shares("100", &yen(), &[], &[], &["2", "1", "1"]),
            vec!["50", "25", "25"]
        );
        assert_eq!(written_shares("0", &yen(), &[], &[], &[]), vec!["0", "0"]);
    }

    #[test]
    fn test_compute_beneficiaries_refuses_subunits_the_currency_does_not_have() {
        let uuids = uuids(2);
        let none = HashMap::new();
        let compute = |amount: &str, currency: &Currency, fixed: &HashMap<String, String>| {
            compute_beneficiaries(amount, currency, &uuids, fixed, &none, &none).map(|_| ())
        };

        assert_eq!(
            compute("12.50", &yen(), &none),
            Err(ExpenseError::UnsupportedSubunits)
        );
        assert_eq!(
            compute("12", &yen(), &settings_of(&uuids, &["1.50"])),
            Err(ExpenseError::UnsupportedSubunits)
        );
        assert_eq!(
            compute("12.345", &euro(), &none),
            Err(ExpenseError::MalformedAmount)
        );
        assert_eq!(
            compute("12", &euro(), &settings_of(&uuids, &["1.005"])),
            Err(ExpenseError::MalformedAmount)
        );
    }

    #[test]
    fn test_what_compute_beneficiaries_writes_validate_expense_takes_as_it_is() {
        let uuids = uuids(3);
        let none = HashMap::new();

        let mut fixed_shares = HashMap::new();
        fixed_shares.insert(uuids[0].clone(), "10".to_string());

        let beneficiaries =
            compute_beneficiaries("100.00", &euro(), &uuids, &fixed_shares, &none, &none).unwrap();

        assert_eq!(validate_expense("100.00", &euro(), &beneficiaries), Ok(()));
    }

    #[test]
    fn test_an_expense_holds_its_amounts_written_the_one_way() {
        let beneficiaries = vec![
            Beneficiary::new(&Uuid::new_v4().to_string(), "12.5"),
            Beneficiary::with_percentage(&Uuid::new_v4().to_string(), "87.50", "87.5"),
        ];

        let expense =
            Expense::new(&Uuid::new_v4().to_string(), "100", &euro(), &beneficiaries).unwrap();

        assert_eq!(expense.amount, "100.00");
        assert_eq!(expense.beneficiaries[0].share, "12.50");
        assert_eq!(expense.beneficiaries[1].share, "87.50");
        assert_eq!(
            expense.beneficiaries[1].share_percentage.as_deref(),
            Some("87.5")
        );
    }

    #[test]
    fn test_an_expense_refuses_more_subunits_than_its_currency_has() {
        let creditor_uuid = Uuid::new_v4().to_string();

        assert_eq!(
            Expense::new(&creditor_uuid, "1.005", &euro(), &one_beneficiary("1.005"))
                .map(|_| ())
                .unwrap_err(),
            ExpenseError::UnsupportedSubunits
        );
    }
}
