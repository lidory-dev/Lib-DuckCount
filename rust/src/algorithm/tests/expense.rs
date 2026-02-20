#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::algorithm::{
        beneficiary::Beneficiary,
        expense::{Expense, ExpenseError},
    };
    use bigdecimal::{BigDecimal, Zero};
    use uuid::Uuid;

    #[test]
    fn test_expense_new_success() {
        let creditor_id = Uuid::new_v4().to_string();
        let amount = "100.00";
        let beneficiaries = vec![
            Beneficiary::new(&Uuid::new_v4().to_string(), Some(String::from("50.00"))),
            Beneficiary::new(&Uuid::new_v4().to_string(), None),
        ];

        let expense = Expense::new(&creditor_id, amount, beneficiaries).unwrap();

        assert_eq!(expense.creditor_id, creditor_id);
        assert_eq!(expense.amount, amount);
        assert_eq!(expense.total_share_amount, String::from("50.00"));
        assert_eq!(
            expense.number_of_beneficiaries_without_share,
            String::from("1")
        );
    }

    #[test]
    fn test_expense_new_non_positive_amount() {
        let creditor_id = Uuid::new_v4().to_string();
        let amount = "-100.00";
        let beneficiaries = vec![Beneficiary::new(
            &Uuid::new_v4().to_string(),
            Some(String::from("50.00")),
        )];

        let expense_result = Expense::new(&creditor_id, amount, beneficiaries);

        assert!(expense_result.is_err());
        assert_eq!(expense_result.unwrap_err(), ExpenseError::NonPositiveAmount);
    }

    #[test]
    fn test_expense_new_no_beneficiaries() {
        let creditor_id = Uuid::new_v4().to_string();
        let amount = "100.00";
        let beneficiaries = vec![];

        let expense_result = Expense::new(&creditor_id, amount, beneficiaries);

        assert!(expense_result.is_err());
        assert_eq!(expense_result.unwrap_err(), ExpenseError::NoBeneficiaries);
    }

    #[test]
    fn test_expense_new_shares_exceed_total_amount() {
        let creditor_id = Uuid::new_v4().to_string();
        let amount = "100.00";
        let beneficiaries = vec![
            Beneficiary::new(&Uuid::new_v4().to_string(), Some(String::from("60.00"))),
            Beneficiary::new(&Uuid::new_v4().to_string(), Some(String::from("50.00"))),
        ];

        let expense_result = Expense::new(&creditor_id, amount, beneficiaries);

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
            Beneficiary::new(&Uuid::new_v4().to_string(), Some(String::from("60.00"))),
            Beneficiary::new(&Uuid::new_v4().to_string(), Some(String::from("30.00"))),
        ];

        let expense_result = Expense::new(&creditor_id, amount, beneficiaries);

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
        let beneficiaries = vec![Beneficiary::new(
            &Uuid::new_v4().to_string(),
            Some(String::from("-10.00")),
        )];

        let expense_result = Expense::new(&creditor_id, amount, beneficiaries);

        assert!(expense_result.is_err());
        assert_eq!(expense_result.unwrap_err(), ExpenseError::NonPositiveShare);
    }

    #[test]
    fn test_simple_rounding_needed() {
        let creditor_id = Uuid::new_v4().to_string();
        let alice_id = Uuid::new_v4().to_string();
        let bob_id = Uuid::new_v4().to_string();
        let charlie_id = Uuid::new_v4().to_string();

        let beneficiaries = vec![
            Beneficiary::new(&alice_id, None),
            Beneficiary::new(&bob_id, None),
            Beneficiary::new(&charlie_id, None),
        ];

        let expense = Expense::new(&creditor_id, "100.00", beneficiaries).unwrap();
        let shares = expense.calculate_equal_shares().unwrap();

        // One share should be 33.34 and the others 33.33
        let mut count_33_34 = 0;
        let mut count_33_33 = 0;

        for share in shares.values() {
            println!("share: {}", share);

            if *share == "33.34" {
                count_33_34 += 1;
            } else if *share == "33.33" {
                count_33_33 += 1;
            }
        }

        assert_eq!(count_33_34, 1);
        assert_eq!(count_33_33, 2);

        // Also check that the total is correct (100.0)
        let sum = shares
            .values()
            .map(|s| BigDecimal::from_str(s).expect("Failed to parse string as BigDecimal"))
            .fold(BigDecimal::zero(), |acc, x| acc + x);

        assert!(sum == BigDecimal::from_str("100.00").unwrap());
    }

    #[test]
    fn test_no_rounding_needed() {
        let creditor_id = Uuid::new_v4().to_string();
        let alice_id = Uuid::new_v4().to_string();
        let bob_id = Uuid::new_v4().to_string();
        let charlie_id = Uuid::new_v4().to_string();

        let beneficiaries = vec![
            Beneficiary::new(&alice_id, None),
            Beneficiary::new(&bob_id, None),
            Beneficiary::new(&charlie_id, None),
        ];

        let expense = Expense::new(&creditor_id, "99999", beneficiaries).unwrap();
        let shares = expense.calculate_equal_shares().unwrap();

        let mut count_33333 = 0;

        for share in shares.values() {
            if *share == "33333" {
                count_33333 += 1;
            }
        }

        assert_eq!(count_33333, shares.values().len());

        // Also check that the total is correct (100.0)
        let sum = shares
            .values()
            .map(|s| BigDecimal::from_str(s).expect("Failed to parse string as BigDecimal"))
            .fold(BigDecimal::zero(), |acc, x| acc + x);

        assert!(sum == BigDecimal::from_str("99999").unwrap());
    }
}
