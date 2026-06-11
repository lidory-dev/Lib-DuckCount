#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::algorithm::debt::Debt;
    use bigdecimal::BigDecimal;
    use uuid::Uuid;

    #[test]
    fn test_debt_new() {
        let amount = BigDecimal::from_str("100.00").unwrap();
        let user_uuid = Uuid::new_v4().to_string();
        let debt = Debt::new(&amount, &user_uuid);

        assert_eq!(debt.amount, amount);
        assert_eq!(debt.user_uuid, user_uuid);
    }

    #[test]
    fn test_debt_ord() {
        let debt1 = Debt::new(
            &BigDecimal::from_str("100.00").unwrap(),
            &Uuid::new_v4().to_string(),
        );
        let debt2 = Debt::new(
            &BigDecimal::from_str("200.00").unwrap(),
            &Uuid::new_v4().to_string(),
        );

        assert!(debt1 < debt2);
    }

    #[test]
    fn test_debt_ord_tie_breaker_needed() {
        let uuid_2 = Uuid::new_v4().to_string();
        let uuid_1 = Uuid::new_v4().to_string();

        let debt1 = Debt::new(&BigDecimal::from_str("100.00").unwrap(), &uuid_1);
        let debt2 = Debt::new(&BigDecimal::from_str("100.00").unwrap(), &uuid_2);

        if uuid_1 < uuid_2 {
            assert!(debt1 < debt2);
        } else {
            assert!(debt1 > debt2);
        }
    }
}
