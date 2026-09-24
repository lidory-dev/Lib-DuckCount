#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::cryptography::one_time_expense_id::{derive, new_one_time_expense_id};

    #[test]
    fn test_the_uuid_is_the_one_the_server_derives() {
        // The same vector is checked by DuckCount-API: if either side changes
        // how it derives the UUID, one of the two tests fails.
        let creditor_uuid = Uuid::parse_str("01234567-89ab-4cde-8f01-23456789abcd").unwrap();
        let nonce = std::array::from_fn(|index| index as u8);

        assert_eq!(
            derive(&creditor_uuid, &nonce).to_string(),
            "8d1e5823-c00c-83b7-8212-500089e3b975"
        );
    }

    #[test]
    fn test_a_minted_id_carries_the_uuid_derived_from_its_nonce() {
        let creditor_uuid = Uuid::new_v4();

        let id = new_one_time_expense_id(creditor_uuid.to_string()).unwrap();
        let nonce: [u8; 16] = id.nonce.as_slice().try_into().unwrap();

        assert_eq!(id.uuid, derive(&creditor_uuid, &nonce).to_string());
        assert_eq!(Uuid::parse_str(&id.uuid).unwrap().get_version_num(), 8);
    }

    #[test]
    fn test_each_id_is_new() {
        let creditor_uuid = Uuid::new_v4().to_string();

        let first = new_one_time_expense_id(creditor_uuid.clone()).unwrap();
        let second = new_one_time_expense_id(creditor_uuid).unwrap();

        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.uuid, second.uuid);
    }

    #[test]
    fn test_another_creditor_gets_another_uuid_from_the_same_nonce() {
        let nonce = [7u8; 16];

        assert_ne!(
            derive(&Uuid::new_v4(), &nonce),
            derive(&Uuid::new_v4(), &nonce)
        );
    }

    #[test]
    fn test_a_creditor_that_is_not_a_uuid_gets_no_id() {
        assert!(new_one_time_expense_id("not a uuid".to_string()).is_none());
    }
}
