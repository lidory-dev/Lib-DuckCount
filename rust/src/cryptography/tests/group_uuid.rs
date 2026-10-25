#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::cryptography::derived_uuid::derive;
    use crate::cryptography::group_uuid::new_group_id;
    use crate::cryptography::one_time_expense_id::is_one_time_expense_creditor;

    #[test]
    fn test_a_minted_id_carries_the_uuid_derived_from_its_nonce() {
        let creator_uuid = Uuid::new_v4();

        let id = new_group_id(creator_uuid.to_string()).unwrap();
        let nonce: [u8; 16] = id.nonce.as_slice().try_into().unwrap();

        assert_eq!(id.uuid, derive(&creator_uuid, &nonce).to_string());
        assert_eq!(Uuid::parse_str(&id.uuid).unwrap().get_version_num(), 8);
    }

    /// The DuckCount API derives a group's UUID exactly as a one-time
    /// expense's, so a group's has to be the one a one-time expense would take
    /// from the same creator and nonce.
    #[test]
    fn test_the_uuid_is_the_one_a_one_time_expense_would_take() {
        let creator_uuid = Uuid::new_v4().to_string();

        let id = new_group_id(creator_uuid.clone()).unwrap();

        assert!(is_one_time_expense_creditor(
            id.uuid,
            creator_uuid,
            id.nonce
        ));
    }

    #[test]
    fn test_each_id_is_new() {
        let creator_uuid = Uuid::new_v4().to_string();

        let first = new_group_id(creator_uuid.clone()).unwrap();
        let second = new_group_id(creator_uuid).unwrap();

        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.uuid, second.uuid);
    }

    #[test]
    fn test_nobody_else_derives_the_uuid_from_the_same_nonce() {
        let id = new_group_id(Uuid::new_v4().to_string()).unwrap();
        let nonce: [u8; 16] = id.nonce.as_slice().try_into().unwrap();

        assert_ne!(derive(&Uuid::new_v4(), &nonce).to_string(), id.uuid);
    }

    #[test]
    fn test_a_creator_that_is_not_a_uuid_gets_no_id() {
        assert!(new_group_id("not a uuid".to_string()).is_none());
    }
}
