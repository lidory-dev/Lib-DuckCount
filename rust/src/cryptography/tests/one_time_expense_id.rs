#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::cryptography::one_time_expense_id::{
        derive, is_one_time_expense_creditor, new_one_time_expense_id,
    };

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

    #[test]
    fn test_the_creditor_is_shown_by_the_nonce_of_the_shared_vector() {
        assert!(is_one_time_expense_creditor(
            "8d1e5823-c00c-83b7-8212-500089e3b975".to_string(),
            "01234567-89ab-4cde-8f01-23456789abcd".to_string(),
            (0..16).collect(),
        ));
    }

    #[test]
    fn test_the_creditor_is_shown_by_the_nonce_their_id_was_minted_with() {
        let creditor_uuid = Uuid::new_v4().to_string();

        let id = new_one_time_expense_id(creditor_uuid.clone()).unwrap();

        assert!(is_one_time_expense_creditor(
            id.uuid,
            creditor_uuid,
            id.nonce
        ));
    }

    /// What a co-beneficiary handing over a key of their own would look like: the
    /// right expense and the right nonce, from somebody else.
    #[test]
    fn test_nobody_else_is_shown_to_be_the_creditor_by_the_same_nonce() {
        let id = new_one_time_expense_id(Uuid::new_v4().to_string()).unwrap();

        assert!(!is_one_time_expense_creditor(
            id.uuid,
            Uuid::new_v4().to_string(),
            id.nonce,
        ));
    }

    #[test]
    fn test_another_nonce_does_not_show_the_creditor() {
        let creditor_uuid = Uuid::new_v4().to_string();

        let id = new_one_time_expense_id(creditor_uuid.clone()).unwrap();
        let other = new_one_time_expense_id(creditor_uuid.clone()).unwrap();

        assert!(!is_one_time_expense_creditor(
            id.uuid,
            creditor_uuid,
            other.nonce
        ));
    }

    #[test]
    fn test_a_nonce_of_the_wrong_length_shows_nothing() {
        let creditor_uuid = Uuid::new_v4().to_string();

        let id = new_one_time_expense_id(creditor_uuid.clone()).unwrap();

        let mut longer = id.nonce.clone();
        longer.push(0);

        assert!(!is_one_time_expense_creditor(
            id.uuid.clone(),
            creditor_uuid.clone(),
            id.nonce[..15].to_vec(),
        ));
        assert!(!is_one_time_expense_creditor(
            id.uuid,
            creditor_uuid,
            longer
        ));
    }

    #[test]
    fn test_an_expense_uuid_written_otherwise_shows_nothing() {
        let creditor_uuid = Uuid::new_v4().to_string();

        let id = new_one_time_expense_id(creditor_uuid.clone()).unwrap();

        assert!(!is_one_time_expense_creditor(
            id.uuid.to_uppercase(),
            creditor_uuid,
            id.nonce,
        ));
    }

    #[test]
    fn test_a_creditor_that_is_not_a_uuid_is_shown_to_be_nobody_s() {
        let id = new_one_time_expense_id(Uuid::new_v4().to_string()).unwrap();

        assert!(!is_one_time_expense_creditor(
            id.uuid,
            "not a uuid".to_string(),
            id.nonce
        ));
    }
}
