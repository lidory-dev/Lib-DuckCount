#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::prelude::BASE64_STANDARD;
    use uuid::Uuid;

    use crate::cryptography::derived_uuid::derive;
    use crate::cryptography::group_expense_id::{GroupExpenseId, new_group_expense_id};
    use crate::cryptography::one_time_expense_id::is_one_time_expense_creditor;

    /// The bytes `id`'s nonce stands for, as the server decodes them.
    fn nonce_of(id: &GroupExpenseId) -> [u8; 16] {
        BASE64_STANDARD
            .decode(&id.nonce)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap()
    }

    #[test]
    fn test_a_minted_id_carries_the_uuid_derived_from_its_nonce() {
        let author_uuid = Uuid::new_v4();

        let id = new_group_expense_id(author_uuid.to_string()).unwrap();

        assert_eq!(id.uuid, derive(&author_uuid, &nonce_of(&id)).to_string());
        assert_eq!(Uuid::parse_str(&id.uuid).unwrap().get_version_num(), 8);
    }

    /// Standard Base64 pads, so 16 bytes always take 24 characters, the last
    /// two of them `=`: what the server's decoder takes.
    #[test]
    fn test_the_nonce_is_sixteen_bytes_in_standard_base64() {
        let id = new_group_expense_id(Uuid::new_v4().to_string()).unwrap();

        assert_eq!(id.nonce.len(), 24);
        assert!(id.nonce.ends_with("=="));
        assert_eq!(BASE64_STANDARD.encode(nonce_of(&id)), id.nonce);
    }

    /// The DuckCount API derives a group expense's UUID exactly as a one-time
    /// expense's, so a group expense's has to be the one a one-time expense
    /// would take from the same author and nonce.
    #[test]
    fn test_the_uuid_is_the_one_a_one_time_expense_would_take() {
        let author_uuid = Uuid::new_v4().to_string();

        let id = new_group_expense_id(author_uuid.clone()).unwrap();
        let nonce = nonce_of(&id).to_vec();

        assert!(is_one_time_expense_creditor(id.uuid, author_uuid, nonce));
    }

    #[test]
    fn test_each_id_is_new() {
        let author_uuid = Uuid::new_v4().to_string();

        let first = new_group_expense_id(author_uuid.clone()).unwrap();
        let second = new_group_expense_id(author_uuid).unwrap();

        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.uuid, second.uuid);
    }

    #[test]
    fn test_nobody_else_derives_the_uuid_from_the_same_nonce() {
        let id = new_group_expense_id(Uuid::new_v4().to_string()).unwrap();

        assert_ne!(derive(&Uuid::new_v4(), &nonce_of(&id)).to_string(), id.uuid);
    }

    #[test]
    fn test_an_author_that_is_not_a_uuid_gets_no_id() {
        assert!(new_group_expense_id("not a uuid".to_string()).is_none());
    }
}
