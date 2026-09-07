#[cfg(test)]
mod tests {
    use sha3::{Digest, Sha3_512};

    use crate::cryptography::{
        encryption::keys::generate_symmetric_encryption_key,
        profile::{PROFILE_ENCRYPTION_KEY_DOMAIN, profile_encryption_key_partial_hash},
    };

    #[test]
    fn test_partial_hash_is_ten_lowercase_hexadecimal_characters() {
        let partial_hash = profile_encryption_key_partial_hash(&b"a profile key".to_vec());

        // The length the server stores and compares against.
        assert_eq!(partial_hash.len(), 10);
        assert!(
            partial_hash
                .chars()
                .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
        );
    }

    #[test]
    fn test_partial_hash_is_stable_for_one_key() {
        let key = generate_symmetric_encryption_key();

        assert_eq!(
            profile_encryption_key_partial_hash(&key),
            profile_encryption_key_partial_hash(&key)
        );
    }

    #[test]
    fn test_partial_hash_differs_between_keys() {
        assert_ne!(
            profile_encryption_key_partial_hash(&generate_symmetric_encryption_key()),
            profile_encryption_key_partial_hash(&generate_symmetric_encryption_key())
        );
    }

    #[test]
    fn test_partial_hash_is_domain_separated() {
        let key = b"a profile key".to_vec();

        let mut hasher = Sha3_512::new();
        hasher.update(&key);
        let undomained: String = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        assert_ne!(
            profile_encryption_key_partial_hash(&key),
            undomained.chars().take(10).collect::<String>()
        );

        let mut hasher = Sha3_512::new();
        hasher.update(PROFILE_ENCRYPTION_KEY_DOMAIN.as_bytes());
        hasher.update(&key);
        let domained: String = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        assert_eq!(
            profile_encryption_key_partial_hash(&key),
            domained.chars().take(10).collect::<String>()
        );
    }

    /// Pins the value every client must reproduce. Changing it silently would lock
    /// every existing profile behind a proof nobody can compute any more, the
    /// owner's and every contact's alike.
    #[test]
    fn test_partial_hash_known_answer() {
        assert_eq!(
            profile_encryption_key_partial_hash(&b"a profile key".to_vec()),
            "90cfca8ae2"
        );
    }
}
