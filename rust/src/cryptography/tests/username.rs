#[cfg(test)]
mod tests {
    use sha3::{Digest, Sha3_512};

    use crate::cryptography::username::{
        DISCOVERY_USERNAME_DOMAIN, UsernameError, hash_discovery_username, hash_login_username,
        normalize_username, validate_username,
    };

    #[test]
    fn test_normalize_username() {
        assert_eq!(normalize_username("Alice"), "alice");
        assert_eq!(normalize_username("  alice  "), "alice");
        assert_eq!(normalize_username("AlIcE42"), "alice42");
    }

    #[test]
    fn test_validate_username_rejects_empty() {
        assert_eq!(validate_username("").unwrap_err(), UsernameError::Empty);
        assert_eq!(validate_username("   ").unwrap_err(), UsernameError::Empty);
    }

    #[test]
    fn test_validate_username_rejects_too_long() {
        assert_eq!(
            validate_username("duckcountduckcountduckcountduckcount").unwrap_err(),
            UsernameError::TooLong
        );
    }

    #[test]
    fn test_validate_username_rejects_not_starting_with_a_letter() {
        assert_eq!(
            validate_username("42alice").unwrap_err(),
            UsernameError::MustStartWithLetter
        );
    }

    #[test]
    fn test_validate_username_rejects_invalid_characters() {
        assert_eq!(
            validate_username("alice@duckcount.app").unwrap_err(),
            UsernameError::InvalidCharacter
        );
        assert_eq!(
            validate_username("alice bob").unwrap_err(),
            UsernameError::InvalidCharacter
        );
        // Non-ASCII letters are refused: the same handle could be spelled with
        // different byte sequences, and peers would compute different digests.
        assert_eq!(
            validate_username("alicé").unwrap_err(),
            UsernameError::InvalidCharacter
        );
    }

    #[test]
    fn test_hash_discovery_username_is_a_128_lowercase_hexadecimal_digest() {
        let digest = hash_discovery_username("alice").unwrap();

        // The shape the server enforces before storing the reservation.
        assert_eq!(digest.len(), 128);
        assert!(
            digest
                .chars()
                .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
        );
    }

    #[test]
    fn test_hash_discovery_username_is_domain_separated() {
        let digest = hash_discovery_username("alice").unwrap();

        let mut hasher = Sha3_512::new();
        hasher.update(b"alice");
        let undomained: String = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        assert_ne!(digest, undomained);

        let mut hasher = Sha3_512::new();
        hasher.update(DISCOVERY_USERNAME_DOMAIN.as_bytes());
        hasher.update(b"alice");
        let domained: String = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        assert_eq!(digest, domained);
    }

    /// Pins the digest peers must reproduce. Changing it silently would make
    /// every already-reserved username unresolvable.
    #[test]
    fn test_hash_discovery_username_known_answer() {
        assert_eq!(
            hash_discovery_username("alice").unwrap(),
            "c4d69b529d5dc6184ba2ac6ba7af94a44ac8b76d93deb917650496c41e42a22\
            6f9acfa863bfa69d887288174ff3921b3a3d1f97ab6be5fedfffb72a0b00595d5"
        );
    }

    #[test]
    fn test_hash_discovery_username_ignores_case_and_surrounding_whitespace() {
        let digest = hash_discovery_username("alice").unwrap();

        assert_eq!(hash_discovery_username("Alice").unwrap(), digest);
        assert_eq!(hash_discovery_username("  ALICE  ").unwrap(), digest);
    }

    #[test]
    fn test_hash_discovery_username_rejects_an_invalid_username() {
        assert_eq!(
            hash_discovery_username("42alice").unwrap_err(),
            UsernameError::MustStartWithLetter
        );
    }

    #[test]
    fn test_hash_login_username_is_a_128_lowercase_hexadecimal_digest() {
        let digest = hash_login_username("alice@duckcount.app").unwrap(); // TODO: Invalid char.

        assert_eq!(digest.len(), 128);
        assert!(
            digest
                .chars()
                .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
        );
    }

    #[test]
    fn test_hash_login_username_ignores_case_and_surrounding_whitespace() {
        let digest = hash_login_username("alice@duckcount.app").unwrap();

        assert_eq!(hash_login_username("Alice@DuckCount.app").unwrap(), digest);
        assert_eq!(
            hash_login_username("  alice@duckcount.app  ").unwrap(),
            digest
        );
    }

    /// The two domains keep the same handle from ever producing the same digest.
    #[test]
    fn test_login_and_discovery_digests_never_collide() {
        assert_ne!(
            hash_login_username("alice").unwrap(),
            hash_discovery_username("alice").unwrap()
        );
    }

    /// Pins the digest the server knows an account by. Changing it silently would
    /// lock every existing user out.
    #[test]
    fn test_hash_login_username_known_answer() {
        assert_eq!(
            hash_login_username("alice").unwrap(),
            "2ab95e8ae3df0cce2d7704137ae571ac960d213459e866b539adc43af64f48a8\
             7bb98f79add573fa32530d70fe7761ad0ad4f98f2ead61414d30ece777d6aedc"
        );
    }
}
