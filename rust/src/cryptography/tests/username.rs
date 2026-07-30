#[cfg(test)]
mod tests {
    use sha3::{Digest, Sha3_512};

    use crate::cryptography::username::{
        RESERVED_USERNAME_DOMAIN, UsernameError, hash_reserved_username, validate_username,
    };

    #[test]
    fn test_validate_username_normalizes() {
        assert_eq!(validate_username("Alice").unwrap(), "alice");
        assert_eq!(validate_username("  alice  ").unwrap(), "alice");
        assert_eq!(validate_username("AlIcE42").unwrap(), "alice42");
    }

    #[test]
    fn test_validate_username_rejects_empty() {
        assert_eq!(validate_username("").unwrap_err(), UsernameError::Empty);
        assert_eq!(validate_username("   ").unwrap_err(), UsernameError::Empty);
    }

    #[test]
    fn test_validate_username_rejects_not_starting_with_a_letter() {
        assert_eq!(
            validate_username("42alice").unwrap_err(),
            UsernameError::MustStartWithLetter
        );
        assert_eq!(
            validate_username("_alice").unwrap_err(),
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
    fn test_hash_reserved_username_is_a_128_lowercase_hexadecimal_digest() {
        let digest = hash_reserved_username("alice").unwrap();

        // The shape the server enforces before storing the reservation.
        assert_eq!(digest.len(), 128);
        assert!(
            digest
                .chars()
                .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
        );
    }

    #[test]
    fn test_hash_reserved_username_is_domain_separated() {
        let digest = hash_reserved_username("alice").unwrap();

        let mut hasher = Sha3_512::new();
        hasher.update(b"alice");
        let undomained: String = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        assert_ne!(digest, undomained);

        let mut hasher = Sha3_512::new();
        hasher.update(RESERVED_USERNAME_DOMAIN.as_bytes());
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
    fn test_hash_reserved_username_known_answer() {
        assert_eq!(
            hash_reserved_username("alice").unwrap(),
            "a4ffbe96046f6da332c64d705c10160718c2dde036cc62d03f2eba92048021ac\
             88ec5179d78651bec20bdc3587881c065eb6b6db6006138cd45d556abb9055b4"
        );
    }

    #[test]
    fn test_hash_reserved_username_ignores_case_and_surrounding_whitespace() {
        let digest = hash_reserved_username("alice").unwrap();

        assert_eq!(hash_reserved_username("Alice").unwrap(), digest);
        assert_eq!(hash_reserved_username("  ALICE  ").unwrap(), digest);
    }

    #[test]
    fn test_hash_reserved_username_rejects_an_invalid_username() {
        assert_eq!(
            hash_reserved_username("42alice").unwrap_err(),
            UsernameError::MustStartWithLetter
        );
    }
}
