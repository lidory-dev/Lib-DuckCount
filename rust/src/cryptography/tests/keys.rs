#[cfg(test)]
mod tests {
    use crate::cryptography::{
        encryption::keys::{
            DETERMINISTIC_ENCRYPTION_KEY_SIZE, KeyUsage, NON_DETERMINISTIC_ENCRYPTION_KEY_SIZE,
            derive_key, generate_symmetric_deterministic_encryption_key,
            generate_symmetric_encryption_key,
        },
        password::generate_password,
    };
    use argon2::password_hash::SaltString;
    use rand::rngs::OsRng;

    #[test]
    fn test_generate_symmetric_deterministic_encryption_key() {
        let symmetric_deterministic_encryption_key =
            generate_symmetric_deterministic_encryption_key();

        let symmetric_deterministic_encryption_key_bis =
            generate_symmetric_deterministic_encryption_key();

        assert_eq!(
            symmetric_deterministic_encryption_key.len(),
            DETERMINISTIC_ENCRYPTION_KEY_SIZE
        );

        assert_ne!(
            symmetric_deterministic_encryption_key,
            symmetric_deterministic_encryption_key_bis
        );
    }

    #[test]
    fn test_generate_symmetric_encryption_key() {
        let symmetric_encryption_key = generate_symmetric_encryption_key();

        let symmetric_encryption_key_bis = generate_symmetric_encryption_key();

        assert_eq!(
            symmetric_encryption_key.len(),
            NON_DETERMINISTIC_ENCRYPTION_KEY_SIZE
        );

        assert_ne!(symmetric_encryption_key, symmetric_encryption_key_bis)
    }

    #[test]
    fn test_derive_key_deterministic() {
        let rng = OsRng;

        let password = generate_password();
        let salt = SaltString::generate(rng);

        let key1 = derive_key(
            &password.as_bytes().to_vec(),
            salt.to_string(),
            KeyUsage::Deterministic,
        )
        .unwrap();

        let key2 = derive_key(
            &password.as_bytes().to_vec(),
            salt.to_string(),
            KeyUsage::Deterministic,
        )
        .unwrap();

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), DETERMINISTIC_ENCRYPTION_KEY_SIZE);
    }

    #[test]
    fn test_derive_key_non_deterministic() {
        let rng = OsRng;

        let password = generate_password();
        let salt = SaltString::generate(rng);

        let key1 = derive_key(
            &password.as_bytes().to_vec(),
            salt.to_string(),
            KeyUsage::NonDeterministic,
        )
        .unwrap();

        let key2 = derive_key(
            &password.as_bytes().to_vec(),
            salt.to_string(),
            KeyUsage::NonDeterministic,
        )
        .unwrap();

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), NON_DETERMINISTIC_ENCRYPTION_KEY_SIZE);
    }
}
