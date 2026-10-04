#[cfg(test)]
mod tests {
    use crate::cryptography::encryption::{
        EncryptionError,
        decrypt::{
            decrypt_deterministically_using_symmetric_key, decrypt_using_symmetric_key,
            decrypt_using_symmetric_key_with_associated_data,
        },
        encrypt::{
            encrypt_deterministically_using_symmetric_key, encrypt_using_symmetric_key,
            encrypt_using_symmetric_key_with_associated_data,
        },
        keys::{
            generate_symmetric_deterministic_encryption_key, generate_symmetric_encryption_key,
        },
    };
    use aes_gcm::{AeadCore, Aes256Gcm};
    use rand::rngs::OsRng;

    #[test]
    fn test_encrypt_deterministically() {
        let key = generate_symmetric_deterministic_encryption_key();
        let plaintext = b"hello world".to_vec();

        let ciphertext1 = encrypt_deterministically_using_symmetric_key(&key, &plaintext).unwrap();

        let ciphertext2 = encrypt_deterministically_using_symmetric_key(&key, &plaintext).unwrap();

        assert_eq!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_encrypt_decrypt_deterministic() {
        let key = generate_symmetric_deterministic_encryption_key();
        let plaintext = b"hello world".to_vec();

        let ciphertext = encrypt_deterministically_using_symmetric_key(&key, &plaintext).unwrap();

        let decrypted = decrypt_deterministically_using_symmetric_key(&key, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_deterministic_failure() {
        let key = generate_symmetric_deterministic_encryption_key();
        let wrong_key = generate_symmetric_deterministic_encryption_key();
        let plaintext = b"hello world".to_vec();

        let ciphertext = encrypt_deterministically_using_symmetric_key(&key, &plaintext).unwrap();

        // Wrong key should fail.
        assert!(decrypt_deterministically_using_symmetric_key(&wrong_key, &ciphertext).is_err());

        // Corrupted ciphertext should fail.
        let mut corrupted_ciphertext = ciphertext.clone();
        corrupted_ciphertext[0] ^= 0xFF;

        assert!(
            decrypt_deterministically_using_symmetric_key(&key, &corrupted_ciphertext).is_err()
        );
    }

    #[test]
    fn test_encrypt_decrypt_non_deterministic() {
        let key = generate_symmetric_encryption_key();
        let plaintext = b"hello world".to_vec();

        let encrypted = encrypt_using_symmetric_key(&key, &plaintext).unwrap();

        let decrypted =
            decrypt_using_symmetric_key(&key, &encrypted.ciphertext, &encrypted.nonce).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_non_deterministic_failure() {
        let key = generate_symmetric_encryption_key();
        let wrong_key = generate_symmetric_encryption_key();
        let plaintext = b"hello world".to_vec();

        let encrypted = encrypt_using_symmetric_key(&key, &plaintext).unwrap();

        // Wrong key should fail.
        assert!(
            decrypt_using_symmetric_key(&wrong_key, &encrypted.ciphertext, &encrypted.nonce)
                .is_err()
        );

        // Corrupted ciphertext should fail.
        let mut corrupted_ciphertext = encrypted.ciphertext.clone();
        corrupted_ciphertext[0] ^= 0xFF;
        assert!(
            decrypt_using_symmetric_key(&key, &corrupted_ciphertext, &encrypted.nonce).is_err()
        );

        // Wrong nonce should fail.
        let wrong_nonce = Aes256Gcm::generate_nonce(&mut OsRng).to_vec();
        assert!(decrypt_using_symmetric_key(&key, &encrypted.ciphertext, &wrong_nonce).is_err());
    }

    #[test]
    fn test_decrypt_non_deterministic_refuses_a_nonce_of_the_wrong_length() {
        let key = generate_symmetric_encryption_key();
        let encrypted = encrypt_using_symmetric_key(&key, &b"hello world".to_vec()).unwrap();

        for length in [0, 3, 11, 13, 64] {
            assert!(
                matches!(
                    decrypt_using_symmetric_key(&key, &encrypted.ciphertext, &vec![0; length]),
                    Err(EncryptionError::DecryptionFailed)
                ),
                "{length}"
            );
        }
    }

    #[test]
    fn test_associated_data_round_trips() {
        let key = generate_symmetric_encryption_key();
        let plaintext = b"12.34".to_vec();
        let associated_data = b"amount".to_vec();

        let encrypted =
            encrypt_using_symmetric_key_with_associated_data(&key, &plaintext, &associated_data)
                .unwrap();

        let decrypted = decrypt_using_symmetric_key_with_associated_data(
            &key,
            &encrypted.ciphertext,
            &encrypted.nonce,
            &associated_data,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    /// Opens what was sealed under `sealed_for` with `opened_as` as the associated data.
    fn opens_as(sealed_for: &[u8], opened_as: &[u8]) -> bool {
        let key = generate_symmetric_encryption_key();

        let encrypted = encrypt_using_symmetric_key_with_associated_data(
            &key,
            &b"40.00".to_vec(),
            &sealed_for.to_vec(),
        )
        .unwrap();

        decrypt_using_symmetric_key_with_associated_data(
            &key,
            &encrypted.ciphertext,
            &encrypted.nonce,
            &opened_as.to_vec(),
        )
        .is_ok()
    }

    #[test]
    fn test_other_associated_data_does_not_decrypt() {
        assert!(opens_as(b"amount", b"amount"));
        assert!(!opens_as(b"amount", b"timestamp"));
        assert!(!opens_as(b"amount", b""));
    }

    /// The swap associated data exists to stop: two beneficiaries' shares of one expense are
    /// sealed under the same key, so only what they are bound to tells them apart.
    #[test]
    fn test_a_share_bound_for_one_beneficiary_does_not_open_as_another_s() {
        let bob = b"share:11111111-1111-1111-1111-111111111111";
        let carol = b"share:22222222-2222-2222-2222-222222222222";

        assert!(!opens_as(bob, carol));
    }

    /// Associated data that another one starts with must not pass for it, either way round.
    #[test]
    fn test_associated_data_that_prefixes_another_does_not_open_it() {
        assert!(!opens_as(b"share:abc", b"share"));
        assert!(!opens_as(b"share", b"share:abc"));
    }

    /// Test case 14 of the GCM specification: AES-256 under an all-zero key and nonce, with
    /// no associated data. Pinned against the bytes rather than a round trip, so that how
    /// the functions are arranged can change without ciphertexts sealed before associated
    /// data existed, the vault's among them, ceasing to open.
    #[test]
    fn test_decryption_without_associated_data_opens_a_known_ciphertext() {
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 12];

        let sealed = hex(concat!(
            "cea7403d4d606b6e074ec5d3baf39d18",
            "d0d1c8a799996bf0265b98b5d48ab919",
        ));

        assert_eq!(
            decrypt_using_symmetric_key(&key, &sealed, &nonce).unwrap(),
            vec![0u8; 16],
        );

        assert_eq!(
            decrypt_using_symmetric_key_with_associated_data(&key, &sealed, &nonce, &Vec::new())
                .unwrap(),
            vec![0u8; 16],
        );

        assert!(
            decrypt_using_symmetric_key_with_associated_data(&key, &sealed, &nonce, &b"x".to_vec())
                .is_err()
        );
    }

    fn hex(digits: &str) -> Vec<u8> {
        (0..digits.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&digits[index..index + 2], 16).unwrap())
            .collect()
    }
}
