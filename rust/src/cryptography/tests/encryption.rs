#[cfg(test)]
mod tests {
    use crate::cryptography::encryption::{
        decrypt::{decrypt_deterministically_using_symmetric_key, decrypt_using_symmetric_key},
        encrypt::{encrypt_deterministically_using_symmetric_key, encrypt_using_symmetric_key},
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
            decrypt_using_symmetric_key(&key, &encrypted.cipher_text, &encrypted.nonce).unwrap();

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
            decrypt_using_symmetric_key(&wrong_key, &encrypted.cipher_text, &encrypted.nonce)
                .is_err()
        );

        // Corrupted ciphertext should fail.
        let mut corrupted_ciphertext = encrypted.cipher_text.clone();
        corrupted_ciphertext[0] ^= 0xFF;
        assert!(
            decrypt_using_symmetric_key(&key, &corrupted_ciphertext, &encrypted.nonce).is_err()
        );

        // Wrong nonce should fail.
        let wrong_nonce = Aes256Gcm::generate_nonce(&mut OsRng).to_vec();
        assert!(decrypt_using_symmetric_key(&key, &encrypted.cipher_text, &wrong_nonce).is_err());
    }
}
