use aes_gcm::Aes256Gcm;
use aes_siv::{Aes256SivAead, KeyInit};
use argon2::Argon2;
use rand::rngs::OsRng;

use crate::cryptography::encryption::KeyError;

pub const DETERMINISTIC_ENCRYPTION_KEY_SIZE: usize = 64;
pub const NON_DETERMINISTIC_ENCRYPTION_KEY_SIZE: usize = 32;

/// Generates a cryptographically secure symmetric encryption key for AES-256-SIV (AES-CMAC-SIV in AEAD mode).
///
/// This method uses the operating system's cryptographically secure random number generator
/// to create a new 512-bit (64-byte) key suitable for use with the AES-256-SIV encryption algorithm.
/// The generated key is intended for deterministic encryption, where the same plaintext and key
/// will always produce the same ciphertext when combined with a fixed nonce.
///
/// # Returns
///
/// * `Vec<u8>` - A byte vector containing the newly generated 512-bit symmetric encryption key.
///
/// # Example
///
/// ```rust
/// use lib_duckcount::cryptography::encryption::keys::generate_symmetric_deterministic_encryption_key;
///
/// let key = generate_symmetric_deterministic_encryption_key();
///
/// println!("Generated deterministic key: {:?}", key);
/// ```
#[uniffi::export]
pub fn generate_symmetric_deterministic_encryption_key() -> Vec<u8> {
    let rng = OsRng;

    Aes256SivAead::generate_key(rng).to_vec()
}

/// Generates a cryptographically secure symmetric encryption key for AES-256-GCM.
///
/// This method uses the operating system's cryptographically secure random number generator
/// to create a new 256-bit (32-byte) key suitable for use with the AES-256-GCM encryption algorithm.
///
/// # Returns
///
/// * `Vec<u8>` - A byte vector containing the newly generated 256-bit symmetric encryption key.
///
/// # Example
///
/// ```rust
/// use lib_duckcount::cryptography::encryption::keys::generate_symmetric_encryption_key;
///
/// let key = generate_symmetric_encryption_key();
///
/// println!("Generated key: {:?}", key);
/// ```
#[uniffi::export]
pub fn generate_symmetric_encryption_key() -> Vec<u8> {
    let rng = OsRng;

    Aes256Gcm::generate_key(rng).to_vec()
}

/// Defines if a key will be used for deterministic or non-deterministic encryption.
#[derive(uniffi::Enum)]
pub enum KeyUsage {
    Deterministic,
    NonDeterministic,
}

/// Derives a cryptographic key from a secret using **Argon2id** (a memory-hard and GPU-resistant password hashing function).
///
/// This method uses the provided `secret`, `salt`, and `key_usage` to derive a key of the appropriate size.
/// The derived key can be used for either deterministic or non-deterministic encryption,
/// depending on the `KeyUsage` variant provided.
///
/// # Arguments
///
/// * `secret` - A reference to a byte vector representing the base secret used for key derivation.
/// * `salt` - A salt string used to add randomness to the key derivation process.
/// * `key_usage` - Specifies the intended use of the derived key, determining the output key size:
///   - `KeyUsage::Deterministic`: Derives a key of size `DETERMINISTIC_ENCRYPTION_KEY_SIZE`.
///   - `KeyUsage::NonDeterministic`: Derives a key of size `NON_DETERMINISTIC_ENCRYPTION_KEY_SIZE`.
///
/// # Returns
///
/// * `Result<Vec<u8>, KeyError>` - The derived key as a byte vector if successful, or an error if key derivation fails.
///
/// # Errors
///
/// * `KeyError::DerivationFailed` - If the key derivation process fails.
///
/// # Example
///
/// ```rust
/// use argon2::password_hash::SaltString;
/// use lib_duckcount::cryptography::encryption::keys::{derive_key, KeyUsage};
/// use rand::rngs::OsRng;
///
/// let secret = "&eHml-C_AFyWdylXLd50".as_bytes().to_vec();
///
/// let salt = SaltString::generate(&mut OsRng); // Optional salt
///
/// let key = derive_key(&secret, salt.to_string(), KeyUsage::NonDeterministic).unwrap();
///
/// println!("Derived key: {:?}", key);
/// ```
#[uniffi::export]
pub fn derive_key(
    secret: &Vec<u8>,
    salt: String,
    key_usage: KeyUsage,
) -> Result<Vec<u8>, KeyError> {
    match key_usage {
        KeyUsage::Deterministic => {
            let mut key = [0u8; DETERMINISTIC_ENCRYPTION_KEY_SIZE];

            Argon2::default()
                .hash_password_into(secret, salt.as_bytes(), &mut key)
                .map_err(|e| {
                    println!("Derivation error: {:?}", e);
                    KeyError::DerivationFailed
                })?;

            Ok(key.to_vec())
        }
        KeyUsage::NonDeterministic => {
            let mut key = [0u8; NON_DETERMINISTIC_ENCRYPTION_KEY_SIZE];

            Argon2::default()
                .hash_password_into(secret, salt.as_bytes(), &mut key)
                .map_err(|_| KeyError::DerivationFailed)?;

            Ok(key.to_vec())
        }
    }
}
