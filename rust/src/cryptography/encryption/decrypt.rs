use aes_gcm::aead::Aead;

use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use aes_siv::{Aes256SivAead, Key as KeySiv, Nonce as NonceSiv};

use crate::cryptography::encryption::keys::{
    DETERMINISTIC_ENCRYPTION_KEY_SIZE, NON_DETERMINISTIC_ENCRYPTION_KEY_SIZE,
};
use crate::cryptography::encryption::{EncryptionError, FIXED_NONCE};

/// Decrypts ciphertext deterministically using a symmetric key and a fixed nonce.
///
/// This method uses the AES-256-SIV algorithm (AES-CMAC-SIV in AEAD mode) to decrypt the provided `cipher_text` with the given `key`.
/// The nonce used for decryption is fixed, ensuring deterministic behavior (the same ciphertext and key
/// will always produce the same plaintext).
///
/// # Arguments
///
/// * `key` - A reference to a byte vector representing the symmetric encryption key.
///           The key must be exactly `DETERMINISTIC_ENCRYPTION_KEY_SIZE` bytes long.
/// * `cipher_text` - A reference to a byte vector containing the encrypted data to decrypt.
///
/// # Returns
///
/// * `Result<Vec<u8>, EncryptionError>` - The decrypted plaintext as a byte vector if successful,
///                                        or an error if decryption fails.
///
/// # Errors
///
/// * `EncryptionError::WrongKeySize` - If the provided key is not the correct size for AES-256-SIV.
/// * `EncryptionError::DecryptionFailed` - If the decryption process fails (e.g., due to incorrect key or corrupted ciphertext).
///
/// # Example
///
/// ```rust
/// use lib_duckcount::cryptography::encryption::{
///     encrypt::encrypt_deterministically_using_symmetric_key,
///     decrypt::decrypt_deterministically_using_symmetric_key,
///     keys::generate_symmetric_deterministic_encryption_key,
/// };
///
/// let key = generate_symmetric_deterministic_encryption_key();
///
/// let plaintext = b"hello world".to_vec();
/// let cipher_text = encrypt_deterministically_using_symmetric_key(&key, &plaintext).unwrap();
///
/// let decrypted = decrypt_deterministically_using_symmetric_key(&key, &cipher_text).unwrap();
///
/// println!("Decrypted text: {:?}", decrypted);
/// ```
#[uniffi::export]
pub fn decrypt_deterministically_using_symmetric_key(
    key: &Vec<u8>,
    cipher_text: &Vec<u8>,
) -> Result<Vec<u8>, EncryptionError> {
    let key: [u8; DETERMINISTIC_ENCRYPTION_KEY_SIZE] = key
        .to_owned()
        .try_into()
        .map_err(|_| EncryptionError::WrongKeySize)?;

    let key = KeySiv::<Aes256SivAead>::from_slice(&key);
    let cipher = Aes256SivAead::new(&key);

    let fixed_nonce = NonceSiv::from_slice(&FIXED_NONCE);

    let plain_text = cipher
        .decrypt(fixed_nonce, cipher_text.as_ref())
        .map_err(|_| EncryptionError::DecryptionFailed)?;

    Ok(plain_text)
}

/// Decrypts ciphertext using a symmetric key and a nonce.
///
/// This method uses the AES-256-GCM algorithm to decrypt the provided `cipher_text` with the given `key` and `nonce`.
/// The nonce must match the one used during encryption to ensure successful decryption.
///
/// # Arguments
///
/// * `key` - A reference to a byte vector representing the symmetric encryption key.
///           The key must be exactly `NON_DETERMINISTIC_ENCRYPTION_KEY_SIZE` bytes long.
/// * `cipher_text` - A reference to a byte vector containing the encrypted data to decrypt.
/// * `nonce` - A reference to a byte vector representing the nonce used during encryption.
///
/// # Returns
///
/// * `Result<Vec<u8>, EncryptionError>` - The decrypted plaintext as a byte vector if successful,
///                                        or an error if decryption fails.
///
/// # Errors
///
/// * `EncryptionError::WrongKeySize` - If the provided key is not the correct size for AES-256-GCM.
/// * `EncryptionError::DecryptionFailed` - If the decryption process fails (e.g., due to incorrect key, nonce, or corrupted ciphertext).
///
/// # Example
///
/// ```rust
/// use lib_duckcount::cryptography::encryption::{
///     encrypt::encrypt_using_symmetric_key,
///     decrypt::decrypt_using_symmetric_key,
///     keys::generate_symmetric_encryption_key,
/// };
///
/// let key = generate_symmetric_encryption_key();
///
/// let plaintext = b"hello world".to_vec();
/// let encrypted = encrypt_using_symmetric_key(&key, &plaintext).unwrap();
///
/// let decrypted =
///     decrypt_using_symmetric_key(&key, &encrypted.cipher_text, &encrypted.nonce).unwrap();
///
/// println!("Decrypted text: {:?}", decrypted);
/// ```
#[uniffi::export]
pub fn decrypt_using_symmetric_key(
    key: &Vec<u8>,
    cipher_text: &Vec<u8>,
    nonce: &Vec<u8>,
) -> Result<Vec<u8>, EncryptionError> {
    let key: [u8; NON_DETERMINISTIC_ENCRYPTION_KEY_SIZE] = key
        .to_owned()
        .try_into()
        .map_err(|_| EncryptionError::WrongKeySize)?;

    let key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(&key);

    let nonce = Nonce::from_slice(nonce);

    let plain_text = cipher
        .decrypt(nonce, cipher_text.as_ref())
        .map_err(|_| EncryptionError::DecryptionFailed)?;

    Ok(plain_text)
}
