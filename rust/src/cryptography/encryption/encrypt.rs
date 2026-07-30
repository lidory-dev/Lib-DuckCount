use aes_gcm::aead::Aead;

use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit};
use aes_siv::{Aes256SivAead, Key as KeySiv, Nonce as NonceSiv};
use rand::rngs::OsRng;

use crate::cryptography::encryption::encrypted_field::EncryptedField;
use crate::cryptography::encryption::keys::{
    DETERMINISTIC_ENCRYPTION_KEY_SIZE, NON_DETERMINISTIC_ENCRYPTION_KEY_SIZE,
};
use crate::cryptography::encryption::{EncryptionError, FIXED_NONCE};

/// Encrypts plaintext deterministically using a symmetric key and a fixed nonce.
///
/// This method uses the AES-256-SIV algorithm (AES-CMAC-SIV in AEAD mode) to encrypt the provided `plaintext_message` with the given `key`.
/// The nonce used for encryption is fixed, ensuring that the same plaintext and key will always produce the same ciphertext.
/// This is useful for scenarios where deterministic encryption is required.
///
/// # Arguments
///
/// * `key` - A reference to a byte vector representing the symmetric encryption key.
///           The key must be exactly `DETERMINISTIC_ENCRYPTION_KEY_SIZE` bytes long.
/// * `plaintext_message` - A reference to a byte vector containing the data to encrypt.
///
/// # Returns
///
/// * `Result<Vec<u8>, EncryptionError>` - The encrypted ciphertext as a byte vector if successful,
///                                        or an error if encryption fails.
///
/// # Errors
///
/// * `EncryptionError::WrongKeySize` - If the provided key is not the correct size for AES-256-SIV.
/// * `EncryptionError::EncryptionFailed` - If the encryption process fails.
///
/// # Example
///
/// ```rust
/// use lib_duckcount::cryptography::encryption::{
///     encrypt::encrypt_deterministically_using_symmetric_key,
///     keys::generate_symmetric_deterministic_encryption_key,
/// };
///
/// let key = generate_symmetric_deterministic_encryption_key();
///
/// let plaintext = b"hello world".to_vec();
/// let ciphertext = encrypt_deterministically_using_symmetric_key(&key, &plaintext).unwrap();
///
/// println!("Encrypted text: {:?}", ciphertext);
/// ```
#[uniffi::export]
pub fn encrypt_deterministically_using_symmetric_key(
    key: &Vec<u8>,
    plaintext_message: &Vec<u8>,
) -> Result<Vec<u8>, EncryptionError> {
    let key: [u8; DETERMINISTIC_ENCRYPTION_KEY_SIZE] = key
        .to_owned()
        .try_into()
        .map_err(|_| EncryptionError::WrongKeySize)?;

    let key = KeySiv::<Aes256SivAead>::from_slice(&key);
    let cipher = Aes256SivAead::new(&key);

    let fixed_nonce = NonceSiv::from_slice(&FIXED_NONCE);

    let ciphertext = cipher
        .encrypt(fixed_nonce, plaintext_message.as_ref())
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    Ok(ciphertext)
}

/// Encrypts plaintext using a symmetric key and a randomly generated nonce.
///
/// This method uses the AES-256-GCM algorithm to encrypt the provided `plaintext_message` with the given `key`.
/// A cryptographically secure, random nonce is generated for each encryption operation, ensuring that
/// the same plaintext and key will produce different ciphertexts each time.
///
/// # Arguments
///
/// * `key` - A reference to a byte vector representing the symmetric encryption key.
///           The key must be exactly `NON_DETERMINISTIC_ENCRYPTION_KEY_SIZE` bytes long.
/// * `plaintext_message` - A reference to a byte vector containing the data to encrypt.
///
/// # Returns
///
/// * `Result<EncryptedTextAndNonce, EncryptionError>` - A struct containing the encrypted ciphertext and the generated nonce as byte vectors if successful,
///                                                     or an error if encryption fails.
///
/// # Errors
///
/// * `EncryptionError::WrongKeySize` - If the provided key is not the correct size for AES-256-GCM.
/// * `EncryptionError::EncryptionFailed` - If the encryption process fails.
///
/// # Example
///
/// ```rust
/// use lib_duckcount::cryptography::encryption::{
///     encrypt::encrypt_using_symmetric_key,
///     keys::generate_symmetric_encryption_key,
/// };
///
/// let key = generate_symmetric_encryption_key();
///
/// let plaintext = b"hello world".to_vec();
/// let encrypted = encrypt_using_symmetric_key(&key, &plaintext).unwrap();
///
/// println!("Ciphertext: {:?}, Nonce: {:?}", encrypted.ciphertext, encrypted.nonce);
/// ```
#[uniffi::export]
pub fn encrypt_using_symmetric_key(
    key: &Vec<u8>,
    plaintext_message: &Vec<u8>,
) -> Result<EncryptedField, EncryptionError> {
    let key: [u8; NON_DETERMINISTIC_ENCRYPTION_KEY_SIZE] = key
        .to_owned()
        .try_into()
        .map_err(|_| EncryptionError::WrongKeySize)?;

    let mut rng = OsRng;

    let key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(&key);

    let nonce = Aes256Gcm::generate_nonce(&mut rng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext_message.as_ref())
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    Ok(EncryptedField {
        ciphertext,
        nonce: nonce.to_vec(),
    })
}
