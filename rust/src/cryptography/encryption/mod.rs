pub mod database_encryption_key;
pub mod decrypt;
pub mod encrypt;
pub mod encrypted_field;
pub mod keys;

use std::fmt::Display;

/// Fixed nonce for use in deterministic encryption.
const FIXED_NONCE: [u8; 16] = *b"0000000000000000";

/// Encryption related errors.
#[derive(Debug, uniffi::Error)]
pub enum EncryptionError {
    WrongKeySize,
    EncryptionFailed,
    DecryptionFailed,
}

impl Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionError::WrongKeySize => write!(f, "Wrong key size."),
            EncryptionError::EncryptionFailed => write!(f, "Encryption failed."),
            EncryptionError::DecryptionFailed => write!(f, "Decryption failed."),
        }
    }
}

/// Key related errors.
#[derive(Debug, uniffi::Error)]
pub enum KeyError {
    WrongSize,
    DerivationFailed,
}

impl Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::WrongSize => write!(f, "Wrong key size."),
            KeyError::DerivationFailed => write!(f, "Key derivation failed."),
        }
    }
}
