use std::fmt::Display;

use argon2::Argon2;
use opaque_ke::CipherSuite;
use zeroize::Zeroizing;

use crate::cryptography::encryption::keys::NON_DETERMINISTIC_ENCRYPTION_KEY_SIZE;

pub(crate) mod login;
pub(crate) mod password_change;
pub(crate) mod reauth;
pub(crate) mod registration;

pub(crate) struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    // type KeyExchange = opaque_ke::TripleDhKem<
    //     opaque_ke::Ristretto255,
    //     sha3::Sha3_512, // TODO: Check if the use of SHA3 does not pose a security risk.
    //     opaque_ke::ml_kem::MlKem768,
    // >;

    type Ksf = Argon2<'static>;
}

/// The AEAD key that seals the vault root key: the first
/// [NON_DETERMINISTIC_ENCRYPTION_KEY_SIZE] bytes of the OPAQUE export key.
///
/// The export key is wider than AES-256-GCM takes. [DefaultCipherSuite] hashes
/// with SHA-512 (`OprfCs = Ristretto255`), so `export_key` is 64 bytes, while
/// [encrypt_using_symmetric_key](crate::cryptography::encryption::encrypt::encrypt_using_symmetric_key)
/// and its decrypt counterpart accept exactly 32 and reject anything else as
/// [EncryptionError::WrongKeySize](crate::cryptography::encryption::EncryptionError::WrongKeySize).
///
/// # Returns
///
/// `None` when `export_key` is shorter than a key, which is how a **spent**
/// export key presents itself: `Zeroize for Vec<u8>` clears the vector as well
/// as zeroing it, so an export key consumed by
/// [Login::unseal_root_key](login::Login::unseal_root_key) comes back empty
/// rather than short-but-nonzero. Callers turn that into their own error, which
/// is what keeps a second unseal a failure instead of a panic on an
/// out-of-range slice.
pub(crate) fn root_key_wrapping_key(export_key: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    export_key
        .get(..NON_DETERMINISTIC_ENCRYPTION_KEY_SIZE)
        .map(|key| Zeroizing::new(key.to_vec()))
}

#[derive(Debug, uniffi::Error)]
pub enum AuthenticationError {
    ClientRegistrationStateDeserializationFailed,
    RegistrationResponseDeserializationFailed,
    ClientRegistrationFinalizationFailed,
    StartingRegistrationFailed,
    StartingLoginFailed,
    ClientLoginStateDeserializationFailed,
    ClientLoginFinalizationFailed(String),
    MutexAcquisitionFailed,
    FinishCalledBeforeStart,
    CredentialResponseDeserializationFailed,
    RootKeyEncryptionFailed,
    RootKeyDecryptionFailed,
}

impl Display for AuthenticationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthenticationError::ClientRegistrationStateDeserializationFailed => {
                write!(f, "Could not deserialize client registration state.")
            }
            AuthenticationError::RegistrationResponseDeserializationFailed => {
                write!(f, "Could not deserialize registration response.")
            }
            AuthenticationError::ClientRegistrationFinalizationFailed => {
                write!(f, "Could not finish registration.")
            }
            AuthenticationError::StartingRegistrationFailed => {
                write!(f, "Could not start registration.")
            }
            AuthenticationError::StartingLoginFailed => write!(f, "Could not start login."),
            AuthenticationError::ClientLoginStateDeserializationFailed => {
                write!(f, "Could not deserialize client login state.")
            }
            AuthenticationError::ClientLoginFinalizationFailed(error) => {
                write!(f, "Could not finish login: {}", error)
            }
            AuthenticationError::MutexAcquisitionFailed => {
                write!(f, "Mutex acquisition failed.")
            }
            AuthenticationError::FinishCalledBeforeStart => {
                write!(
                    f,
                    "finish() was called before start(). No session state is available."
                )
            }
            AuthenticationError::CredentialResponseDeserializationFailed => {
                write!(f, "Could not deserialize credential response.")
            }
            AuthenticationError::RootKeyEncryptionFailed => {
                write!(f, "Could not encrypt the root key.")
            }
            AuthenticationError::RootKeyDecryptionFailed => {
                write!(f, "Could not decrypt the root key.")
            }
        }
    }
}
