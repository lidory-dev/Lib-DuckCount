use std::fmt::Display;

use argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::{
    CipherSuite, ClientLoginFinishParameters,
    errors::InternalError,
    generic_array::{ArrayLength, GenericArray},
    ksf::Ksf,
};
use zeroize::Zeroizing;

use crate::cryptography::encryption::keys::NON_DETERMINISTIC_ENCRYPTION_KEY_SIZE;

pub(crate) mod login;
pub(crate) mod password_change;
pub(crate) mod reauth;
pub(crate) mod registration;

pub(crate) struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    // type KeyExchange = opaque_ke::TripleDhKem<
    //     opaque_ke::Ristretto255,
    //     sha3::Sha3_512, // TODO: Check if the use of SHA3 does not pose a security risk.
    //     opaque_ke::ml_kem::MlKem768,
    // >;

    type Ksf = PasswordStretching;
}

/// What both sides mix into the transcript of every login, re-authentications
/// included, so that one only completes between two ends that agree on this
/// protocol and its configuration: a new cipher suite moves it to `v2`, and an
/// end still on the old one cannot finish a login.
///
/// It never goes over the wire. DuckCount-API holds the same string, and a
/// difference between the two fails every login the way a wrong password does.
pub(crate) const LOGIN_CONTEXT: &[u8] = b"duckcount:opaque:v1";

/// The parameters of every login's finish step: [LOGIN_CONTEXT], the suite's
/// defaults otherwise.
pub(crate) fn login_finish_parameters()
-> ClientLoginFinishParameters<'static, 'static, 'static, DefaultCipherSuite> {
    ClientLoginFinishParameters {
        context: Some(LOGIN_CONTEXT),
        ..Default::default()
    }
}

/// What each guess at a password costs: 64 MiB and 3 passes of Argon2id, on one
/// lane.
///
/// Whoever holds both the password files and the server's OPRF seed can guess
/// offline, and a right guess opens the vault root key, so this cost is all that
/// slows them down. It is RFC 9106's memory-constrained option, except for the
/// lanes: `argon2` runs them one after the other, so more would cost the phone
/// the same time while an attacker's hardware runs them side by side.
///
/// A password file only opens under the cost it was written with, so changing
/// these locks out every account.
const PASSWORD_STRETCHING_PARAMS: Params = match Params::new(64 * 1024, 3, 1, None) {
    Ok(params) => params,
    Err(_) => panic!("Argon2 parameters out of range"),
};

/// OPAQUE's key stretching, at [PASSWORD_STRETCHING_PARAMS].
///
/// Only the client ever runs it, so the cost is set here alone: the API's suite
/// names a plain `Argon2` that only its test client runs. The cost belongs to
/// the suite's type rather than to a parameter passed at each call, so no flow
/// can end up on another one, and a plain `Argon2` here would run at the crate's
/// defaults, OWASP's minimum.
pub(crate) struct PasswordStretching(Argon2<'static>);

impl Default for PasswordStretching {
    fn default() -> Self {
        Self(Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            PASSWORD_STRETCHING_PARAMS,
        ))
    }
}

impl Ksf for PasswordStretching {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        self.0.hash(input)
    }
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
