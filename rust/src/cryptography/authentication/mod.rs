use std::fmt::Display;

use argon2::Argon2;
use opaque_ke::CipherSuite;

mod login;
mod registration;

struct DefaultCipherSuite;

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
        }
    }
}
