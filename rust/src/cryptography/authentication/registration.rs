use std::sync::Mutex;

use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters, RegistrationResponse};
use rand::rngs::OsRng;

use crate::cryptography::authentication::{AuthenticationError, DefaultCipherSuite};

/// Represents a client-side OPAQUE registration session.
///
/// Holds the intermediate registration state between the `start` and `finish`
/// steps of the OPAQUE password-authenticated key exchange protocol. The state
/// is guarded by a [`Mutex`] so the object can be shared safely across threads
/// via the UniFFI bindings.
#[derive(uniffi::Object)]
struct Registration {
    /// Serialized `ClientRegistration` state produced by `start` and consumed
    /// by `finish`. Empty until `start` has been called successfully.
    state: Mutex<Vec<u8>>,
}

#[derive(uniffi::Record)]
pub struct RegistrationFinishResult {
    /// Serialized RegistrationUpload message to send to the server.
    pub message: Vec<u8>,
    /// Export key derived from the password. Stable across registration
    /// and login, so it can be used to derive client-side encryption keys.
    pub export_key: Vec<u8>,
}

#[uniffi::export]
impl Registration {
    /// Creates a new [`Registration`] with an empty internal state.
    ///
    /// The returned instance must have [`start`](Self::start) called on it
    /// before [`finish`](Self::finish) can succeed.
    ///
    /// # Returns
    ///
    /// A fresh `Registration` ready to begin the OPAQUE registration flow.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(Vec::new()),
        }
    }

    /// Generates the registration request bytes using the provided password.
    ///
    /// # Arguments
    ///
    /// * `password` - A string slice that holds the password for registration.
    ///
    /// # Returns
    ///
    /// A `Result` containing `Vec<u8>` if successful, or an [AuthenticationError] otherwise.
    fn start(&self, password: &str) -> Result<Vec<u8>, AuthenticationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthenticationError::MutexAcquisitionFailed)?;

        let mut rng = OsRng;

        let client_registration =
            ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password.as_bytes())
                .map_err(|_| AuthenticationError::StartingRegistrationFailed)?;

        state.clear();
        state.append(&mut client_registration.state.serialize().to_vec());

        Ok(client_registration.message.serialize().to_vec())
    }

    /// Completes the registration process, producing the message to send to
    /// the server and the export key derived from the password.
    ///
    /// # Arguments
    ///
    /// * `registration_response_bytes` - A reference to a byte vector representing the serialized registration response.
    /// * `password` - A string slice that holds the password for registration.
    ///
    /// # Returns
    ///
    /// A `Result` containing a [`RegistrationFinishResult`] if successful, or an
    /// [`AuthenticationError`] otherwise. On success the result holds the
    /// serialized `RegistrationUpload` message to send to the server and the
    /// export key derived from the password. The export key is reproducible at
    /// login time and never leaves the client, so it is suitable for deriving
    /// client-side encryption keys.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError::FinishCalledBeforeStart`] if [`start`](Self::start)
    /// has not been called, or a deserialization/finalization error if the
    /// stored state, the registration response, or the finish step is invalid.
    fn finish(
        &self,
        registration_response_bytes: &Vec<u8>,
        password: &str,
    ) -> Result<RegistrationFinishResult, AuthenticationError> {
        let state = self
            .state
            .lock()
            .map_err(|_| AuthenticationError::MutexAcquisitionFailed)?;

        if state.is_empty() {
            return Err(AuthenticationError::FinishCalledBeforeStart);
        }

        let mut rng = OsRng;

        let client_registration = ClientRegistration::<DefaultCipherSuite>::deserialize(&state)
            .map_err(|_| AuthenticationError::ClientRegistrationStateDeserializationFailed)?;

        match client_registration.finish(
            &mut rng,
            password.as_bytes(),
            RegistrationResponse::deserialize(registration_response_bytes)
                .map_err(|_| AuthenticationError::RegistrationResponseDeserializationFailed)?,
            ClientRegistrationFinishParameters::default(),
        ) {
            Ok(result) => Ok(RegistrationFinishResult {
                message: result.message.serialize().to_vec(),
                export_key: result.export_key.to_vec(),
            }),
            Err(_) => Err(AuthenticationError::ClientRegistrationFinalizationFailed),
        }
    }
}
