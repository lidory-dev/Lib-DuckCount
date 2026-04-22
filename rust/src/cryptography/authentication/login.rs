use std::sync::Mutex;

use opaque_ke::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};
use rand::rngs::OsRng;

use crate::cryptography::authentication::{AuthenticationError, DefaultCipherSuite};

/// Represents a client-side OPAQUE login session.
///
/// Holds the intermediate login state between the `start` and `finish`
/// steps of the OPAQUE password-authenticated key exchange protocol. The state
/// is guarded by a [`Mutex`] so the object can be shared safely across threads
/// via the UniFFI bindings.
#[derive(uniffi::Object)]
struct Login {
    /// Serialized `ClientLogin` state produced by `start` and consumed by
    /// `finish`. Empty until `start` has been called successfully.
    state: Mutex<Vec<u8>>,
}

#[uniffi::export]
impl Login {
    /// Creates a new [`Login`] with an empty internal state.
    ///
    /// The returned instance must have [`start`](Self::start) called on it
    /// before [`finish`](Self::finish) can succeed.
    ///
    /// # Returns
    ///
    /// A fresh `Login` ready to begin the OPAQUE login flow.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(Vec::new()),
        }
    }

    /// Generates the credential request bytes using the provided password.
    ///
    /// # Arguments
    ///
    /// * `password` - A string slice that holds the password for login.
    ///
    /// # Returns
    ///
    /// A `Result` containing containing a vector of bytes representing the serialized message if successful,
    /// or an [AuthenticationError] otherwise.
    fn start(&self, password: &str) -> Result<Vec<u8>, AuthenticationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthenticationError::MutexAcquisitionFailed)?;

        let mut rng = OsRng;

        let client_login = ClientLogin::<DefaultCipherSuite>::start(&mut rng, password.as_bytes())
            .map_err(|_| AuthenticationError::StartingLoginFailed)?;

        state.clear();
        state.append(&mut client_login.state.serialize().to_vec());

        Ok(client_login.message.serialize().to_vec())
    }

    /// Generates the final message bytes for completing the credential login process.
    ///
    /// # Arguments
    ///
    /// * `credential_response_bytes` - A reference to a byte vector representing the serialized credential response.
    /// * `password` - A string slice that holds the password for login.
    ///
    /// # Returns
    ///
    /// A `Result` containing a vector of bytes representing the serialized final message if successful,
    /// or an [AuthenticationError] otherwise.
    fn finish(
        &self,
        credential_response_bytes: &Vec<u8>,
        password: &str,
    ) -> Result<Vec<u8>, AuthenticationError> {
        let state = self
            .state
            .lock()
            .map_err(|_| AuthenticationError::MutexAcquisitionFailed)?;

        let mut rng = OsRng;

        if state.is_empty() {
            return Err(AuthenticationError::FinishCalledBeforeStart);
        }

        let client_login = ClientLogin::<DefaultCipherSuite>::deserialize(&state)
            .map_err(|_| AuthenticationError::ClientLoginStateDeserializationFailed)?;

        let client_login_finish = client_login
            .finish(
                &mut rng,
                password.as_bytes(),
                CredentialResponse::deserialize(credential_response_bytes).unwrap(),
                ClientLoginFinishParameters::default(),
            )
            .map_err(|error| {
                AuthenticationError::ClientLoginFinalizationFailed(error.to_string())
            })?;

        Ok(client_login_finish.message.serialize().to_vec())
    }
}
