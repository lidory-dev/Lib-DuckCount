use std::sync::Mutex;

use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters, RegistrationResponse};
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};

use crate::cryptography::{
    authentication::{AuthenticationError, DefaultCipherSuite, root_key_wrapping_key},
    encryption::{
        encrypt::{EncryptedTextAndNonce, encrypt_using_symmetric_key},
        keys::generate_symmetric_encryption_key,
    },
};

/// Represents a client-side OPAQUE registration session.
///
/// Holds the intermediate registration state between the `start` and `finish`
/// steps of the OPAQUE password-authenticated key exchange protocol. The state
/// is guarded by a [`Mutex`] so the object can be shared safely across threads
/// via the UniFFI bindings.
#[derive(uniffi::Object)]
pub(crate) struct Registration {
    /// Serialized `ClientRegistration` state produced by `start` and consumed
    /// by `finish`. Empty until `start` has been called successfully.
    state: Mutex<Zeroizing<Vec<u8>>>,
}

#[derive(uniffi::Record)]
pub struct RegistrationFinishResult {
    /// Serialized RegistrationUpload message to send to the server.
    pub message: Vec<u8>,
    /// The vault root key generated for this account, used to seal the vault
    /// key ring, before saving the vault on the server.
    pub root_key: Vec<u8>,
    /// The sealed root key; to be added to the user vault and sent to the server.
    pub encrypted_root_key: EncryptedTextAndNonce,
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
            state: Mutex::new(Zeroizing::new(Vec::new())),
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
    pub(crate) fn start(&self, password: &str) -> Result<Vec<u8>, AuthenticationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthenticationError::MutexAcquisitionFailed)?;

        let mut rng = OsRng;

        let client_registration =
            ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password.as_bytes())
                .map_err(|_| AuthenticationError::StartingRegistrationFailed)?;

        let mut serialized = client_registration.state.serialize();
        *state = Zeroizing::new(serialized.to_vec());
        serialized.zeroize();

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
    pub(crate) fn finish(
        &self,
        registration_response_bytes: &Vec<u8>,
        password: &str,
    ) -> Result<RegistrationFinishResult, AuthenticationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthenticationError::MutexAcquisitionFailed)?;

        if state.is_empty() {
            return Err(AuthenticationError::FinishCalledBeforeStart);
        }

        let mut rng = OsRng;

        let client_registration = ClientRegistration::<DefaultCipherSuite>::deserialize(&state)
            .map_err(|_| AuthenticationError::ClientRegistrationStateDeserializationFailed)?;

        state.zeroize();

        match client_registration.finish(
            &mut rng,
            password.as_bytes(),
            RegistrationResponse::deserialize(registration_response_bytes)
                .map_err(|_| AuthenticationError::RegistrationResponseDeserializationFailed)?,
            ClientRegistrationFinishParameters::default(),
        ) {
            Ok(result) => {
                let message = result.message.serialize().to_vec();

                let export_key = Zeroizing::new(result.export_key.to_vec());
                let wrapping_key = root_key_wrapping_key(&export_key)
                    .ok_or(AuthenticationError::RootKeyEncryptionFailed)?;

                let root_key = generate_symmetric_encryption_key();
                let encrypted_root_key = encrypt_using_symmetric_key(&wrapping_key, &root_key)
                    .map_err(|_| AuthenticationError::RootKeyEncryptionFailed)?;

                Ok(RegistrationFinishResult {
                    message,
                    root_key,
                    encrypted_root_key,
                })
            }
            Err(_) => Err(AuthenticationError::ClientRegistrationFinalizationFailed),
        }
    }
}
