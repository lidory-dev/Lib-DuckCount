use std::sync::Mutex;

use opaque_ke::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};

use crate::cryptography::{
    authentication::{AuthenticationError, DefaultCipherSuite},
    encryption::decrypt::decrypt_using_symmetric_key,
    vault::encrypted_field::EncryptedField,
};

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
    state: Mutex<Zeroizing<Vec<u8>>>,
    /// Export key derived from the password by `finish` and consumed by
    /// `unseal_root_key`. Empty until `finish` has been called successfully,
    /// and zeroized again once the root key has been unsealed.
    export_key: Mutex<Zeroizing<Vec<u8>>>,
}

#[derive(uniffi::Record)]
pub struct LoginFinishResult {
    /// Serialized `CredentialFinalization` message to send to the server.
    pub message: Vec<u8>,
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
            state: Mutex::new(Zeroizing::new(Vec::new())),
            export_key: Mutex::new(Zeroizing::new(Vec::new())),
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

        let mut serialized = client_login.state.serialize();
        *state = Zeroizing::new(serialized.to_vec());
        serialized.zeroize();

        Ok(client_login.message.serialize().to_vec())
    }

    /// Completes the login process, producing the final message to send to the
    /// server and the export key derived from the password.
    ///
    /// # Arguments
    ///
    /// * `credential_response_bytes` - A reference to a byte vector representing the serialized credential response.
    /// * `password` - A string slice that holds the password for login.
    ///
    /// # Returns
    ///
    /// A `Result` containing a [`LoginFinishResult`] if successful, or an
    /// [`AuthenticationError`] otherwise. On success the result holds the
    /// serialized `CredentialFinalization` message to send to the server and
    /// the export key derived from the password. The export key matches the one
    /// returned by registration for the same password and never leaves the
    /// client, so it is suitable for deriving client-side encryption keys.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError::FinishCalledBeforeStart`] if
    /// [`start`](Self::start) has not been called, or a deserialization error if
    /// the stored state or the credential response is invalid. A failure of the
    /// finish step itself (which includes an incorrect password) yields
    /// [`AuthenticationError::ClientLoginFinalizationFailed`].
    fn finish(
        &self,
        credential_response_bytes: &Vec<u8>,
        password: &str,
    ) -> Result<LoginFinishResult, AuthenticationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthenticationError::MutexAcquisitionFailed)?;

        if state.is_empty() {
            return Err(AuthenticationError::FinishCalledBeforeStart);
        }

        let client_login = ClientLogin::<DefaultCipherSuite>::deserialize(&state)
            .map_err(|_| AuthenticationError::ClientLoginStateDeserializationFailed)?;

        state.zeroize();

        let client_login_finish = client_login
            .finish(
                password.as_bytes(),
                CredentialResponse::deserialize(credential_response_bytes)
                    .map_err(|_| AuthenticationError::CredentialResponseDeserializationFailed)?,
                ClientLoginFinishParameters::default(),
            )
            .map_err(|error| {
                AuthenticationError::ClientLoginFinalizationFailed(error.to_string())
            })?;

        let message = client_login_finish.message.serialize().to_vec();

        let mut export_key = self
            .export_key
            .lock()
            .map_err(|_| AuthenticationError::MutexAcquisitionFailed)?;

        *export_key = Zeroizing::new(client_login_finish.export_key.to_vec());

        Ok(LoginFinishResult { message })
    }

    /// Decrypts the root key that was sealed with the export key derived from
    /// the user's password.
    ///
    /// Uses the export key stored by [`finish`](Self::finish) as the symmetric
    /// key. The export key is zeroized once the root key has been recovered, so
    /// this method succeeds at most once per login session.
    ///
    /// # Arguments
    ///
    /// * `encrypted_root_key` - A reference to the [`EncryptedField`] holding the ciphertext and nonce of the sealed root key.
    ///
    /// # Returns
    ///
    /// A `Result` containing a vector of bytes representing the plaintext root
    /// key if successful, or an [`AuthenticationError`] otherwise. The root key
    /// never leaves the client and is suitable for decrypting the vault's key ring.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError::MutexAcquisitionFailed`] if the export key
    /// mutex is poisoned, or [`AuthenticationError::RootKeyDecryptionFailed`] if
    /// decryption fails. The latter also covers the case where
    /// [`finish`](Self::finish) has not been called and no export key is
    /// available.
    fn unseal_root_key(
        &self,
        encrypted_root_key: &EncryptedField,
    ) -> Result<Vec<u8>, AuthenticationError> {
        let mut export_key = self
            .export_key
            .lock()
            .map_err(|_| AuthenticationError::MutexAcquisitionFailed)?;

        let root_key = decrypt_using_symmetric_key(
            &export_key,
            &encrypted_root_key.field,
            &encrypted_root_key.nonce,
        )
        .map_err(|_| AuthenticationError::RootKeyDecryptionFailed)?;

        export_key.zeroize();

        Ok(root_key)
    }
}
