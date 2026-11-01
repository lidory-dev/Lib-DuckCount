use std::sync::Mutex;

use opaque_ke::{
    ClientLogin, ClientRegistration, ClientRegistrationFinishParameters, CredentialResponse,
    RegistrationResponse,
};
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};

use crate::cryptography::{
    authentication::{
        AuthenticationError, DefaultCipherSuite, login_finish_parameters, root_key_wrapping_key,
    },
    encryption::{encrypt::encrypt_using_symmetric_key, encrypted_field::EncryptedField},
};

/// Represents a client-side OPAQUE password change session.
///
/// A password change is two OPAQUE handshakes run side by side, started by
/// `POST /users/{user_uuid}/password` and finished by `PUT` on the same route: a
/// login with the current password, which proves to the server that the user
/// still knows it, and a registration of the new password under the same
/// credential identifier, from which the server builds the new password file.
/// Holds the intermediate state of both between the `start` and `finish` steps.
/// The states are guarded by [`Mutex`]es so the object can be shared safely
/// across threads via the UniFFI bindings.
///
/// The user stays who they are. Where
/// [Registration](super::registration::Registration) generates a root key,
/// [`finish`](Self::finish) is handed the one the user already has and seals
/// that same key under the new password. The root key seals the key ring, which
/// seals everything else, so its seal is the only thing a password reaches:
/// besides the password file, it is the only thing a change replaces.
#[derive(uniffi::Object)]
pub(crate) struct PasswordChange {
    /// Serialized `ClientLogin` state for the current password, produced by
    /// `start` and consumed by `finish`. Empty until `start` has been called
    /// successfully.
    ///
    /// Locked before `registration_state` whenever both are, so that two calls
    /// on the same object never each hold one while waiting for the other.
    login_state: Mutex<Zeroizing<Vec<u8>>>,
    /// Serialized `ClientRegistration` state for the new password. Filled and
    /// emptied together with `login_state`, so the two are either both empty or
    /// both filled.
    registration_state: Mutex<Zeroizing<Vec<u8>>>,
}

/// The client's half of the first round of both handshakes.
#[derive(uniffi::Record)]
pub struct PasswordChangeStartResult {
    /// Serialized `CredentialRequest` message, for the current password, to send
    /// to the server.
    pub credential_request: Vec<u8>,
    /// Serialized `RegistrationRequest` message, for the new password, to send
    /// to the server.
    pub registration_request: Vec<u8>,
}

/// What the client sends to finish both handshakes, in one request.
#[derive(uniffi::Object)]
pub struct PasswordChangeFinishResult {
    /// Serialized `CredentialFinalization` message to send to the server, which
    /// proves the current password to it.
    pub credential_finalization: Vec<u8>,
    /// Serialized `RegistrationUpload` message to send to the server, from
    /// which it builds the new password file.
    pub registration_upload: Vec<u8>,
    /// The root key handed to [`PasswordChange::finish`], sealed under the new
    /// password; to be sent with the two messages, the server writing it in the
    /// same transaction as the new password file. Once that file is in,
    /// the seal it replaces opens no more, even if the password did not change:
    /// the export key is derived from the file's envelope, which a registration
    /// builds anew every time.
    pub encrypted_root_key: EncryptedField,
}

/// PasswordChangeFinishResult getters.
#[uniffi::export]
impl PasswordChangeFinishResult {
    fn credential_finalization(&self) -> Vec<u8> {
        self.credential_finalization.clone()
    }

    fn registration_upload(&self) -> Vec<u8> {
        self.registration_upload.clone()
    }

    fn encrypted_root_key(&self) -> EncryptedField {
        self.encrypted_root_key.clone()
    }
}

#[uniffi::export]
impl PasswordChange {
    /// Creates a new [`PasswordChange`] with an empty internal state.
    ///
    /// The returned instance must have [`start`](Self::start) called on it
    /// before [`finish`](Self::finish) can succeed.
    ///
    /// # Returns
    ///
    /// A fresh `PasswordChange` ready to begin both OPAQUE flows.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            login_state: Mutex::new(Zeroizing::new(Vec::new())),
            registration_state: Mutex::new(Zeroizing::new(Vec::new())),
        }
    }

    /// Generates the request bytes of both handshakes: a credential request for
    /// the current password and a registration request for the new one.
    ///
    /// Both states are kept only once both handshakes have started, so a
    /// failure leaves this object as it was.
    ///
    /// # Arguments
    ///
    /// * `current_password` - A string slice that holds the user's current password.
    /// * `new_password` - A string slice that holds the password replacing it.
    ///
    /// # Returns
    ///
    /// A `Result` containing a [`PasswordChangeStartResult`] if successful, or
    /// an [AuthenticationError] otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError::StartingLoginFailed`] or
    /// [`AuthenticationError::StartingRegistrationFailed`] if either handshake
    /// cannot be started.
    pub(crate) fn start(
        &self,
        current_password: &str,
        new_password: &str,
    ) -> Result<PasswordChangeStartResult, AuthenticationError> {
        let mut login_state = self
            .login_state
            .lock()
            .map_err(|_| AuthenticationError::MutexAcquisitionFailed)?;

        let mut registration_state = self
            .registration_state
            .lock()
            .map_err(|_| AuthenticationError::MutexAcquisitionFailed)?;

        let mut rng = OsRng;

        let client_login =
            ClientLogin::<DefaultCipherSuite>::start(&mut rng, current_password.as_bytes())
                .map_err(|_| AuthenticationError::StartingLoginFailed)?;

        let client_registration =
            ClientRegistration::<DefaultCipherSuite>::start(&mut rng, new_password.as_bytes())
                .map_err(|_| AuthenticationError::StartingRegistrationFailed)?;

        let mut serialized = client_login.state.serialize();
        *login_state = Zeroizing::new(serialized.to_vec());
        serialized.zeroize();

        let mut serialized = client_registration.state.serialize();
        *registration_state = Zeroizing::new(serialized.to_vec());
        serialized.zeroize();

        Ok(PasswordChangeStartResult {
            credential_request: client_login.message.serialize().to_vec(),
            registration_request: client_registration.message.serialize().to_vec(),
        })
    }

    /// Completes both handshakes, producing the two messages to send to the
    /// server and `root_key` sealed under the new password.
    ///
    /// The login is finished first, and it is what checks the current password:
    /// OPAQUE opens the envelope of the current password file with it, on this
    /// device. A wrong one therefore fails here, before the registration upload,
    /// the message that would replace the password file, is even built, and
    /// nothing is left to send. What protects the account is the server's own
    /// check of the credential finalization, which nobody can produce without
    /// the current password; this one is what lets the caller tell a wrong
    /// password from any other failure before anything is sent.
    ///
    /// Both states are consumed as soon as they are read back, whatever comes
    /// after, so a session finishes at most once, and a retry starts over from
    /// [`start`](Self::start), with a new `POST /users/{user_uuid}/password`:
    /// the server's state for an attempt is single-use as well.
    ///
    /// # Arguments
    ///
    /// * `credential_response_bytes` - The serialized credential response, the server's half of the login.
    /// * `registration_response_bytes` - The serialized registration response, the server's half of the registration.
    /// * `current_password` - A string slice that holds the password given to [`start`](Self::start) as the current one.
    /// * `new_password` - A string slice that holds the password given to [`start`](Self::start) as the new one.
    /// * `root_key` - The vault root key the user already has, as registration generated it and every login since unsealed it.
    ///   Taken by value so that this crate's copy of it is wiped once sealed.
    ///
    /// # Returns
    ///
    /// A `Result` containing a [`PasswordChangeFinishResult`] if successful, or
    /// an [`AuthenticationError`] otherwise. On success the result holds the
    /// serialized `CredentialFinalization` and `RegistrationUpload` messages and
    /// `root_key` sealed under the first
    /// [NON_DETERMINISTIC_ENCRYPTION_KEY_SIZE](crate::cryptography::encryption::keys::NON_DETERMINISTIC_ENCRYPTION_KEY_SIZE)
    /// bytes of the new password's export key, which a later
    /// [Login::unseal_root_key](super::login::Login::unseal_root_key) with the
    /// new password opens.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError::FinishCalledBeforeStart`] if
    /// [`start`](Self::start) has not been called, or a deserialization error if
    /// the stored states or either response is invalid. A failure of the login's
    /// finish step, which includes a wrong current password, yields
    /// [`AuthenticationError::ClientLoginFinalizationFailed`], as it does for a
    /// [Login](super::login::Login).
    pub(crate) fn finish(
        &self,
        credential_response_bytes: Vec<u8>,
        registration_response_bytes: Vec<u8>,
        current_password: &str,
        new_password: &str,
        root_key: Vec<u8>,
    ) -> Result<PasswordChangeFinishResult, AuthenticationError> {
        let root_key = Zeroizing::new(root_key);

        let mut login_state = self
            .login_state
            .lock()
            .map_err(|_| AuthenticationError::MutexAcquisitionFailed)?;

        let mut registration_state = self
            .registration_state
            .lock()
            .map_err(|_| AuthenticationError::MutexAcquisitionFailed)?;

        // The two states are filled and emptied together, one tells for both.
        if login_state.is_empty() {
            return Err(AuthenticationError::FinishCalledBeforeStart);
        }

        let client_login = ClientLogin::<DefaultCipherSuite>::deserialize(&login_state)
            .map_err(|_| AuthenticationError::ClientLoginStateDeserializationFailed)?;

        let client_registration =
            ClientRegistration::<DefaultCipherSuite>::deserialize(&registration_state)
                .map_err(|_| AuthenticationError::ClientRegistrationStateDeserializationFailed)?;

        login_state.zeroize();
        registration_state.zeroize();

        let mut rng = OsRng;

        let mut client_login_finish = client_login
            .finish(
                &mut rng,
                current_password.as_bytes(),
                CredentialResponse::deserialize(&credential_response_bytes)
                    .map_err(|_| AuthenticationError::CredentialResponseDeserializationFailed)?,
                login_finish_parameters(),
            )
            .map_err(|error| {
                AuthenticationError::ClientLoginFinalizationFailed(error.to_string())
            })?;

        // Neither is of any use here: the current password's export key opens
        // only the seal this change replaces, and nothing runs on the session key.
        client_login_finish.export_key.zeroize();
        client_login_finish.session_key.zeroize();

        let mut client_registration_finish = client_registration
            .finish(
                &mut rng,
                new_password.as_bytes(),
                RegistrationResponse::deserialize(&registration_response_bytes)
                    .map_err(|_| AuthenticationError::RegistrationResponseDeserializationFailed)?,
                ClientRegistrationFinishParameters::default(),
            )
            .map_err(|_| AuthenticationError::ClientRegistrationFinalizationFailed)?;

        let wrapping_key = root_key_wrapping_key(&client_registration_finish.export_key)
            .ok_or(AuthenticationError::RootKeyEncryptionFailed)?;

        client_registration_finish.export_key.zeroize();

        let encrypted_root_key = encrypt_using_symmetric_key(&wrapping_key, &root_key)
            .map_err(|_| AuthenticationError::RootKeyEncryptionFailed)?;

        Ok(PasswordChangeFinishResult {
            credential_finalization: client_login_finish.message.serialize().to_vec(),
            registration_upload: client_registration_finish.message.serialize().to_vec(),
            encrypted_root_key,
        })
    }
}
