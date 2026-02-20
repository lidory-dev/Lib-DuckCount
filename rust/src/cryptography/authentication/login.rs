use opaque_ke::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};
use rand::rngs::OsRng;

use crate::cryptography::authentication::{AuthenticationError, DefaultCipherSuite};

/// Struct representing the bytes of a credential request.
/// Contains the serialized state and message bytes for client login.
#[derive(uniffi::Record)]
struct CredentialRequestBytes {
    /// Serialized state bytes for the client login process.
    client_login_state_bytes: Vec<u8>,
    /// Serialized message bytes for the client login process.
    client_login_message_bytes: Vec<u8>,
}

/// Generates a credential request bytes structure using the provided password.
///
/// # Arguments
/// * `password` - A string slice that holds the password for login.
///
/// # Returns
/// A `Result` containing `CredentialRequestBytes` if successful, or an [AuthenticationError] otherwise.
#[uniffi::export]
fn generate_credential_request_bytes(
    password: &str,
) -> Result<CredentialRequestBytes, AuthenticationError> {
    let mut rng = OsRng;

    let client_login = ClientLogin::<DefaultCipherSuite>::start(&mut rng, password.as_bytes())
        .map_err(|_| AuthenticationError::StartingLoginFailed)?;

    Ok(CredentialRequestBytes {
        client_login_state_bytes: client_login.state.serialize().to_vec(),
        client_login_message_bytes: client_login.message.serialize().to_vec(),
    })
}

/// Generates the final message bytes for completing the credential login process.
///
/// # Arguments
/// * `client_login_state_bytes` - A reference to a byte vector representing the serialized client login state.
/// * `credential_response_bytes` - A reference to a byte vector representing the serialized credential response.
/// * `password` - A string slice that holds the password for login.
///
/// # Returns
/// A `Result` containing a vector of bytes representing the serialized final message if successful, or an [AuthenticationError] otherwise.
#[uniffi::export]
fn generate_credential_finalization_bytes(
    client_login_state_bytes: &Vec<u8>,
    credential_response_bytes: &Vec<u8>,
    password: &str,
) -> Result<Vec<u8>, AuthenticationError> {
    let mut rng = OsRng;

    let client_login_state =
        ClientLogin::<DefaultCipherSuite>::deserialize(client_login_state_bytes)
            .map_err(|_| AuthenticationError::ClientLoginStateDeserializationFailed)?;

    let client_login_finish = client_login_state
        .finish(
            &mut rng,
            password.as_bytes(),
            CredentialResponse::deserialize(credential_response_bytes).unwrap(),
            ClientLoginFinishParameters::default(),
        )
        .map_err(|error| AuthenticationError::ClientLoginFinalizationFailed(error.to_string()))?;

    Ok(client_login_finish.message.serialize().to_vec())
}
