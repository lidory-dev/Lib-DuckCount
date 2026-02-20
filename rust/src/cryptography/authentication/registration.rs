use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters, RegistrationResponse};
use rand::rngs::OsRng;

use crate::cryptography::authentication::{AuthenticationError, DefaultCipherSuite};

/// Struct representing the bytes of a registration request.
/// Contains the serialized state and message bytes for client registration.
#[derive(uniffi::Record)]
struct RegistrationRequestBytes {
    /// Serialized state bytes for the client registration process.
    client_registration_state_bytes: Vec<u8>,
    /// Serialized message bytes for the client registration process.
    client_registration_message_bytes: Vec<u8>,
}

/// Generates a registration request bytes structure using the provided password.
///
/// # Arguments
/// * `password` - A string slice that holds the password for registration.
///
/// # Returns
/// A `Result` containing `RegistrationRequestBytes` if successful, or an [AuthenticationError] otherwise.
#[uniffi::export]
fn generate_registration_request_bytes(
    password: &str,
) -> Result<RegistrationRequestBytes, AuthenticationError> {
    let mut rng = OsRng;

    let client_registration =
        ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password.as_bytes())
            .map_err(|_| AuthenticationError::StartingRegistrationFailed)?;

    Ok(RegistrationRequestBytes {
        client_registration_state_bytes: client_registration.state.serialize().to_vec(),
        client_registration_message_bytes: client_registration.message.serialize().to_vec(),
    })
}

/// Generates message bytes for completing the registration process.
///
/// # Arguments
/// * `client_registration_state_bytes` - A reference to a byte vector representing the serialized client registration state.
/// * `registration_response_bytes` - A reference to a byte vector representing the serialized registration response.
/// * `password` - A string slice that holds the password for registration.
///
/// # Returns
/// A `Result` containing a vector of bytes representing the serialized message if successful, or an [AuthenticationError] otherwise.
#[uniffi::export]
fn generate_message_bytes(
    client_registration_state_bytes: &Vec<u8>,
    registration_response_bytes: &Vec<u8>,
    password: &str,
) -> Result<Vec<u8>, AuthenticationError> {
    let mut rng = OsRng;

    let client_registration =
        ClientRegistration::<DefaultCipherSuite>::deserialize(client_registration_state_bytes)
            .map_err(|_| AuthenticationError::ClientRegistrationStateDeserializationFailed)?;

    match client_registration.finish(
        &mut rng,
        password.as_bytes(),
        RegistrationResponse::deserialize(registration_response_bytes)
            .map_err(|_| AuthenticationError::RegistrationResponseDeserializationFailed)?,
        ClientRegistrationFinishParameters::default(),
    ) {
        Ok(result) => Ok(result.message.serialize().to_vec()),
        Err(_) => Err(AuthenticationError::ClientRegistrationFinalizationFailed),
    }
}
