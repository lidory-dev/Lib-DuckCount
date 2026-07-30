//! The MLS credential asserting a DuckCount user UUID.

use mls_rs::identity::{Credential, basic::BasicCredential};
use uuid::Uuid;

use crate::cryptography::mls::MlsError;

/// Builds the MLS credential asserting `user_uuid`.
///
/// # Arguments
///
/// * `user_uuid` - The user's UUID, in canonical hyphenated lowercase form.
///
/// # Returns
///
/// * `Result<Credential, MlsError>` - The credential to place in a signing identity.
///
/// # Errors
///
/// * `MlsError::InvalidCredential` - If `user_uuid` is not a canonical UUID.
pub fn credential_for(user_uuid: &str) -> Result<Credential, MlsError> {
    validate(user_uuid)?;

    Ok(BasicCredential::new(user_uuid.as_bytes().to_vec()).into_credential())
}

/// Extracts the user UUID a credential asserts.
///
/// # Arguments
///
/// * `credential` - The credential taken from a member's signing identity.
///
/// # Returns
///
/// * `Result<String, MlsError>` - The asserted user UUID.
///
/// # Errors
///
/// * `MlsError::InvalidCredential` - If the credential is not a basic credential,
///   or does not hold a canonical UUID.
pub fn user_uuid_from(credential: &Credential) -> Result<String, MlsError> {
    let Credential::Basic(basic_credential) = credential else {
        return Err(MlsError::InvalidCredential);
    };

    let user_uuid = std::str::from_utf8(basic_credential.identifier())
        .map_err(|_| MlsError::InvalidCredential)?;

    validate(user_uuid)?;

    Ok(user_uuid.to_string())
}

/// Rejects anything but a canonical hyphenated lowercase UUID.
///
/// MLS requires a member's identity to be unique within a group and stable for
/// its lifetime. `Uuid::parse_str` also accepts braced, URN and unhyphenated
/// spellings, so accepting whatever parses would let one user appear under
/// several distinct identities. Only the canonical spelling is allowed, and the
/// check is a byte comparison against it.
fn validate(user_uuid: &str) -> Result<(), MlsError> {
    let parsed = Uuid::parse_str(user_uuid).map_err(|_| MlsError::InvalidCredential)?;

    if parsed.to_string() != user_uuid {
        return Err(MlsError::InvalidCredential);
    }

    Ok(())
}
