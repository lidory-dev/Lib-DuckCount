//! Turning fetched key packages into per-member Welcome messages.
//!
//! Both group creation and later additions follow the same shape: the host
//! fetches one key package per invitee from the server, this module checks each
//! one really belongs to the user it was fetched for, and the Welcomes the
//! commit produces are matched back to those users so the DuckCount API can
//! address each one individually. Once the commit is built, each invitee's
//! signature key is pinned to them.

use mls_rs::MlsMessage;

use crate::cryptography::mls::{
    CIPHER_SUITE, MlsError, config::cipher_suite_provider, identity::credential::user_uuid_from,
    storage::identity_pin::IdentityPinStore, types::InviteeKeyPackage,
};

/// One validated invitee: the user, the key package they will join with, and
/// the signature key it carries.
pub struct Invitee {
    pub user_uuid: String,
    pub key_package: MlsMessage,
    pub signature_key: Vec<u8>,
}

/// Parses and checks the key packages the host fetched for a set of invitees.
///
/// Each key package must be a key package (not some other MLS message), must
/// use the configured cipher suite, and must carry a credential asserting the
/// very user it was fetched for. The last check is what stops a server from
/// answering "give me Bob's key package" with somebody else's: without it the
/// wrong person would silently end up in the group.
///
/// # Arguments
///
/// * `invitees` - The user UUID and key package bytes of each invitee.
///
/// # Returns
///
/// * `Result<Vec<Invitee>, MlsError>` - The validated invitees, in the order given.
///
/// # Errors
///
/// * `MlsError::InvalidKeyPackage` - If a key package cannot be parsed, is not a
///   key package, or uses a different cipher suite.
/// * `MlsError::InvalidCredential` - If a key package asserts a different user
///   than the one it was fetched for.
pub fn validate_invitees(invitees: Vec<InviteeKeyPackage>) -> Result<Vec<Invitee>, MlsError> {
    invitees
        .into_iter()
        .map(|invitee| {
            let message = MlsMessage::from_bytes(&invitee.key_package)
                .map_err(|_| MlsError::InvalidKeyPackage)?;

            let key_package = message
                .as_key_package()
                .ok_or(MlsError::InvalidKeyPackage)?;

            if key_package.cipher_suite() != CIPHER_SUITE {
                return Err(MlsError::InvalidKeyPackage);
            }

            let asserted_user_uuid = user_uuid_from(&key_package.signing_identity().credential)?;

            if asserted_user_uuid != invitee.user_uuid {
                return Err(MlsError::InvalidCredential);
            }

            let signature_key = key_package.signing_identity().signature_key.to_vec();

            Ok(Invitee {
                user_uuid: invitee.user_uuid,
                key_package: message,
                signature_key,
            })
        })
        .collect()
}

/// Pins each invitee's signature key to their user UUID.
///
/// Call this once the commit adding them has been built: mls-rs checks each
/// key package's signature while building it, and pinning any earlier would
/// remember a key nobody has proved they hold.
///
/// # Errors
///
/// * `MlsError::IdentityKeyMismatch` - If a different key is already pinned for
///   an invitee.
/// * `MlsError::StorageFailed` - If the host storage fails.
/// * `MlsError::StorageIntegrityFailed` - If a stored pin fails authentication.
pub fn pin_invitees(pins: &IdentityPinStore, invitees: &[Invitee]) -> Result<(), MlsError> {
    invitees
        .iter()
        .try_for_each(|invitee| pins.verify_or_pin(&invitee.user_uuid, &invitee.signature_key))
}

/// Matches each Welcome message produced by a commit back to the invitee it was
/// produced for.
///
/// mls-rs is configured to emit one Welcome per added member rather than a
/// single fan-out message, because the DuckCount API addresses each invitee
/// separately. The link between the two is the key package reference: a Welcome
/// names the key packages it carries secrets for, and each invitee's key package
/// hashes to exactly one of them.
///
/// # Arguments
///
/// * `welcomes` - The Welcome messages from a commit's output.
/// * `invitees` - The validated invitees the commit added.
///
/// # Returns
///
/// * `Result<Vec<WelcomeForMember>, MlsError>` - One Welcome per invitee.
///
/// # Errors
///
/// * `MlsError::UnmatchedWelcome` - If any invitee has no Welcome. Sending an
///   incomplete set would leave that member unable to join a group they are
///   already listed in, so this fails rather than returning a partial result.
/// * `MlsError::ProtocolFailed` - If a key package reference cannot be computed
///   or a Welcome cannot be serialised.
pub fn match_welcomes(
    welcomes: &[MlsMessage],
    invitees: &[Invitee],
) -> Result<Vec<super::types::WelcomeForMember>, MlsError> {
    let cipher_suite_provider = cipher_suite_provider()?;

    invitees
        .iter()
        .map(|invitee| {
            let reference = invitee
                .key_package
                .key_package_reference(&cipher_suite_provider)?
                .ok_or(MlsError::InvalidKeyPackage)?;

            let welcome = welcomes
                .iter()
                .find(|welcome| {
                    welcome
                        .welcome_key_package_references()
                        .into_iter()
                        .any(|welcome_reference| *welcome_reference == reference)
                })
                .ok_or_else(|| MlsError::UnmatchedWelcome(invitee.user_uuid.clone()))?;

            Ok(super::types::WelcomeForMember {
                user_uuid: invitee.user_uuid.clone(),
                welcome: welcome.to_bytes()?,
            })
        })
        .collect()
}
