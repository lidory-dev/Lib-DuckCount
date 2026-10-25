//! Turning fetched key packages into the one Welcome a commit adds them with.
//!
//! Both group creation and later additions follow the same shape: the host
//! fetches one key package per invitee from the server, this module checks each
//! one really belongs to the user it was fetched for, and the one Welcome the
//! commit produces is checked to carry a secret for every one of them, so the
//! DuckCount API can hand that same Welcome to each. Once the commit is built,
//! each invitee's signature key is pinned to them.
//!
//! The Welcome can also carry a payload of the host's to the members it adds,
//! see [`WELCOME_PAYLOAD_EXTENSION`].

use mls_rs::extension::ExtensionType;
use mls_rs::time::MlsTime;
use mls_rs::{Extension, ExtensionList, MlsMessage};

use crate::cryptography::mls::{
    CIPHER_SUITE, MlsError, config::cipher_suite_provider, identity::credential::user_uuid_from,
    storage::identity_pin::IdentityPinStore, types::InviteeKeyPackage,
};

/// The GroupInfo extension a Welcome carries the host's payload in, see
/// [`MlsClient::create_group`].
///
/// A GroupInfo travels inside the Welcome encrypted under a secret of the
/// epoch it opens, and signed by the member who wrote it, so the payload is
/// both without this library doing anything more. That secret is held by the
/// members the Welcome adds and by those already in the group at that epoch,
/// who have it from the Commit, which at creation is only the creator. It is
/// in the private-use range of RFC 9420
/// (0xF000 to 0xFFFF), as what it carries is DuckCount's own, and needs no
/// member to list it among their capabilities: those only cover the extensions
/// of the group context and of leaves, which every member has to understand,
/// not those of a GroupInfo, which only the joiner reads.
///
/// [`MlsClient::create_group`]: crate::cryptography::mls::client::MlsClient::create_group
pub const WELCOME_PAYLOAD_EXTENSION: ExtensionType = ExtensionType::new(0xF0DC);

/// The GroupInfo extensions carrying `payload`, none when there is none.
pub fn welcome_payload_extensions(payload: Option<Vec<u8>>) -> ExtensionList {
    payload
        .map(|payload| Extension::new(WELCOME_PAYLOAD_EXTENSION, payload))
        .into_iter()
        .collect()
}

/// The payload a Welcome carried in the GroupInfo `extensions` it held.
pub fn welcome_payload(extensions: &ExtensionList) -> Option<Vec<u8>> {
    extensions
        .get(WELCOME_PAYLOAD_EXTENSION)
        .map(|extension| extension.extension_data)
}

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
/// use the configured cipher suite, must not have expired, and must carry a
/// credential asserting the very user it was fetched for. The last check is
/// what stops a server from answering "give me Bob's key package" with
/// somebody else's: without it the wrong person would silently end up in the
/// group.
///
/// Every invitee whose key package fails is named, not only the first, so the
/// host can tell the user about all of them at once rather than one attempt at
/// a time, each attempt spending a key package of every other invitee. Expiry
/// is checked here for the same reason: mls-rs checks it too, but only once
/// the Commit is built, failing it for nobody in particular.
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
/// * `MlsError::UnusableKeyPackages` - Naming every invitee whose key package
///   cannot be parsed, is not a key package, uses a different cipher suite,
///   has expired, or asserts a user other than the one it was fetched for.
pub fn validate_invitees(invitees: Vec<InviteeKeyPackage>) -> Result<Vec<Invitee>, MlsError> {
    let now = MlsTime::now();

    let mut validated = Vec::with_capacity(invitees.len());
    let mut unusable = Vec::new();

    for invitee in invitees {
        match usable_key_package(&invitee.key_package, &invitee.user_uuid, now) {
            Some((key_package, signature_key)) => validated.push(Invitee {
                user_uuid: invitee.user_uuid,
                key_package,
                signature_key,
            }),
            None => unusable.push(invitee.user_uuid),
        }
    }

    if !unusable.is_empty() {
        return Err(MlsError::UnusableKeyPackages(unusable));
    }

    Ok(validated)
}

/// The key package `key_package` fetched for `user_uuid`, parsed, and the
/// signature key it carries, or `None` when it is not one `user_uuid` can be
/// added with at `now`, see [`validate_invitees`].
fn usable_key_package(
    key_package: &[u8],
    user_uuid: &str,
    now: MlsTime,
) -> Option<(MlsMessage, Vec<u8>)> {
    let message = MlsMessage::from_bytes(key_package).ok()?;
    let parsed = message.as_key_package()?;

    if parsed.cipher_suite() != CIPHER_SUITE || parsed.expiration().ok()? < now {
        return None;
    }

    if user_uuid_from(&parsed.signing_identity().credential).ok()? != user_uuid {
        return None;
    }

    let signature_key = parsed.signing_identity().signature_key.to_vec();

    Some((message, signature_key))
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

/// The one Welcome a commit adding `invitees` produced, serialised, provided
/// it carries a secret for every one of them.
///
/// mls-rs is configured to emit a single Welcome for all the members a commit
/// adds (see `mls_rules` in config.rs), which the DuckCount API hands to each.
/// A Welcome names the key packages it carries secrets for, and each invitee's
/// key package hashes to exactly one of them, which is how it is checked.
///
/// # Arguments
///
/// * `welcomes` - The Welcome messages from a commit's output.
/// * `invitees` - The validated invitees the commit added.
///
/// # Returns
///
/// * `Result<Vec<u8>, MlsError>` - The Welcome every invitee joins from.
///
/// # Errors
///
/// * `MlsError::UnmatchedWelcome` - If an invitee has no secret in it. Sending
///   it all the same would leave that member unable to join a group they are
///   already listed in, so this fails rather than returning it.
/// * `MlsError::ProtocolFailed` - If the commit added nobody, and so produced
///   no Welcome, a key package reference cannot be computed, or the Welcome
///   cannot be serialised.
pub fn shared_welcome(welcomes: &[MlsMessage], invitees: &[Invitee]) -> Result<Vec<u8>, MlsError> {
    let welcome = welcomes.first().ok_or_else(|| {
        MlsError::ProtocolFailed("A commit adding nobody produces no Welcome.".to_string())
    })?;

    let cipher_suite_provider = cipher_suite_provider()?;
    let references = welcome.welcome_key_package_references();

    for invitee in invitees {
        let reference = invitee
            .key_package
            .key_package_reference(&cipher_suite_provider)?
            .ok_or(MlsError::InvalidKeyPackage)?;

        if !references.contains(&&reference) {
            return Err(MlsError::UnmatchedWelcome(invitee.user_uuid.clone()));
        }
    }

    welcome.to_bytes().map_err(Into::into)
}
