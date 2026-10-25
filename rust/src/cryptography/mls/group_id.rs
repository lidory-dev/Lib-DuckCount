//! The MLS id of a group, derived from what names the group rather than
//! chosen by whoever creates it.
//!
//! A client keeps every group in one store, keyed by that id, and refuses a
//! Welcome to a group it holds or held, see
//! [`MlsClient::join_group`](crate::cryptography::mls::client::MlsClient::join_group).
//! MLS leaves the id to the creator, and every member reads it. Were it
//! chosen, any of them could take a group's id first with a group of their
//! own, a contact request say, which a client joins from anybody, and leave
//! the real group unjoinable on that device for good. Derived, a Welcome is
//! accepted only as the group its id was derived for, and a channel or a
//! contact request can never take the id of a group the API holds:
//!
//! * A group the DuckCount API holds takes it from the UUID it is created
//!   under: SHA3-256 of [`SERVER_GROUP_DOMAIN`] and the UUID. The API never
//!   lets two groups share a UUID, and derives each from its creator's, see
//!   [`group_uuid`](crate::cryptography::group_uuid), so nobody but its
//!   creator can have the API hold another group under its UUID, even once it
//!   is deleted.
//! * Any other, a direct channel or a contact request, takes it from a nonce
//!   its creator draws, which its Welcome carries in a GroupInfo extension,
//!   [`CHANNEL_NONCE_EXTENSION`]: SHA3-256 of [`CHANNEL_DOMAIN`] and the nonce.
//!
//! A joiner checks the id against the one derived for the group it expects,
//! see [`check`], before anything looks the group up. The two domains never
//! meet, so no channel lands on the id of a group the API holds, and no
//! Welcome is taken for one to a group under a UUID its id was not derived
//! from.
//!
//! Derivation binds only the group the API holds: what it leaves open is the
//! id of a group the API holds being anybody's to derive who knows its UUID,
//! which every one of its invitees does. Such a member can create a group of
//! their own under that UUID, with
//! [`MlsClient::create_group`](crate::cryptography::mls::client::MlsClient::create_group),
//! and post its Welcome to the group's members, which the API lets any member
//! do: its id is the real group's, and [`check`] lets it through. Which
//! Welcome to such a group a joiner takes is the host's to decide, see
//! [`MlsClient::join_group`](crate::cryptography::mls::client::MlsClient::join_group).

use mls_rs::extension::ExtensionType;
use mls_rs::{Extension, ExtensionList};
use rand::RngCore;
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256};

use crate::cryptography::mls::MlsError;

/// Domain separator of the id of a group the DuckCount API holds.
///
/// It differs from [`CHANNEL_DOMAIN`] before either ends, so the bytes hashed
/// for a group are never those hashed for a channel, and nothing follows it
/// but the one value, so no two values hash the same bytes.
const SERVER_GROUP_DOMAIN: &[u8] = b"DuckCount MLS group id v1";

/// Domain separator of the id of a group the DuckCount API holds no UUID for.
const CHANNEL_DOMAIN: &[u8] = b"DuckCount MLS channel id v1";

/// Length of the nonce a channel's id is derived from, in bytes.
const CHANNEL_NONCE_LENGTH: usize = 32;

/// The GroupInfo extension the Welcome to a channel carries its nonce in.
///
/// Signed and encrypted with the rest of the GroupInfo, and read by the
/// joiner alone, as [`WELCOME_PAYLOAD_EXTENSION`] is, whose range it shares
/// for the same reason.
///
/// [`WELCOME_PAYLOAD_EXTENSION`]: crate::cryptography::mls::invitation::WELCOME_PAYLOAD_EXTENSION
pub const CHANNEL_NONCE_EXTENSION: ExtensionType = ExtensionType::new(0xF0DD);

/// The id of the group the DuckCount API holds under `group_uuid`, in
/// canonical hyphenated lowercase form, as the API writes it.
pub fn server_group_id(group_uuid: &str) -> Vec<u8> {
    Sha3_256::new()
        .chain_update(SERVER_GROUP_DOMAIN)
        .chain_update(group_uuid.as_bytes())
        .finalize()
        .to_vec()
}

/// The id of the channel whose creator drew `nonce`.
pub fn channel_group_id(nonce: &[u8]) -> Vec<u8> {
    Sha3_256::new()
        .chain_update(CHANNEL_DOMAIN)
        .chain_update(nonce)
        .finalize()
        .to_vec()
}

/// The id of a new group, the one the DuckCount API is to hold under
/// `group_uuid`, or a channel when there is none, and the GroupInfo
/// extensions its Welcome needs for a joiner to check it.
pub fn new_mls_group_id(group_uuid: Option<&str>) -> (Vec<u8>, ExtensionList) {
    match group_uuid {
        Some(group_uuid) => (server_group_id(group_uuid), ExtensionList::default()),
        None => {
            let mut nonce = vec![0u8; CHANNEL_NONCE_LENGTH];
            OsRng.fill_bytes(&mut nonce);

            let group_id = channel_group_id(&nonce);
            let extensions = [Extension::new(CHANNEL_NONCE_EXTENSION, nonce)]
                .into_iter()
                .collect();

            (group_id, extensions)
        }
    }
}

/// Checks that `group_id`, the id of the group a Welcome is for, is the one
/// derived for the group the host expects it to be: the group the DuckCount
/// API holds under `expected_group_uuid`, or, with none, a channel, whose
/// nonce the Welcome's GroupInfo `extensions` carry.
///
/// # Errors
///
/// * `MlsError::UnexpectedGroupId` - If it is not.
pub fn check(
    group_id: &[u8],
    expected_group_uuid: Option<&str>,
    extensions: &ExtensionList,
) -> Result<(), MlsError> {
    let expected = match expected_group_uuid {
        Some(group_uuid) => server_group_id(group_uuid),
        None => match extensions.get(CHANNEL_NONCE_EXTENSION) {
            Some(nonce) => channel_group_id(&nonce.extension_data),
            None => return Err(MlsError::UnexpectedGroupId),
        },
    };

    if group_id != expected.as_slice() {
        return Err(MlsError::UnexpectedGroupId);
    }

    Ok(())
}
