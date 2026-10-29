//! The owner's signature over a group's information.
//!
//! A group's title, description and currency are sealed under the group's key,
//! which every member holds, so a seal says nothing about who wrote it: any
//! member can seal a title of their own. Only the group's owner may change its
//! information, though: its creator, who alone changes who is in it too, see
//! [`group`](super::group). The owner therefore signs each version with their
//! MLS identity key, and a member shows a version only when that signature
//! checks out under the key they hold for the owner. Nobody else can sign one:
//! not another member, who holds the group's key but not the owner's identity
//! key, and not the server, which holds neither.
//!
//! # What is signed
//!
//! What the fields open to, and not the sealed bytes the server stores: the
//! group's key is rotated whenever a member is removed, every field sealed
//! again under the new one, and a version signed in the clear says the same
//! under either key, its signature as good after a rotation as before. A
//! member therefore opens a version before checking it, which is unlike a
//! one-time expense, see [`one_time_expense`](super::one_time_expense).
//!
//! The group's UUID is signed too, since nothing else ties a version to its
//! group: somebody in two groups of the same owner holds both keys, and could
//! otherwise seal one group's version, signature and all, into the other.
//!
//! The currency is chosen when the group is created and never changes, but it
//! is signed with the rest, so that it too is the owner's word and nobody
//! else's.
//!
//! # Domain separation
//!
//! The identity key also signs MLS messages, and one-time expenses. A version
//! is signed as [`sign_content`] describes, under a label of its own, so that
//! no other kind of signature can be passed off as a version's, or a version's
//! as one of another kind.

use mls_rs_codec::{MlsEncode, MlsSize};
use mls_rs_core::crypto::SignatureSecretKey;

use crate::cryptography::mls::{
    MlsError,
    sign_content::{self, labelled},
};

/// The `SignContent` label of a group information signature.
pub(crate) const LABEL: &[u8] = b"DuckCount 1.0 GroupInformation";

/// One version of a group's information, as its owner signs it: what its
/// fields open to, and the group they are of.
///
/// Named so as not to be taken for MLS's own `GroupInfo`, which is something
/// else entirely.
#[derive(uniffi::Record, MlsSize, MlsEncode, Clone)]
pub struct GroupInformation {
    /// The UUID the DuckCount API holds the group under.
    pub group_uuid: String,
    /// 1 for the version the group was created with, one more for each edit,
    /// so that a member can refuse to go back to a version older than one it
    /// has shown. Rotating the group's key leaves it as it was.
    pub revision: u64,
    pub title: String,
    pub description: String,
    /// The UUID of the currency the group was created in.
    pub currency_uuid: String,
}

/// Whether `signature` is `owner_uuid`'s signature over `information`, made
/// with the private half of `owner_signature_key`.
///
/// # Arguments
///
/// * `owner_uuid` - The group's owner, its creator.
/// * `owner_signature_key` - The MLS signature public key held for them.
/// * `information` - The version to check, its fields opened, with the group
///   and the revision the server served it for.
/// * `signature` - The signature that came with it.
#[uniffi::export]
pub fn verify_group_information(
    owner_uuid: String,
    owner_signature_key: Vec<u8>,
    information: GroupInformation,
    signature: Vec<u8>,
) -> bool {
    let Ok(signed) = labelled(LABEL, &owner_uuid, &information) else {
        return false;
    };

    sign_content::verifies(owner_signature_key, &signature, &signed)
}

/// Signs `information` as `owner_uuid`, whose MLS signature private key is
/// `secret_key`.
///
/// # Errors
///
/// * `MlsError::ProtocolFailed` - If the information cannot be encoded or
///   signed.
pub(crate) fn sign(
    secret_key: &SignatureSecretKey,
    owner_uuid: &str,
    information: GroupInformation,
) -> Result<Vec<u8>, MlsError> {
    let signed = labelled(LABEL, owner_uuid, &information)
        .map_err(|error| MlsError::ProtocolFailed(error.to_string()))?;

    sign_content::sign(secret_key, &signed)
}
