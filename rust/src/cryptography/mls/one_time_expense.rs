//! The creditor's signature over a one-time expense.
//!
//! Every field of a one-time expense is sealed under a key all its participants
//! hold, so a seal says nothing about who wrote it: any participant can seal new
//! values, and what the server keeps in the clear (who paid, who owes) is not
//! sealed at all. The creditor therefore signs each version with their MLS
//! identity key, over everything the server stores for it, and a participant
//! accepts a version only when that signature checks out under the key they
//! hold for the creditor.
//!
//! What is signed is the sealed bytes rather than what they open to, so a
//! version is checked before anything in it is decrypted. The expense's UUID is
//! not part of it: the fields are sealed under a key that belongs to that one
//! expense and reached each participant tied to its UUID.
//!
//! # Domain separation
//!
//! The identity key also signs MLS messages, the information of the groups its
//! user owns and the group expenses they write. A version is signed as
//! [`sign_content`] describes, under a label of its own, so that no other kind
//! of signature can be passed off as a version's, or a version's as one of
//! another kind.
//!
//! # Settled marks
//!
//! Whether the expense has been paid back is not part of a version: marking it
//! is no edit, may happen any number of times, and leaves the versions as they
//! are. The creditor signs it apart, as a [`OneTimeExpenseSettledMark`], under
//! a label of its own, so that a version's signature cannot be passed off as a
//! mark's or the other way round.

use mls_rs_codec::{MlsEncode, MlsSize};
use mls_rs_core::crypto::SignatureSecretKey;

use crate::cryptography::mls::{
    MlsError,
    sign_content::{self, labelled},
};

/// The `SignContent` label of a one-time expense signature.
pub(crate) const LABEL: &[u8] = b"DuckCount 1.0 OneTimeExpense";

/// The `SignContent` label of a settled mark's signature.
pub(crate) const SETTLED_MARK_LABEL: &[u8] = b"DuckCount 1.0 OneTimeExpenseSettledMark";

/// One sealed field, as the server stores it.
#[derive(uniffi::Record, MlsSize, MlsEncode, Clone)]
pub struct SealedValue {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// One beneficiary of a one-time expense, with their sealed share.
#[derive(uniffi::Record, MlsSize, MlsEncode, Clone)]
pub struct OneTimeExpenseBeneficiary {
    pub user_uuid: String,
    pub share: SealedValue,
    pub is_share_fixed: SealedValue,
    pub share_percentage: SealedValue,
}

/// One version of a one-time expense, as the creditor signs it: everything the
/// server stores for it, apart from its UUID and its creditor.
///
/// Beneficiaries may come in any order; they are signed sorted by UUID.
#[derive(uniffi::Record, MlsSize, MlsEncode, Clone)]
pub struct OneTimeExpenseManifest {
    /// 0 for the version created, one more for each edit, so that a participant
    /// can refuse to go back to a version older than one it has shown.
    pub revision: u64,
    pub title: SealedValue,
    pub description: SealedValue,
    pub amount: SealedValue,
    pub currency: SealedValue,
    pub timestamp: SealedValue,
    pub beneficiaries: Vec<OneTimeExpenseBeneficiary>,
}

/// The creditor's mark saying whether a one-time expense has been paid back.
///
/// Unlike a version, it names its expense: nothing else ties a mark to one, the
/// server keeping it next to whichever expense it likes.
#[derive(uniffi::Record, MlsSize, MlsEncode, Clone)]
pub struct OneTimeExpenseSettledMark {
    pub expense_uuid: String,
    /// When the creditor made it, in milliseconds since the Unix epoch, so that
    /// a participant can refuse to go back to a mark older than one it has
    /// shown. Their client never signs one older than the newest it has shown,
    /// whatever its clock says.
    pub marked_at: u64,
    pub is_settled: bool,
}

/// Whether `signature` is `creditor_uuid`'s signature over `manifest`, made
/// with the private half of `creditor_signature_key`.
///
/// # Arguments
///
/// * `creditor_uuid` - The creditor the expense names.
/// * `creditor_signature_key` - The MLS signature public key held for them.
/// * `manifest` - The version to check, as the server served it.
/// * `signature` - The signature that came with it.
#[uniffi::export]
pub fn verify_one_time_expense(
    creditor_uuid: String,
    creditor_signature_key: Vec<u8>,
    manifest: OneTimeExpenseManifest,
    signature: Vec<u8>,
) -> bool {
    let Ok(signed) = to_be_signed(&creditor_uuid, manifest) else {
        return false;
    };

    sign_content::verifies(creditor_signature_key, &signature, &signed)
}

/// Whether `signature` is `creditor_uuid`'s signature over `mark`, made with
/// the private half of `creditor_signature_key`.
///
/// # Arguments
///
/// * `creditor_uuid` - The creditor of the expense the mark is about.
/// * `creditor_signature_key` - The MLS signature public key held for them.
/// * `mark` - The mark to check, naming the expense it was served with.
/// * `signature` - The signature that came with it.
#[uniffi::export]
pub fn verify_one_time_expense_settled_mark(
    creditor_uuid: String,
    creditor_signature_key: Vec<u8>,
    mark: OneTimeExpenseSettledMark,
    signature: Vec<u8>,
) -> bool {
    let Ok(signed) = labelled(SETTLED_MARK_LABEL, &creditor_uuid, &mark) else {
        return false;
    };

    sign_content::verifies(creditor_signature_key, &signature, &signed)
}

/// Signs `manifest` as `creditor_uuid`, whose MLS signature private key is
/// `secret_key`.
///
/// # Errors
///
/// * `MlsError::ProtocolFailed` - If the manifest cannot be encoded or signed.
pub(crate) fn sign(
    secret_key: &SignatureSecretKey,
    creditor_uuid: &str,
    manifest: OneTimeExpenseManifest,
) -> Result<Vec<u8>, MlsError> {
    let signed = to_be_signed(creditor_uuid, manifest)
        .map_err(|error| MlsError::ProtocolFailed(error.to_string()))?;

    sign_content::sign(secret_key, &signed)
}

/// Signs `mark` as `creditor_uuid`, whose MLS signature private key is
/// `secret_key`.
///
/// # Errors
///
/// * `MlsError::ProtocolFailed` - If the mark cannot be encoded or signed.
pub(crate) fn sign_settled_mark(
    secret_key: &SignatureSecretKey,
    creditor_uuid: &str,
    mark: OneTimeExpenseSettledMark,
) -> Result<Vec<u8>, MlsError> {
    let signed = labelled(SETTLED_MARK_LABEL, creditor_uuid, &mark)
        .map_err(|error| MlsError::ProtocolFailed(error.to_string()))?;

    sign_content::sign(secret_key, &signed)
}

/// The bytes a signature is made over: the creditor and the manifest, with the
/// beneficiaries in UUID order, wrapped in a labelled `SignContent`.
fn to_be_signed(
    creditor_uuid: &str,
    mut manifest: OneTimeExpenseManifest,
) -> Result<Vec<u8>, mls_rs_codec::Error> {
    manifest
        .beneficiaries
        .sort_by(|first, second| first.user_uuid.cmp(&second.user_uuid));

    labelled(LABEL, creditor_uuid, &manifest)
}
