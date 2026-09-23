//! The creditor's signature over a one-time expense.
//!
//! Every field of a one-time expense is sealed under a key all its participants
//! hold, so a seal says nothing about who wrote it: any participant can seal new
//! values, and what the server keeps in the clear (who paid, whether it is a
//! settlement, who owes) is not sealed at all. The creditor therefore signs each
//! version with their MLS identity key, over everything the server stores for
//! it, and a participant believes a version only when that signature checks out
//! under the key they hold for the creditor.
//!
//! What is signed is the sealed bytes rather than what they open to, so a
//! version is checked before anything in it is decrypted. The expense's UUID is
//! not part of it: the server assigns it after the creditor has signed, and the
//! fields are sealed under a key that belongs to that one expense and reached
//! each participant tied to its UUID.
//!
//! # Domain separation
//!
//! The identity key also signs MLS messages. The signed bytes are MLS's own
//! `SignContent` (RFC 9420, section 5.1.2) with a label of this crate's, and
//! every MLS label starts with "MLS 1.0 ", which this one does not, so neither
//! kind of signature can be passed off as the other.

use mls_rs::CipherSuiteProvider;
use mls_rs_codec::{MlsEncode, MlsSize};
use mls_rs_core::crypto::{SignaturePublicKey, SignatureSecretKey};

use crate::cryptography::mls::{MlsError, config::cipher_suite_provider};

/// The `SignContent` label of a one-time expense signature.
const LABEL: &[u8] = b"DuckCount 1.0 OneTimeExpense";

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
    pub is_settlement: bool,
    pub title: SealedValue,
    pub description: SealedValue,
    pub amount: SealedValue,
    pub currency: SealedValue,
    pub timestamp: SealedValue,
    pub beneficiaries: Vec<OneTimeExpenseBeneficiary>,
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

    let Ok(cipher_suite_provider) = cipher_suite_provider() else {
        return false;
    };

    cipher_suite_provider
        .verify(
            &SignaturePublicKey::new(creditor_signature_key),
            &signature,
            &signed,
        )
        .is_ok()
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

    cipher_suite_provider()?
        .sign(secret_key, &signed)
        .map_err(|error| MlsError::ProtocolFailed(error.to_string()))
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

    let mut content = creditor_uuid.mls_encode_to_vec()?;
    manifest.mls_encode(&mut content)?;

    SignContent {
        label: LABEL.to_vec(),
        content,
    }
    .mls_encode_to_vec()
}

/// `SignContent` from RFC 9420, section 5.1.2.
#[derive(MlsSize, MlsEncode)]
struct SignContent {
    label: Vec<u8>,
    content: Vec<u8>,
}
