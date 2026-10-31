//! Signatures over what is not an MLS message.
//!
//! A user's MLS identity key signs more than MLS messages: each version of a
//! one-time expense they are the creditor of, see [`one_time_expense`], each
//! version of the information of a group they own, see
//! [`group_information`], and each version of a group expense they write and
//! each flag deleting or restoring one, see [`group_expense`]. Every such
//! signature is made the same way, over MLS's own `SignContent` (RFC 9420,
//! section 5.1.2), holding a label of its kind's and, ahead of what is
//! signed, the UUID of the user signing it.
//!
//! Every MLS label starts with "MLS 1.0 ", which none of this crate's does, and
//! no two of this crate's are the same, so a signature of one kind cannot be
//! passed off as one of another, an MLS message's included. And with the
//! signer's UUID signed, a signature holds for the user it was made as and
//! nobody else, whichever key it is checked under.
//!
//! [`one_time_expense`]: super::one_time_expense
//! [`group_information`]: super::group_information
//! [`group_expense`]: super::group_expense

use mls_rs::CipherSuiteProvider;
use mls_rs_codec::{MlsEncode, MlsSize};
use mls_rs_core::crypto::{SignaturePublicKey, SignatureSecretKey};

use crate::cryptography::mls::{MlsError, config::cipher_suite_provider};

/// The bytes a signature is made over: `signer_uuid` and `signed`, wrapped in a
/// `SignContent` labelled `label`.
pub(crate) fn labelled(
    label: &[u8],
    signer_uuid: &str,
    signed: &impl MlsEncode,
) -> Result<Vec<u8>, mls_rs_codec::Error> {
    let mut content = signer_uuid.mls_encode_to_vec()?;
    signed.mls_encode(&mut content)?;

    SignContent {
        label: label.to_vec(),
        content,
    }
    .mls_encode_to_vec()
}

/// Signs `signed`, as [`labelled`] built it, with `secret_key`.
///
/// # Errors
///
/// * `MlsError::ProtocolFailed` - If the cipher suite is unavailable or the
///   signing fails.
pub(crate) fn sign(secret_key: &SignatureSecretKey, signed: &[u8]) -> Result<Vec<u8>, MlsError> {
    cipher_suite_provider()?
        .sign(secret_key, signed)
        .map_err(|error| MlsError::ProtocolFailed(error.to_string()))
}

/// Whether `signature` is over `signed`, as [`labelled`] built it, made with
/// the private half of `signature_key`.
pub(crate) fn verifies(signature_key: Vec<u8>, signature: &[u8], signed: &[u8]) -> bool {
    let Ok(cipher_suite_provider) = cipher_suite_provider() else {
        return false;
    };

    cipher_suite_provider
        .verify(&SignaturePublicKey::new(signature_key), signature, signed)
        .is_ok()
}

/// `SignContent` from RFC 9420, section 5.1.2.
#[derive(MlsSize, MlsEncode)]
struct SignContent {
    label: Vec<u8>,
    content: Vec<u8>,
}
