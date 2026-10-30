//! The author's signature over a group expense.
//!
//! Every version of a group expense is sealed under the group's key, which
//! every member holds, so a seal says nothing about who wrote it: any member
//! can seal a version of their own. Any member may also add, edit and delete
//! any of the group's expenses but its settlements, so who wrote one of those
//! is no permission to check, but it is what the expense's history shows, and
//! a member must not get to pass off their version as somebody else's. The
//! author therefore signs each version with their MLS identity key, and a
//! member takes a version as theirs only when that signature checks out under
//! the key they hold for them. Nobody else can sign one: not another member,
//! who holds the group's key but not the author's identity key, and not the
//! server, which holds neither.
//!
//! # Settlements
//!
//! A settlement is the one expense whose author is a permission to check. It
//! says that its creditor paid its only beneficiary back, and only the member
//! paid can say so: were anybody else's word taken for it, any member could
//! make up a repayment and move everyone's balances. A settlement is therefore
//! recorded by its recipient alone, and deleted by them alone, and
//! [`verify_group_expense`] refuses one signed by anybody else, however good
//! the signature. That it is never edited, and never restored once deleted, is
//! the host's to hold it to: either is what a version is next to the one
//! before it, which a version alone cannot tell.
//!
//! # What is signed
//!
//! What the version opens to, and not the sealed bytes the server stores: the
//! author's UUID and the signature are sealed along with the rest, so that the
//! server never learns who wrote a version, and a signature cannot be over the
//! bytes it is itself sealed in. A member therefore opens a version before
//! checking it, as for a group's information, see
//! [`group_information`](super::group_information).
//!
//! The group's UUID and the expense's are signed too, since nothing else in a
//! version ties it to either: a member can seal any version they hold into any
//! expense of any group they are in, signature and all. So is the revision,
//! for a member to refuse to go back to a version older than one it has shown,
//! and whether the expense is deleted, a deletion and a restore being versions
//! like any edit, their author's word like the rest.
//!
//! Every field is signed as the host gives it, its text and not what it means:
//! what a version says, its amount and its shares among the rest, is the
//! host's to check once its signature checks out, with
//! [`validate_expense`](crate::algorithm::expense::validate_expense) for one.
//!
//! # Domain separation
//!
//! The identity key also signs MLS messages, one-time expenses and the
//! information of the groups its user owns. A version is signed as
//! [`sign_content`] describes, under a label of its own, so that no other kind
//! of signature can be passed off as a version's, or a version's as one of
//! another kind.

use mls_rs_codec::{MlsEncode, MlsSize};
use mls_rs_core::crypto::SignatureSecretKey;

use crate::cryptography::mls::{
    MlsError,
    sign_content::{self, labelled},
};

/// The `SignContent` label of a group expense signature.
pub(crate) const LABEL: &[u8] = b"DuckCount 1.0 GroupExpense";

/// One beneficiary of a group expense, with their share.
#[derive(uniffi::Record, MlsSize, MlsEncode, Clone)]
pub struct GroupExpenseBeneficiary {
    pub user_uuid: String,
    pub share: String,
    /// Whether the share was set by hand, rather than split from what the
    /// others' fixed shares leave.
    pub is_share_fixed: bool,
}

/// One version of a group expense, as its author signs it: what it opens to,
/// and the group and expense it is of.
///
/// Beneficiaries may come in any order; they are signed sorted by UUID.
#[derive(uniffi::Record, MlsSize, MlsEncode, Clone)]
pub struct GroupExpenseVersion {
    /// The UUID the DuckCount API holds the group under.
    pub group_uuid: String,
    /// The UUID the DuckCount API holds the expense under, derived from its
    /// creator's, see
    /// [`group_expense_id`](crate::cryptography::group_expense_id).
    pub expense_uuid: String,
    /// 1 for the version the expense was created with, one more for each
    /// version since, so that a member can refuse to go back to a version
    /// older than one it has shown.
    pub revision: u64,
    pub title: String,
    pub description: String,
    pub amount: String,
    pub timestamp: String,
    /// The member who paid.
    pub creditor_uuid: String,
    pub beneficiaries: Vec<GroupExpenseBeneficiary>,
    /// Whether the expense is a payment settling a debt between two members,
    /// rather than something bought: paid by its creditor to its only
    /// beneficiary, who alone may sign it, see [`verify_group_expense`].
    pub is_settlement: bool,
    /// Whether the expense is deleted as of this version.
    pub is_deleted: bool,
}

/// Whether `signature` is `author_uuid`'s signature over `version`, made with
/// the private half of `author_signature_key`, and `version` is one they may
/// sign: a settlement, only when they are the member it was paid to, its only
/// beneficiary.
///
/// # Arguments
///
/// * `version` - The version to check, its fields opened, with the group, the
///   expense and the revision the server served it for.
/// * `author_uuid` - The member the version says wrote it.
/// * `author_signature_key` - The MLS signature public key held for them.
/// * `signature` - The signature that came with it.
#[uniffi::export]
pub fn verify_group_expense(
    version: GroupExpenseVersion,
    author_uuid: String,
    author_signature_key: Vec<u8>,
    signature: Vec<u8>,
) -> bool {
    if version.is_settlement && !is_recipient(&author_uuid, &version) {
        return false;
    }

    let Ok(signed) = to_be_signed(&author_uuid, version) else {
        return false;
    };

    sign_content::verifies(author_signature_key, &signature, &signed)
}

/// Whether `member_uuid` is who `settlement` was paid to: its one beneficiary.
fn is_recipient(member_uuid: &str, settlement: &GroupExpenseVersion) -> bool {
    matches!(
        settlement.beneficiaries.as_slice(),
        [recipient] if recipient.user_uuid == member_uuid
    )
}

/// Signs `version` as `author_uuid`, whose MLS signature private key is
/// `secret_key`.
///
/// # Errors
///
/// * `MlsError::ProtocolFailed` - If the version cannot be encoded or signed.
pub(crate) fn sign(
    secret_key: &SignatureSecretKey,
    author_uuid: &str,
    version: GroupExpenseVersion,
) -> Result<Vec<u8>, MlsError> {
    let signed = to_be_signed(author_uuid, version)
        .map_err(|error| MlsError::ProtocolFailed(error.to_string()))?;

    sign_content::sign(secret_key, &signed)
}

/// The bytes a signature is made over: the author and the version, with the
/// beneficiaries in UUID order, wrapped in a labelled `SignContent`.
fn to_be_signed(
    author_uuid: &str,
    mut version: GroupExpenseVersion,
) -> Result<Vec<u8>, mls_rs_codec::Error> {
    version
        .beneficiaries
        .sort_by(|first, second| first.user_uuid.cmp(&second.user_uuid));

    labelled(LABEL, author_uuid, &version)
}
