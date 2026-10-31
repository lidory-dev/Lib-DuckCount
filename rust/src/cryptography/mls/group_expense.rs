//! The author's signature over a group expense.
//!
//! Every version of a group expense is sealed under the group's key, which
//! every member holds, so a seal says nothing about who wrote it: any member
//! can seal a version of their own. Any member may also add, edit, delete and
//! restore any of the group's expenses but its settlements, so who wrote one
//! of those is no permission to check, but it is what the expense's history
//! shows, and a member must not get to pass off their version as somebody
//! else's. The author therefore signs each version with their MLS identity
//! key, and a member takes a version as theirs only when that signature checks
//! out under the key they hold for them. Nobody else can sign one: not another
//! member, who holds the group's key but not the author's identity key, and
//! not the server, which holds neither.
//!
//! # Settlements
//!
//! A settlement is the one expense whose author is a permission to check. It
//! says that its creditor paid its only beneficiary back, and only the member
//! paid can say so: were anybody else's word taken for it, any member could
//! make up a repayment and move everyone's balances. A settlement is therefore
//! recorded by its recipient alone, never edited, deleted by them alone, and
//! never restored: [`verify_group_expense`] refuses a version of one signed by
//! anybody else, however good the signature, or at any revision but 1,
//! whoever signed it, and [`verify_group_expense_deletion`] a deletion flag
//! signed by anybody else, or one restoring it, whoever signed it.
//!
//! Deleting a settlement being no version, the version it is recorded with is
//! the only one it ever has, so one past revision 1 is an edit by its revision
//! alone, and is refused even by a member that never showed the first, having
//! joined the group or logged out since, which would otherwise take a
//! rewritten repayment for the one recorded. That a settlement is not edited
//! into an expense of another kind is still the host's to hold it to: such an
//! edit is what a version is next to the one before it, which a version alone
//! cannot tell.
//!
//! That it is never restored holds on a member that showed its deletion. One
//! that shows no version of it yet, having joined the group or logged out
//! since, has only the newest flag the server keeps to go by, which any member
//! can write over its recipient's: refusing that flag, it shows nothing of the
//! settlement, rather than the repayment counted again, see
//! [Deleting and restoring](#deleting-and-restoring).
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
//! for a member to refuse to go back to a version older than one it has shown.
//!
//! Every field is signed as the host gives it, its text and not what it means:
//! what a version says, its amount and its shares among the rest, is the
//! host's to check once its signature checks out, with
//! [`validate_expense`](crate::algorithm::expense::validate_expense) for one.
//!
//! # Edits
//!
//! An expense is edited [`MAX_GROUP_EXPENSE_EDITS`] times at most, its
//! revision going from 1, as created, to one more than that, and the server
//! keeps every version of it for its history. [`verify_group_expense`] refuses
//! a revision past the last, or of 0, however good the signature, so that the
//! cap holds even against a server that would store more versions than the
//! DuckCount API does.
//!
//! # Deleting and restoring
//!
//! Whether an expense is deleted is no part of its versions: deleting it and
//! restoring it are no edit, use up none of its edits and leave its versions
//! as they are, so that an expense that has had all of them can still be
//! deleted, and restored. The member deleting or restoring it signs a
//! [`GroupExpenseDeletion`] instead, a flag sealed apart from the versions,
//! of which the server keeps the newest alone. It names its group and its
//! expense, a member being able to seal any flag they hold into any expense
//! of any group they are in, signature and all, and carries a revision of its
//! own, for a member to refuse to go back to a flag older than one it has
//! shown: the server could otherwise serve a deleted expense's flags from
//! before the one deleting it, and so restore it. That revision is served in
//! the clear, as a version's is, so the server can tell from it how many times
//! an expense was deleted or restored, which usually tells it whether it is
//! deleted now: a client mostly sets the flag to the opposite of the one it
//! shows, but writes over a flag it refused, or could not read, in the state
//! asked.
//!
//! The server keeps the newest flag alone, though, and cannot tell one that
//! verifies, so any member can replace a flag, a settlement's deletion by its
//! recipient among them, with one that every member refuses. A member that
//! showed the flag replaced goes on showing it. One that shows no version of
//! the expense yet, having joined the group or logged out since, has no older
//! flag to go by, so the host is to take a version of such an expense only
//! together with the flag listed with it, and neither when it refuses the
//! flag: it then shows nothing of the expense, as when it refuses the only
//! version listed, rather than the expense as though nobody deleted it, a
//! deleted settlement counted again. A member can so keep an expense from
//! showing on a member that never showed it, as they can by writing a version
//! nobody can verify, but not have it shown restored.
//!
//! # Domain separation
//!
//! The identity key also signs MLS messages, one-time expenses and the
//! information of the groups its user owns. A version and a deletion flag are
//! each signed as [`sign_content`] describes, under a label of their own, so
//! that no other kind of signature can be passed off as either, or either as
//! one of another kind.

use mls_rs_codec::{MlsEncode, MlsSize};
use mls_rs_core::crypto::SignatureSecretKey;

use crate::algorithm::expense::MAX_GROUP_EXPENSE_EDITS;
use crate::cryptography::mls::{
    MlsError,
    sign_content::{self, labelled},
};

/// The `SignContent` label of a group expense signature.
pub(crate) const LABEL: &[u8] = b"DuckCount 1.0 GroupExpense";

/// The `SignContent` label of a deletion flag's signature.
pub(crate) const DELETION_LABEL: &[u8] = b"DuckCount 1.0 GroupExpenseDeletion";

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
    /// 1 for the version the expense was created with, one more for each edit
    /// since, up to `1 + MAX_GROUP_EXPENSE_EDITS`, so that a member can refuse
    /// to go back to a version older than one it has shown.
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
    /// beneficiary, who alone may sign it, and never edited, so only ever at
    /// revision 1, see [`verify_group_expense`].
    pub is_settlement: bool,
}

/// The flag saying whether a group expense is deleted, as the member deleting
/// or restoring it signs it.
///
/// It says nothing of what the expense is, and so holds whichever of its
/// versions is shown.
#[derive(uniffi::Record, MlsSize, MlsEncode, Clone)]
pub struct GroupExpenseDeletion {
    /// The UUID the DuckCount API holds the group under.
    pub group_uuid: String,
    /// The UUID the DuckCount API holds the expense under.
    pub expense_uuid: String,
    /// 1 for the flag the expense was first deleted with, one more for each
    /// deletion or restoring since, so that a member can refuse to go back to
    /// a flag older than one it has shown. Deleting and restoring leave the
    /// revision of the expense's versions as it is, and editing leaves this one.
    pub deletion_revision: u64,
    /// Whether the expense is deleted, rather than restored.
    pub is_deleted: bool,
}

/// Whether `signature` is `author_uuid`'s signature over `version`, made with
/// the private half of `author_signature_key`, and `version` is one they may
/// sign: one at a revision an expense may reach, from 1 to one more than
/// [`MAX_GROUP_EXPENSE_EDITS`], and for a settlement, only at revision 1, a
/// settlement being never edited, and only when they are the member it was
/// paid to, its only beneficiary.
///
/// What `version` may be is checked first, in that order, and the signature
/// only once it is one they may sign, so that each refusal holds however good
/// the signature.
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
    if !(1..=1 + MAX_GROUP_EXPENSE_EDITS).contains(&version.revision) {
        return false;
    }

    if version.is_settlement && (version.revision != 1 || !is_recipient(&author_uuid, &version)) {
        return false;
    }

    let Ok(signed) = to_be_signed(&author_uuid, version) else {
        return false;
    };

    sign_content::verifies(author_signature_key, &signature, &signed)
}

/// Whether `signature` is `author_uuid`'s signature over `deletion`, made with
/// the private half of `author_signature_key`, and `deletion` is one they may
/// sign for `expense`: one naming the expense and its group, at a deletion
/// revision of 1 or more, and for a settlement, only when they are the member
/// it was paid to, its only beneficiary, and only deleting it.
///
/// `expense` itself is not checked: it is the version the flag is checked
/// against, which the host checked with [`verify_group_expense`] already, the
/// one it shows or, for an expense it shows no version of yet, the one listed
/// with the flag, which it takes only together with the flag, see
/// [Deleting and restoring](self#deleting-and-restoring).
///
/// # Arguments
///
/// * `deletion` - The flag to check, opened, with the group, the expense and
///   the deletion revision the server served it for.
/// * `expense` - The version of the expense the flag is checked against.
/// * `author_uuid` - The member the flag says wrote it.
/// * `author_signature_key` - The MLS signature public key held for them.
/// * `signature` - The signature that came with it.
#[uniffi::export]
pub fn verify_group_expense_deletion(
    deletion: GroupExpenseDeletion,
    expense: GroupExpenseVersion,
    author_uuid: String,
    author_signature_key: Vec<u8>,
    signature: Vec<u8>,
) -> bool {
    if deletion.group_uuid != expense.group_uuid || deletion.expense_uuid != expense.expense_uuid {
        return false;
    }

    if deletion.deletion_revision == 0 {
        return false;
    }

    if expense.is_settlement && (!is_recipient(&author_uuid, &expense) || !deletion.is_deleted) {
        return false;
    }

    let Ok(signed) = labelled(DELETION_LABEL, &author_uuid, &deletion) else {
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

/// Signs `deletion` as `author_uuid`, whose MLS signature private key is
/// `secret_key`.
///
/// # Errors
///
/// * `MlsError::ProtocolFailed` - If the flag cannot be encoded or signed.
pub(crate) fn sign_deletion(
    secret_key: &SignatureSecretKey,
    author_uuid: &str,
    deletion: GroupExpenseDeletion,
) -> Result<Vec<u8>, MlsError> {
    let signed = labelled(DELETION_LABEL, author_uuid, &deletion)
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
