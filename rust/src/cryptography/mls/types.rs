//! Values crossing the uniffi boundary.
//!
//! Every byte vector here is a serialised MLS message. The host relays them to
//! the DuckCount API verbatim (Base64 encoded by the transport layer) and never
//! needs to look inside.

/// A key package fetched from the server, together with the user it belongs to.
///
/// The pairing is the caller's assertion: the host asked the server for *this*
/// user's key package, so it knows which UUID the bytes came back for. It is
/// checked rather than trusted (the credential inside the key package must
/// assert the same UUID), and its signature key must match whatever is already
/// pinned for that user.
#[derive(uniffi::Record, Debug)]
pub struct InviteeKeyPackage {
    /// UUID of the user the key package was fetched for.
    pub user_uuid: String,
    /// The serialised MLS key package.
    pub key_package: Vec<u8>,
}

/// The result of creating a group.
#[derive(uniffi::Record, Debug)]
pub struct GroupCreation {
    /// Identifier of the new MLS group.
    ///
    /// It is not the DuckCount API's group UUID but derived from it, or from
    /// a nonce this library draws for a group the API holds no UUID for, see
    /// [`group_id`](crate::cryptography::mls::group_id). The host is
    /// responsible for recording the mapping between them.
    pub mls_group_id: Vec<u8>,
    /// The one Welcome every invitee joins from, ready for `POST /groups`,
    /// which delivers it to each of them. It carries a secret for each
    /// invitee's key package, and opens with no other.
    pub welcome: Vec<u8>,
}

/// The result of adding members to an existing group.
#[derive(uniffi::Record, Debug)]
pub struct AddMembersOutput {
    /// The Commit advancing the group's epoch, for every member that was
    /// already in the group.
    pub commit: Vec<u8>,
    /// The one Welcome every new member joins from, as in
    /// [`GroupCreation::welcome`].
    pub welcome: Vec<u8>,
}

/// A member of a group, as the host recorded them while it held the group:
/// someone [`MlsClient::rejoin_group`] takes that group's GroupInfo from, under
/// this key, when no pin says otherwise.
///
/// [`MlsClient::rejoin_group`]: crate::cryptography::mls::client::MlsClient::rejoin_group
#[derive(uniffi::Record, Debug, Clone)]
pub struct VouchedMember {
    /// UUID asserted by the member's credential.
    pub user_uuid: String,
    /// The member's MLS signature public key, as their leaf in the group held
    /// it.
    pub signature_key: Vec<u8>,
}

/// The result of rejoining a group from outside it, see
/// [`MlsClient::rejoin_group`].
///
/// [`MlsClient::rejoin_group`]: crate::cryptography::mls::client::MlsClient::rejoin_group
#[derive(uniffi::Record, Debug)]
pub struct GroupRejoin {
    /// Identifier of the group rejoined, the one derived for the UUID the
    /// DuckCount API holds it under, see
    /// [`group_id`](crate::cryptography::mls::group_id), as it was before.
    pub mls_group_id: Vec<u8>,
    /// The external commit removing the leaf this user had and seating the
    /// one this device holds, for every member of the group. It is a
    /// PublicMessage, as every Commit from outside a group is.
    pub commit: Vec<u8>,
    /// Whether the GroupInfo's signer was this user or a member pinned on this
    /// device, rather than one the host vouched for alone: the host hands the
    /// group's older keys only to the former, as what it vouches for may be
    /// out of date, a member removed since among it.
    pub is_signer_pinned: bool,
    /// The epoch the Commit takes the group to, one past the one the
    /// GroupInfo it was built from is for: the one this device's state is in
    /// already.
    pub epoch: u64,
}

/// What a Welcome says, read without joining the group it is for, see
/// [`MlsClient::inspect_welcome`].
///
/// [`MlsClient::inspect_welcome`]: crate::cryptography::mls::client::MlsClient::inspect_welcome
#[derive(uniffi::Record, Debug)]
pub struct WelcomeInspection {
    /// UUID of the member whose Commit added this user, as the group's tree
    /// names them: the one who wrote the Welcome and signed what it carries,
    /// the payload included. For a group just created, its creator.
    pub committer_user_uuid: String,
    /// The UUIDs of every member other than this user, sorted, as the tree
    /// the Welcome carries names them: who was in the group at the epoch the
    /// Welcome opens, signed by its committer. Somebody who has left since,
    /// with nobody committing their removal yet, is still among them.
    pub member_uuids: Vec<String>,
    /// What the committer handed the members the Welcome adds, see
    /// [`MlsClient::create_group`], or `None` when they handed nothing.
    ///
    /// It is encrypted under a secret of the epoch the Welcome opens, so the
    /// members it adds can read it, and so can those already in the group at
    /// that epoch, who have the secret from the Commit: for a group just
    /// created, only its creator. Nobody but the committer can have written
    /// it, but it is their word like the rest of the Welcome: the host checks
    /// it is what it expects.
    ///
    /// [`MlsClient::create_group`]: crate::cryptography::mls::client::MlsClient::create_group
    pub welcome_payload: Option<Vec<u8>>,
}

/// Key packages ready to be published with `PUT /users/{uuid}/key-package`.
#[derive(uniffi::Record, Debug)]
pub struct KeyPackageBundle {
    /// The reusable key package, handed out when the one-time pool runs dry.
    pub last_resort_key_package: Vec<u8>,
    /// Key packages each consumed by at most one peer.
    pub one_time_key_packages: Vec<Vec<u8>>,
}

/// A current member of a group.
#[derive(uniffi::Record, Debug)]
pub struct MemberInfo {
    /// UUID asserted by the member's credential.
    pub user_uuid: String,
    /// Fingerprint of the member's identity as this group holds it: their
    /// half of every safety number they are part of, see
    /// [`safety_number`](crate::cryptography::mls::identity::fingerprint::safety_number).
    pub fingerprint: String,
    /// The member's MLS signature public key, as their leaf in this group
    /// holds it.
    ///
    /// A group expense the member wrote is checked under it when no better key
    /// is held for them, the user's own or the one pinned for a contact, see
    /// [`group_expense`](crate::cryptography::mls::group_expense). The host
    /// is to keep it once they have left, since what they wrote while in the
    /// group stays in it.
    pub signature_key: Vec<u8>,
}

/// Whose Commits a member of a group the DuckCount API holds applies, given
/// for each message it processes, see
/// [`process_incoming_message`](crate::cryptography::mls::group::MlsGroup::process_incoming_message).
#[derive(uniffi::Record, Clone, Debug)]
pub struct CommitPolicy {
    /// UUID of the group's creator, whose Commits are applied whatever they
    /// change.
    pub creator_uuid: String,
    /// UUIDs of the members the DuckCount API stored the message being
    /// processed with, its `departed_member_uuids`: for a Commit stored
    /// through `DELETE /groups/{uuid}/departed`, the members the server
    /// checked had left the group, or deleted their account, as it stored
    /// it, and nobody for any other message. Any other member's Commit is
    /// applied only if it removes exactly these members, all of them and
    /// nobody else; the order they are named in does not matter, nor a member
    /// named twice. A member's resync of their own leaf, the Commit from
    /// outside the group they rejoin with after a log-out, is applied only if
    /// this names nobody, as it does for the Commit
    /// `POST /groups/{uuid}/commits/rejoin` stores.
    ///
    /// It is the server's list for that one message, never this device's own
    /// view of who has departed, so that every member decides alike about
    /// every Commit, and one they all refuse is replaced by the creator.
    pub departed_uuids: Vec<String>,
}

/// What processing an incoming message produced.
#[derive(uniffi::Enum, Debug)]
pub enum ProcessedMessage {
    /// An application message was decrypted.
    ApplicationMessage {
        /// UUID of the member that sent it.
        sender_user_uuid: String,
        /// The plaintext payload.
        payload: Vec<u8>,
        /// Whether it was signed with the key pinned for its sender.
        ///
        /// False for a sender nobody pinned yet, such as the sender of a
        /// contact request not accepted yet or a member somebody else
        /// committed in, and for a leaf whose key was never checked against
        /// the pin: mls-rs checks a leaf when it enters the group, not against
        /// a pin taken later.
        is_sender_pinned: bool,
    },
    /// A Commit was applied: the group advanced to a new epoch, or the local
    /// user was removed from it.
    Commit {
        /// UUID of the member that committed.
        ///
        /// Never absent in practice: mls-rs refuses a Commit removing its own
        /// committer, so they are still in the group once it is applied, and
        /// every member's credential was checked as they entered it. A member
        /// rejoining from outside the group removes the leaf they had and is
        /// read from the one they took, which names them too.
        committer_user_uuid: Option<String>,
        /// The epoch the group is now in. For the local user removed by this
        /// Commit, the epoch it was in before: mls-rs does not take a removed
        /// member into an epoch they are no longer part of.
        epoch: u64,
        /// Whether this Commit removed the local user from the group. When
        /// true, no further messages can be sent or read, and the host should
        /// drop the group's stored state.
        removed_self: bool,
    },
    /// A Proposal was received and cached. It changes nothing until a member
    /// commits it, which for a departing member's self-removal, somebody
    /// still in the group has to do.
    Proposal {
        /// UUID of the member that proposed, absent for proposals not sent by
        /// a current member.
        sender_user_uuid: Option<String>,
    },
    /// The message was valid but carries nothing for the caller to act on.
    Ignored,
}

/// An application message, read out of a group by
/// [`read_application_message`](crate::cryptography::mls::group::MlsGroup::read_application_message).
#[derive(uniffi::Record, Debug)]
pub struct ApplicationMessage {
    /// UUID of the member that sent it.
    pub sender_user_uuid: String,
    /// The plaintext payload.
    pub payload: Vec<u8>,
    /// Whether it was signed with the key pinned for its sender.
    ///
    /// False for a sender nobody pinned yet, such as the sender of a contact
    /// request not accepted yet, and for a leaf whose key was never checked
    /// against the pin: mls-rs checks a leaf when it enters the group, not
    /// against a pin taken later.
    pub is_sender_pinned: bool,
}
