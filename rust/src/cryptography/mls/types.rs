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
    /// A Commit was applied and the group advanced to a new epoch.
    Commit {
        /// UUID of the member that committed, absent when that member left the
        /// group in this very Commit.
        committer_user_uuid: Option<String>,
        /// The epoch the group is now in.
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
