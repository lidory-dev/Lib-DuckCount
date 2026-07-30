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

/// A Welcome message addressed to exactly one invited member.
///
/// Maps directly onto the API's `InvitedGroupMember`.
#[derive(uniffi::Record, Debug)]
pub struct WelcomeForMember {
    /// UUID of the member this Welcome is for.
    pub user_uuid: String,
    /// The serialised MLS Welcome message.
    pub welcome: Vec<u8>,
}

/// The result of creating a group.
#[derive(uniffi::Record, Debug)]
pub struct GroupCreation {
    /// Identifier of the new MLS group.
    ///
    /// MLS group ids are chosen by the creator, while the DuckCount API mints
    /// its own group UUID only once the create request (Welcomes included)
    /// has been accepted. The two therefore cannot be the same value, and the
    /// host is responsible for recording the mapping between them.
    pub mls_group_id: Vec<u8>,
    /// One Welcome per invited member, ready for `POST /groups`.
    pub welcomes: Vec<WelcomeForMember>,
}

/// The result of adding members to an existing group.
#[derive(uniffi::Record, Debug)]
pub struct AddMembersOutput {
    /// The Commit advancing the group's epoch, for every member that was
    /// already in the group.
    pub commit: Vec<u8>,
    /// One Welcome per new member.
    pub welcomes: Vec<WelcomeForMember>,
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
    /// Safety number of the member's signature key, for out-of-band comparison.
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
