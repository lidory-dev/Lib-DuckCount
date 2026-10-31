//! [`GroupStateStorage`] backed by the host's [`MlsStore`].

use std::cell::Cell;
use std::sync::Arc;

use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use zeroize::Zeroizing;

use crate::cryptography::mls::{
    MAX_GROUP_MEMBERS, MlsError,
    storage::{MlsNamespace, MlsStore, sealed_record::SealingKey},
};

/// How many prior epochs of a group are kept.
///
/// A member who commits while a peer's application message is still in flight
/// would otherwise be unable to decrypt that message, because it was sealed
/// under the epoch that just ended. Three is the same depth mls-rs's own
/// in-memory provider retains.
const MAX_EPOCH_RETENTION: usize = 3;

/// The most a group of two may store as it builds a Commit, in bytes before
/// sealing: its state, and the record of each epoch it retains. Anything else
/// it stores is held to less, see [`max_group_state_len_at_rest`].
///
/// A group's state grows with the message keys mls-rs keeps for the
/// generations a sender skipped, so that a message overtaken by a later one
/// can still be read. One message can skip up to 1024 of them, some 35 KB,
/// and a key nobody ever uses is never dropped: unbounded, a peer could grow a
/// group without end, and every operation on it would load, unseal and store
/// all of it again. A group shared with one peer starts near 12 KB, which
/// leaves it room at rest for some fourteen thousand skipped keys: that many
/// sends that never arrived, or some fourteen messages from a peer skipping as
/// many as allowed.
///
/// Past that, a message that skips anything is refused, and as a refused
/// message moves nothing forward, so is every later one from the same sender:
/// the group is of no more use for reading them.
///
/// A larger group may store more, see [`max_group_state_len`].
pub(crate) const MAX_GROUP_STATE_LEN: usize = 512 * 1024;

/// How much more than [`MAX_GROUP_STATE_LEN`] a group may store for each member
/// past two, see [`max_group_state_len`].
///
/// A group's state grows with its members too: each member keeps the whole
/// ratchet tree, some 3 KB a member where only the creator commits, as in a
/// group the DuckCount API holds whose other members never had a departed
/// member to remove, and 4 KB where every member has committed once, and a
/// Commit pending takes some 8 KB a member more, see
/// [`COMMIT_ROOM_PER_MEMBER`]. Twelve KiB a member leaves a group whose
/// creator alone commits as much room for skipped keys at rest as a group of
/// two has, some 480 KB, up to a hundred, and one whose every member has
/// committed some 375 KB at a hundred.
pub(crate) const MAX_GROUP_STATE_LEN_PER_MEMBER: usize = 12 * 1024;

/// How much of what a group may store is kept for the Commit it builds, for
/// each member and one more, see [`max_group_state_len_at_rest`].
///
/// A group holding a pending Commit stores the group the Commit makes beside
/// the one it is: some 8.2 KB a member where every member has committed once,
/// and up to 10 KB a member in the smallest groups. Nine KiB for each member
/// and one more holds the largest Commit this library builds, an update, with
/// 6 KB to spare at any size, and a removal with more. An addition takes less
/// for each member it adds than [`MAX_GROUP_STATE_LEN_PER_MEMBER`], which a
/// Commit adding them may store more.
pub(crate) const COMMIT_ROOM_PER_MEMBER: usize = 9 * 1024;

/// The most a group of `member_count` members may store as it builds a
/// Commit: [`MAX_GROUP_STATE_LEN`], and [`MAX_GROUP_STATE_LEN_PER_MEMBER`] more
/// for each member past two, up to [`MAX_GROUP_MEMBERS`].
///
/// A Commit adding members is stored as the group it makes, those it adds
/// counted, and one removing them as the group it removes them from.
///
/// Members past the cap do not count: a group that somebody else committed
/// past it, which this library never does, is held to what a group of a
/// hundred may store. Nor do members short of two: a group left with its
/// creator alone may store what a group of two may.
pub(crate) const fn max_group_state_len(member_count: usize) -> usize {
    MAX_GROUP_STATE_LEN + MAX_GROUP_STATE_LEN_PER_MEMBER * (counted(member_count) - 2)
}

/// The most a group of `member_count` members may store but as it builds a
/// Commit: [`max_group_state_len`], less [`COMMIT_ROOM_PER_MEMBER`] for each
/// member and one more.
///
/// What a group takes in at rest, skipped keys above all, is still there as
/// its creator builds the next Commit. Held to [`max_group_state_len`], a
/// member sending message after message, each skipping as many generations
/// as allowed, would leave no room for the Commit removing them, the only
/// thing that rids the group of what they had it take in. Held to less, a
/// group stored at rest has room for any Commit this library builds.
///
/// Everything stored while a Commit is pending is held to it too, the Commit
/// included: skipped keys taken into the room the Commit takes would still be
/// there once it is discarded, and leave the next one no room. A group
/// holding one, the more so the larger the group or the more the Commit adds,
/// may then have no room to read or send anything until the Commit is
/// applied or discarded. Discarding it is stored as building it was, see
/// [`MlsGroup::clear_pending_commit`](crate::cryptography::mls::group::MlsGroup::clear_pending_commit).
///
/// A Commit applied, this user's or a member's, stores the record of the
/// epoch it ends, which holds what the group took in at rest as it was then:
/// it is stored as the larger of the group it ends and the group it makes. A
/// removal leaving a group much smaller would otherwise refuse the record of
/// what the larger group took in, and leave this user in the epoch everybody
/// else has left.
pub(crate) const fn max_group_state_len_at_rest(member_count: usize) -> usize {
    max_group_state_len(member_count) - commit_room(member_count)
}

/// What a test lets a group of `member_count` members store at rest: 64 KiB
/// for two, and 2 KiB more for each member past two, rather than
/// [`max_group_state_len_at_rest`].
///
/// Small enough for a test to reach in two messages, and for a group of a
/// hundred, some 300 KB at rest, to be refused as it is created or joined, or
/// as the Commit adding members up to a hundred is applied, where outside
/// tests it may store 780 KiB. Every other test stores less, its members
/// counted as outside tests.
#[cfg(test)]
pub(crate) const fn max_group_state_len_at_rest_in_tests(member_count: usize) -> usize {
    64 * 1024 + 2 * 1024 * (counted(member_count) - 2)
}

/// What a test lets a group of `member_count` members store as it builds a
/// Commit: [`max_group_state_len_at_rest_in_tests`], and as much room for the
/// Commit as outside tests, which every Commit a test builds then takes as it
/// would there.
#[cfg(test)]
pub(crate) const fn max_group_state_len_in_tests(member_count: usize) -> usize {
    max_group_state_len_at_rest_in_tests(member_count) + commit_room(member_count)
}

/// The room kept for a Commit in what a group of `member_count` members may
/// store, see [`COMMIT_ROOM_PER_MEMBER`].
const fn commit_room(member_count: usize) -> usize {
    COMMIT_ROOM_PER_MEMBER * (counted(member_count) + 1)
}

/// `member_count` as what a group may store counts it: from two, up to
/// [`MAX_GROUP_MEMBERS`].
const fn counted(member_count: usize) -> usize {
    if member_count < 2 {
        2
    } else if member_count > MAX_GROUP_MEMBERS {
        MAX_GROUP_MEMBERS
    } else {
        member_count
    }
}

/// What a write of a group may store, see [`with_allowance`].
#[derive(Clone, Copy)]
pub(crate) enum Allowance {
    /// A write building a Commit, of a group of this many members, see
    /// [`max_group_state_len`].
    BuildingCommit(usize),
    /// Any other write, of a group of this many members, see
    /// [`max_group_state_len_at_rest`].
    AtRest(usize),
}

impl Allowance {
    /// How many bytes each record the write stores may hold.
    fn max_len(self) -> usize {
        #[cfg(test)]
        if !OUTSIDE_TEST_LIMITS.get() {
            return match self {
                Allowance::BuildingCommit(member_count) => {
                    max_group_state_len_in_tests(member_count)
                }
                Allowance::AtRest(member_count) => {
                    max_group_state_len_at_rest_in_tests(member_count)
                }
            };
        }

        match self {
            Allowance::BuildingCommit(member_count) => max_group_state_len(member_count),
            Allowance::AtRest(member_count) => max_group_state_len_at_rest(member_count),
        }
    }
}

thread_local! {
    /// What the group this thread is storing may store, see
    /// [`with_allowance`].
    static ALLOWANCE: Cell<Allowance> = const { Cell::new(Allowance::AtRest(2)) };
}

#[cfg(test)]
thread_local! {
    /// Whether the test on this thread holds what it stores to what a group
    /// may store outside tests, see [`with_limits_outside_tests`].
    static OUTSIDE_TEST_LIMITS: Cell<bool> = const { Cell::new(false) };
}

/// Runs `test`, holding every group it stores on this thread to what a group
/// may store outside tests rather than in one.
///
/// For what only those limits reach: a test lets a group store 2 KiB more for
/// each member, less than its tree takes, so that the record of an epoch of a
/// large group never holds more than a smaller one may store at rest, where
/// outside tests the record of an epoch of a group of a hundred, as full as
/// it may be, holds more than a group of three may, see
/// [`max_group_state_len_at_rest`].
#[cfg(test)]
pub(crate) fn with_limits_outside_tests<T>(test: impl FnOnce() -> T) -> T {
    /// Puts back the limits there were, however `test` ends.
    struct Restore(bool);

    impl Drop for Restore {
        fn drop(&mut self) {
            OUTSIDE_TEST_LIMITS.set(self.0);
        }
    }

    let _restore = Restore(OUTSIDE_TEST_LIMITS.replace(true));

    test()
}

/// Runs `store`, which stores a group, holding it to `allowance`.
///
/// mls-rs hands [`SealedGroupStateStorage::write`] a group's encoded state and
/// nothing more: neither its members nor what the write is for can be told
/// from it, and each group writes through a copy of the storage of its own,
/// which this library cannot reach. That write runs within the group's
/// `write_to_storage`, though, on the thread that called it, so an allowance
/// kept for that thread while `store` runs reaches that write and no other.
///
/// A write nobody set an allowance for is held to what a group of two may
/// store at rest, the least any group may.
pub(crate) fn with_allowance<T>(allowance: Allowance, store: impl FnOnce() -> T) -> T {
    /// Puts back the allowance there was, however `store` ends.
    struct Restore(Allowance);

    impl Drop for Restore {
        fn drop(&mut self) {
            ALLOWANCE.set(self.0);
        }
    }

    let _restore = Restore(ALLOWANCE.replace(allowance));

    store()
}

/// Prefix of the [`MlsNamespace::Metadata`] key recording that a group was
/// deleted. The group id follows it.
const DELETED_GROUP_PREFIX: &[u8] = b"deleted-group/";

/// What the record of a deleted group holds, see
/// [`SealedGroupStateStorage::delete_group`].
struct DeletedGroup {
    /// When the last key package this device held as it deleted the group
    /// expires, in seconds since the Unix epoch.
    openable_until: u64,
    /// The epoch the group was at.
    epoch: u64,
}

impl DeletedGroup {
    /// The record's value: `openable_until` then `epoch`, eight bytes each,
    /// big-endian.
    fn encode(&self) -> Vec<u8> {
        [self.openable_until.to_be_bytes(), self.epoch.to_be_bytes()].concat()
    }

    /// Reads a record's value back, `None` for one not of that shape.
    fn decode(value: &[u8]) -> Option<Self> {
        let (openable_until, epoch) = value.split_first_chunk::<8>()?;

        Some(DeletedGroup {
            openable_until: u64::from_be_bytes(*openable_until),
            epoch: u64::from_be_bytes(epoch.try_into().ok()?),
        })
    }
}

/// Group state storage that seals every record before the host sees it.
///
/// All clones share the same underlying host store.
#[derive(Clone)]
pub struct SealedGroupStateStorage {
    store: Arc<dyn MlsStore>,
    sealing_key: SealingKey,
}

impl SealedGroupStateStorage {
    /// Creates a storage adapter over `store`.
    pub fn new(store: Arc<dyn MlsStore>, sealing_key: SealingKey) -> Self {
        Self { store, sealing_key }
    }

    /// Whether a Welcome putting the group with this id at `epoch` is for a
    /// group this device holds, or held at that epoch or a later one before
    /// deleting it.
    ///
    /// Every Welcome this device was joined from put the group at an epoch it
    /// went on to hold, so one delivered again is refused even once the group
    /// is deleted, until [`prune_deleted_groups`](Self::prune_deleted_groups)
    /// forgets the deletion. A Welcome for an epoch past the last one held is
    /// none of those, and opens epochs this device never held: it is let
    /// through. It can be the group adding this user back after removing
    /// them, or a group of somebody else's under the same id, which anybody
    /// who knows the UUID of a group the DuckCount API holds can create, at an
    /// epoch of their choosing, see
    /// [`group_id`](crate::cryptography::mls::group_id). Which of the two it
    /// is, the host tells from who wrote it, see
    /// [`MlsClient::join_group`](crate::cryptography::mls::client::MlsClient::join_group).
    /// A record that cannot be read refuses every Welcome, as it cannot tell
    /// them apart.
    ///
    /// # Errors
    ///
    /// * `MlsError::StorageFailed` - If the host storage fails.
    pub fn has_held(&self, group_id: &[u8], epoch: u64) -> Result<bool, MlsError> {
        let held = self
            .store
            .get(MlsNamespace::GroupState, group_id.to_vec())
            .map_err(|error| MlsError::StorageFailed(error.to_string()))?
            .is_some();

        if held {
            return Ok(true);
        }

        let deleted = self
            .store
            .get(MlsNamespace::Metadata, Self::deleted_group_key(group_id))
            .map_err(|error| MlsError::StorageFailed(error.to_string()))?;

        Ok(deleted.is_some_and(|value| {
            DeletedGroup::decode(&value).is_none_or(|deleted| epoch <= deleted.epoch)
        }))
    }

    /// Deletes a group's current state and every retained prior epoch.
    ///
    /// Group state is deliberately *not* removed by the protocol when the local
    /// member is removed from a group, so callers that want the secrets gone
    /// have to ask.
    ///
    /// That the group existed is kept, see [`has_held`](Self::has_held): the
    /// key package its Welcome was sealed to can outlive it, a last-resort one
    /// is never spent, and the Welcome must not bring the group back. The
    /// record is written first, so a delete that fails leaves the group either
    /// stored or remembered, never joinable again from a Welcome it was
    /// joined from.
    ///
    /// It holds `openable_until`, when the last key package this device holds
    /// as the group goes expires: the one any Welcome it was joined from was
    /// sealed to is among them. Once they are all pruned, that Welcome can no
    /// longer be opened, and [`prune_deleted_groups`](Self::prune_deleted_groups)
    /// forgets the group. Taken from the key packages themselves rather than
    /// from the clock now, which a device set wrong would have the record
    /// forgotten while the Welcome still opens.
    ///
    /// It holds `epoch` too, the epoch the group is at as it goes: the latest
    /// any of those Welcomes can be for, and the one a Welcome adding this
    /// user back has to be past.
    ///
    /// # Errors
    ///
    /// * `MlsError::StorageFailed` - If the host storage fails.
    pub fn delete_group(
        &self,
        group_id: &[u8],
        openable_until: u64,
        epoch: u64,
    ) -> Result<(), MlsError> {
        let deleted = DeletedGroup {
            openable_until,
            epoch,
        };

        self.store
            .put(
                MlsNamespace::Metadata,
                Self::deleted_group_key(group_id),
                deleted.encode(),
            )
            .map_err(|error| MlsError::StorageFailed(error.to_string()))?;

        for key in self.epoch_keys(group_id)? {
            self.store
                .delete(MlsNamespace::GroupEpoch, key)
                .map_err(|error| MlsError::StorageFailed(error.to_string()))?;
        }

        self.store
            .delete(MlsNamespace::GroupState, group_id.to_vec())
            .map_err(|error| MlsError::StorageFailed(error.to_string()))
    }

    /// Forgets the deleted groups whose Welcome no key package left can open,
    /// those whose record holds an expiration before `expired_before`, in
    /// seconds since the Unix epoch, and returns how many. Run right after the
    /// key packages that expired before it are pruned, see
    /// [`delete_group`](Self::delete_group).
    ///
    /// A peer can make this device join, and so in time delete, a group with
    /// every message they send, and each would otherwise leave its record until
    /// a log-out. A record whose expiration cannot be read is kept.
    ///
    /// # Errors
    ///
    /// * `MlsError::StorageFailed` - If the host storage fails. The records
    ///   deleted before it did stay deleted.
    pub fn prune_deleted_groups(&self, expired_before: u64) -> Result<u32, MlsError> {
        let keys = self
            .store
            .keys(MlsNamespace::Metadata)
            .map_err(|error| MlsError::StorageFailed(error.to_string()))?;

        let mut pruned = 0;

        for key in keys
            .into_iter()
            .filter(|key| key.starts_with(DELETED_GROUP_PREFIX))
        {
            let deleted = self
                .store
                .get(MlsNamespace::Metadata, key.clone())
                .map_err(|error| MlsError::StorageFailed(error.to_string()))?
                .and_then(|value| DeletedGroup::decode(&value));

            if deleted.is_some_and(|deleted| deleted.openable_until < expired_before) {
                self.store
                    .delete(MlsNamespace::Metadata, key)
                    .map_err(|error| MlsError::StorageFailed(error.to_string()))?;

                pruned += 1;
            }
        }

        Ok(pruned)
    }

    /// Builds the store key recording that a group was deleted.
    fn deleted_group_key(group_id: &[u8]) -> Vec<u8> {
        [DELETED_GROUP_PREFIX, group_id].concat()
    }

    /// Builds the store key of one epoch record.
    ///
    /// The group id is length-prefixed so that `epoch_keys` can match on a
    /// prefix without one group id ever being mistaken for the start of a
    /// longer one.
    fn epoch_key(group_id: &[u8], epoch_id: u64) -> Vec<u8> {
        let mut key = Self::epoch_key_prefix(group_id);

        key.extend_from_slice(&epoch_id.to_be_bytes());

        key
    }

    /// Builds the shared prefix of every epoch record of one group.
    fn epoch_key_prefix(group_id: &[u8]) -> Vec<u8> {
        let group_id_length = group_id.len() as u16;

        let mut prefix = Vec::with_capacity(2 + group_id.len());

        prefix.extend_from_slice(&group_id_length.to_be_bytes());
        prefix.extend_from_slice(group_id);

        prefix
    }

    /// Lists the store keys of every retained epoch of one group.
    fn epoch_keys(&self, group_id: &[u8]) -> Result<Vec<Vec<u8>>, MlsError> {
        let prefix = Self::epoch_key_prefix(group_id);
        let key_length = prefix.len() + size_of::<u64>();

        Ok(self
            .store
            .keys(MlsNamespace::GroupEpoch)
            .map_err(|error| MlsError::StorageFailed(error.to_string()))?
            .into_iter()
            .filter(|key| key.len() == key_length && key.starts_with(&prefix))
            .collect())
    }

    /// Lists the retained epoch numbers of one group, in ascending order.
    fn epoch_ids(&self, group_id: &[u8]) -> Result<Vec<u64>, MlsError> {
        let prefix_length = Self::epoch_key_prefix(group_id).len();

        let mut epoch_ids = self
            .epoch_keys(group_id)?
            .into_iter()
            .filter_map(|key| key[prefix_length..].try_into().ok().map(u64::from_be_bytes))
            .collect::<Vec<_>>();

        epoch_ids.sort_unstable();

        Ok(epoch_ids)
    }

    /// Writes one epoch record.
    fn write_epoch(&self, group_id: &[u8], epoch: &EpochRecord) -> Result<(), MlsError> {
        let key = Self::epoch_key(group_id, epoch.id);
        let sealed = self
            .sealing_key
            .seal(MlsNamespace::GroupEpoch, &key, &epoch.data)?;

        self.store
            .put(MlsNamespace::GroupEpoch, key, sealed)
            .map_err(|error| MlsError::StorageFailed(error.to_string()))
    }

    /// Drops the oldest epochs of a group beyond [`MAX_EPOCH_RETENTION`].
    fn trim_epochs(&self, group_id: &[u8]) -> Result<(), MlsError> {
        let epoch_ids = self.epoch_ids(group_id)?;

        let Some(excess) = epoch_ids.len().checked_sub(MAX_EPOCH_RETENTION) else {
            return Ok(());
        };

        for epoch_id in &epoch_ids[..excess] {
            self.store
                .delete(
                    MlsNamespace::GroupEpoch,
                    Self::epoch_key(group_id, *epoch_id),
                )
                .map_err(|error| MlsError::StorageFailed(error.to_string()))?;
        }

        Ok(())
    }
}

impl GroupStateStorage for SealedGroupStateStorage {
    type Error = MlsError;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        let Some(sealed) = self
            .store
            .get(MlsNamespace::GroupState, group_id.to_vec())
            .map_err(|error| MlsError::StorageFailed(error.to_string()))?
        else {
            return Ok(None);
        };

        self.sealing_key
            .unseal(MlsNamespace::GroupState, group_id, &sealed)
            .map(Some)
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        let key = Self::epoch_key(group_id, epoch_id);

        let Some(sealed) = self
            .store
            .get(MlsNamespace::GroupEpoch, key.clone())
            .map_err(|error| MlsError::StorageFailed(error.to_string()))?
        else {
            return Ok(None);
        };

        self.sealing_key
            .unseal(MlsNamespace::GroupEpoch, &key, &sealed)
            .map(Some)
    }

    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        let max_len = ALLOWANCE.get().max_len();

        // Refused before anything is written. The epochs are bounded as well: a
        // message read in an epoch the group retains keeps the keys it skipped
        // in that epoch's record.
        let too_large = std::iter::once(&state.data)
            .chain(
                epoch_inserts
                    .iter()
                    .chain(&epoch_updates)
                    .map(|epoch| &epoch.data),
            )
            .any(|data| data.len() > max_len);

        if too_large {
            return Err(MlsError::GroupStateTooLarge);
        }

        // Epochs are written first and the group state last: the state record is
        // the commit point. A crash between the two leaves epoch records nothing
        // refers to, which the next write overwrites, rather than a group state
        // referring to epochs that were never stored.
        for epoch in epoch_inserts.iter().chain(epoch_updates.iter()) {
            self.write_epoch(&state.id, epoch)?;
        }

        let sealed = self
            .sealing_key
            .seal(MlsNamespace::GroupState, &state.id, &state.data)?;

        self.store
            .put(MlsNamespace::GroupState, state.id.clone(), sealed)
            .map_err(|error| MlsError::StorageFailed(error.to_string()))?;

        // Past the commit point, so a failure is not reported as a write that
        // did not happen: the caller would try again what is already stored, a
        // message read again once its key is spent. The next write trims what
        // this one could not.
        let _ = self.trim_epochs(&state.id);

        Ok(())
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        Ok(self.epoch_ids(group_id)?.last().copied())
    }
}
