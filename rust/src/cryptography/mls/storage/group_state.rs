//! [`GroupStateStorage`] backed by the host's [`MlsStore`].

use std::sync::Arc;

use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use zeroize::Zeroizing;

use crate::cryptography::mls::{
    MlsError,
    storage::{MlsNamespace, MlsStore, sealed_record::SealingKey},
};

/// How many prior epochs of a group are kept.
///
/// A member who commits while a peer's application message is still in flight
/// would otherwise be unable to decrypt that message, because it was sealed
/// under the epoch that just ended. Three is the same depth mls-rs's own
/// in-memory provider retains.
const MAX_EPOCH_RETENTION: usize = 3;

/// The most a group may store, in bytes before sealing: its state, and the
/// record of each epoch it retains.
///
/// A group's state grows with its members, and with the message keys mls-rs
/// keeps for the generations a sender skipped, so that a message overtaken by
/// a later one can still be read. One message can skip up to 1024 of them,
/// some 35 KB, and a key nobody ever uses is never dropped: unbounded, a peer
/// could grow a group without end, and every operation on it would load,
/// unseal and store all of it again. A group shared with one peer starts near
/// 12 KB, which leaves room for some fifteen thousand skipped keys: that many
/// sends that never arrived, or some fifteen messages from a peer skipping as
/// many as allowed.
///
/// Past that, a message that skips anything is refused, and as a refused
/// message moves nothing forward, so is every later one from the same sender:
/// the group is of no more use for reading them.
///
/// It bounds the members too: a group holding a pending Add stores some 9 KB
/// per member, so somewhere past fifty members a Commit no longer fits.
#[cfg(not(test))]
pub(crate) const MAX_GROUP_STATE_LEN: usize = 512 * 1024;

/// Small enough for a test to reach in two messages, and still above the most
/// any other test stores, some 42 KB for a group of three holding a pending
/// removal. A group of four holding a pending Add would not fit.
#[cfg(test)]
pub(crate) const MAX_GROUP_STATE_LEN: usize = 64 * 1024;

/// Prefix of the [`MlsNamespace::Metadata`] key recording that a group was
/// deleted. The group id follows it.
const DELETED_GROUP_PREFIX: &[u8] = b"deleted-group/";

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

    /// Whether this device holds a group with this id, or held one and deleted
    /// it.
    ///
    /// # Errors
    ///
    /// * `MlsError::StorageFailed` - If the host storage fails.
    pub fn has_held(&self, group_id: &[u8]) -> Result<bool, MlsError> {
        for (namespace, key) in [
            (MlsNamespace::GroupState, group_id.to_vec()),
            (MlsNamespace::Metadata, Self::deleted_group_key(group_id)),
        ] {
            let record = self
                .store
                .get(namespace, key)
                .map_err(|error| MlsError::StorageFailed(error.to_string()))?;

            if record.is_some() {
                return Ok(true);
            }
        }

        Ok(false)
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
    /// stored or remembered, never joinable again.
    ///
    /// # Errors
    ///
    /// * `MlsError::StorageFailed` - If the host storage fails.
    pub fn delete_group(&self, group_id: &[u8]) -> Result<(), MlsError> {
        self.store
            .put(
                MlsNamespace::Metadata,
                Self::deleted_group_key(group_id),
                Vec::new(),
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
            .any(|data| data.len() > MAX_GROUP_STATE_LEN);

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
