use std::collections::HashMap;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{cmp, fmt};

use atomicwrites::{AllowOverwrite, AtomicFile};
use collection::operations::types::PeerMetadata;
use collection::shards::shard::PeerId;
use data_encoding::BASE64URL_NOPAD;
use fs_err as fs;
use fs_err::File;
use http::Uri;
use parking_lot::RwLock;
use raft::RaftState;
use raft::eraftpb::{ConfState, HardState, SnapshotMetadata};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::StorageError;
use crate::content_manager::consensus::entry_queue::{EntryApplyProgressQueue, EntryId};
use crate::content_manager::consensus_ops::{
    CompareAndSwapPrivateOramEpoch, CompareAndSwapPrivateOramLayout,
    CompareAndSwapPrivateOramSessionLease, PrivateOramCollectionLayoutTransition,
    PrivateOramConsensusEpoch, PrivateOramConsensusLayout, PrivateOramEpochKey,
    PrivateOramIndexKind, PrivateOramLayoutKey, PrivateOramSessionLease,
    canonical_private_oram_index_state_digest,
};
use crate::types::{PeerAddressById, PeerMetadataById};

// Deprecated, use `STATE_FILE_NAME` instead
const STATE_FILE_NAME_CBOR: &str = "raft_state";

const STATE_FILE_NAME: &str = "raft_state.json";
const PRIVATE_ORAM_EPOCH_KEY_DOMAIN: &[u8] = b"qdrant-sec/private-oram-consensus-epoch-key/v1";
const PRIVATE_ORAM_LAYOUT_KEY_DOMAIN: &[u8] = b"qdrant-sec/private-oram-consensus-layout-key/v1";
const PRIVATE_ORAM_EPOCH_MAX_RECORDS: usize = 1_000_000;
const PRIVATE_ORAM_LAYOUT_MAX_OWNERS: usize = 10_000;
const PRIVATE_ORAM_SHA256_BASE64URL_LEN: usize = 43;
const PRIVATE_ORAM_SESSION_LEASE_MAX_SECS: u64 = 3_600;

/// State of the Raft consensus, which should be saved between restarts.
/// State of the collections, aliases and transfers are stored as regular storage.
#[derive(Serialize, Deserialize, Default)]
pub struct Persistent {
    /// last known state of the Raft consensus
    #[serde(with = "RaftStateDef")]
    pub state: RaftState,
    /// Store last applied snapshot index, required in case if there are no raft change log except
    /// for this last snapshot ID (term + commit)
    #[serde(default)] // TODO quick fix to avoid breaking the compat. with 0.8.1
    pub latest_snapshot_meta: SnapshotMetadataSer,
    /// Operations to be applied, consensus considers them committed, but this peer didn't apply them yet
    #[serde(default)]
    pub apply_progress_queue: EntryApplyProgressQueue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_voter: Option<PeerId>,
    /// Last known cluster topology
    #[serde(with = "serialize_peer_addresses")]
    pub peer_address_by_id: Arc<RwLock<PeerAddressById>>,
    #[serde(default)]
    pub peer_metadata_by_id: Arc<RwLock<PeerMetadataById>>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub cluster_metadata: HashMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub private_oram_epochs: HashMap<String, PrivateOramConsensusEpoch>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub private_oram_session_leases: HashMap<String, PrivateOramSessionLease>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub private_oram_layouts: HashMap<String, PrivateOramConsensusLayout>,
    pub this_peer_id: PeerId,
    #[serde(skip)]
    pub path: PathBuf,
    /// Tracks if there are some unsaved changes due to the failure on save
    #[serde(skip)]
    pub dirty: AtomicBool,
}

impl fmt::Debug for Persistent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let peer_address_count = self.peer_address_by_id.read().len();
        let peer_metadata = self.peer_metadata_by_id.read();
        let peer_metadata_count = peer_metadata.len();
        let peer_crypto_fingerprint_count = peer_metadata
            .values()
            .filter(|metadata| metadata.crypto_runtime_capability_fingerprint().is_some())
            .count();
        let mut cluster_metadata_keys = self.cluster_metadata.keys().collect::<Vec<_>>();
        cluster_metadata_keys.sort();

        f.debug_struct("Persistent")
            .field("state", &self.state)
            .field("latest_snapshot_meta", &self.latest_snapshot_meta)
            .field("apply_progress_queue", &self.apply_progress_queue)
            .field("first_voter", &self.first_voter)
            .field("peer_address_count", &peer_address_count)
            .field("peer_metadata_count", &peer_metadata_count)
            .field(
                "peer_crypto_runtime_capability_fingerprint_count",
                &peer_crypto_fingerprint_count,
            )
            .field("cluster_metadata_keys", &cluster_metadata_keys)
            .field("private_oram_epoch_count", &self.private_oram_epochs.len())
            .field(
                "private_oram_session_lease_count",
                &self.private_oram_session_leases.len(),
            )
            .field(
                "private_oram_layout_count",
                &self.private_oram_layouts.len(),
            )
            .field("this_peer_id", &self.this_peer_id)
            .field("path", &self.path)
            .field("dirty", &self.dirty.load(Ordering::Relaxed))
            .finish()
    }
}

impl Persistent {
    pub fn state(&self) -> &RaftState {
        &self.state
    }

    pub fn latest_snapshot_meta(&self) -> &SnapshotMetadataSer {
        &self.latest_snapshot_meta
    }

    pub fn update_from_snapshot(
        &mut self,
        meta: &SnapshotMetadata,
        address_by_id: PeerAddressById,
        mut metadata_by_id: PeerMetadataById,
        new_cluster_metadata: HashMap<String, serde_json::Value>,
        new_private_oram_epochs: HashMap<String, PrivateOramConsensusEpoch>,
        new_private_oram_session_leases: HashMap<String, PrivateOramSessionLease>,
        new_private_oram_layouts: HashMap<String, PrivateOramConsensusLayout>,
    ) -> Result<(), StorageError> {
        validate_private_oram_epoch_snapshot(&new_private_oram_epochs)?;
        validate_private_oram_session_lease_snapshot(&new_private_oram_session_leases)?;
        validate_private_oram_layout_snapshot(&new_private_oram_layouts)?;
        // IF YOU ADD NEW DATA INTO `PERSISTENT` STATE, DON'T FORGET TO ALSO ADD IT INTO RAFT SNAPSHOT!
        let Self {
            state,
            latest_snapshot_meta,
            apply_progress_queue,
            first_voter: _,
            peer_address_by_id,
            peer_metadata_by_id,
            cluster_metadata,
            private_oram_epochs,
            private_oram_session_leases,
            private_oram_layouts,
            this_peer_id: _,
            path: _,
            dirty: _,
        } = self;

        state.conf_state = meta.get_conf_state().clone();
        state.hard_state.term = cmp::max(state.hard_state.term, meta.term);
        state.hard_state.commit = meta.index;

        apply_progress_queue.set_from_snapshot(meta.index);
        *latest_snapshot_meta = meta.into();

        metadata_by_id.retain(|peer_id, _| address_by_id.contains_key(peer_id));

        *peer_address_by_id.write() = address_by_id;
        *peer_metadata_by_id.write() = metadata_by_id;
        *cluster_metadata = new_cluster_metadata;
        *private_oram_epochs = new_private_oram_epochs;
        *private_oram_session_leases = new_private_oram_session_leases;
        *private_oram_layouts = new_private_oram_layouts;

        // Last Raft commit and last snapshot index must be equal and persisted in one operation
        // Our `ConsensusManager::new` function relies on this for reconciling WAL clears
        debug_assert_eq!(
            state.hard_state.commit, latest_snapshot_meta.index,
            "applied Raft commit and last snapshot index must be equal",
        );

        self.save()
    }

    /// Returns state and if it was initialized for the first time
    ///
    /// `peer_id` is used only when raft state is not found.
    pub fn load_or_init(
        storage_path: impl AsRef<Path>,
        first_peer: bool,
        reinit: bool,
        peer_id: Option<PeerId>,
    ) -> Result<Self, StorageError> {
        fs::create_dir_all(storage_path.as_ref())?;
        let path_legacy = storage_path.as_ref().join(STATE_FILE_NAME_CBOR);
        let path_json = storage_path.as_ref().join(STATE_FILE_NAME);
        let mut state = if path_json.exists() {
            log::info!("Loading raft state from {}", path_json.display());
            Self::load_json(path_json.clone())?
        } else if path_legacy.exists() {
            log::info!("Loading raft state from {}", path_legacy.display());
            let mut state = Self::load(path_legacy)?;
            // migrate to json
            state.path = path_json.clone();
            state.save()?;
            state
        } else {
            log::info!("Initializing new raft state at {}", path_json.display());
            if let Some(peer_id) = peer_id {
                log::debug!("Using peer ID: {peer_id}");
            };
            Self::init(path_json.clone(), first_peer, peer_id)?
        };

        let state = if reinit {
            if first_peer {
                // Re-initialize consensus of the first peer is different from the rest
                // Effectively, we should remove all other peers from voters and learners
                // assuming that other peers would need to join consensus again.
                // PeerId if the current peer should stay in the list of voters,
                // so we can accept consensus operations.
                state.state.conf_state.voters = vec![state.this_peer_id];
                state.state.conf_state.learners = vec![];
                state.state.hard_state.vote = state.this_peer_id;
                state.save()?;
                state
            } else {
                // We want to re-initialize consensus while preserve the peer ID
                // which is needed for migration from one cluster to another
                let keep_peer_id = state.this_peer_id;
                Self::init(path_json, first_peer, Some(keep_peer_id))?
            }
        } else {
            state
        };

        state.remove_unknown_peer_metadata()?;

        log::debug!("State: {state:?}");
        Ok(state)
    }

    fn remove_unknown_peer_metadata(&self) -> Result<(), StorageError> {
        let is_updated = {
            let mut peer_metadata = self.peer_metadata_by_id.write();
            let peer_address = self.peer_address_by_id.read();
            peer_metadata
                .extract_if(|peer_id, _| !peer_address.contains_key(peer_id))
                .count()
                > 0
        };

        if is_updated {
            self.save()?;
        }

        Ok(())
    }

    pub fn unapplied_entities_count(&self) -> usize {
        self.apply_progress_queue.len()
    }

    pub fn apply_state_update(
        &mut self,
        update: impl FnOnce(&mut RaftState),
    ) -> Result<(), StorageError> {
        let mut state = self.state.clone();
        update(&mut state);
        self.state = state;
        self.save()
    }

    pub fn current_unapplied_entry(&self) -> Option<EntryId> {
        self.apply_progress_queue.current()
    }

    pub fn entry_applied(&mut self) -> Result<(), StorageError> {
        self.apply_progress_queue.applied();
        self.save()
    }

    pub fn set_unapplied_entries(
        &mut self,
        first_index: EntryId,
        last_index: EntryId,
    ) -> Result<(), StorageError> {
        self.apply_progress_queue = EntryApplyProgressQueue::new(first_index, last_index);
        self.save()
    }

    pub fn set_peer_address_by_id(
        &mut self,
        peer_address_by_id: PeerAddressById,
    ) -> Result<(), StorageError> {
        *self.peer_address_by_id.write() = peer_address_by_id;
        self.save()
    }

    pub fn insert_peer(&mut self, peer_id: PeerId, address: Uri) -> Result<(), StorageError> {
        let address_display = address.to_string();
        match self
            .peer_address_by_id
            .write()
            .insert(peer_id, address.clone())
        {
            Some(prev_address) if prev_address != address => log::warn!(
                "Replaced address of peer {peer_id} from {prev_address} to {address_display}"
            ),
            Some(_) => log::debug!(
                "Re-added peer with id {peer_id} with the same address {address_display}"
            ),
            None => log::debug!("Added peer with id {peer_id} and address {address_display}"),
        }
        self.save()
    }

    pub fn update_peer_metadata(
        &mut self,
        peer_id: PeerId,
        metadata: PeerMetadata,
    ) -> Result<(), StorageError> {
        if let Some(prev_metadata) = self
            .peer_metadata_by_id
            .write()
            .insert(peer_id, metadata.clone())
        {
            log::info!(
                "Replaced metadata of peer {peer_id} from {prev_metadata:?} to {metadata:?}"
            );
        } else {
            log::debug!("Added metadata for peer with id {peer_id}: {metadata:?}")
        }
        self.save()
    }

    pub fn get_cluster_metadata_keys(&self) -> Vec<String> {
        self.cluster_metadata.keys().cloned().collect()
    }

    pub fn get_cluster_metadata_key(&self, key: &str) -> serde_json::Value {
        self.cluster_metadata
            .get(key)
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    }

    pub fn update_cluster_metadata_key(&mut self, key: String, value: serde_json::Value) {
        if !value.is_null() {
            self.cluster_metadata.insert(key, value);
        } else {
            self.cluster_metadata.remove(&key);
        }
    }

    pub fn private_oram_epoch(
        &self,
        key: &PrivateOramEpochKey,
    ) -> Option<PrivateOramConsensusEpoch> {
        self.private_oram_epochs
            .get(&private_oram_epoch_key_digest(key))
            .cloned()
    }

    pub fn compare_and_swap_private_oram_epoch(
        &mut self,
        operation: &CompareAndSwapPrivateOramEpoch,
    ) -> Result<(), StorageError> {
        validate_private_oram_epoch_cas(operation)?;
        let key = private_oram_epoch_key_digest(&operation.key);
        let current = self.private_oram_epochs.get(&key);
        if current == Some(&operation.new) {
            return Ok(());
        }
        if current != operation.expected.as_ref() {
            return Err(StorageError::bad_request(
                "private ORAM consensus epoch/root CAS precondition failed",
            ));
        }
        if operation.expected.is_none()
            && self.private_oram_epochs.len() >= PRIVATE_ORAM_EPOCH_MAX_RECORDS
        {
            return Err(StorageError::bad_request(
                "private ORAM consensus epoch capacity exceeded",
            ));
        }

        let previous = self
            .private_oram_epochs
            .insert(key.clone(), operation.new.clone());
        if let Err(err) = self.save() {
            match previous {
                Some(previous) => {
                    self.private_oram_epochs.insert(key, previous);
                }
                None => {
                    self.private_oram_epochs.remove(&key);
                }
            }
            return Err(err);
        }
        Ok(())
    }

    pub fn private_oram_session_lease(
        &self,
        key: &PrivateOramEpochKey,
    ) -> Option<PrivateOramSessionLease> {
        self.private_oram_session_leases
            .get(&private_oram_epoch_key_digest(key))
            .cloned()
    }

    pub fn compare_and_swap_private_oram_session_lease(
        &mut self,
        operation: &CompareAndSwapPrivateOramSessionLease,
    ) -> Result<(), StorageError> {
        validate_private_oram_session_lease_cas(operation)?;
        let key = private_oram_epoch_key_digest(&operation.key);
        let current = self.private_oram_session_leases.get(&key);
        if current == operation.new.as_ref() {
            return Ok(());
        }
        if current != operation.expected.as_ref() {
            return Err(StorageError::bad_request(
                "private ORAM consensus session lease CAS precondition failed",
            ));
        }
        if current.is_none()
            && operation.new.is_some()
            && self.private_oram_session_leases.len() >= PRIVATE_ORAM_EPOCH_MAX_RECORDS
        {
            return Err(StorageError::bad_request(
                "private ORAM consensus session lease capacity exceeded",
            ));
        }

        let previous = match &operation.new {
            Some(new) => self
                .private_oram_session_leases
                .insert(key.clone(), new.clone()),
            None => self.private_oram_session_leases.remove(&key),
        };
        if let Err(err) = self.save() {
            match previous {
                Some(previous) => {
                    self.private_oram_session_leases.insert(key, previous);
                }
                None => {
                    self.private_oram_session_leases.remove(&key);
                }
            }
            return Err(err);
        }
        Ok(())
    }

    pub fn private_oram_layout(
        &self,
        key: &PrivateOramLayoutKey,
    ) -> Option<PrivateOramConsensusLayout> {
        self.private_oram_layouts
            .get(&private_oram_layout_key_digest(key))
            .cloned()
    }

    pub fn validate_private_oram_collection_layout_transition(
        &self,
        transition: &PrivateOramCollectionLayoutTransition,
    ) -> Result<(), StorageError> {
        validate_private_oram_layout_cas(&transition.layout)?;
        let Some(expected_layout) = transition.layout.expected.as_ref() else {
            return Err(invalid_private_oram_collection_layout_transition());
        };
        if transition.leases.is_empty()
            || transition.leases.len() > PRIVATE_ORAM_EPOCH_MAX_RECORDS
            || expected_layout.layout_digest == transition.layout.new.layout_digest
        {
            return Err(invalid_private_oram_collection_layout_transition());
        }

        let mut states = Vec::with_capacity(transition.leases.len());
        let mut previous_key = None;
        let expected_lease = &transition.leases[0].lease;
        for binding in &transition.leases {
            if binding.key.collection_id != transition.layout.key.collection_id
                || &binding.lease != expected_lease
                || self.private_oram_session_lease(&binding.key).as_ref() != Some(&binding.lease)
            {
                return Err(invalid_private_oram_collection_layout_transition());
            }
            let key_order = private_oram_epoch_key_order(&binding.key);
            if previous_key
                .as_ref()
                .is_some_and(|previous| previous >= &key_order)
            {
                return Err(invalid_private_oram_collection_layout_transition());
            }
            previous_key = Some(key_order);
            let state = self
                .private_oram_epoch(&binding.key)
                .ok_or_else(invalid_private_oram_collection_layout_transition)?;
            states.push((binding.key.clone(), state));
        }

        let index_state_digest = canonical_private_oram_index_state_digest(
            &transition.layout.key.collection_id,
            &states,
        )?;
        if transition.layout.new.index_state_digest != index_state_digest {
            return Err(invalid_private_oram_collection_layout_transition());
        }

        let current = self.private_oram_layout(&transition.layout.key);
        if current.as_ref() != Some(expected_layout)
            && current.as_ref() != Some(&transition.layout.new)
        {
            return Err(invalid_private_oram_collection_layout_transition());
        }
        Ok(())
    }

    pub fn compare_and_swap_private_oram_layout(
        &mut self,
        operation: &CompareAndSwapPrivateOramLayout,
    ) -> Result<(), StorageError> {
        validate_private_oram_layout_cas(operation)?;
        let key = private_oram_layout_key_digest(&operation.key);
        let current = self.private_oram_layouts.get(&key);
        if current == Some(&operation.new) {
            return Ok(());
        }
        if current != operation.expected.as_ref() {
            return Err(StorageError::bad_request(
                "private ORAM consensus layout CAS precondition failed",
            ));
        }
        if operation.expected.is_none()
            && self.private_oram_layouts.len() >= PRIVATE_ORAM_EPOCH_MAX_RECORDS
        {
            return Err(StorageError::bad_request(
                "private ORAM consensus layout capacity exceeded",
            ));
        }

        let previous = self
            .private_oram_layouts
            .insert(key.clone(), operation.new.clone());
        if let Err(err) = self.save() {
            match previous {
                Some(previous) => {
                    self.private_oram_layouts.insert(key, previous);
                }
                None => {
                    self.private_oram_layouts.remove(&key);
                }
            }
            return Err(err);
        }
        Ok(())
    }

    pub fn last_applied_entry(&self) -> Option<u64> {
        self.apply_progress_queue.get_last_applied()
    }

    /// Get the last applied commit and term, reflected in our current state.
    pub fn applied_commit_term(&self) -> (u64, u64) {
        let hard_state = &self.state().hard_state;

        // Fall back to 0 because it's always less than any commit
        let last_commit = self.last_applied_entry().unwrap_or(0);

        (last_commit, hard_state.term)
    }

    pub fn first_voter(&self) -> Option<PeerId> {
        self.first_voter
    }

    pub fn set_first_voter(&mut self, id: PeerId) -> Result<(), StorageError> {
        self.first_voter = Some(id);
        self.save()
    }

    pub fn peer_address_by_id(&self) -> PeerAddressById {
        self.peer_address_by_id.read().clone()
    }

    pub fn peer_metadata_by_id(&self) -> PeerMetadataById {
        self.peer_metadata_by_id.read().clone()
    }

    pub fn is_our_metadata_outdated(&self, current_metadata: &PeerMetadata) -> bool {
        self.peer_metadata_by_id
            .read()
            .get(&self.this_peer_id())
            .is_none_or(|metadata| metadata.is_different_from(current_metadata))
    }

    pub fn this_peer_id(&self) -> PeerId {
        self.this_peer_id
    }

    /// ## Arguments
    /// `path` - full name of the file where state will be saved
    ///
    /// `first_peer` - if this is a first peer in a new deployment (e.g. it does not bootstrap from anyone)
    /// It is `None` if distributed deployment is disabled
    fn init(
        path: PathBuf,
        first_peer: bool,
        peer_id: Option<PeerId>,
    ) -> Result<Self, StorageError> {
        // Do not generate too big peer ID, to avoid problems with serialization
        // (especially in json format)
        let this_peer_id = peer_id.unwrap_or_else(|| rand::random::<PeerId>() % (1 << 53) + 1);
        let voters = if first_peer {
            vec![this_peer_id]
        } else {
            // `Some(false)` - Leave empty the network topology for the peer, if it is not starting a network itself.
            // This way it will not be able to become a leader and commit data
            // until it joins an existing network.
            vec![]
        };
        let state = Self {
            state: RaftState {
                hard_state: HardState::default(),
                // For network with 1 node, set it as voter.
                // First vec is voters, second is learners.
                conf_state: ConfState::from((voters, vec![])),
            },
            apply_progress_queue: Default::default(),
            first_voter: if first_peer { Some(this_peer_id) } else { None },
            peer_address_by_id: Default::default(),
            peer_metadata_by_id: Default::default(),
            cluster_metadata: Default::default(),
            private_oram_epochs: Default::default(),
            private_oram_session_leases: Default::default(),
            private_oram_layouts: Default::default(),
            this_peer_id,
            path,
            latest_snapshot_meta: Default::default(),
            dirty: AtomicBool::new(false),
        };
        state.save()?;
        Ok(state)
    }

    fn load(path: PathBuf) -> Result<Self, StorageError> {
        let reader = BufReader::new(File::open(&path)?);
        let mut state: Self = serde_cbor::from_reader(reader)?;
        validate_private_oram_epoch_snapshot(&state.private_oram_epochs)?;
        validate_private_oram_session_lease_snapshot(&state.private_oram_session_leases)?;
        validate_private_oram_layout_snapshot(&state.private_oram_layouts)?;
        state.path = path;
        Ok(state)
    }

    fn load_json(path: PathBuf) -> Result<Self, StorageError> {
        let reader = BufReader::new(File::open(&path)?);
        let mut state: Self = serde_json::from_reader(reader)?;
        validate_private_oram_epoch_snapshot(&state.private_oram_epochs)?;
        validate_private_oram_session_lease_snapshot(&state.private_oram_session_leases)?;
        validate_private_oram_layout_snapshot(&state.private_oram_layouts)?;
        state.path = path;
        Ok(state)
    }

    pub fn save(&self) -> Result<(), StorageError> {
        let result = AtomicFile::new(&self.path, AllowOverwrite).write(|file| {
            let mut writer = BufWriter::new(file);
            serde_json::to_writer(&mut writer, self)?;
            writer.flush()
        });
        log::trace!("Saved state: {self:?}");
        self.dirty.store(result.is_err(), Ordering::Relaxed);
        Ok(result?)
    }

    pub fn save_if_dirty(&mut self) -> Result<(), StorageError> {
        if self.dirty.load(Ordering::Relaxed) {
            self.save()?;
        }
        Ok(())
    }
}

fn private_oram_epoch_key_digest(key: &PrivateOramEpochKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_ORAM_EPOCH_KEY_DOMAIN);
    update_length_prefixed(&mut hasher, key.collection_id.as_bytes());
    hasher.update([match key.index_kind {
        PrivateOramIndexKind::Hnsw => 1,
        PrivateOramIndexKind::ResultPayload => 2,
    }]);
    update_length_prefixed(&mut hasher, key.index_name.as_bytes());
    BASE64URL_NOPAD.encode(&hasher.finalize())
}

fn private_oram_layout_key_digest(key: &PrivateOramLayoutKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_ORAM_LAYOUT_KEY_DOMAIN);
    update_length_prefixed(&mut hasher, key.collection_id.as_bytes());
    BASE64URL_NOPAD.encode(&hasher.finalize())
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn validate_private_oram_epoch_cas(
    operation: &CompareAndSwapPrivateOramEpoch,
) -> Result<(), StorageError> {
    validate_private_oram_epoch_key(&operation.key)?;

    validate_private_oram_consensus_root_hash(&operation.new.root_hash)?;
    validate_private_oram_consensus_writeback_digest(operation.new.writeback_digest.as_deref())?;
    if let Some(expected) = &operation.expected {
        validate_private_oram_consensus_root_hash(&expected.root_hash)?;
        validate_private_oram_consensus_writeback_digest(expected.writeback_digest.as_deref())?;
        if operation.new.index_epoch <= expected.index_epoch {
            return Err(StorageError::bad_request(
                "private ORAM consensus epoch must increase",
            ));
        }
    }
    Ok(())
}

fn validate_private_oram_epoch_key(key: &PrivateOramEpochKey) -> Result<(), StorageError> {
    let valid_key = !key.collection_id.is_empty()
        && key.collection_id.len() <= 1024
        && match key.index_kind {
            PrivateOramIndexKind::Hnsw => !key.index_name.is_empty() && key.index_name.len() <= 128,
            PrivateOramIndexKind::ResultPayload => key.index_name.is_empty(),
        };
    if !valid_key {
        return Err(StorageError::bad_request(
            "private ORAM consensus epoch key is invalid",
        ));
    }

    Ok(())
}

fn validate_private_oram_layout_cas(
    operation: &CompareAndSwapPrivateOramLayout,
) -> Result<(), StorageError> {
    validate_private_oram_layout_key(&operation.key)?;
    validate_private_oram_consensus_layout(&operation.new)?;
    match &operation.expected {
        Some(expected) => {
            validate_private_oram_consensus_layout(expected)?;
            if expected
                .generation
                .checked_add(1)
                .is_none_or(|next_generation| operation.new.generation != next_generation)
            {
                return Err(StorageError::bad_request(
                    "private ORAM consensus layout generation must increase by one",
                ));
            }
        }
        None if operation.new.generation != 1 => {
            return Err(StorageError::bad_request(
                "private ORAM consensus layout must start at generation one",
            ));
        }
        None => {}
    }
    Ok(())
}

fn private_oram_epoch_key_order(key: &PrivateOramEpochKey) -> (u8, &[u8]) {
    let kind = match key.index_kind {
        PrivateOramIndexKind::Hnsw => 1,
        PrivateOramIndexKind::ResultPayload => 2,
    };
    (kind, key.index_name.as_bytes())
}

fn invalid_private_oram_collection_layout_transition() -> StorageError {
    StorageError::bad_request("private ORAM collection layout transition is invalid")
}

fn validate_private_oram_layout_key(key: &PrivateOramLayoutKey) -> Result<(), StorageError> {
    if key.collection_id.is_empty() || key.collection_id.len() > 1024 {
        return Err(StorageError::bad_request(
            "private ORAM consensus layout key is invalid",
        ));
    }
    Ok(())
}

fn validate_private_oram_consensus_layout(
    layout: &PrivateOramConsensusLayout,
) -> Result<(), StorageError> {
    let owners_are_canonical = !layout.owner_peer_ids.is_empty()
        && layout.owner_peer_ids.len() <= PRIVATE_ORAM_LAYOUT_MAX_OWNERS
        && layout
            .owner_peer_ids
            .windows(2)
            .all(|owners| owners[0] < owners[1]);
    if layout.generation == 0 || !owners_are_canonical {
        return Err(StorageError::bad_request(
            "private ORAM consensus layout is invalid",
        ));
    }
    validate_private_oram_consensus_digest(&layout.layout_digest)
        .map_err(|_| StorageError::bad_request("private ORAM consensus layout is invalid"))?;
    validate_private_oram_consensus_digest(&layout.index_state_digest)
        .map_err(|_| StorageError::bad_request("private ORAM consensus layout is invalid"))?;
    Ok(())
}

fn validate_private_oram_session_lease_cas(
    operation: &CompareAndSwapPrivateOramSessionLease,
) -> Result<(), StorageError> {
    validate_private_oram_epoch_key(&operation.key)?;
    if operation.expected.is_none() && operation.new.is_none() {
        return Err(StorageError::bad_request(
            "private ORAM consensus session lease CAS is invalid",
        ));
    }
    if let Some(expected) = &operation.expected {
        validate_private_oram_session_lease(expected)?;
    }
    if let Some(new) = &operation.new {
        validate_private_oram_session_lease(new)?;
    }
    if let (Some(expected), Some(new)) = (&operation.expected, &operation.new) {
        let same_owner = expected.owner_peer_id == new.owner_peer_id
            && expected.lease_id_hash == new.lease_id_hash;
        let valid_renewal = same_owner
            && new.issued_at_unix >= expected.issued_at_unix
            && new.expires_at_unix > expected.expires_at_unix;
        let valid_takeover = !same_owner && new.issued_at_unix >= expected.expires_at_unix;
        if !valid_renewal && !valid_takeover {
            return Err(StorageError::bad_request(
                "private ORAM consensus session lease transition is invalid",
            ));
        }
    }
    Ok(())
}

fn validate_private_oram_session_lease(
    lease: &PrivateOramSessionLease,
) -> Result<(), StorageError> {
    validate_private_oram_consensus_digest(&lease.lease_id_hash).map_err(|_| {
        StorageError::bad_request("private ORAM consensus session lease is invalid")
    })?;
    if lease.expires_at_unix <= lease.issued_at_unix
        || lease.expires_at_unix - lease.issued_at_unix > PRIVATE_ORAM_SESSION_LEASE_MAX_SECS
    {
        return Err(StorageError::bad_request(
            "private ORAM consensus session lease is invalid",
        ));
    }
    Ok(())
}

fn validate_private_oram_consensus_root_hash(root_hash: &str) -> Result<(), StorageError> {
    if root_hash.len() != PRIVATE_ORAM_SHA256_BASE64URL_LEN {
        return Err(StorageError::bad_request(
            "private ORAM consensus root hash is invalid",
        ));
    }
    let decoded = BASE64URL_NOPAD
        .decode(root_hash.as_bytes())
        .map_err(|_| StorageError::bad_request("private ORAM consensus root hash is invalid"))?;
    if decoded.len() != 32 || BASE64URL_NOPAD.encode(&decoded) != root_hash {
        return Err(StorageError::bad_request(
            "private ORAM consensus root hash is invalid",
        ));
    }
    Ok(())
}

fn validate_private_oram_consensus_writeback_digest(
    digest: Option<&str>,
) -> Result<(), StorageError> {
    let Some(digest) = digest else {
        return Ok(());
    };
    if digest.len() != PRIVATE_ORAM_SHA256_BASE64URL_LEN {
        return Err(StorageError::bad_request(
            "private ORAM consensus writeback digest is invalid",
        ));
    }
    let decoded = BASE64URL_NOPAD.decode(digest.as_bytes()).map_err(|_| {
        StorageError::bad_request("private ORAM consensus writeback digest is invalid")
    })?;
    if decoded.len() != 32 || BASE64URL_NOPAD.encode(&decoded) != digest {
        return Err(StorageError::bad_request(
            "private ORAM consensus writeback digest is invalid",
        ));
    }
    Ok(())
}

fn validate_private_oram_epoch_snapshot(
    epochs: &HashMap<String, PrivateOramConsensusEpoch>,
) -> Result<(), StorageError> {
    if epochs.len() > PRIVATE_ORAM_EPOCH_MAX_RECORDS {
        return Err(StorageError::bad_request(
            "private ORAM consensus epoch snapshot is invalid",
        ));
    }
    for (key_digest, epoch) in epochs {
        validate_private_oram_consensus_digest(key_digest)?;
        validate_private_oram_consensus_root_hash(&epoch.root_hash)?;
        validate_private_oram_consensus_writeback_digest(epoch.writeback_digest.as_deref())?;
    }
    Ok(())
}

fn validate_private_oram_session_lease_snapshot(
    leases: &HashMap<String, PrivateOramSessionLease>,
) -> Result<(), StorageError> {
    if leases.len() > PRIVATE_ORAM_EPOCH_MAX_RECORDS {
        return Err(StorageError::bad_request(
            "private ORAM consensus session lease snapshot is invalid",
        ));
    }
    for (key_digest, lease) in leases {
        validate_private_oram_consensus_digest(key_digest).map_err(|_| {
            StorageError::bad_request("private ORAM consensus session lease snapshot is invalid")
        })?;
        validate_private_oram_session_lease(lease).map_err(|_| {
            StorageError::bad_request("private ORAM consensus session lease snapshot is invalid")
        })?;
    }
    Ok(())
}

fn validate_private_oram_layout_snapshot(
    layouts: &HashMap<String, PrivateOramConsensusLayout>,
) -> Result<(), StorageError> {
    if layouts.len() > PRIVATE_ORAM_EPOCH_MAX_RECORDS {
        return Err(StorageError::bad_request(
            "private ORAM consensus layout snapshot is invalid",
        ));
    }
    for (key_digest, layout) in layouts {
        validate_private_oram_consensus_digest(key_digest).map_err(|_| {
            StorageError::bad_request("private ORAM consensus layout snapshot is invalid")
        })?;
        validate_private_oram_consensus_layout(layout).map_err(|_| {
            StorageError::bad_request("private ORAM consensus layout snapshot is invalid")
        })?;
    }
    Ok(())
}

fn validate_private_oram_consensus_digest(digest: &str) -> Result<(), StorageError> {
    if digest.len() != PRIVATE_ORAM_SHA256_BASE64URL_LEN {
        return Err(StorageError::bad_request(
            "private ORAM consensus epoch snapshot is invalid",
        ));
    }
    let decoded = BASE64URL_NOPAD.decode(digest.as_bytes()).map_err(|_| {
        StorageError::bad_request("private ORAM consensus epoch snapshot is invalid")
    })?;
    if decoded.len() != 32 || BASE64URL_NOPAD.encode(&decoded) != digest {
        return Err(StorageError::bad_request(
            "private ORAM consensus epoch snapshot is invalid",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_debug_redacts_peer_and_cluster_metadata_values() {
        let mut peer_address_by_id = PeerAddressById::new();
        peer_address_by_id.insert(
            7,
            "http://qdrant-sec-peer-address-sentinel:6335"
                .parse()
                .unwrap(),
        );

        let mut peer_metadata_by_id = PeerMetadataById::new();
        peer_metadata_by_id.insert(
            7,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "qdrant-sec-peer-fingerprint-sentinel".to_string(),
            )),
        );

        let mut cluster_metadata = HashMap::new();
        cluster_metadata.insert(
            "crypto_policy".to_string(),
            serde_json::json!("qdrant-sec-cluster-metadata-sentinel"),
        );

        let private_oram_key = PrivateOramEpochKey {
            collection_id: "qdrant-sec-private-oram-collection-sentinel".to_string(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "qdrant-sec-private-oram-vector-sentinel".to_string(),
        };
        let private_oram_root = BASE64URL_NOPAD.encode(b"private-oram-root-hash-sentinel");
        let private_oram_epochs = HashMap::from([(
            private_oram_epoch_key_digest(&private_oram_key),
            PrivateOramConsensusEpoch {
                index_epoch: 42,
                root_hash: private_oram_root.clone(),
                writeback_digest: None,
            },
        )]);
        let private_oram_layout_key = PrivateOramLayoutKey {
            collection_id: "qdrant-sec-private-oram-layout-collection-sentinel".to_string(),
        };
        let private_oram_layout_digest = BASE64URL_NOPAD.encode(&[51; 32]);
        let private_oram_index_state_digest = BASE64URL_NOPAD.encode(&[52; 32]);
        let private_oram_layouts = HashMap::from([(
            private_oram_layout_key_digest(&private_oram_layout_key),
            PrivateOramConsensusLayout {
                generation: 1,
                owner_peer_ids: vec![7, 9],
                layout_digest: private_oram_layout_digest.clone(),
                index_state_digest: private_oram_index_state_digest.clone(),
            },
        )]);

        let persistent = Persistent {
            state: RaftState::default(),
            latest_snapshot_meta: SnapshotMetadataSer::default(),
            apply_progress_queue: EntryApplyProgressQueue::default(),
            first_voter: Some(7),
            peer_address_by_id: Arc::new(RwLock::new(peer_address_by_id)),
            peer_metadata_by_id: Arc::new(RwLock::new(peer_metadata_by_id)),
            cluster_metadata,
            private_oram_epochs,
            private_oram_session_leases: Default::default(),
            private_oram_layouts,
            this_peer_id: 7,
            path: PathBuf::from("/tmp/qdrant-sec-persistent-state"),
            dirty: AtomicBool::new(false),
        };

        let rendered = format!("{persistent:?}");

        assert!(rendered.contains("peer_address_count: 1"), "{rendered}");
        assert!(
            rendered.contains("peer_crypto_runtime_capability_fingerprint_count: 1"),
            "{rendered}",
        );
        assert!(rendered.contains("crypto_policy"), "{rendered}");
        assert!(
            rendered.contains("private_oram_epoch_count: 1"),
            "{rendered}"
        );
        assert!(
            rendered.contains("private_oram_layout_count: 1"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("qdrant-sec-peer-address-sentinel"),
            "{rendered}",
        );
        assert!(
            !rendered.contains("qdrant-sec-peer-fingerprint-sentinel"),
            "{rendered}",
        );
        assert!(
            !rendered.contains("qdrant-sec-cluster-metadata-sentinel"),
            "{rendered}",
        );
        assert!(!rendered.contains(&private_oram_root), "{rendered}");
        assert!(
            !rendered.contains("qdrant-sec-private-oram-collection-sentinel"),
            "{rendered}",
        );
        assert!(
            !rendered.contains("qdrant-sec-private-oram-vector-sentinel"),
            "{rendered}",
        );
        assert!(
            !rendered.contains(&private_oram_layout_digest),
            "{rendered}"
        );
        assert!(
            !rendered.contains(&private_oram_index_state_digest),
            "{rendered}"
        );
        assert!(
            !rendered.contains("qdrant-sec-private-oram-layout-collection-sentinel"),
            "{rendered}"
        );
    }

    #[test]
    fn private_oram_epoch_cas_persists_and_rejects_stale_or_invalid_updates() {
        let temp = tempfile::tempdir().unwrap();
        let key = PrivateOramEpochKey {
            collection_id: "collection-uuid-1".to_string(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "text".to_string(),
        };
        let initial = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
            writeback_digest: None,
        };
        let next = PrivateOramConsensusEpoch {
            index_epoch: 43,
            root_hash: BASE64URL_NOPAD.encode(&[43; 32]),
            writeback_digest: Some(BASE64URL_NOPAD.encode(&[11; 32])),
        };
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();

        persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: None,
                new: initial.clone(),
            })
            .unwrap();
        persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: None,
                new: initial.clone(),
            })
            .unwrap();
        assert_eq!(persistent.private_oram_epoch(&key), Some(initial.clone()));

        let stale = persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: None,
                new: next.clone(),
            })
            .unwrap_err();
        assert!(
            stale
                .to_string()
                .contains("consensus epoch/root CAS precondition failed"),
        );
        assert_eq!(persistent.private_oram_epoch(&key), Some(initial.clone()));

        let non_increasing = persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: Some(initial.clone()),
                new: PrivateOramConsensusEpoch {
                    index_epoch: initial.index_epoch,
                    root_hash: next.root_hash.clone(),
                    writeback_digest: next.writeback_digest.clone(),
                },
            })
            .unwrap_err();
        assert!(
            non_increasing
                .to_string()
                .contains("consensus epoch must increase"),
        );

        let invalid_root_sentinel = "private-oram-invalid-root-sentinel";
        let invalid_root = persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: Some(initial.clone()),
                new: PrivateOramConsensusEpoch {
                    index_epoch: 43,
                    root_hash: invalid_root_sentinel.to_string(),
                    writeback_digest: next.writeback_digest.clone(),
                },
            })
            .unwrap_err();
        assert!(
            invalid_root
                .to_string()
                .contains("consensus root hash is invalid"),
        );
        assert!(!invalid_root.to_string().contains(invalid_root_sentinel));

        let invalid_writeback_digest_sentinel = "private-oram-invalid-writeback-digest-sentinel";
        let invalid_writeback_digest = persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: Some(initial.clone()),
                new: PrivateOramConsensusEpoch {
                    index_epoch: 43,
                    root_hash: next.root_hash.clone(),
                    writeback_digest: Some(invalid_writeback_digest_sentinel.to_string()),
                },
            })
            .unwrap_err();
        assert!(
            invalid_writeback_digest
                .to_string()
                .contains("consensus writeback digest is invalid"),
        );
        assert!(
            !invalid_writeback_digest
                .to_string()
                .contains(invalid_writeback_digest_sentinel),
        );

        persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: Some(initial.clone()),
                new: next.clone(),
            })
            .unwrap();

        let conflicting_digest = persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: Some(initial),
                new: PrivateOramConsensusEpoch {
                    index_epoch: next.index_epoch,
                    root_hash: next.root_hash.clone(),
                    writeback_digest: Some(BASE64URL_NOPAD.encode(&[12; 32])),
                },
            })
            .unwrap_err();
        assert!(
            conflicting_digest
                .to_string()
                .contains("consensus epoch/root CAS precondition failed"),
        );
        assert_eq!(persistent.private_oram_epoch(&key), Some(next.clone()));
        drop(persistent);

        let mut reloaded = Persistent::load_or_init(temp.path(), true, false, None).unwrap();
        reloaded
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: Some(PrivateOramConsensusEpoch {
                    index_epoch: 42,
                    root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
                    writeback_digest: None,
                }),
                new: next.clone(),
            })
            .unwrap();
        assert_eq!(reloaded.private_oram_epoch(&key), Some(next));
    }

    #[test]
    fn private_oram_layout_cas_persists_and_enforces_canonical_transitions() {
        let temp = tempfile::tempdir().unwrap();
        let key = PrivateOramLayoutKey {
            collection_id: "collection-uuid-1".to_string(),
        };
        let initial = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![7, 9],
            layout_digest: BASE64URL_NOPAD.encode(&[41; 32]),
            index_state_digest: BASE64URL_NOPAD.encode(&[42; 32]),
        };
        let next = PrivateOramConsensusLayout {
            generation: 2,
            owner_peer_ids: vec![7, 9, 11],
            layout_digest: BASE64URL_NOPAD.encode(&[43; 32]),
            index_state_digest: BASE64URL_NOPAD.encode(&[44; 32]),
        };
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();

        let invalid_initial_generation = persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: key.clone(),
                expected: None,
                new: PrivateOramConsensusLayout {
                    generation: 2,
                    ..initial.clone()
                },
            })
            .unwrap_err()
            .to_string();
        assert!(
            invalid_initial_generation.contains("layout must start at generation one"),
            "{invalid_initial_generation}"
        );

        let initial_operation = CompareAndSwapPrivateOramLayout {
            key: key.clone(),
            expected: None,
            new: initial.clone(),
        };
        persistent
            .compare_and_swap_private_oram_layout(&initial_operation)
            .unwrap();
        persistent
            .compare_and_swap_private_oram_layout(&initial_operation)
            .unwrap();
        assert_eq!(persistent.private_oram_layout(&key), Some(initial.clone()));

        let stale = persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: key.clone(),
                expected: None,
                new: PrivateOramConsensusLayout {
                    layout_digest: BASE64URL_NOPAD.encode(&[45; 32]),
                    ..initial.clone()
                },
            })
            .unwrap_err()
            .to_string();
        assert!(stale.contains("layout CAS precondition failed"), "{stale}");

        let skipped_generation = persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: key.clone(),
                expected: Some(initial.clone()),
                new: PrivateOramConsensusLayout {
                    generation: 3,
                    ..next.clone()
                },
            })
            .unwrap_err()
            .to_string();
        assert!(
            skipped_generation.contains("layout generation must increase by one"),
            "{skipped_generation}"
        );

        let invalid_owner_sets = [
            Vec::new(),
            vec![9, 7],
            vec![7, 7],
            (0..=PRIVATE_ORAM_LAYOUT_MAX_OWNERS as PeerId).collect(),
        ];
        for owner_peer_ids in invalid_owner_sets {
            let noncanonical_owners = persistent
                .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                    key: key.clone(),
                    expected: Some(initial.clone()),
                    new: PrivateOramConsensusLayout {
                        owner_peer_ids,
                        ..next.clone()
                    },
                })
                .unwrap_err()
                .to_string();
            assert!(
                noncanonical_owners.contains("consensus layout is invalid"),
                "{noncanonical_owners}"
            );
        }

        let invalid_digest_sentinel = "private-oram-layout-digest-sentinel";
        let invalid_digest = persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: key.clone(),
                expected: Some(initial.clone()),
                new: PrivateOramConsensusLayout {
                    layout_digest: invalid_digest_sentinel.to_string(),
                    ..next.clone()
                },
            })
            .unwrap_err()
            .to_string();
        assert!(invalid_digest.contains("consensus layout is invalid"));
        assert!(!invalid_digest.contains(invalid_digest_sentinel));

        let transition = CompareAndSwapPrivateOramLayout {
            key: key.clone(),
            expected: Some(initial),
            new: next.clone(),
        };
        persistent
            .compare_and_swap_private_oram_layout(&transition)
            .unwrap();
        persistent
            .compare_and_swap_private_oram_layout(&transition)
            .unwrap();
        assert_eq!(persistent.private_oram_layout(&key), Some(next.clone()));
        drop(persistent);

        let reloaded = Persistent::load_or_init(temp.path(), true, false, None).unwrap();
        assert_eq!(reloaded.private_oram_layout(&key), Some(next));
    }

    #[test]
    fn private_oram_collection_layout_transition_binds_exact_lease_and_current_index_state() {
        let temp = tempfile::tempdir().unwrap();
        let collection_id = "collection-uuid-1";
        let epoch_key = PrivateOramEpochKey {
            collection_id: collection_id.to_string(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "text".to_string(),
        };
        let epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
            writeback_digest: Some(BASE64URL_NOPAD.encode(&[43; 32])),
        };
        let lease = PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: BASE64URL_NOPAD.encode(&[44; 32]),
            issued_at_unix: 100,
            expires_at_unix: 160,
        };
        let layout_key = PrivateOramLayoutKey {
            collection_id: collection_id.to_string(),
        };
        let current = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![7, 9],
            layout_digest: BASE64URL_NOPAD.encode(&[45; 32]),
            index_state_digest: BASE64URL_NOPAD.encode(&[46; 32]),
        };
        let current_index_state_digest = canonical_private_oram_index_state_digest(
            collection_id,
            &[(epoch_key.clone(), epoch.clone())],
        )
        .unwrap();
        let next = PrivateOramConsensusLayout {
            generation: 2,
            owner_peer_ids: vec![7],
            layout_digest: BASE64URL_NOPAD.encode(&[47; 32]),
            index_state_digest: current_index_state_digest,
        };
        let transition = PrivateOramCollectionLayoutTransition {
            layout: CompareAndSwapPrivateOramLayout {
                key: layout_key.clone(),
                expected: Some(current.clone()),
                new: next,
            },
            leases: vec![
                crate::content_manager::consensus_ops::PrivateOramLayoutLeaseBinding {
                    key: epoch_key.clone(),
                    lease: lease.clone(),
                },
            ],
            collection_meta: Box::new(
                crate::content_manager::collection_meta_ops::CollectionMetaOperations::Nop {
                    token: 7,
                },
            ),
        };
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: epoch_key.clone(),
                expected: None,
                new: epoch,
            })
            .unwrap();
        persistent
            .compare_and_swap_private_oram_session_lease(&CompareAndSwapPrivateOramSessionLease {
                key: epoch_key,
                expected: None,
                new: Some(lease),
            })
            .unwrap();
        persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: layout_key,
                expected: None,
                new: current,
            })
            .unwrap();

        persistent
            .validate_private_oram_collection_layout_transition(&transition)
            .unwrap();

        let mut wrong_lease = transition.clone();
        wrong_lease.leases[0].lease.lease_id_hash = BASE64URL_NOPAD.encode(&[48; 32]);
        let error = persistent
            .validate_private_oram_collection_layout_transition(&wrong_lease)
            .unwrap_err()
            .to_string();
        assert!(error.contains("layout transition is invalid"), "{error}");
        assert!(!error.contains(&wrong_lease.leases[0].lease.lease_id_hash));
    }

    #[test]
    fn private_oram_layout_snapshot_validation_rejects_malformed_records_before_replace() {
        let temp = tempfile::tempdir().unwrap();
        let key = PrivateOramLayoutKey {
            collection_id: "collection-uuid-1".to_string(),
        };
        let initial = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![7, 9],
            layout_digest: BASE64URL_NOPAD.encode(&[61; 32]),
            index_state_digest: BASE64URL_NOPAD.encode(&[62; 32]),
        };
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: key.clone(),
                expected: None,
                new: initial.clone(),
            })
            .unwrap();

        let invalid_key_sentinel = "private-oram-layout-snapshot-key-sentinel";
        let invalid_key_error = persistent
            .update_from_snapshot(
                &SnapshotMetadata::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                HashMap::from([(invalid_key_sentinel.to_string(), initial.clone())]),
            )
            .unwrap_err()
            .to_string();
        assert!(
            invalid_key_error.contains("consensus layout snapshot is invalid"),
            "{invalid_key_error}"
        );
        assert!(!invalid_key_error.contains(invalid_key_sentinel));
        assert_eq!(persistent.private_oram_layout(&key), Some(initial.clone()));

        let invalid_digest_sentinel = "private-oram-layout-snapshot-digest-sentinel";
        let invalid_layout_error = persistent
            .update_from_snapshot(
                &SnapshotMetadata::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                HashMap::from([(
                    private_oram_layout_key_digest(&key),
                    PrivateOramConsensusLayout {
                        layout_digest: invalid_digest_sentinel.to_string(),
                        ..initial.clone()
                    },
                )]),
            )
            .unwrap_err()
            .to_string();
        assert!(
            invalid_layout_error.contains("consensus layout snapshot is invalid"),
            "{invalid_layout_error}"
        );
        assert!(!invalid_layout_error.contains(invalid_digest_sentinel));
        assert_eq!(persistent.private_oram_layout(&key), Some(initial));
    }

    #[test]
    fn private_oram_session_lease_cas_enforces_renewal_takeover_and_release() {
        let temp = tempfile::tempdir().unwrap();
        let key = PrivateOramEpochKey {
            collection_id: "collection-uuid-1".to_string(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "text".to_string(),
        };
        let lease_hash_a = BASE64URL_NOPAD.encode(&[21; 32]);
        let lease_hash_b = BASE64URL_NOPAD.encode(&[22; 32]);
        let lease_a = PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: lease_hash_a.clone(),
            issued_at_unix: 100,
            expires_at_unix: 160,
        };
        let renewed_a = PrivateOramSessionLease {
            issued_at_unix: 120,
            expires_at_unix: 220,
            ..lease_a.clone()
        };
        let lease_b = PrivateOramSessionLease {
            owner_peer_id: 9,
            lease_id_hash: lease_hash_b.clone(),
            issued_at_unix: 220,
            expires_at_unix: 280,
        };
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();

        let acquire = CompareAndSwapPrivateOramSessionLease {
            key: key.clone(),
            expected: None,
            new: Some(lease_a.clone()),
        };
        persistent
            .compare_and_swap_private_oram_session_lease(&acquire)
            .unwrap();
        persistent
            .compare_and_swap_private_oram_session_lease(&acquire)
            .unwrap();
        assert_eq!(
            persistent.private_oram_session_lease(&key),
            Some(lease_a.clone())
        );

        let early_takeover = persistent
            .compare_and_swap_private_oram_session_lease(&CompareAndSwapPrivateOramSessionLease {
                key: key.clone(),
                expected: Some(lease_a.clone()),
                new: Some(PrivateOramSessionLease {
                    issued_at_unix: 159,
                    expires_at_unix: 219,
                    ..lease_b.clone()
                }),
            })
            .unwrap_err()
            .to_string();
        assert!(early_takeover.contains("session lease transition is invalid"));

        persistent
            .compare_and_swap_private_oram_session_lease(&CompareAndSwapPrivateOramSessionLease {
                key: key.clone(),
                expected: Some(lease_a.clone()),
                new: Some(renewed_a.clone()),
            })
            .unwrap();
        let stale_release = persistent
            .compare_and_swap_private_oram_session_lease(&CompareAndSwapPrivateOramSessionLease {
                key: key.clone(),
                expected: Some(lease_a),
                new: None,
            })
            .unwrap_err()
            .to_string();
        assert!(stale_release.contains("session lease CAS precondition failed"));

        persistent
            .compare_and_swap_private_oram_session_lease(&CompareAndSwapPrivateOramSessionLease {
                key: key.clone(),
                expected: Some(renewed_a),
                new: Some(lease_b.clone()),
            })
            .unwrap();
        assert_eq!(
            persistent.private_oram_session_lease(&key),
            Some(lease_b.clone())
        );

        let rendered = format!("{:?}", persistent.private_oram_session_lease(&key).unwrap());
        assert!(rendered.contains("owner_peer_id: 9"));
        assert!(!rendered.contains(&lease_hash_a));
        assert!(!rendered.contains(&lease_hash_b));

        persistent
            .compare_and_swap_private_oram_session_lease(&CompareAndSwapPrivateOramSessionLease {
                key: key.clone(),
                expected: Some(lease_b),
                new: None,
            })
            .unwrap();
        assert_eq!(persistent.private_oram_session_lease(&key), None);
        drop(persistent);

        let reloaded = Persistent::load_or_init(temp.path(), true, false, None).unwrap();
        assert_eq!(reloaded.private_oram_session_lease(&key), None);

        let invalid_hash = "private-oram-session-lease-hash-sentinel";
        let invalid = validate_private_oram_session_lease(&PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: invalid_hash.to_string(),
            issued_at_unix: 100,
            expires_at_unix: 160,
        })
        .unwrap_err()
        .to_string();
        assert!(invalid.contains("session lease is invalid"));
        assert!(!invalid.contains(invalid_hash));

        let overlong = validate_private_oram_session_lease(&PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: BASE64URL_NOPAD.encode(&[23; 32]),
            issued_at_unix: 100,
            expires_at_unix: 100 + PRIVATE_ORAM_SESSION_LEASE_MAX_SECS + 1,
        })
        .unwrap_err()
        .to_string();
        assert!(overlong.contains("session lease is invalid"));

        let malformed_snapshot_key = "private-oram-session-lease-snapshot-key-sentinel";
        let malformed_snapshot = validate_private_oram_session_lease_snapshot(&HashMap::from([(
            malformed_snapshot_key.to_string(),
            PrivateOramSessionLease {
                owner_peer_id: 7,
                lease_id_hash: BASE64URL_NOPAD.encode(&[24; 32]),
                issued_at_unix: 100,
                expires_at_unix: 160,
            },
        )]))
        .unwrap_err()
        .to_string();
        assert!(malformed_snapshot.contains("session lease snapshot is invalid"));
        assert!(!malformed_snapshot.contains(malformed_snapshot_key));
    }

    #[test]
    fn private_oram_epoch_cas_rolls_back_memory_state_when_persist_fails() {
        let temp = tempfile::tempdir().unwrap();
        let key = PrivateOramEpochKey {
            collection_id: "collection-uuid-1".to_string(),
            index_kind: PrivateOramIndexKind::ResultPayload,
            index_name: String::new(),
        };
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        persistent.path = temp.path().join("missing-parent").join("raft_state.json");

        persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: None,
                new: PrivateOramConsensusEpoch {
                    index_epoch: 7,
                    root_hash: BASE64URL_NOPAD.encode(&[7; 32]),
                    writeback_digest: None,
                },
            })
            .unwrap_err();

        assert_eq!(persistent.private_oram_epoch(&key), None);
    }

    #[test]
    fn private_oram_epoch_snapshot_validation_rejects_malformed_records_before_replace() {
        let temp = tempfile::tempdir().unwrap();
        let key = PrivateOramEpochKey {
            collection_id: "collection-uuid-1".to_string(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "text".to_string(),
        };
        let initial = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
            writeback_digest: None,
        };
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: None,
                new: initial.clone(),
            })
            .unwrap();

        let invalid_key_digest_sentinel = "private-oram-invalid-key-digest-sentinel";
        let malformed_key_digest = HashMap::from([(
            invalid_key_digest_sentinel.to_string(),
            PrivateOramConsensusEpoch {
                index_epoch: 43,
                root_hash: BASE64URL_NOPAD.encode(&[43; 32]),
                writeback_digest: None,
            },
        )]);
        let digest_error = persistent
            .update_from_snapshot(
                &SnapshotMetadata::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                malformed_key_digest,
                Default::default(),
                Default::default(),
            )
            .unwrap_err();
        assert!(
            digest_error
                .to_string()
                .contains("consensus epoch snapshot is invalid"),
        );
        assert!(
            !digest_error
                .to_string()
                .contains(invalid_key_digest_sentinel),
        );
        assert_eq!(persistent.private_oram_epoch(&key), Some(initial.clone()));

        let invalid_writeback_digest_sentinel =
            "private-oram-invalid-snapshot-writeback-digest-sentinel";
        let malformed_writeback_digest = HashMap::from([(
            private_oram_epoch_key_digest(&key),
            PrivateOramConsensusEpoch {
                index_epoch: 43,
                root_hash: BASE64URL_NOPAD.encode(&[43; 32]),
                writeback_digest: Some(invalid_writeback_digest_sentinel.to_string()),
            },
        )]);
        let writeback_digest_error = persistent
            .update_from_snapshot(
                &SnapshotMetadata::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                malformed_writeback_digest,
                Default::default(),
                Default::default(),
            )
            .unwrap_err();
        assert!(
            writeback_digest_error
                .to_string()
                .contains("consensus writeback digest is invalid"),
        );
        assert!(
            !writeback_digest_error
                .to_string()
                .contains(invalid_writeback_digest_sentinel),
        );
        assert_eq!(persistent.private_oram_epoch(&key), Some(initial.clone()));

        let invalid_root_sentinel = "private-oram-invalid-snapshot-root-sentinel";
        let malformed_root = HashMap::from([(
            private_oram_epoch_key_digest(&key),
            PrivateOramConsensusEpoch {
                index_epoch: 43,
                root_hash: invalid_root_sentinel.to_string(),
                writeback_digest: None,
            },
        )]);
        let root_error = persistent
            .update_from_snapshot(
                &SnapshotMetadata::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                malformed_root,
                Default::default(),
                Default::default(),
            )
            .unwrap_err();
        assert!(
            root_error
                .to_string()
                .contains("consensus root hash is invalid"),
        );
        assert!(!root_error.to_string().contains(invalid_root_sentinel));
        assert_eq!(persistent.private_oram_epoch(&key), Some(initial));
    }

    #[test]
    fn private_oram_epoch_load_rejects_malformed_persisted_state() {
        let temp = tempfile::tempdir().unwrap();
        let key = PrivateOramEpochKey {
            collection_id: "collection-uuid-1".to_string(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "text".to_string(),
        };
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key,
                expected: None,
                new: PrivateOramConsensusEpoch {
                    index_epoch: 42,
                    root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
                    writeback_digest: None,
                },
            })
            .unwrap();
        drop(persistent);

        let state_path = temp.path().join(STATE_FILE_NAME);
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        let epochs = state["private_oram_epochs"].as_object_mut().unwrap();
        let epoch = epochs.values_mut().next().unwrap().as_object_mut().unwrap();
        let invalid_root_sentinel = "private-oram-persisted-root-sentinel";
        epoch.insert(
            "root_hash".to_string(),
            serde_json::json!(invalid_root_sentinel),
        );
        fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();

        let error = Persistent::load_or_init(temp.path(), true, false, None).unwrap_err();
        let rendered = error.to_string();
        assert!(
            rendered.contains("consensus root hash is invalid"),
            "{rendered}"
        );
        assert!(!rendered.contains(invalid_root_sentinel), "{rendered}");
    }
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct SnapshotMetadataSer {
    pub term: u64,
    /// Aka: commit
    pub index: u64,
}

impl From<&SnapshotMetadata> for SnapshotMetadataSer {
    fn from(meta: &SnapshotMetadata) -> Self {
        Self {
            term: meta.term,
            index: meta.index,
        }
    }
}

mod serialize_peer_addresses {
    use std::collections::HashMap;
    use std::sync::Arc;

    use http::Uri;
    use parking_lot::RwLock;
    use serde::{self, Deserializer, Serializer};

    use crate::serialize_peer_addresses;
    use crate::types::PeerAddressById;

    pub fn serialize<S>(
        addresses: &Arc<RwLock<PeerAddressById>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_peer_addresses::serialize(&addresses.read(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Arc<RwLock<PeerAddressById>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let addresses: HashMap<u64, Uri> = serialize_peer_addresses::deserialize(deserializer)?;
        Ok(Arc::new(RwLock::new(addresses)))
    }
}

/// Definition of struct to help with serde serialization.
/// Should be used only in `[serde(with=...)]`
#[derive(Serialize, Deserialize)]
#[serde(remote = "RaftState")]
struct RaftStateDef {
    #[serde(with = "HardStateDef")]
    hard_state: HardState,
    #[serde(with = "ConfStateDef")]
    conf_state: ConfState,
}

/// Definition of struct to help with serde serialization.
/// Should be used only in `[serde(with=...)]`
#[derive(Serialize, Deserialize)]
#[serde(remote = "HardState")]
struct HardStateDef {
    term: u64,
    vote: u64,
    commit: u64,
}

/// Definition of struct to help with serde serialization.
/// Should be used only in `[serde(with=...)]`
#[derive(Serialize, Deserialize)]
#[serde(remote = "ConfState")]
struct ConfStateDef {
    voters: Vec<u64>,
    learners: Vec<u64>,
    voters_outgoing: Vec<u64>,
    learners_next: Vec<u64>,
    auto_leave: bool,
}
