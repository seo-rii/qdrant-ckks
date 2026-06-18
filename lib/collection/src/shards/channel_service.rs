use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use api::grpc::qdrant::WaitOnConsensusCommitRequest;
use api::grpc::qdrant::qdrant_internal_client::QdrantInternalClient;
use api::grpc::transport_channel_pool::{AddTimeout, TransportChannelPool};
use futures::Future;
use futures::future::try_join_all;
use semver::Version;
use tonic::codegen::InterceptedService;
use tonic::transport::{Channel, Uri};
use tonic::{Request, Status};
use url::Url;

use crate::operations::types::{CollectionError, CollectionResult, PeerMetadata};
use crate::shards::shard::PeerId;

#[derive(Clone)]
pub struct ChannelService {
    // Shared with consensus_state
    pub id_to_address: Arc<parking_lot::RwLock<HashMap<PeerId, Uri>>>,
    // Shared with consensus_state
    pub id_to_metadata: Arc<parking_lot::RwLock<HashMap<PeerId, PeerMetadata>>>,
    pub channel_pool: Arc<TransportChannelPool>,
    /// Port at which the public REST API is exposed for the current peer.
    pub current_rest_port: u16,
    /// Indicates whether the TLS is enabled for the public REST API.
    pub rest_tls_enabled: bool,

    /// Instance wide API key if configured, must be used with care.
    pub api_key: Option<String>,

    /// Alternative API key, works the same as `api_key`. Intended for rolling key updates.
    pub alt_api_key: Option<String>,
}

impl ChannelService {
    /// Construct a new channel service with the given REST port.
    pub fn new(
        current_rest_port: u16,
        rest_tls_enabled: bool,
        api_key: Option<String>,
        alt_api_key: Option<String>,
    ) -> Self {
        Self {
            id_to_address: Default::default(),
            id_to_metadata: Default::default(),
            channel_pool: Default::default(),
            current_rest_port,
            rest_tls_enabled,
            api_key,
            alt_api_key,
        }
    }

    pub async fn remove_peer(&self, peer_id: PeerId) {
        let removed = self.id_to_address.write().remove(&peer_id);
        if let Some(uri) = removed {
            self.channel_pool.drop_pool(&uri).await;
        }
    }

    /// Wait until all other known peers reach the given commit
    ///
    /// # Errors
    ///
    /// This errors if:
    /// - any of the peers is not on the same term
    /// - waiting takes longer than the specified timeout
    /// - any of the peers cannot be reached
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe.
    pub async fn await_commit_on_all_peers(
        &self,
        this_peer_id: PeerId,
        commit: u64,
        term: u64,
        timeout: Duration,
    ) -> CollectionResult<()> {
        let requests = self
            .id_to_address
            .read()
            .keys()
            .filter(|id| **id != this_peer_id)
            // The collective timeout at the bottom of this function handles actually timing out.
            // Since an explicit timeout must be given here as well, it is multiplied by two to
            // give the collective timeout some space.
            .map(|peer_id| self.await_commit_on_peer(*peer_id, commit, term, timeout * 2))
            .collect::<Vec<_>>();
        let responses = try_join_all(requests);

        // Handle requests with timeout
        tokio::time::timeout(timeout, responses)
            .await
            // Timeout error
            .map_err(|_elapsed| CollectionError::Timeout {
                description: "Failed to wait for consensus commit on all peers, timed out.".into(),
            })?
            // Await consensus error
            .map_err(|err| {
                CollectionError::service_error(format!(
                    "Failed to wait for consensus commit on peer: {err}"
                ))
            })?;
        Ok(())
    }

    /// Wait until the given peer reaches the given commit
    ///
    /// # Errors
    ///
    /// This errors if the given peer is on a different term. Also errors if the peer cannot be reached.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe.
    async fn await_commit_on_peer(
        &self,
        peer_id: PeerId,
        commit: u64,
        term: u64,
        timeout: Duration,
    ) -> CollectionResult<()> {
        let response = self
            .with_qdrant_client(peer_id, |mut client| async move {
                let request = WaitOnConsensusCommitRequest {
                    commit: commit as i64,
                    term: term as i64,
                    timeout: timeout.as_secs() as i64,
                };
                client.wait_on_consensus_commit(Request::new(request)).await
            })
            .await
            .map_err(|err| {
                CollectionError::service_error(format!(
                    "Failed to wait for consensus commit on peer {peer_id}: {err}"
                ))
            })?
            .into_inner();

        // Create error if wait request failed
        if !response.ok {
            return Err(CollectionError::service_error(format!(
                "Failed to wait for consensus commit on peer {peer_id}, has diverged commit/term or timed out."
            )));
        }
        Ok(())
    }

    pub async fn with_qdrant_client<T, O: Future<Output = Result<T, Status>>>(
        &self,
        peer_id: PeerId,
        f: impl Fn(QdrantInternalClient<InterceptedService<Channel, AddTimeout>>) -> O,
    ) -> CollectionResult<T> {
        let address = self
            .id_to_address
            .read()
            .get(&peer_id)
            .ok_or_else(|| CollectionError::service_error("Address for peer ID is not found."))?
            .clone();
        self.channel_pool
            .with_channel(&address, |channel| {
                let client = QdrantInternalClient::new(channel);
                let client = client.max_decoding_message_size(usize::MAX);
                f(client)
            })
            .await
            .map_err(Into::into)
    }

    /// Check whether all peers are running at least the given version
    ///
    /// If the version is not known for any peer, this returns `false`.
    /// Peer versions are known since 1.9 and up.
    pub fn all_peers_at_version(&self, version: &Version) -> bool {
        let id_to_address = self.id_to_address.read();
        let id_to_metadata = self.id_to_metadata.read();

        // Ensure there aren't more peer addresses than metadata
        if id_to_address.len() > id_to_metadata.len() {
            let peers_without_metadata =
                peers_without_metadata_for_log(&id_to_address, &id_to_metadata);
            log::info!(
                "Not all peers at version:{version} because there are peers without metadata:{peers_without_metadata:?}"
            );
            return false;
        }

        let all = id_to_metadata
            .values()
            .all(|metadata| &metadata.version >= version);

        if !all {
            let peers_below_version = peers_below_version_for_log(&id_to_metadata, version);
            log::info!(
                "Not all peers at version:{version} peers_below_version:{peers_below_version:?}"
            );
        }

        all
    }

    /// Check whether the specified peer is running at least the given version
    ///
    /// If the version is not known for the peer, this returns `false`.
    /// Peer versions are known since 1.9 and up.
    pub fn peer_is_at_version(&self, peer_id: PeerId, version: &Version) -> bool {
        self.id_to_metadata
            .read()
            .get(&peer_id)
            .is_some_and(|metadata| &metadata.version >= version)
    }

    /// Get the REST address for the current peer.
    pub fn current_rest_address(&self, this_peer_id: PeerId) -> CollectionResult<Url> {
        // Get local peer URI
        let local_peer_uri = self
            .id_to_address
            .read()
            .get(&this_peer_id)
            .cloned()
            .ok_or_else(|| {
                CollectionError::service_error(format!(
                    "Cannot determine REST address, this peer not found in cluster by ID {this_peer_id} ",
                ))
            })?;

        // Construct REST URL from URI
        let mut url = Url::parse(&local_peer_uri.to_string()).map_err(|err| {
            CollectionError::service_error(format!(
                "Cannot determine REST address, peer URI {local_peer_uri} is malformed: {err}",
            ))
        })?;
        url.set_port(Some(self.current_rest_port))
            .map_err(|()| {
                CollectionError::service_error(format!(
                    "Cannot determine REST address, cannot specify port on address {url} for peer ID {this_peer_id}",
                ))
            })?;
        let scheme = if self.rest_tls_enabled {
            "https"
        } else {
            "http"
        };
        url.set_scheme(scheme).map_err(|()| {
            CollectionError::service_error(format!(
                "Cannot determine REST address, cannot set {scheme} scheme on address {url} for peer ID {this_peer_id}",
            ))
        })?;

        Ok(url)
    }

    pub fn other_peers(&self, this_peer_id: PeerId) -> Vec<PeerId> {
        self.id_to_address
            .read()
            .keys()
            .filter(|id| **id != this_peer_id)
            .copied()
            .collect()
    }

    pub fn request_timeout(&self) -> Duration {
        self.channel_pool.request_timeout()
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PeerVersionLogEntry {
    peer_id: PeerId,
    version: String,
    crypto_fingerprint_present: bool,
}

fn peers_without_metadata_for_log(
    id_to_address: &HashMap<PeerId, Uri>,
    id_to_metadata: &HashMap<PeerId, PeerMetadata>,
) -> Vec<PeerId> {
    let mut peers_without_metadata = id_to_address
        .keys()
        .filter(|id| !id_to_metadata.contains_key(id))
        .copied()
        .collect::<Vec<_>>();
    peers_without_metadata.sort_unstable();
    peers_without_metadata
}

fn peers_below_version_for_log(
    id_to_metadata: &HashMap<PeerId, PeerMetadata>,
    version: &Version,
) -> Vec<PeerVersionLogEntry> {
    let mut peers_below_version = id_to_metadata
        .iter()
        .filter(|(_peer_id, metadata)| &metadata.version < version)
        .map(|(peer_id, metadata)| PeerVersionLogEntry {
            peer_id: *peer_id,
            version: metadata.version.to_string(),
            crypto_fingerprint_present: metadata.crypto_runtime_capability_fingerprint().is_some(),
        })
        .collect::<Vec<_>>();
    peers_below_version.sort_unstable_by_key(|entry| entry.peer_id);
    peers_below_version
}

#[cfg(test)]
impl Default for ChannelService {
    fn default() -> Self {
        Self {
            id_to_address: Default::default(),
            id_to_metadata: Default::default(),
            channel_pool: Default::default(),
            current_rest_port: 6333,
            rest_tls_enabled: false,
            api_key: None,
            alt_api_key: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_version_logs_omit_peer_urls_and_crypto_fingerprint_values() {
        let id_to_address = HashMap::from([(
            7,
            Uri::from_static("http://peer-with-token.example.test:6333"),
        )]);
        let id_to_metadata = HashMap::new();

        let missing = peers_without_metadata_for_log(&id_to_address, &id_to_metadata);
        let missing_log = format!("{missing:?}");
        assert_eq!(missing, vec![7]);
        assert!(!missing_log.contains("peer-with-token"));

        let id_to_metadata = HashMap::from([(
            3,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "crypto-fingerprint-sentinel".to_string(),
            )),
        )]);
        let peers_below = peers_below_version_for_log(&id_to_metadata, &Version::new(999, 0, 0));
        let peers_below_log = format!("{peers_below:?}");
        assert!(peers_below_log.contains("crypto_fingerprint_present: true"));
        assert!(!peers_below_log.contains("crypto-fingerprint-sentinel"));
    }
}
