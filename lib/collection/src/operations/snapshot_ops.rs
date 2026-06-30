use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::SystemTime;

use api::grpc::conversions::naive_date_time_to_proto;
use chrono::{DateTime, NaiveDateTime};
use fs_err::tokio as tokio_fs;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;
use validator::Validate;

use crate::operations::types::{CollectionError, CollectionResult};

/// Defines source of truth for snapshot recovery:
///
/// `NoSync` means - restore snapshot without *any* additional synchronization.
/// `Snapshot` means - prefer snapshot data over the current state.
/// `Replica` means - prefer existing data over the snapshot.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Default, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotPriority {
    NoSync,
    #[default]
    Snapshot,
    Replica,
    // `ShardTransfer` is for internal use only, and should not be exposed/used in public API
    #[serde(skip)]
    ShardTransfer,
}

impl TryFrom<i32> for SnapshotPriority {
    type Error = tonic::Status;

    fn try_from(snapshot_priority: i32) -> Result<Self, Self::Error> {
        api::grpc::qdrant::ShardSnapshotPriority::try_from(snapshot_priority)
            .map(Into::into)
            .map_err(|_| tonic::Status::invalid_argument("Malformed shard snapshot priority"))
    }
}

impl From<api::grpc::qdrant::ShardSnapshotPriority> for SnapshotPriority {
    fn from(snapshot_priority: api::grpc::qdrant::ShardSnapshotPriority) -> Self {
        match snapshot_priority {
            api::grpc::qdrant::ShardSnapshotPriority::NoSync => Self::NoSync,
            api::grpc::qdrant::ShardSnapshotPriority::Snapshot => Self::Snapshot,
            api::grpc::qdrant::ShardSnapshotPriority::Replica => Self::Replica,
            api::grpc::qdrant::ShardSnapshotPriority::ShardTransfer => Self::ShardTransfer,
        }
    }
}

impl From<SnapshotPriority> for api::grpc::qdrant::ShardSnapshotPriority {
    fn from(snapshot_priority: SnapshotPriority) -> Self {
        match snapshot_priority {
            SnapshotPriority::NoSync => Self::NoSync,
            SnapshotPriority::Snapshot => Self::Snapshot,
            SnapshotPriority::Replica => Self::Replica,
            SnapshotPriority::ShardTransfer => Self::ShardTransfer,
        }
    }
}

#[derive(Deserialize, Serialize, JsonSchema, Validate, Clone)]
pub struct SnapshotRecover {
    /// Examples:
    /// - URL `http://localhost:8080/collections/my_collection/snapshots/my_snapshot`
    /// - Local path `file:///qdrant/snapshots/test_collection-2022-08-04-10-49-10.snapshot`
    pub location: Url,

    /// Defines which data should be used as a source of truth if there are other replicas in the cluster.
    /// If set to `Snapshot`, the snapshot will be used as a source of truth, and the current state will be overwritten.
    /// If set to `Replica`, the current state will be used as a source of truth, and after recovery if will be synchronized with the snapshot.
    #[serde(default)]
    pub priority: Option<SnapshotPriority>,

    /// Optional SHA256 checksum to verify snapshot integrity before recovery.
    #[serde(default)]
    #[validate(custom(function = "common::validation::validate_sha256_hash"))]
    pub checksum: Option<String>,

    /// Optional API key used when fetching the snapshot from a remote URL.
    #[serde(default)]
    pub api_key: Option<String>,
}

impl fmt::Debug for SnapshotRecover {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnapshotRecover")
            .field("location", &RedactedSnapshotUrl(&self.location))
            .field("priority", &self.priority)
            .field("checksum", &self.checksum)
            .field("api_key", &self.api_key.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

fn snapshot_description_example() -> SnapshotDescription {
    SnapshotDescription {
        name: "my-collection-3766212330831337-2024-07-22-08-31-55.snapshot".to_string(),
        creation_time: Some(NaiveDateTime::from_str("2022-08-04T10:49:10").unwrap()),
        size: 1_000_000,
        checksum: Some("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0".to_string()),
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
#[schemars(example = "snapshot_description_example")]
pub struct SnapshotDescription {
    pub name: String,
    pub creation_time: Option<NaiveDateTime>,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
}

impl From<SnapshotDescription> for api::grpc::qdrant::SnapshotDescription {
    fn from(value: SnapshotDescription) -> Self {
        let SnapshotDescription {
            name,
            creation_time,
            size,
            checksum,
        } = value;

        Self {
            name,
            creation_time: creation_time.map(naive_date_time_to_proto),
            size: size as i64,
            checksum,
        }
    }
}

pub async fn get_snapshot_description(path: &Path) -> CollectionResult<SnapshotDescription> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            CollectionError::service_error(format!(
                "snapshot path {} does not end with a valid UTF-8 file name",
                path.display(),
            ))
        })?;
    let file_meta = tokio_fs::metadata(&path).await?;
    let creation_time = file_meta.created().ok().and_then(|created_time| {
        created_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|duration| DateTime::from_timestamp(duration.as_secs() as i64, 0))
            .map(|dt| dt.naive_utc())
    });

    let checksum = read_checksum_for_snapshot(path).await;
    let size = file_meta.len();
    Ok(SnapshotDescription {
        name: name.to_string(),
        creation_time,
        size,
        checksum,
    })
}

async fn read_checksum_for_snapshot(snapshot_path: impl Into<PathBuf>) -> Option<String> {
    let checksum_path = get_checksum_path(snapshot_path);
    tokio_fs::read_to_string(&checksum_path).await.ok()
}

pub fn get_checksum_path(snapshot_path: impl Into<PathBuf>) -> PathBuf {
    let mut checksum_path = snapshot_path.into().into_os_string();
    checksum_path.push(".checksum");
    checksum_path.into()
}

#[derive(Clone, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct ShardSnapshotRecover {
    pub location: ShardSnapshotLocation,

    #[serde(default)]
    pub priority: Option<SnapshotPriority>,

    /// Optional SHA256 checksum to verify snapshot integrity before recovery.
    #[validate(custom(function = "common::validation::validate_sha256_hash"))]
    #[serde(default)]
    pub checksum: Option<String>,

    /// Optional API key used when fetching the snapshot from a remote URL.
    #[serde(default)]
    pub api_key: Option<String>,
}

impl fmt::Debug for ShardSnapshotRecover {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShardSnapshotRecover")
            .field("location", &self.location)
            .field("priority", &self.priority)
            .field("checksum", &self.checksum)
            .field("api_key", &self.api_key.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

#[derive(Clone, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ShardSnapshotLocation {
    Url(Url),
    Path(PathBuf),
}

impl fmt::Debug for ShardSnapshotLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShardSnapshotLocation::Url(location) => f
                .debug_tuple("Url")
                .field(&RedactedSnapshotUrl(location))
                .finish(),
            ShardSnapshotLocation::Path(path) => f.debug_tuple("Path").field(path).finish(),
        }
    }
}

struct RedactedSnapshotUrl<'a>(&'a Url);

impl fmt::Debug for RedactedSnapshotUrl<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut location = self.0.clone();
        if !location.username().is_empty() {
            location
                .set_username("[redacted]")
                .map_err(|_| fmt::Error)?;
        }
        if location.password().is_some() {
            location
                .set_password(Some("[redacted]"))
                .map_err(|_| fmt::Error)?;
        }
        if location.query().is_some() {
            location.set_query(Some("[redacted]"));
        }
        if location.fragment().is_some() {
            location.set_fragment(Some("[redacted]"));
        }
        f.debug_tuple("Url").field(&location.as_str()).finish()
    }
}

impl TryFrom<Option<api::grpc::qdrant::ShardSnapshotLocation>> for ShardSnapshotLocation {
    type Error = tonic::Status;

    fn try_from(
        snapshot_location: Option<api::grpc::qdrant::ShardSnapshotLocation>,
    ) -> Result<Self, Self::Error> {
        let Some(snapshot_location) = snapshot_location else {
            return Err(tonic::Status::invalid_argument(
                "Malformed shard snapshot location",
            ));
        };

        snapshot_location.try_into()
    }
}

impl TryFrom<api::grpc::qdrant::ShardSnapshotLocation> for ShardSnapshotLocation {
    type Error = tonic::Status;

    fn try_from(location: api::grpc::qdrant::ShardSnapshotLocation) -> Result<Self, Self::Error> {
        use api::grpc::qdrant::shard_snapshot_location;

        let api::grpc::qdrant::ShardSnapshotLocation { location } = location;

        let Some(location) = location else {
            return Err(tonic::Status::invalid_argument(
                "Malformed shard snapshot location",
            ));
        };

        let location = match location {
            shard_snapshot_location::Location::Url(url) => {
                let url = Url::parse(&url)
                    .map_err(|_| tonic::Status::invalid_argument("Invalid shard snapshot URL"))?;

                Self::Url(url)
            }

            shard_snapshot_location::Location::Path(path) => {
                let path = PathBuf::from(path);
                Self::Path(path)
            }
        };

        Ok(location)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_recover_debug_redacts_remote_credentials() {
        let recover = SnapshotRecover {
            location: Url::parse(
                "https://snapshot-user:snapshot-password@example.com/snapshots/a.snapshot?api_key=qdrant-sec-query-key-sentinel#qdrant-sec-fragment-sentinel",
            )
            .unwrap(),
            priority: Some(SnapshotPriority::Snapshot),
            checksum: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
            ),
            api_key: Some("qdrant-sec-snapshot-api-key-sentinel".to_string()),
        };

        let rendered = format!("{recover:?}");

        assert!(rendered.contains("[redacted]"), "{rendered}");
        assert!(rendered.contains("example.com"), "{rendered}");
        assert!(!rendered.contains("snapshot-user"), "{rendered}");
        assert!(!rendered.contains("snapshot-password"), "{rendered}");
        assert!(
            !rendered.contains("qdrant-sec-query-key-sentinel"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("qdrant-sec-fragment-sentinel"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("qdrant-sec-snapshot-api-key-sentinel"),
            "{rendered}",
        );
    }

    #[test]
    fn shard_snapshot_recover_debug_redacts_remote_credentials() {
        let recover = ShardSnapshotRecover {
            location: ShardSnapshotLocation::Url(
                Url::parse(
                    "https://shard-user:shard-password@example.com/shards/a.snapshot?token=qdrant-sec-shard-query-token#qdrant-sec-shard-fragment",
                )
                .unwrap(),
            ),
            priority: Some(SnapshotPriority::Replica),
            checksum: Some(
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                    .to_string(),
            ),
            api_key: Some("qdrant-sec-shard-api-key-sentinel".to_string()),
        };

        let rendered = format!("{recover:?}");

        assert!(rendered.contains("[redacted]"), "{rendered}");
        assert!(rendered.contains("example.com"), "{rendered}");
        assert!(!rendered.contains("shard-user"), "{rendered}");
        assert!(!rendered.contains("shard-password"), "{rendered}");
        assert!(
            !rendered.contains("qdrant-sec-shard-query-token"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("qdrant-sec-shard-fragment"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("qdrant-sec-shard-api-key-sentinel"),
            "{rendered}",
        );
    }

    #[test]
    fn shard_snapshot_location_debug_redacts_remote_credentials() {
        let location = ShardSnapshotLocation::Url(
            Url::parse(
                "https://location-user:location-password@example.com/shards/a.snapshot?token=qdrant-sec-location-query-token#qdrant-sec-location-fragment",
            )
            .unwrap(),
        );

        let rendered = format!("{location:?}");

        assert!(rendered.contains("[redacted]"), "{rendered}");
        assert!(rendered.contains("example.com"), "{rendered}");
        assert!(!rendered.contains("location-user"), "{rendered}");
        assert!(!rendered.contains("location-password"), "{rendered}");
        assert!(
            !rendered.contains("qdrant-sec-location-query-token"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("qdrant-sec-location-fragment"),
            "{rendered}"
        );
    }

    #[test]
    fn invalid_grpc_shard_snapshot_url_redacts_remote_credentials() {
        let location = api::grpc::qdrant::ShardSnapshotLocation {
            location: Some(api::grpc::qdrant::shard_snapshot_location::Location::Url(
                "https://grpc-user:grpc-password@example.com:bad/shards/a.snapshot?token=qdrant-sec-grpc-query-token#qdrant-sec-grpc-fragment"
                    .to_string(),
            )),
        };

        let status = ShardSnapshotLocation::try_from(location)
            .expect_err("invalid URL must fail without echoing the raw URL");
        let rendered = status.message();

        assert_eq!(rendered, "Invalid shard snapshot URL");
        assert!(!rendered.contains("grpc-user"), "{rendered}");
        assert!(!rendered.contains("grpc-password"), "{rendered}");
        assert!(
            !rendered.contains("qdrant-sec-grpc-query-token"),
            "{rendered}"
        );
        assert!(!rendered.contains("qdrant-sec-grpc-fragment"), "{rendered}");
        assert!(!rendered.contains("invalid port"), "{rendered}");
    }
}
