use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use validator::{Validate, ValidateArgs, ValidationError, ValidationErrors};

use crate::content_manager::errors::StorageError;

pub mod auditable_operation;
pub mod auth;
mod ops_checks;

pub use auth::Auth;

/// How the request was authenticated.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuthType {
    Jwt,
    ApiKey,
    /// No authentication was configured or required.
    None,
    /// Request originated from the cluster itself (internal P2P communication).
    /// These requests are not audit-logged.
    Internal,
}

/// A structure that defines access rights.
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
#[serde(untagged)]
pub enum Access {
    /// Global access.
    Global(GlobalAccessMode),
    /// Access to specific collections.
    Collection(CollectionAccessList),
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct CollectionAccessList(pub Vec<CollectionAccess>);

pub struct ExistingCollections {
    inner: HashSet<String>,
}

#[derive(Serialize, Deserialize, Validate, PartialEq, Clone, Debug)]
#[validate(context = ExistingCollections, mutable)]
pub struct CollectionAccess {
    /// Collection names that are allowed to be accessed
    #[validate(custom(function = "validate_unique_collections", use_context))]
    pub collection: String,

    pub access: CollectionAccessMode,

    /// Permit server-side decryption of `$qdrant_sec` payload envelopes for this collection.
    ///
    /// This does not allow decrypting client-side `$qdrant_client_aead` envelopes because Qdrant
    /// intentionally does not hold client data keys.
    #[serde(default, skip_serializing_if = "is_false")]
    pub payload_decrypt: bool,

    /// Permit bulk export of raw snapshot archives for this collection.
    ///
    /// Snapshot archives may contain encrypted envelope metadata, wrapped-key
    /// manifests, nonce caches, sidecar indexes, and other backup-grade crypto
    /// artifacts. This is separate from ordinary point reads.
    #[serde(default, skip_serializing_if = "is_false")]
    pub snapshot_export: bool,

    /// Payload constraints.
    /// An object where each key is a JSON path, and each value is JSON value.
    ///
    /// Deprecation: this parameter is kept for preventing old keys to become valid after parameter removal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[deprecated(since = "1.15.0")]
    #[validate(custom(function = "validate_payload_empty"))]
    pub payload: Option<Value>, // Value is a placeholder for a now removed type
}

fn validate_payload_empty(_payload: &Value) -> Result<(), ValidationError> {
    Err(ValidationError {
        code: Cow::from("deprecated"),
        message: Some(Cow::from(
            "The 'payload' constraint is deprecated and should not be used",
        )),
        params: HashMap::new(),
    })
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl CollectionAccess {
    fn view(&self) -> CollectionAccessView<'_> {
        CollectionAccessView {
            collection: &self.collection,
            access: self.access,
            payload_decrypt: self.payload_decrypt,
            snapshot_export: self.snapshot_export,
        }
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Copy, Clone, Debug)]
pub enum GlobalAccessMode {
    /// Read-only access
    #[serde(rename = "r")]
    Read,

    /// Read and write access
    #[serde(rename = "m")]
    Manage,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Copy, Clone, Debug)]
pub enum CollectionAccessMode {
    /// Read-only access to a collection.
    #[serde(rename = "r")]
    Read,

    /// Read and write access to a collection, with some restrictions.
    #[serde(rename = "rw")]
    ReadWrite,

    /// Points read and write - access to update and modify points in the collection,
    /// but not snapshots or payload indexes.
    #[serde(rename = "prw")]
    PointsReadWrite,
}

impl Access {
    /// Create an `Access` object with full access.
    /// The ``_reason`` parameter is not used in the code, but serves as a mandatory commentary to
    /// explain why the access is granted, e.g. ``Access::full("Internal API")`` or
    /// ``Access::full("Test")``.
    pub const fn full(_reason: &'static str) -> Self {
        Self::Global(GlobalAccessMode::Manage)
    }

    pub const fn full_ro(_reason: &'static str) -> Self {
        Self::Global(GlobalAccessMode::Read)
    }

    /// Check if the user has global access.
    pub fn check_global_access(
        &self,
        requirements: AccessRequirements,
    ) -> Result<CollectionMultipass, StorageError> {
        match self {
            Access::Global(mode) => mode.meets_requirements(requirements)?,
            Access::Collection(_) => {
                return Err(StorageError::forbidden("Global access is required"));
            }
        }
        Ok(CollectionMultipass)
    }

    /// Check if the user has access to a collection with given requirements.
    pub fn check_collection_access<'a>(
        &self,
        collection_name: &'a str,
        requirements: AccessRequirements,
    ) -> Result<CollectionPass<'a>, StorageError> {
        match self {
            Access::Global(mode) => mode.meets_requirements(requirements)?,
            Access::Collection(list) => list
                .find_view(collection_name)?
                .meets_requirements(requirements)?,
        }
        Ok(CollectionPass(Cow::Borrowed(collection_name)))
    }
}

impl CollectionAccessList {
    pub(self) fn find_view<'a>(
        &'a self,
        collection_name: &'a str,
    ) -> Result<CollectionAccessView<'a>, StorageError> {
        let access = self
            .0
            .iter()
            .find(|collections| collections.collection == collection_name)
            .ok_or_else(|| {
                StorageError::forbidden(format!(
                    "Access to collection {collection_name} is required"
                ))
            })?;
        Ok(access.view())
    }

    /// Lists the collections which fulfill the requirements.
    pub fn meeting_requirements(&self, requirements: AccessRequirements) -> Vec<&String> {
        self.0
            .iter()
            .filter(|access| access.view().meets_requirements(requirements).is_ok())
            .map(|access| &access.collection)
            .collect()
    }
}

#[derive(Debug)]
struct CollectionAccessView<'a> {
    pub collection: &'a str,
    pub access: CollectionAccessMode,
    pub payload_decrypt: bool,
    pub snapshot_export: bool,
}

impl CollectionAccessView<'_> {
    fn meets_requirements(&self, requirements: AccessRequirements) -> Result<(), StorageError> {
        let AccessRequirements {
            write,
            manage,
            extras,
            payload_decrypt,
            snapshot_export,
        } = requirements;

        if payload_decrypt && !self.payload_decrypt {
            return Err(StorageError::forbidden(format!(
                "Payload decrypt access to collection {} is required",
                self.collection,
            )));
        }

        if snapshot_export && !self.snapshot_export {
            return Err(StorageError::forbidden(format!(
                "Snapshot export access to collection {} is required",
                self.collection,
            )));
        }

        if extras {
            match self.access {
                CollectionAccessMode::Read => {}      // Ok
                CollectionAccessMode::ReadWrite => {} // Ok
                CollectionAccessMode::PointsReadWrite => {
                    return Err(StorageError::forbidden(format!(
                        "Only points access is allowed for collection {}",
                        self.collection,
                    )));
                }
            }
        }

        if write {
            match self.access {
                CollectionAccessMode::Read => {
                    return Err(StorageError::forbidden(format!(
                        "Write access to collection {} is required",
                        self.collection,
                    )));
                }
                CollectionAccessMode::ReadWrite => (),
                CollectionAccessMode::PointsReadWrite => {
                    // Extras are checked above.
                }
            }
        }
        if manage {
            // Don't specify collection name since the manage access could be enabled globally, and
            // not per collection.
            return Err(StorageError::forbidden(
                "Manage access for this operation is required",
            ));
        }
        Ok(())
    }
}

/// Creates [CollectionPass] objects for all collections
pub struct CollectionMultipass;

impl CollectionMultipass {
    pub fn issue_pass<'a>(&self, name: &'a str) -> CollectionPass<'a> {
        CollectionPass(Cow::Borrowed(name))
    }
}

/// A pass that allows access to a specific collection.
#[derive(Debug)]
pub struct CollectionPass<'a>(pub(self) Cow<'a, str>);

impl<'a> CollectionPass<'a> {
    pub fn name(&'a self) -> &'a str {
        &self.0
    }

    pub fn into_static(self) -> CollectionPass<'static> {
        CollectionPass(Cow::Owned(self.0.into_owned()))
    }
}

impl std::fmt::Display for CollectionPass<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Default, Debug, Copy, Clone)]
pub struct AccessRequirements {
    /// Write access is required.
    pub write: bool,
    /// Manage access is required, implies write access.
    pub manage: bool,
    /// Require access to collection extras, like snapshots, payload indexes, cluster info.
    pub extras: bool,
    /// Require permission to decrypt server-side encrypted payload fields.
    pub payload_decrypt: bool,
    /// Require permission to export raw snapshot archives.
    pub snapshot_export: bool,
}

impl AccessRequirements {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn write(&self) -> Self {
        Self {
            write: true,
            ..*self
        }
    }

    pub fn manage(&self) -> Self {
        Self {
            manage: true,
            ..*self
        }
    }

    pub fn extras(&self) -> Self {
        Self {
            extras: true,
            ..*self
        }
    }

    pub fn payload_decrypt(&self) -> Self {
        Self {
            payload_decrypt: true,
            ..*self
        }
    }

    pub fn snapshot_export(&self) -> Self {
        Self {
            snapshot_export: true,
            ..*self
        }
    }
}

impl GlobalAccessMode {
    fn meets_requirements(&self, requirements: AccessRequirements) -> Result<(), StorageError> {
        let AccessRequirements {
            write,
            manage,
            payload_decrypt,
            snapshot_export,
            extras: _,
        } = requirements;
        if write || manage || payload_decrypt || snapshot_export {
            match self {
                GlobalAccessMode::Read => {
                    let message = if snapshot_export && !write && !manage {
                        "Global manage or snapshot export collection access is required"
                    } else if payload_decrypt && !write && !manage {
                        "Global manage or payload decrypt collection access is required"
                    } else {
                        "Global manage access is required"
                    };
                    return Err(StorageError::forbidden(message));
                }
                GlobalAccessMode::Manage => (),
            }
        }
        Ok(())
    }
}

impl Access {
    /// Return a list of validation errors in a format suitable for [ValidationErrors::merge_all].
    pub fn validate(&self) -> Vec<Result<(), ValidationErrors>> {
        match self {
            Access::Global(_) => Vec::new(),
            Access::Collection(list) => {
                let mut used_collections = ExistingCollections {
                    inner: HashSet::new(),
                };
                list.0
                    .iter()
                    .map(|x| {
                        ValidationErrors::merge(
                            Ok(()),
                            "access",
                            x.validate_with_args(&mut used_collections),
                        )
                    })
                    .collect::<Vec<_>>()
            }
        }
    }
}

fn validate_unique_collections(
    collection: &str,
    used_collections: &mut ExistingCollections,
) -> Result<(), ValidationError> {
    let unique = used_collections.inner.insert(collection.to_owned());
    if unique {
        Ok(())
    } else {
        Err(ValidationError {
            code: Cow::from("unique"),
            message: Some(Cow::from("Collection name should be unique")),
            params: HashMap::from([(Cow::from("collection"), collection.to_owned().into())]),
        })
    }
}

#[cfg(test)]
struct AccessCollectionBuilder(pub Vec<CollectionAccess>);

#[cfg(test)]
impl AccessCollectionBuilder {
    pub(self) fn new() -> Self {
        Self(Vec::new())
    }

    pub(self) fn add(mut self, name: &str, write: bool) -> Self {
        self.0.push(CollectionAccess {
            collection: name.to_string(),
            access: if write {
                CollectionAccessMode::ReadWrite
            } else {
                CollectionAccessMode::Read
            },
            payload_decrypt: false,
            snapshot_export: false,
            #[expect(deprecated)]
            payload: None,
        });
        self
    }

    pub(self) fn add_with_payload_decrypt(mut self, name: &str) -> Self {
        self.0.push(CollectionAccess {
            collection: name.to_string(),
            access: CollectionAccessMode::Read,
            payload_decrypt: true,
            snapshot_export: false,
            #[expect(deprecated)]
            payload: None,
        });
        self
    }

    pub(self) fn add_with_snapshot_export(mut self, name: &str) -> Self {
        self.0.push(CollectionAccess {
            collection: name.to_string(),
            access: CollectionAccessMode::Read,
            payload_decrypt: false,
            snapshot_export: true,
            #[expect(deprecated)]
            payload: None,
        });
        self
    }
}

#[cfg(test)]
impl From<AccessCollectionBuilder> for Access {
    fn from(builder: AccessCollectionBuilder) -> Self {
        Access::Collection(CollectionAccessList(builder.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_payload_decrypt_capability_is_separate_from_read() {
        let read_only: Access = AccessCollectionBuilder::new().add("docs", false).into();
        assert!(
            read_only
                .check_collection_access("docs", AccessRequirements::new().payload_decrypt(),)
                .is_err()
        );

        let decrypt: Access = AccessCollectionBuilder::new()
            .add_with_payload_decrypt("docs")
            .into();
        decrypt
            .check_collection_access("docs", AccessRequirements::new().payload_decrypt())
            .expect("payload decrypt capability must satisfy decrypt-only reads");
    }

    #[test]
    fn global_manage_satisfies_payload_decrypt_but_global_read_does_not() {
        Access::full("test")
            .check_collection_access("docs", AccessRequirements::new().payload_decrypt())
            .expect("global manage satisfies payload decrypt");

        assert!(
            Access::full_ro("test")
                .check_collection_access("docs", AccessRequirements::new().payload_decrypt())
                .is_err()
        );
    }

    #[test]
    fn collection_snapshot_export_capability_is_separate_from_read_and_extras() {
        let read_only: Access = AccessCollectionBuilder::new().add("docs", false).into();
        assert!(
            read_only
                .check_collection_access(
                    "docs",
                    AccessRequirements::new().extras().snapshot_export(),
                )
                .is_err()
        );

        let snapshot_export: Access = AccessCollectionBuilder::new()
            .add_with_snapshot_export("docs")
            .into();
        snapshot_export
            .check_collection_access("docs", AccessRequirements::new().extras().snapshot_export())
            .expect("snapshot export capability must satisfy raw archive reads");
    }

    #[test]
    fn global_manage_satisfies_snapshot_export_but_global_read_does_not() {
        Access::full("test")
            .check_global_access(AccessRequirements::new().snapshot_export())
            .expect("global manage satisfies snapshot export");

        assert!(
            Access::full_ro("test")
                .check_global_access(AccessRequirements::new().snapshot_export())
                .is_err()
        );
    }
}
