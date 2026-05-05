use std::io::BufReader;
use std::path::{Path, PathBuf};

use collection::collection::Collection;
use collection::config::CollectionConfigInternal;
use collection::shards::shard::PeerId;
use common::fs::safe_delete_in_tmp;
use common::tar_unpack::tar_unpack_file;
use fs_err as fs;
use fs_err::File;
use log::info;
use shard::snapshots::snapshot_data::SnapshotData;
use storage::content_manager::alias_mapping::AliasPersistence;
use storage::content_manager::snapshots::SnapshotConfig;
use storage::content_manager::toc::{ALIASES_PATH, COLLECTIONS_DIR};

use crate::common::crypto::validate_recovered_collection_crypto_config;
#[cfg(test)]
use crate::common::crypto::validate_recovered_collection_crypto_runtime;
use crate::settings::Settings;

/// Recover snapshots from the given arguments
///
/// # Arguments
///
/// * `mapping` - `[ <path>:<collection_name> ]`
/// * `force` - if true, allow to overwrite collections from snapshots
///
/// # Returns
///
/// * `Vec<String>` - list of collections that were recovered
pub fn recover_snapshots(
    mapping: &[String],
    force: bool,
    temp_dir: Option<&Path>,
    storage_dir: &Path,
    this_peer_id: PeerId,
    is_distributed: bool,
    settings: &Settings,
) -> Vec<String> {
    let collection_dir_path = storage_dir.join(COLLECTIONS_DIR);
    let mut recovered_collections: Vec<String> = vec![];

    for snapshot_params in mapping {
        let mut split = snapshot_params.split(':');
        let path = split
            .next()
            .unwrap_or_else(|| panic!("Snapshot path is missing: {snapshot_params}"));

        let snapshot_data = SnapshotData::new_packed_persistent(path);

        let collection_name = split
            .next()
            .unwrap_or_else(|| panic!("Collection name is missing: {snapshot_params}"));
        recovered_collections.push(collection_name.to_string());
        assert!(
            split.next().is_none(),
            "Too many parts in snapshot mapping: {snapshot_params}"
        );
        info!("Recovering snapshot {collection_name} from {path}");
        // check if collection already exists
        // if it does, we need to check if we want to overwrite it
        // if not, we need to abort
        let collection_path = collection_dir_path.join(collection_name);
        info!("Collection path: {}", collection_path.display());
        if collection_path.exists() {
            if !force {
                panic!(
                    "Collection {collection_name} already exists. Use --force-snapshot to overwrite it."
                );
            }
            info!("Overwriting collection {collection_name}");
        }
        let collection_temp_path =
            temp_dir.map_or_else(|| collection_path.with_extension("tmp"), PathBuf::from);
        if let Err(err) = Collection::restore_snapshot(
            snapshot_data,
            &collection_temp_path,
            this_peer_id,
            is_distributed,
        ) {
            panic!("Failed to recover snapshot {collection_name}: {err}");
        }
        if let Err(err) = validate_restored_collection_crypto_runtime(
            settings,
            collection_name,
            &collection_temp_path,
        ) {
            let _ = safe_delete_in_tmp(&collection_temp_path, &storage_dir.join(".deleted"))
                .and_then(|to_delete| to_delete.close());
            panic!("{err}");
        }
        // Remove collection_path directory if exists
        if collection_path.exists()
            && let Err(err) = safe_delete_in_tmp(&collection_path, &storage_dir.join(".deleted"))
                .and_then(|to_delete| to_delete.close())
        {
            panic!("Failed to remove collection {collection_name}: {err}");
        }
        fs::rename(&collection_temp_path, &collection_path).unwrap();
    }
    recovered_collections
}

pub fn recover_full_snapshot(
    temp_dir: Option<&Path>,
    snapshot_path: &str,
    storage_dir: &Path,
    force: bool,
    this_peer_id: PeerId,
    is_distributed: bool,
    settings: &Settings,
) -> Vec<String> {
    let snapshot_temp_path = temp_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| storage_dir.join("snapshots_recovery_tmp"));
    fs::create_dir_all(&snapshot_temp_path).unwrap();

    // Un-tar snapshot into temporary directory
    tar_unpack_file(Path::new(snapshot_path), &snapshot_temp_path).unwrap();

    // Read configuration file with snapshot-to-collection mapping
    let config_path = snapshot_temp_path.join("config.json");
    let config_file = BufReader::new(File::open(config_path).unwrap());
    let config_json: SnapshotConfig = serde_json::from_reader(config_file).unwrap();

    // Create mapping from the configuration file
    let mapping: Vec<String> = config_json
        .collections_mapping
        .iter()
        .map(|(collection_name, snapshot_file)| {
            format!(
                "{}:{collection_name}",
                snapshot_temp_path.join(snapshot_file).to_str().unwrap(),
            )
        })
        .collect();

    // Launch regular recovery of snapshots
    let recovered_collection = recover_snapshots(
        &mapping,
        force,
        temp_dir,
        storage_dir,
        this_peer_id,
        is_distributed,
        settings,
    );

    let alias_path = storage_dir.join(ALIASES_PATH);
    let mut alias_persistence =
        AliasPersistence::open(&alias_path).expect("Can't open database by the provided config");
    for (alias, collection_name) in config_json.collections_aliases {
        if alias_persistence.get(&alias).is_some() && !force {
            panic!("Alias {alias} already exists. Use --force-snapshot to overwrite it.");
        }
        alias_persistence.insert(alias, collection_name).unwrap();
    }

    // Remove temporary directory
    fs::remove_dir_all(&snapshot_temp_path).unwrap();
    recovered_collection
}

fn validate_restored_collection_crypto_runtime(
    settings: &Settings,
    collection_name: &str,
    collection_path: &Path,
) -> Result<(), String> {
    let config = CollectionConfigInternal::load(collection_path).map_err(|err| {
        format!("Failed to load recovered snapshot config for collection {collection_name}: {err}",)
    })?;
    validate_recovered_collection_crypto_config(settings, collection_name, &config).map_err(
        |err| {
            format!(
                "Failed to validate crypto runtime for recovered snapshot {collection_name}: {err}",
            )
        },
    )
}

#[cfg(test)]
fn validate_restored_collection_crypto_params(
    settings: &Settings,
    collection_name: &str,
    params: &collection::config::CollectionParams,
) -> Result<(), String> {
    validate_recovered_collection_crypto_runtime(settings, collection_name, params).map_err(|err| {
        format!(
            "Failed to validate crypto runtime for recovered snapshot {collection_name}: {err}",
        )
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use collection::config::{
        CollectionEncryptionConfig, CollectionParams, CryptoMigrationState, EncryptionRuleRef,
        EncryptionSelector,
    };
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_crypto::{
        LocalMasterKeyProvider, MasterKeyProvider, RESOURCE_KEY_WRAP_ALGORITHM, SecretKey,
    };
    use serde_json::json;

    use super::*;
    use crate::settings::{CryptoInstanceConfig, CryptoMaterialConfig, CryptoSettings};

    #[test]
    fn cli_snapshot_crypto_preflight_rejects_missing_runtime_instance() {
        let settings = Settings::new(None).unwrap();
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = validate_restored_collection_crypto_params(&settings, "docs", &params)
            .expect_err("missing runtime instance must fail CLI snapshot preflight");

        assert!(err.contains("recovered snapshot docs"));
        assert!(err.contains("unknown payload crypto instance docs_payload_v1"));
    }

    #[test]
    fn cli_snapshot_crypto_preflight_rejects_missing_runtime_material() {
        let settings = Settings {
            crypto: CryptoSettings {
                instances: HashMap::from([(
                    "docs_payload_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: "payload/aes-256-gcm@v1".to_string(),
                        materials: HashMap::from([(
                            "sym_key".to_string(),
                            "tenant-a/missing-payload-rk".to_string(),
                        )]),
                        backend_ref: None,
                        options: json!({
                            "key_id": "tenant-a:docs",
                            "material_fingerprint_id": "tenant-a/payload@v1",
                        }),
                    },
                )]),
                ..CryptoSettings::default()
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = validate_restored_collection_crypto_params(&settings, "docs", &params)
            .expect_err("missing runtime material must fail CLI snapshot preflight");

        assert!(err.contains("recovered snapshot docs"));
        assert!(err.contains("must bind role sym_key"));
    }

    #[test]
    fn cli_snapshot_crypto_preflight_rejects_wrong_wrapping_key() {
        let mk_material = "tenant-a/mk-v1";
        let rk_material = "tenant-a/payload-rk-v1";
        let rk_epoch = 1;
        let rk_scope = "collection:docs";
        let wrapping_key = SecretKey::from_bytes([91; 32]);
        let resource_key = SecretKey::from_bytes([92; 32]);
        let wrap_provider =
            LocalMasterKeyProvider::new(mk_material, wrapping_key).expect("valid test MK");
        let wrapped = wrap_provider
            .wrap_resource_key(
                &resource_key,
                &resource_key_wrap_test_aad(
                    rk_material,
                    rk_epoch,
                    rk_scope,
                    mk_material,
                    RESOURCE_KEY_WRAP_ALGORITHM,
                ),
            )
            .expect("test RK should wrap");

        let settings = Settings {
            crypto: CryptoSettings {
                allow_inline_key_material: true,
                instances: HashMap::from([(
                    "docs_payload_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: "payload/aes-256-gcm@v1".to_string(),
                        materials: HashMap::from([(
                            "sym_key".to_string(),
                            rk_material.to_string(),
                        )]),
                        backend_ref: None,
                        options: json!({
                            "key_id": "tenant-a:docs",
                            "material_fingerprint_id": "tenant-a/payload@v1",
                        }),
                    },
                )]),
                materials: HashMap::from([
                    (
                        mk_material.to_string(),
                        CryptoMaterialConfig {
                            kind: "wrapping_key_32".to_string(),
                            source: Some("inline".to_string()),
                            value_b64: Some(BASE64URL_NOPAD.encode(&[99; 32])),
                            ..CryptoMaterialConfig::default()
                        },
                    ),
                    (
                        rk_material.to_string(),
                        CryptoMaterialConfig {
                            kind: "wrapped_symmetric_key_32".to_string(),
                            wrapped_by: Some(mk_material.to_string()),
                            wrap_algorithm: Some(RESOURCE_KEY_WRAP_ALGORITHM.to_string()),
                            nonce: Some(wrapped.nonce),
                            wrapped_key_b64: Some(wrapped.wrapped_key),
                            rk_epoch: Some(rk_epoch),
                            state: Some("active".to_string()),
                            scope: Some(rk_scope.to_string()),
                            ..CryptoMaterialConfig::default()
                        },
                    ),
                ]),
                ..CryptoSettings::default()
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = validate_restored_collection_crypto_params(&settings, "docs", &params)
            .expect_err("wrong wrapping key must fail CLI snapshot preflight");

        assert!(err.contains("recovered snapshot docs"));
        assert!(err.contains("decryption authentication failed"));
    }

    #[test]
    fn cli_snapshot_crypto_preflight_rejects_runtime_key_id_mismatch() {
        let mk_material = "tenant-a/mk-v1";
        let rk_material = "tenant-a/payload-rk-v1";
        let rk_epoch = 1;
        let rk_scope = "collection:docs";
        let wrapping_key_bytes = [91; 32];
        let wrapping_key = SecretKey::from_bytes(wrapping_key_bytes);
        let resource_key = SecretKey::from_bytes([92; 32]);
        let wrap_provider =
            LocalMasterKeyProvider::new(mk_material, wrapping_key).expect("valid test MK");
        let wrapped = wrap_provider
            .wrap_resource_key(
                &resource_key,
                &resource_key_wrap_test_aad(
                    rk_material,
                    rk_epoch,
                    rk_scope,
                    mk_material,
                    RESOURCE_KEY_WRAP_ALGORITHM,
                ),
            )
            .expect("test RK should wrap");

        let settings = Settings {
            crypto: CryptoSettings {
                allow_inline_key_material: true,
                instances: HashMap::from([(
                    "docs_payload_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: "payload/aes-256-gcm@v1".to_string(),
                        materials: HashMap::from([(
                            "sym_key".to_string(),
                            rk_material.to_string(),
                        )]),
                        backend_ref: None,
                        options: json!({
                            "key_id": "tenant-a:wrong-docs",
                            "material_fingerprint_id": "tenant-a/payload@v1",
                        }),
                    },
                )]),
                materials: HashMap::from([
                    (
                        mk_material.to_string(),
                        CryptoMaterialConfig {
                            kind: "wrapping_key_32".to_string(),
                            source: Some("inline".to_string()),
                            value_b64: Some(BASE64URL_NOPAD.encode(&wrapping_key_bytes)),
                            ..CryptoMaterialConfig::default()
                        },
                    ),
                    (
                        rk_material.to_string(),
                        CryptoMaterialConfig {
                            kind: "wrapped_symmetric_key_32".to_string(),
                            wrapped_by: Some(mk_material.to_string()),
                            wrap_algorithm: Some(RESOURCE_KEY_WRAP_ALGORITHM.to_string()),
                            nonce: Some(wrapped.nonce),
                            wrapped_key_b64: Some(wrapped.wrapped_key),
                            rk_epoch: Some(rk_epoch),
                            state: Some("active".to_string()),
                            scope: Some(rk_scope.to_string()),
                            ..CryptoMaterialConfig::default()
                        },
                    ),
                ]),
                ..CryptoSettings::default()
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = validate_restored_collection_crypto_params(&settings, "docs", &params)
            .expect_err("runtime key_id mismatch must fail CLI snapshot preflight");

        assert!(err.contains("recovered snapshot docs"));
        assert!(err.contains("key id does not match"));
    }

    fn resource_key_wrap_test_aad(
        material_name: &str,
        epoch: u64,
        scope: &str,
        wrapped_by: &str,
        algorithm: &str,
    ) -> Vec<u8> {
        let epoch = epoch.to_string();
        let values = [
            "qdrant-sec",
            "v1",
            "resource-key-wrap",
            material_name,
            &epoch,
            scope,
            wrapped_by,
            algorithm,
        ];

        let mut aad = Vec::new();
        for value in values {
            let bytes = value.as_bytes();
            aad.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            aad.extend_from_slice(bytes);
        }
        aad
    }
}
