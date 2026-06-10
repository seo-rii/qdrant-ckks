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
use crate::common::private_hnsw::validate_recovered_private_hnsw_oram_snapshot_signatures;
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
    )?;
    Collection::validate_private_hnsw_oram_snapshot_restore_layout(
        collection_name,
        &config,
        collection_path,
    )
    .map_err(|err| {
        let detail = sanitize_private_hnsw_snapshot_layout_error(collection_path, err);
        format!(
            "Failed to validate private HNSW ORAM snapshot layout for recovered snapshot \
             {collection_name}: {detail}",
        )
    })?;
    validate_recovered_private_hnsw_oram_snapshot_signatures(
        settings,
        collection_name,
        &config,
        collection_path,
    )
    .map_err(|err| {
        format!(
            "Failed to validate private HNSW ORAM snapshot manifest signatures for recovered \
             snapshot {collection_name}: {err}",
        )
    })?;
    validate_private_result_oram_snapshot_restore_not_present(collection_path).map_err(|err| {
        format!(
            "Failed to validate private result ORAM snapshot layout for recovered snapshot \
             {collection_name}: {err}",
        )
    })?;
    Ok(())
}

fn sanitize_private_hnsw_snapshot_layout_error(
    _collection_path: &Path,
    err: collection::operations::types::CollectionError,
) -> String {
    let _ = err;
    "private HNSW ORAM snapshot layout validation failed".to_string()
}

fn validate_private_result_oram_snapshot_restore_not_present(
    collection_path: &Path,
) -> Result<(), String> {
    let private_result_oram_path =
        collection_path.join(collection::private_result_oram_store::PRIVATE_RESULT_ORAM_DIR);
    match fs::symlink_metadata(&private_result_oram_path) {
        Ok(_) => Err(format!(
            "private result ORAM snapshot restore requires {} with {} binding and restore support, \
             which are not implemented yet",
            qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
            qdrant_sec::PRIVATE_RESULT_ORAM_BINDING,
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("private result ORAM snapshot layout validation failed".to_string()),
    }
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
    use std::collections::{BTreeMap, HashMap};
    use std::fs;

    use collection::config::{
        COLLECTION_CONFIG_FILE, CollectionConfigInternal, CollectionEncryptionConfig,
        CollectionParams, CryptoMigrationState, EncryptionRuleRef, EncryptionSelector, WalConfig,
    };
    use collection::operations::types::VectorsConfig;
    use collection::operations::vector_params_builder::VectorParamsBuilder;
    use collection::optimizers_builder::OptimizersConfig;
    use collection::private_hnsw_oram_store::{
        PRIVATE_HNSW_ORAM_DIR, PrivateHnswOramEpochState, PrivateHnswOramStore,
    };
    use collection::private_result_oram_store::PRIVATE_RESULT_ORAM_DIR;
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
        LocalMasterKeyProvider, MasterKeyProvider, PRIVATE_HNSW_ORAM_BINDING,
        RESOURCE_KEY_WRAP_ALGORITHM, SecretKey,
    };
    use segment::types::{Distance, HnswConfig};
    use serde_json::json;
    use tempfile::TempDir;
    use uuid::Uuid;

    use super::*;
    use crate::common::private_hnsw_wire_fixture::{
        COLLECTION_ID, KEY_ID, PrivateHnswRouteWireFixture, RK_EPOCH, SIGNING_KEY_ID, VECTOR_NAME,
    };
    use crate::settings::{CryptoInstanceConfig, CryptoMaterialConfig, CryptoSettings};

    fn recovered_private_hnsw_config() -> CollectionConfigInternal {
        CollectionConfigInternal {
            params: CollectionParams {
                vectors: VectorsConfig::Multi(BTreeMap::from([(
                    VECTOR_NAME.to_string(),
                    VectorParamsBuilder::new(2, Distance::Euclid).build(),
                )])),
                encryption: Some(CollectionEncryptionConfig {
                    version: 1,
                    key_id: Some(KEY_ID.to_string()),
                    crypto_schema_version: 1,
                    encryption_epoch: RK_EPOCH,
                    migration_state: CryptoMigrationState::Active,
                    rules: vec![EncryptionRuleRef {
                        id: "text_private_hnsw".to_string(),
                        selector: EncryptionSelector::VectorNames {
                            names: vec![VECTOR_NAME.to_string()],
                        },
                        instance: "docs_private_hnsw_v1".to_string(),
                        binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
                    }],
                }),
                ..CollectionParams::empty()
            },
            hnsw_config: HnswConfig::default(),
            optimizer_config: OptimizersConfig {
                deleted_threshold: 0.1,
                vacuum_min_vector_number: 1000,
                default_segment_number: 0,
                max_segment_size: None,
                #[expect(deprecated)]
                memmap_threshold: None,
                indexing_threshold: Some(100_000),
                flush_interval_sec: 60,
                max_optimization_threads: Some(0),
                prevent_unoptimized: None,
            },
            wal_config: WalConfig::default(),
            quantization_config: None,
            strict_mode_config: None,
            uuid: Some(Uuid::parse_str(COLLECTION_ID).unwrap()),
            metadata: None,
        }
    }

    fn write_recovered_private_hnsw_snapshot_fixture(
        collection_dir: &Path,
        fixture: &PrivateHnswRouteWireFixture,
        corrupt_first_bucket_commitment: bool,
    ) {
        let config = recovered_private_hnsw_config();
        fs::write(
            collection_dir.join(COLLECTION_CONFIG_FILE),
            config.to_bytes().unwrap(),
        )
        .unwrap();

        let store = PrivateHnswOramStore::new(collection_dir, VECTOR_NAME).unwrap();
        store
            .write_manifest(&fixture.manifest, &fixture.manifest_signature)
            .unwrap();
        store
            .write_initial_epoch(&PrivateHnswOramEpochState {
                index_epoch: fixture.encrypted_build.index_epoch,
                root_hash: fixture.encrypted_build.root_hash.clone(),
            })
            .unwrap();
        store
            .write_merkle_tree_from_commitments(
                fixture.encrypted_build.index_epoch,
                fixture.encrypted_build.root_hash.clone(),
                fixture.leaf_commitments.clone(),
            )
            .unwrap();
        for bucket in &fixture.encrypted_build.buckets {
            let mut bucket = bucket.clone();
            if corrupt_first_bucket_commitment && bucket.bucket_id == 0 {
                bucket.bucket_commitment = BASE64URL_NOPAD.encode(&[99; 32]);
            }
            store
                .write_bucket(
                    &bucket,
                    fixture.encrypted_build.index_epoch,
                    fixture.encrypted_build.bucket_count,
                    crate::common::private_hnsw_wire_fixture::MAX_CIPHERTEXT_BYTES,
                )
                .unwrap();
        }
    }

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
    fn cli_snapshot_crypto_preflight_rejects_private_hnsw_bucket_root_mismatch() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let collection_dir = TempDir::new().unwrap();
        write_recovered_private_hnsw_snapshot_fixture(collection_dir.path(), &fixture, true);

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("private HNSW ORAM restore layout mismatch must fail CLI preflight");

        assert!(err.contains("private HNSW ORAM snapshot layout"), "{err}");
        assert!(err.contains("snapshot layout validation failed"), "{err}");
        assert!(!err.contains("bucket 0"), "{err}");
        assert!(!err.contains("commitment context mismatch"), "{err}");
        assert!(
            !err.contains(collection_dir.path().to_string_lossy().as_ref()),
            "{err}"
        );
        assert!(!err.contains("private_hnsw_oram"), "{err}");
        assert!(!err.contains(&fixture.encrypted_build.root_hash), "{err}");
        assert!(
            !err.contains(&fixture.encrypted_build.buckets[0].ciphertext),
            "{err}"
        );
        assert!(!err.contains(SIGNING_KEY_ID), "{err}");
    }

    #[test]
    fn cli_snapshot_crypto_preflight_sanitizes_private_hnsw_store_paths() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let collection_dir = TempDir::new().unwrap();
        write_recovered_private_hnsw_snapshot_fixture(collection_dir.path(), &fixture, false);
        fs::remove_file(
            collection_dir
                .path()
                .join(PRIVATE_HNSW_ORAM_DIR)
                .join(VECTOR_NAME)
                .join("buckets")
                .join("00000000.bucket"),
        )
        .unwrap();

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("missing bucket must fail CLI preflight");

        assert!(
            err.contains("private HNSW ORAM snapshot layout validation failed"),
            "{err}"
        );
        assert!(
            !err.contains(collection_dir.path().to_string_lossy().as_ref()),
            "{err}"
        );
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR), "{err}");
        assert!(!err.contains(&fixture.encrypted_build.root_hash), "{err}");
        assert!(
            !err.contains(&fixture.encrypted_build.buckets[0].ciphertext),
            "{err}"
        );
    }

    #[test]
    fn cli_snapshot_crypto_preflight_accepts_private_hnsw_restore_layout() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let collection_dir = TempDir::new().unwrap();
        write_recovered_private_hnsw_snapshot_fixture(collection_dir.path(), &fixture, false);

        validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
            .expect("valid private HNSW ORAM snapshot layout must pass CLI preflight");
    }

    #[test]
    fn cli_snapshot_crypto_preflight_rejects_private_hnsw_manifest_signature_tamper() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let collection_dir = TempDir::new().unwrap();
        write_recovered_private_hnsw_snapshot_fixture(collection_dir.path(), &fixture, false);
        let store = PrivateHnswOramStore::new(collection_dir.path(), VECTOR_NAME).unwrap();
        let mut tampered_signature = fixture.manifest_signature.clone();
        tampered_signature.sig = BASE64URL_NOPAD.encode(&[9; 64]);
        store
            .write_manifest(&fixture.manifest, &tampered_signature)
            .unwrap();

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("tampered private HNSW manifest signature must fail CLI preflight");

        assert!(
            err.contains("manifest signature verification failed"),
            "{err}"
        );
        assert!(
            !err.contains(collection_dir.path().to_string_lossy().as_ref()),
            "{err}"
        );
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR), "{err}");
        assert!(!err.contains(&fixture.encrypted_build.root_hash), "{err}");
        assert!(
            !err.contains(&fixture.encrypted_build.buckets[0].ciphertext),
            "{err}"
        );
        assert!(!err.contains(SIGNING_KEY_ID), "{err}");
    }

    #[test]
    fn cli_snapshot_crypto_preflight_rejects_reserved_private_result_oram_directory() {
        let settings = Settings::new(None).unwrap();
        let collection_dir = TempDir::new().unwrap();
        let mut config = recovered_private_hnsw_config();
        config.params.encryption = None;
        fs::write(
            collection_dir.path().join(COLLECTION_CONFIG_FILE),
            config.to_bytes().unwrap(),
        )
        .unwrap();
        fs::create_dir(collection_dir.path().join(PRIVATE_RESULT_ORAM_DIR)).unwrap();

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("reserved private result ORAM directory must fail CLI preflight");

        assert!(err.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER));
        assert!(!err.contains(collection_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
    }

    #[cfg(unix)]
    #[test]
    fn cli_snapshot_crypto_preflight_rejects_reserved_private_result_oram_symlink() {
        let settings = Settings::new(None).unwrap();
        let collection_dir = TempDir::new().unwrap();
        let mut config = recovered_private_hnsw_config();
        config.params.encryption = None;
        fs::write(
            collection_dir.path().join(COLLECTION_CONFIG_FILE),
            config.to_bytes().unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            collection_dir.path().join("missing-result-oram-target"),
            collection_dir.path().join(PRIVATE_RESULT_ORAM_DIR),
        )
        .unwrap();

        let err =
            validate_restored_collection_crypto_runtime(&settings, "docs", collection_dir.path())
                .expect_err("reserved private result ORAM symlink must fail CLI preflight");

        assert!(err.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER));
        assert!(!err.contains(collection_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
    }

    #[test]
    fn cli_snapshot_crypto_preflight_rejects_missing_runtime_material() {
        let settings = Settings {
            crypto: CryptoSettings {
                zero_trust_profile: None,
                ckks_grouped_max_candidates: crate::settings::default_ckks_grouped_max_candidates(),
                ckks_scoring_source_batch_max:
                    crate::settings::default_ckks_scoring_source_batch_max(),
                ckks_query_nonce_replay_ttl_secs:
                    crate::settings::default_ckks_query_nonce_replay_ttl_secs(),
                ckks_query_nonce_replay_cache_max_entries:
                    crate::settings::default_ckks_query_nonce_replay_cache_max_entries(),
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
                zero_trust_profile: None,
                ckks_grouped_max_candidates: crate::settings::default_ckks_grouped_max_candidates(),
                ckks_scoring_source_batch_max:
                    crate::settings::default_ckks_scoring_source_batch_max(),
                ckks_query_nonce_replay_ttl_secs:
                    crate::settings::default_ckks_query_nonce_replay_ttl_secs(),
                ckks_query_nonce_replay_cache_max_entries:
                    crate::settings::default_ckks_query_nonce_replay_cache_max_entries(),
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
                zero_trust_profile: None,
                ckks_grouped_max_candidates: crate::settings::default_ckks_grouped_max_candidates(),
                ckks_scoring_source_batch_max:
                    crate::settings::default_ckks_scoring_source_batch_max(),
                ckks_query_nonce_replay_ttl_secs:
                    crate::settings::default_ckks_query_nonce_replay_ttl_secs(),
                ckks_query_nonce_replay_cache_max_entries:
                    crate::settings::default_ckks_query_nonce_replay_cache_max_entries(),
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

    #[test]
    fn cli_snapshot_crypto_preflight_rejects_missing_vector_backend() {
        let settings = Settings {
            crypto: CryptoSettings {
                zero_trust_profile: None,
                ckks_grouped_max_candidates: crate::settings::default_ckks_grouped_max_candidates(),
                ckks_scoring_source_batch_max:
                    crate::settings::default_ckks_scoring_source_batch_max(),
                ckks_query_nonce_replay_ttl_secs:
                    crate::settings::default_ckks_query_nonce_replay_ttl_secs(),
                ckks_query_nonce_replay_cache_max_entries:
                    crate::settings::default_ckks_query_nonce_replay_cache_max_entries(),
                allow_inline_key_material: true,
                instances: HashMap::from([(
                    "docs_vector_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: "vector/openfhe-ckks@v1".to_string(),
                        materials: HashMap::from([(
                            "sym_key".to_string(),
                            "tenant-a/vector-rk-v1".to_string(),
                        )]),
                        backend_ref: None,
                        options: json!({
                            "key_id": "tenant-a:docs",
                            "material_fingerprint_id": "tenant-a/vector@v1",
                            "profile": "ckks-128-n16384-d4-scale50",
                            "crypto_context_b64": BASE64URL_NOPAD.encode(b"openfhe context"),
                            "public_key_b64": BASE64URL_NOPAD.encode(b"openfhe public key"),
                            "score_plaintext_output_tcb_ack": "qdrant-sec-ckks-score-output-tcb-v1",
                        }),
                    },
                )]),
                materials: HashMap::from([(
                    "tenant-a/vector-rk-v1".to_string(),
                    CryptoMaterialConfig {
                        kind: "symmetric_key_32".to_string(),
                        source: Some("inline".to_string()),
                        value_b64: Some(BASE64URL_NOPAD.encode(&[7u8; 32])),
                        ..CryptoMaterialConfig::default()
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
                    id: "vector_conf".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["text".to_string()],
                    },
                    instance: "docs_vector_v1".to_string(),
                    binding: Some("vector-envelope/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = validate_restored_collection_crypto_params(&settings, "docs", &params)
            .expect_err("missing vector backend must fail CLI snapshot preflight");

        assert!(err.contains("recovered snapshot docs"));
        assert!(err.contains("missing backend_ref"));
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
