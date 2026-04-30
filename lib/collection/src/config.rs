use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Write as _};
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::Path;

use atomicwrites::AtomicFile;
use atomicwrites::OverwriteBehavior::AllowOverwrite;
use common::types::PointOffsetType;
use fs_err::File;
use schemars::JsonSchema;
use segment::common::anonymize::Anonymize;
use segment::data_types::vectors::DEFAULT_VECTOR_NAME;
use segment::index::sparse_index::sparse_index_config::{SparseIndexConfig, SparseIndexType};
use segment::types::{
    Distance, HnswConfig, Indexes, Payload, PayloadStorageType, QuantizationConfig, SegmentConfig,
    SparseVectorDataConfig, StrictModeConfig, VectorDataConfig, VectorName, VectorNameBuf,
    VectorStorageDatatype, VectorStorageType,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::{Validate, ValidationError, ValidationErrors};
use wal::WalOptions;

use crate::operations::config_diff::{DiffConfig, QuantizationConfigDiff};
use crate::operations::types::{
    CollectionError, CollectionResult, CollectionWarning, Datatype, SparseVectorParams,
    SparseVectorsConfig, VectorParams, VectorParamsDiff, VectorsConfig, VectorsConfigDiff,
};
use crate::operations::validation;
use crate::optimizers_builder::OptimizersConfig;

pub const COLLECTION_CONFIG_FILE: &str = "config.json";

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate, Anonymize, Clone, PartialEq, Eq)]
#[anonymize(false)]
pub struct WalConfig {
    /// Size of a single WAL segment in MB
    #[validate(range(min = 1))]
    pub wal_capacity_mb: usize,
    /// Number of WAL segments to create ahead of actually used ones
    pub wal_segments_ahead: usize,
    /// Number of closed WAL segments to keep
    #[validate(range(min = 1))]
    #[serde(default = "default_wal_retain_closed")]
    pub wal_retain_closed: usize,
}

fn default_wal_retain_closed() -> usize {
    1
}

impl From<&WalConfig> for WalOptions {
    fn from(config: &WalConfig) -> Self {
        let WalConfig {
            wal_capacity_mb,
            wal_segments_ahead,
            wal_retain_closed,
        } = config;
        WalOptions {
            segment_capacity: wal_capacity_mb * 1024 * 1024,
            segment_queue_len: *wal_segments_ahead,
            retain_closed: NonZeroUsize::new(*wal_retain_closed).unwrap(),
        }
    }
}

#[cfg(test)]
mod ckks_tests {
    use validator::Validate;

    use super::*;

    #[test]
    fn ckks_collection_config_round_trips_without_key_material() {
        let params = CollectionParams {
            ckks: Some(CkksCollectionConfig {
                enabled: true,
                key_id: Some("tenant-a:docs".to_string()),
                payload_text_fields: vec!["body".to_string(), "document.summary".to_string()],
                vector_names: Vec::new(),
            }),
            ..CollectionParams::empty()
        };

        let serialized = serde_json::to_string(&params).unwrap();
        assert!(serialized.contains("\"ckks\""));
        assert!(serialized.contains("tenant-a:docs"));
        assert!(!serialized.contains("master_key"));

        let deserialized: CollectionParams = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.ckks, params.ckks);
        deserialized.validate().unwrap();
    }

    #[test]
    fn ckks_collection_config_rejects_invalid_key_ids_and_field_paths() {
        let invalid_key = CkksCollectionConfig {
            enabled: true,
            key_id: Some("tenant/key".to_string()),
            payload_text_fields: vec!["body".to_string()],
            vector_names: Vec::new(),
        };
        assert!(invalid_key.validate().is_err());

        let invalid_field = CkksCollectionConfig {
            enabled: true,
            key_id: Some("tenant-a:docs".to_string()),
            payload_text_fields: vec!["body..text".to_string()],
            vector_names: Vec::new(),
        };
        assert!(invalid_field.validate().is_err());

        let marker_field = CkksCollectionConfig {
            enabled: true,
            key_id: Some("tenant-a:docs".to_string()),
            payload_text_fields: vec!["$qdrant_ckks.body".to_string()],
            vector_names: Vec::new(),
        };
        assert!(marker_field.validate().is_err());

        for payload_text_field in [
            "$qdrant_client_aead.body",
            "$qdrant_ciphertext.body",
            "items[].name",
            "items.*.name",
            "items.0.name",
        ] {
            let invalid_selector = CkksCollectionConfig {
                enabled: true,
                key_id: Some("tenant-a:docs".to_string()),
                payload_text_fields: vec![payload_text_field.to_string()],
                vector_names: Vec::new(),
            };
            assert!(invalid_selector.validate().is_err());
        }

        let vector_field = CkksCollectionConfig {
            enabled: true,
            key_id: Some("tenant-a:docs".to_string()),
            payload_text_fields: vec!["body".to_string()],
            vector_names: vec!["embedding".to_string()],
        };
        let err = vector_field.validate().unwrap_err();
        assert!(format!("{err:?}").contains("unsupported_ckks_vector_selector"));

        let empty_enabled = CkksCollectionConfig {
            enabled: true,
            key_id: Some("tenant-a:docs".to_string()),
            payload_text_fields: Vec::new(),
            vector_names: Vec::new(),
        };
        assert!(empty_enabled.validate().is_err());
    }

    #[test]
    fn encryption_config_round_trips_and_rejects_legacy_conflicts() {
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

        let serialized = serde_json::to_string(&params).unwrap();
        assert!(serialized.contains("\"encryption\""));
        let deserialized: CollectionParams = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.encryption, params.encryption);
        deserialized.validate().unwrap();

        let conflicting = CollectionParams {
            ckks: Some(CkksCollectionConfig {
                enabled: true,
                key_id: Some("tenant-a:docs".to_string()),
                payload_text_fields: vec!["body".to_string()],
                vector_names: Vec::new(),
            }),
            ..params
        };
        assert!(conflicting.validate().is_err());
    }

    #[test]
    fn encryption_config_rejects_client_envelope_without_collection_key_id() {
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: None,
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_client_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_client_v1".to_string(),
                    binding: Some("client-payload-envelope/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = params.validate().unwrap_err();
        assert!(format!("{err:?}").contains("client_payload_envelope_requires_key_id"));
    }

    #[test]
    fn encryption_config_allows_resource_key_style_key_ids() {
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/client-rk-2026-04@v3".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_client_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_client_v1".to_string(),
                    binding: Some("client-payload-envelope/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        params.validate().unwrap();

        let invalid = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/client key".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_client_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_client_v1".to_string(),
                    binding: Some("client-payload-envelope/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = invalid.validate().unwrap_err();
        assert!(format!("{err:?}").contains("invalid_encryption_key_id"));
    }

    #[test]
    fn encryption_config_rejects_reserved_and_unsupported_payload_paths() {
        for path in [
            "$qdrant_ckks.body",
            "$qdrant_client_aead.body",
            "$qdrant_ciphertext.body",
            "items[].name",
            "items.*.name",
            "items.0.name",
        ] {
            let params = CollectionParams {
                encryption: Some(CollectionEncryptionConfig {
                    version: 1,
                    key_id: Some("tenant-a:docs".to_string()),
                    crypto_schema_version: 1,
                    encryption_epoch: 0,
                    migration_state: CryptoMigrationState::Active,
                    rules: vec![EncryptionRuleRef {
                        id: "payload_conf".to_string(),
                        selector: EncryptionSelector::PayloadPaths {
                            paths: vec![path.to_string()],
                        },
                        instance: "docs_payload_v1".to_string(),
                        binding: Some("payload-field/v1".to_string()),
                    }],
                }),
                ..CollectionParams::empty()
            };

            assert!(params.validate().is_err(), "{path} should be rejected");
        }
    }

    #[test]
    fn encryption_config_rejects_overlapping_payload_paths() {
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![
                    EncryptionRuleRef {
                        id: "document_conf".to_string(),
                        selector: EncryptionSelector::PayloadPaths {
                            paths: vec!["document".to_string()],
                        },
                        instance: "docs_payload_v1".to_string(),
                        binding: Some("payload-field/v1".to_string()),
                    },
                    EncryptionRuleRef {
                        id: "document_body_conf".to_string(),
                        selector: EncryptionSelector::PayloadPaths {
                            paths: vec!["document.body".to_string()],
                        },
                        instance: "docs_payload_v1".to_string(),
                        binding: Some("payload-field/v1".to_string()),
                    },
                ],
            }),
            ..CollectionParams::empty()
        };

        let err = params.validate().unwrap_err();
        assert!(format!("{err:?}").contains("overlapping_encryption_selector"));
    }

    #[test]
    fn encryption_config_rejects_vector_names_until_storage_support_exists() {
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "embedding_conf".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["embedding".to_string()],
                    },
                    instance: "docs_vector_v1".to_string(),
                    binding: Some("vector-envelope/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = params.validate().unwrap_err();
        assert!(format!("{err:?}").contains("unsupported_encryption_selector"));
    }

    #[test]
    fn encryption_config_rejects_direct_migration_state_changes() {
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Rotating,
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

        assert!(params.validate().is_err());
    }

    #[test]
    fn crypto_migration_state_allows_only_job_state_machine_edges() {
        use CryptoMigrationState::{Active, Decrypting, Disabled, Encrypting, Rotating};

        for state in [Disabled, Encrypting, Active, Rotating, Decrypting] {
            assert!(state.can_transition_to(state));
        }

        for (from, to) in [
            (Disabled, Encrypting),
            (Encrypting, Active),
            (Active, Rotating),
            (Rotating, Active),
            (Active, Decrypting),
            (Decrypting, Disabled),
        ] {
            assert!(from.can_transition_to(to), "{from:?} -> {to:?}");
        }

        for (from, to) in [
            (Disabled, Active),
            (Disabled, Rotating),
            (Encrypting, Rotating),
            (Rotating, Decrypting),
            (Decrypting, Active),
            (Active, Disabled),
        ] {
            assert!(!from.can_transition_to(to), "{from:?} -> {to:?}");
        }
    }

    #[test]
    fn crypto_migration_plan_rejects_noop_and_unsafe_edges() {
        use CryptoMigrationState::{Active, Decrypting, Disabled, Encrypting, Rotating};

        let noop = CryptoMigrationPlan {
            from: Active,
            to: Active,
            target_epoch: 3,
            active_rk_id: Some("rk/docs/3".to_string()),
            retired_rk_id: None,
            dry_run: false,
            checkpoints: Vec::new(),
        };
        assert!(noop.validate_admin_plan().is_err());

        let direct_active = CryptoMigrationPlan {
            from: Disabled,
            to: Active,
            target_epoch: 3,
            active_rk_id: Some("rk/docs/3".to_string()),
            retired_rk_id: None,
            dry_run: false,
            checkpoints: Vec::new(),
        };
        assert!(direct_active.validate_admin_plan().is_err());

        let missing_epoch = CryptoMigrationPlan {
            from: Disabled,
            to: Encrypting,
            target_epoch: 0,
            active_rk_id: Some("rk/docs/3".to_string()),
            retired_rk_id: None,
            dry_run: false,
            checkpoints: Vec::new(),
        };
        assert!(missing_epoch.validate_admin_plan().is_err());

        let missing_retired_rk = CryptoMigrationPlan {
            from: Active,
            to: Rotating,
            target_epoch: 4,
            active_rk_id: Some("rk/docs/4".to_string()),
            retired_rk_id: None,
            dry_run: false,
            checkpoints: Vec::new(),
        };
        assert!(missing_retired_rk.validate_admin_plan().is_err());

        let missing_decryption_epoch = CryptoMigrationPlan {
            from: Active,
            to: Decrypting,
            target_epoch: 0,
            active_rk_id: Some("rk/docs/3".to_string()),
            retired_rk_id: None,
            dry_run: false,
            checkpoints: Vec::new(),
        };
        assert!(missing_decryption_epoch.validate_admin_plan().is_err());

        let missing_decryption_rk = CryptoMigrationPlan {
            from: Active,
            to: Decrypting,
            target_epoch: 3,
            active_rk_id: None,
            retired_rk_id: None,
            dry_run: false,
            checkpoints: Vec::new(),
        };
        assert!(missing_decryption_rk.validate_admin_plan().is_err());

        let valid_start = CryptoMigrationPlan {
            from: Disabled,
            to: Encrypting,
            target_epoch: 3,
            active_rk_id: Some("rk/docs/3".to_string()),
            retired_rk_id: None,
            dry_run: false,
            checkpoints: Vec::new(),
        };
        valid_start.validate_admin_plan().unwrap();

        let incomplete_initial_completion = CryptoMigrationPlan {
            from: Encrypting,
            to: Active,
            target_epoch: 3,
            active_rk_id: Some("rk/docs/3".to_string()),
            retired_rk_id: None,
            dry_run: false,
            checkpoints: vec![CryptoMigrationCheckpoint {
                shard_id: 0,
                total_points: 10,
                processed_points: 9,
                rewritten_points: 9,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        };
        assert!(incomplete_initial_completion.validate_admin_plan().is_err());

        let missing_initial_completion_active_rk = CryptoMigrationPlan {
            from: Encrypting,
            to: Active,
            target_epoch: 3,
            active_rk_id: None,
            retired_rk_id: None,
            dry_run: false,
            checkpoints: vec![CryptoMigrationCheckpoint {
                shard_id: 0,
                total_points: 10,
                processed_points: 10,
                rewritten_points: 10,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        };
        assert!(
            missing_initial_completion_active_rk
                .validate_admin_plan()
                .is_err()
        );

        let invalid_resource_key_id = CryptoMigrationPlan {
            from: Disabled,
            to: Encrypting,
            target_epoch: 3,
            active_rk_id: Some("rk docs 3".to_string()),
            retired_rk_id: None,
            dry_run: false,
            checkpoints: Vec::new(),
        };
        assert!(invalid_resource_key_id.validate_admin_plan().is_err());

        let complete_initial = CryptoMigrationPlan {
            from: Encrypting,
            to: Active,
            target_epoch: 3,
            active_rk_id: Some("rk/docs/3".to_string()),
            retired_rk_id: None,
            dry_run: false,
            checkpoints: vec![CryptoMigrationCheckpoint {
                shard_id: 0,
                total_points: 10,
                processed_points: 10,
                rewritten_points: 10,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        };
        complete_initial.validate_admin_plan().unwrap();
    }

    #[test]
    fn crypto_migration_plan_requires_verified_completion_checkpoints() {
        use CryptoMigrationState::{Active, Decrypting, Disabled, Rotating};

        let no_checkpoints = CryptoMigrationPlan {
            from: Rotating,
            to: Active,
            target_epoch: 4,
            active_rk_id: Some("rk/docs/4".to_string()),
            retired_rk_id: Some("rk/docs/3".to_string()),
            dry_run: false,
            checkpoints: Vec::new(),
        };
        assert!(no_checkpoints.validate_admin_plan().is_err());

        let incomplete = CryptoMigrationPlan {
            from: Rotating,
            to: Active,
            target_epoch: 4,
            active_rk_id: Some("rk/docs/4".to_string()),
            retired_rk_id: Some("rk/docs/3".to_string()),
            dry_run: false,
            checkpoints: vec![CryptoMigrationCheckpoint {
                shard_id: 0,
                total_points: 10,
                processed_points: 9,
                rewritten_points: 9,
                status: CryptoMigrationCheckpointStatus::Running,
            }],
        };
        assert!(incomplete.validate_admin_plan().is_err());

        let verified_but_incomplete = CryptoMigrationPlan {
            from: Rotating,
            to: Active,
            target_epoch: 4,
            active_rk_id: Some("rk/docs/4".to_string()),
            retired_rk_id: Some("rk/docs/3".to_string()),
            dry_run: false,
            checkpoints: vec![CryptoMigrationCheckpoint {
                shard_id: 0,
                total_points: 10,
                processed_points: 9,
                rewritten_points: 9,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        };
        assert!(verified_but_incomplete.validate_admin_plan().is_err());

        let invalid_counts = CryptoMigrationPlan {
            from: Active,
            to: Rotating,
            target_epoch: 4,
            active_rk_id: Some("rk/docs/4".to_string()),
            retired_rk_id: Some("rk/docs/3".to_string()),
            dry_run: false,
            checkpoints: vec![CryptoMigrationCheckpoint {
                shard_id: 0,
                total_points: 10,
                processed_points: 11,
                rewritten_points: 11,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        };
        assert!(invalid_counts.validate_admin_plan().is_err());

        let duplicate_shard = CryptoMigrationPlan {
            from: Active,
            to: Rotating,
            target_epoch: 4,
            active_rk_id: Some("rk/docs/4".to_string()),
            retired_rk_id: Some("rk/docs/3".to_string()),
            dry_run: false,
            checkpoints: vec![
                CryptoMigrationCheckpoint {
                    shard_id: 0,
                    total_points: 10,
                    processed_points: 10,
                    rewritten_points: 10,
                    status: CryptoMigrationCheckpointStatus::Verified,
                },
                CryptoMigrationCheckpoint {
                    shard_id: 0,
                    total_points: 8,
                    processed_points: 8,
                    rewritten_points: 8,
                    status: CryptoMigrationCheckpointStatus::Verified,
                },
            ],
        };
        assert!(duplicate_shard.validate_admin_plan().is_err());

        let complete = CryptoMigrationPlan {
            from: Rotating,
            to: Active,
            target_epoch: 4,
            active_rk_id: Some("rk/docs/4".to_string()),
            retired_rk_id: Some("rk/docs/3".to_string()),
            dry_run: false,
            checkpoints: vec![CryptoMigrationCheckpoint {
                shard_id: 0,
                total_points: 10,
                processed_points: 10,
                rewritten_points: 10,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        };
        complete.validate_admin_plan().unwrap();

        let incomplete_decryption = CryptoMigrationPlan {
            from: Decrypting,
            to: Disabled,
            target_epoch: 4,
            active_rk_id: Some("rk/docs/4".to_string()),
            retired_rk_id: None,
            dry_run: false,
            checkpoints: vec![CryptoMigrationCheckpoint {
                shard_id: 0,
                total_points: 10,
                processed_points: 9,
                rewritten_points: 9,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        };
        assert!(incomplete_decryption.validate_admin_plan().is_err());

        let unverified_decryption = CryptoMigrationPlan {
            from: Decrypting,
            to: Disabled,
            target_epoch: 4,
            active_rk_id: Some("rk/docs/4".to_string()),
            retired_rk_id: None,
            dry_run: false,
            checkpoints: vec![CryptoMigrationCheckpoint {
                shard_id: 0,
                total_points: 10,
                processed_points: 10,
                rewritten_points: 10,
                status: CryptoMigrationCheckpointStatus::Running,
            }],
        };
        assert!(unverified_decryption.validate_admin_plan().is_err());

        let complete_decryption = CryptoMigrationPlan {
            from: Decrypting,
            to: Disabled,
            target_epoch: 4,
            active_rk_id: Some("rk/docs/4".to_string()),
            retired_rk_id: None,
            dry_run: false,
            checkpoints: vec![CryptoMigrationCheckpoint {
                shard_id: 0,
                total_points: 10,
                processed_points: 10,
                rewritten_points: 10,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        };
        complete_decryption.validate_admin_plan().unwrap();
    }

    #[test]
    fn crypto_migration_plan_validates_against_current_config() {
        use CryptoMigrationState::{Active, Rotating};

        let current = CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a:docs".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 3,
            migration_state: Active,
            rules: vec![EncryptionRuleRef {
                id: "body_conf".to_string(),
                selector: EncryptionSelector::PayloadPaths {
                    paths: vec!["body".to_string()],
                },
                instance: "docs_payload_v1".to_string(),
                binding: Some("payload-field/v1".to_string()),
            }],
        };

        let stale_rotation = CryptoMigrationPlan {
            from: Active,
            to: Rotating,
            target_epoch: 3,
            active_rk_id: Some("rk/docs/3".to_string()),
            retired_rk_id: Some("rk/docs/2".to_string()),
            dry_run: false,
            checkpoints: Vec::new(),
        };
        assert!(
            stale_rotation
                .validate_admin_plan_for_config(&current)
                .is_err()
        );

        let valid_rotation = CryptoMigrationPlan {
            from: Active,
            to: Rotating,
            target_epoch: 4,
            active_rk_id: Some("rk/docs/4".to_string()),
            retired_rk_id: Some("rk/docs/3".to_string()),
            dry_run: false,
            checkpoints: Vec::new(),
        };
        valid_rotation
            .validate_admin_plan_for_config(&current)
            .unwrap();

        let wrong_decryption_epoch = CryptoMigrationPlan {
            from: Active,
            to: CryptoMigrationState::Decrypting,
            target_epoch: 4,
            active_rk_id: Some("rk/docs/3".to_string()),
            retired_rk_id: None,
            dry_run: false,
            checkpoints: Vec::new(),
        };
        assert!(
            wrong_decryption_epoch
                .validate_admin_plan_for_config(&current)
                .is_err()
        );

        let valid_decryption_start = CryptoMigrationPlan {
            from: Active,
            to: CryptoMigrationState::Decrypting,
            target_epoch: 3,
            active_rk_id: Some("rk/docs/3".to_string()),
            retired_rk_id: None,
            dry_run: false,
            checkpoints: Vec::new(),
        };
        valid_decryption_start
            .validate_admin_plan_for_config(&current)
            .unwrap();

        let mut rotating_current = current.clone();
        rotating_current.migration_state = Rotating;
        rotating_current.encryption_epoch = 4;
        let wrong_completion_epoch = CryptoMigrationPlan {
            from: Rotating,
            to: Active,
            target_epoch: 5,
            active_rk_id: Some("rk/docs/4".to_string()),
            retired_rk_id: Some("rk/docs/3".to_string()),
            dry_run: false,
            checkpoints: vec![CryptoMigrationCheckpoint {
                shard_id: 0,
                total_points: 10,
                processed_points: 10,
                rewritten_points: 10,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        };
        assert!(
            wrong_completion_epoch
                .validate_admin_plan_for_config(&rotating_current)
                .is_err()
        );

        let wrong_current_state = CryptoMigrationPlan {
            from: Rotating,
            to: Active,
            target_epoch: 3,
            active_rk_id: Some("rk/docs/3".to_string()),
            retired_rk_id: Some("rk/docs/2".to_string()),
            dry_run: false,
            checkpoints: vec![CryptoMigrationCheckpoint {
                shard_id: 0,
                total_points: 10,
                processed_points: 10,
                rewritten_points: 10,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        };
        assert!(
            wrong_current_state
                .validate_admin_plan_for_config(&current)
                .is_err()
        );
    }

    #[test]
    fn collection_params_reject_encryption_changes_without_migration() {
        let ckks = CkksCollectionConfig {
            enabled: true,
            key_id: Some("tenant-a:docs".to_string()),
            payload_text_fields: vec!["body".to_string()],
            vector_names: Vec::new(),
        };
        let ckks_params = CollectionParams {
            ckks: Some(ckks.clone()),
            ..CollectionParams::empty()
        };
        assert!(ckks_params.check_compatible(&ckks_params).is_ok());

        let disabled_ckks = CollectionParams {
            ckks: Some(CkksCollectionConfig {
                enabled: false,
                key_id: ckks.key_id.clone(),
                payload_text_fields: Vec::new(),
                vector_names: Vec::new(),
            }),
            ..CollectionParams::empty()
        };
        assert!(ckks_params.check_compatible(&disabled_ckks).is_err());
        assert!(
            CollectionParams::empty()
                .check_compatible(&ckks_params)
                .is_err()
        );

        let encryption_params = CollectionParams {
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
        let changed_encryption = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "summary_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["summary".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        assert!(
            encryption_params
                .check_compatible(&encryption_params)
                .is_ok()
        );
        assert!(
            encryption_params
                .check_compatible(&changed_encryption)
                .is_err()
        );
    }

    #[test]
    fn ckks_config_adapts_to_generic_encryption_rules() {
        let ckks = CkksCollectionConfig {
            enabled: true,
            key_id: Some("tenant-a:docs".to_string()),
            payload_text_fields: vec!["body".to_string()],
            vector_names: Vec::new(),
        };

        let encryption = CollectionEncryptionConfig::from_legacy_ckks(&ckks).unwrap();
        assert_eq!(encryption.crypto_schema_version, 1);
        assert_eq!(encryption.encryption_epoch, 0);
        assert_eq!(encryption.migration_state, CryptoMigrationState::Active);
        assert_eq!(encryption.rules.len(), 1);
        assert_eq!(
            encryption.legacy_ckks_projection(),
            Some(CkksCollectionConfig {
                enabled: true,
                key_id: Some("tenant-a:docs".to_string()),
                payload_text_fields: vec!["body".to_string()],
                vector_names: Vec::new(),
            }),
        );
    }

    #[test]
    fn legacy_ckks_projection_rejects_non_legacy_rules() {
        let encryption = CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a/client-rk-2026-04".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 0,
            migration_state: CryptoMigrationState::Active,
            rules: vec![EncryptionRuleRef {
                id: "body_client_conf".to_string(),
                selector: EncryptionSelector::PayloadPaths {
                    paths: vec!["body".to_string()],
                },
                instance: "docs_payload_client_v1".to_string(),
                binding: Some("client-payload-envelope/v1".to_string()),
            }],
        };

        assert_eq!(encryption.legacy_ckks_projection(), None);
    }

    #[test]
    fn encryption_config_rejects_metadata_selector_until_transport_support_exists() {
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "tenant_index".to_string(),
                    selector: EncryptionSelector::MetadataKeys {
                        keys: vec!["tenant_id".to_string()],
                    },
                    instance: "docs_meta_eq_v1".to_string(),
                    binding: Some("metadata-value/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        assert!(params.validate().is_err());
    }
}

impl Default for WalConfig {
    fn default() -> Self {
        WalConfig {
            wal_capacity_mb: 32,
            wal_segments_ahead: 0,
            wal_retain_closed: default_wal_retain_closed(),
        }
    }
}

#[derive(
    Debug, Deserialize, Serialize, JsonSchema, Anonymize, PartialEq, Eq, Hash, Clone, Copy, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum ShardingMethod {
    #[default]
    Auto,
    Custom,
}

#[derive(
    Debug, Deserialize, Serialize, JsonSchema, Anonymize, PartialEq, Eq, Hash, Clone, Copy, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum CryptoMigrationState {
    #[default]
    Disabled,
    Encrypting,
    Active,
    Rotating,
    Decrypting,
}

impl CryptoMigrationState {
    pub fn can_transition_to(self, next: Self) -> bool {
        self == next
            || matches!(
                (self, next),
                (Self::Disabled, Self::Encrypting)
                    | (Self::Encrypting, Self::Active)
                    | (Self::Active, Self::Rotating)
                    | (Self::Rotating, Self::Active)
                    | (Self::Active, Self::Decrypting)
                    | (Self::Decrypting, Self::Disabled)
            )
    }

    pub fn is_job_transition_to(self, next: Self) -> bool {
        self != next && self.can_transition_to(next)
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Anonymize, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub struct CryptoMigrationPlan {
    pub from: CryptoMigrationState,
    pub to: CryptoMigrationState,
    #[serde(default)]
    #[anonymize(false)]
    pub target_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[anonymize(false)]
    pub active_rk_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[anonymize(false)]
    pub retired_rk_id: Option<String>,
    #[serde(default)]
    #[anonymize(false)]
    pub dry_run: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checkpoints: Vec<CryptoMigrationCheckpoint>,
}

impl CryptoMigrationPlan {
    pub fn validate_admin_plan(&self) -> Result<(), ValidationError> {
        if !self.from.is_job_transition_to(self.to) {
            return Err(ValidationError::new("invalid_crypto_migration_transition"));
        }

        if matches!(
            (self.from, self.to),
            (
                CryptoMigrationState::Disabled,
                CryptoMigrationState::Encrypting
            ) | (CryptoMigrationState::Active, CryptoMigrationState::Rotating)
                | (
                    CryptoMigrationState::Active,
                    CryptoMigrationState::Decrypting
                )
                | (
                    CryptoMigrationState::Decrypting,
                    CryptoMigrationState::Disabled
                )
        ) && self.target_epoch == 0
        {
            return Err(ValidationError::new(
                "missing_crypto_migration_target_epoch",
            ));
        }

        if matches!(
            (self.from, self.to),
            (
                CryptoMigrationState::Disabled,
                CryptoMigrationState::Encrypting
            ) | (
                CryptoMigrationState::Encrypting,
                CryptoMigrationState::Active
            ) | (CryptoMigrationState::Active, CryptoMigrationState::Rotating)
                | (CryptoMigrationState::Rotating, CryptoMigrationState::Active)
                | (
                    CryptoMigrationState::Active,
                    CryptoMigrationState::Decrypting
                )
                | (
                    CryptoMigrationState::Decrypting,
                    CryptoMigrationState::Disabled
                )
        ) && self.active_rk_id.as_deref().is_none_or(str::is_empty)
        {
            return Err(ValidationError::new("missing_crypto_migration_active_rk"));
        }

        if matches!(
            (self.from, self.to),
            (CryptoMigrationState::Active, CryptoMigrationState::Rotating)
                | (CryptoMigrationState::Rotating, CryptoMigrationState::Active)
        ) && self.retired_rk_id.as_deref().is_none_or(str::is_empty)
        {
            return Err(ValidationError::new("missing_crypto_migration_retired_rk"));
        }

        let requires_verified_completion = matches!(
            (self.from, self.to),
            (
                CryptoMigrationState::Encrypting,
                CryptoMigrationState::Active
            ) | (CryptoMigrationState::Rotating, CryptoMigrationState::Active)
                | (
                    CryptoMigrationState::Decrypting,
                    CryptoMigrationState::Disabled
                )
        );

        for rk_id in [&self.active_rk_id, &self.retired_rk_id]
            .into_iter()
            .flatten()
        {
            validate_crypto_identifier(rk_id)
                .map_err(|_| ValidationError::new("invalid_crypto_migration_resource_key"))?;
        }

        for checkpoint in &self.checkpoints {
            if checkpoint.processed_points > checkpoint.total_points
                || checkpoint.rewritten_points > checkpoint.processed_points
            {
                return Err(ValidationError::new("invalid_crypto_migration_checkpoint"));
            }
        }

        let mut shard_ids = std::collections::HashSet::new();
        for checkpoint in &self.checkpoints {
            if !shard_ids.insert(checkpoint.shard_id) {
                return Err(ValidationError::new(
                    "duplicate_crypto_migration_checkpoint",
                ));
            }
        }

        if requires_verified_completion {
            if self.checkpoints.is_empty()
                || self.checkpoints.iter().any(|checkpoint| {
                    checkpoint.status != CryptoMigrationCheckpointStatus::Verified
                        || checkpoint.processed_points != checkpoint.total_points
                })
            {
                return Err(ValidationError::new(
                    "crypto_migration_requires_verified_checkpoints",
                ));
            }
        }

        Ok(())
    }

    pub fn validate_admin_plan_for_config(
        &self,
        current: &CollectionEncryptionConfig,
    ) -> Result<(), ValidationError> {
        self.validate_admin_plan()?;

        if current.migration_state != self.from {
            return Err(ValidationError::new(
                "crypto_migration_current_state_mismatch",
            ));
        }

        if matches!(
            (self.from, self.to),
            (
                CryptoMigrationState::Disabled,
                CryptoMigrationState::Encrypting
            ) | (CryptoMigrationState::Active, CryptoMigrationState::Rotating)
        ) && self.target_epoch <= current.encryption_epoch
        {
            return Err(ValidationError::new(
                "crypto_migration_target_epoch_must_advance",
            ));
        }

        if matches!(
            (self.from, self.to),
            (
                CryptoMigrationState::Encrypting,
                CryptoMigrationState::Active
            ) | (CryptoMigrationState::Rotating, CryptoMigrationState::Active)
                | (
                    CryptoMigrationState::Active,
                    CryptoMigrationState::Decrypting
                )
                | (
                    CryptoMigrationState::Decrypting,
                    CryptoMigrationState::Disabled
                )
        ) && self.target_epoch != 0
            && self.target_epoch != current.encryption_epoch
        {
            return Err(ValidationError::new(
                "crypto_migration_target_epoch_mismatch",
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Anonymize, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub struct CryptoMigrationCheckpoint {
    #[anonymize(false)]
    pub shard_id: u32,
    #[anonymize(false)]
    pub total_points: u64,
    #[anonymize(false)]
    pub processed_points: u64,
    #[anonymize(false)]
    pub rewritten_points: u64,
    #[serde(default)]
    #[anonymize(false)]
    pub status: CryptoMigrationCheckpointStatus,
}

#[derive(
    Debug, Deserialize, Serialize, JsonSchema, Anonymize, Clone, Copy, PartialEq, Eq, Hash, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum CryptoMigrationCheckpointStatus {
    #[default]
    Pending,
    Running,
    Verified,
    RolledBack,
}

#[derive(
    Debug, Deserialize, Serialize, JsonSchema, Validate, Anonymize, Clone, PartialEq, Eq, Hash,
)]
#[validate(schema(function = "validate_ckks_collection_config"))]
#[serde(rename_all = "snake_case")]
pub struct CkksCollectionConfig {
    /// Enable encryption for this collection.
    #[serde(default)]
    #[anonymize(false)]
    pub enabled: bool,
    /// Public key id recorded in encryption envelopes. Key material is resolved from runtime config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(custom(function = "validate_ckks_key_id"))]
    #[anonymize(false)]
    pub key_id: Option<String>,
    /// Dot-separated payload string fields encrypted before storage.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[validate(custom(function = "validate_ckks_payload_fields"))]
    #[anonymize(true)]
    pub payload_text_fields: Vec<String>,
    /// Named dense vectors that should be encrypted through the OpenFHE CKKS bridge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[anonymize(false)]
    pub vector_names: Vec<VectorNameBuf>,
}

impl Default for CkksCollectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            key_id: None,
            payload_text_fields: Vec::new(),
            vector_names: Vec::new(),
        }
    }
}

fn validate_ckks_key_id(key_id: &str) -> Result<(), validator::ValidationError> {
    if key_id.is_empty()
        || key_id.len() > 128
        || !key_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
    {
        return Err(validator::ValidationError::new("invalid_ckks_key_id"));
    }

    Ok(())
}

fn validate_encryption_key_id(key_id: &str) -> Result<(), validator::ValidationError> {
    if key_id.is_empty()
        || key_id.len() > 128
        || !key_id.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-' | b'/' | b'@')
        })
    {
        return Err(validator::ValidationError::new("invalid_encryption_key_id"));
    }

    Ok(())
}

fn validate_ckks_payload_fields(fields: &[String]) -> Result<(), validator::ValidationError> {
    for field in fields {
        if field.is_empty()
            || field.starts_with('.')
            || field.ends_with('.')
            || field.split('.').any(invalid_payload_encryption_path_part)
        {
            return Err(validator::ValidationError::new(
                "invalid_ckks_payload_field",
            ));
        }
    }

    Ok(())
}

fn validate_ckks_collection_config(
    config: &CkksCollectionConfig,
) -> Result<(), validator::ValidationError> {
    if config.enabled && !config.vector_names.is_empty() {
        return Err(validator::ValidationError::new(
            "unsupported_ckks_vector_selector",
        ));
    }

    if config.enabled && config.payload_text_fields.is_empty() && config.vector_names.is_empty() {
        return Err(validator::ValidationError::new("empty_ckks_selectors"));
    }

    Ok(())
}

/// Capability-oriented collection encryption rules.
///
/// Secret key material is never stored here. Metadata selectors are reserved
/// for future metadata value and blind-index support, but are rejected by
/// collection validation in this branch.
#[derive(
    Debug, Deserialize, Serialize, JsonSchema, Validate, Anonymize, Clone, PartialEq, Eq, Hash,
)]
#[validate(schema(function = "validate_collection_encryption_config"))]
#[serde(rename_all = "snake_case")]
pub struct CollectionEncryptionConfig {
    #[validate(range(min = 1))]
    #[anonymize(false)]
    pub version: u16,
    /// Public key id recorded in encryption envelopes. Key material is resolved from runtime config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(custom(function = "validate_encryption_key_id"))]
    #[anonymize(false)]
    pub key_id: Option<String>,
    #[serde(default = "default_crypto_schema_version")]
    #[validate(range(min = 1))]
    #[anonymize(false)]
    pub crypto_schema_version: u16,
    #[serde(default)]
    #[anonymize(false)]
    pub encryption_epoch: u64,
    #[serde(default)]
    #[anonymize(false)]
    pub migration_state: CryptoMigrationState,
    #[validate(nested)]
    #[validate(custom(function = "validate_encryption_rules"))]
    pub rules: Vec<EncryptionRuleRef>,
}

const fn default_crypto_schema_version() -> u16 {
    1
}

fn validate_collection_encryption_config(
    config: &CollectionEncryptionConfig,
) -> Result<(), validator::ValidationError> {
    if config.migration_state != CryptoMigrationState::Active {
        return Err(validator::ValidationError::new(
            "crypto_migration_state_requires_migration_job",
        ));
    }

    if config.rules.iter().any(|rule| {
        rule.binding.as_deref() == Some("client-payload-envelope/v1")
            && config.key_id.as_deref().is_none_or(str::is_empty)
    }) {
        return Err(validator::ValidationError::new(
            "client_payload_envelope_requires_key_id",
        ));
    }

    Ok(())
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Anonymize, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub struct EncryptionRuleRef {
    #[anonymize(false)]
    pub id: String,
    pub selector: EncryptionSelector,
    #[anonymize(false)]
    pub instance: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[anonymize(false)]
    pub binding: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Anonymize, Clone, PartialEq, Eq, Hash)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EncryptionSelector {
    PayloadPaths {
        #[validate(custom(function = "validate_encryption_payload_paths"))]
        #[anonymize(true)]
        paths: Vec<String>,
    },
    VectorNames {
        #[validate(length(min = 1))]
        #[anonymize(false)]
        names: Vec<VectorNameBuf>,
    },
    /// Reserved for future metadata encryption support.
    ///
    /// This selector is currently rejected by collection validation; AEAD alone
    /// does not support metadata filtering semantics such as range, geo, or
    /// full-text filters.
    MetadataKeys {
        #[validate(custom(function = "validate_encryption_metadata_keys"))]
        #[anonymize(true)]
        keys: Vec<String>,
    },
}

impl CollectionEncryptionConfig {
    pub fn from_legacy_ckks(value: &CkksCollectionConfig) -> Option<Self> {
        if !value.enabled {
            return None;
        }

        let mut rules = Vec::new();
        if !value.payload_text_fields.is_empty() {
            rules.push(EncryptionRuleRef {
                id: "legacy_ckks_payload".to_string(),
                selector: EncryptionSelector::PayloadPaths {
                    paths: value.payload_text_fields.clone(),
                },
                instance: "legacy_ckks_payload".to_string(),
                binding: Some("payload-field/v1".to_string()),
            });
        }
        if !value.vector_names.is_empty() {
            rules.push(EncryptionRuleRef {
                id: "legacy_ckks_vector".to_string(),
                selector: EncryptionSelector::VectorNames {
                    names: value.vector_names.clone(),
                },
                instance: "legacy_ckks_vector".to_string(),
                binding: Some("vector-envelope/v1".to_string()),
            });
        }
        if rules.is_empty() {
            return None;
        }

        Some(Self {
            version: 1,
            key_id: value.key_id.clone(),
            crypto_schema_version: default_crypto_schema_version(),
            encryption_epoch: 0,
            migration_state: CryptoMigrationState::Active,
            rules,
        })
    }

    pub fn legacy_ckks_projection(&self) -> Option<CkksCollectionConfig> {
        let mut payload_text_fields = Vec::new();
        let mut vector_names = Vec::new();

        for rule in &self.rules {
            match &rule.selector {
                EncryptionSelector::PayloadPaths { paths } => {
                    if rule.id != "legacy_ckks_payload"
                        || rule.instance != "legacy_ckks_payload"
                        || rule.binding.as_deref() != Some("payload-field/v1")
                    {
                        return None;
                    }
                    payload_text_fields.extend(paths.clone());
                }
                EncryptionSelector::VectorNames { names } => {
                    if rule.id != "legacy_ckks_vector"
                        || rule.instance != "legacy_ckks_vector"
                        || rule.binding.as_deref() != Some("vector-envelope/v1")
                    {
                        return None;
                    }
                    vector_names.extend(names.clone());
                }
                EncryptionSelector::MetadataKeys { .. } => return None,
            }
        }

        if payload_text_fields.is_empty() && vector_names.is_empty() {
            return None;
        }

        Some(CkksCollectionConfig {
            enabled: true,
            key_id: self.key_id.clone(),
            payload_text_fields,
            vector_names,
        })
    }
}

impl Validate for EncryptionSelector {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let (field, result) = match self {
            Self::PayloadPaths { paths } => ("paths", validate_encryption_payload_paths(paths)),
            Self::VectorNames { names } => {
                let result = if names.is_empty() {
                    Err(ValidationError::new("length"))
                } else {
                    Ok(())
                };
                ("names", result)
            }
            Self::MetadataKeys { keys } => ("keys", validate_encryption_metadata_keys(keys)),
        };

        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                let mut errors = ValidationErrors::new();
                errors.add(field, error);
                Err(errors)
            }
        }
    }
}

impl Validate for EncryptionRuleRef {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();

        if let Err(error) = validate_crypto_identifier(&self.id) {
            errors.add("id", error);
        }
        let selector_error = match &self.selector {
            EncryptionSelector::PayloadPaths { paths } => validate_encryption_payload_paths(paths),
            EncryptionSelector::VectorNames { names } => {
                if names.is_empty() {
                    Err(ValidationError::new("length"))
                } else {
                    Ok(())
                }
            }
            EncryptionSelector::MetadataKeys { keys } => validate_encryption_metadata_keys(keys),
        };
        if let Err(error) = selector_error {
            errors.add("selector", error);
        }
        if let Err(error) = validate_crypto_identifier(&self.instance) {
            errors.add("instance", error);
        }
        if let Err(error) = validate_optional_binding_name(&self.binding) {
            errors.add("binding", error);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl EncryptionSelector {
    pub fn payload_paths(&self) -> Option<&[String]> {
        match self {
            Self::PayloadPaths { paths } => Some(paths),
            _ => None,
        }
    }

    pub fn vector_names(&self) -> Option<&[VectorNameBuf]> {
        match self {
            Self::VectorNames { names } => Some(names),
            _ => None,
        }
    }
}

fn validate_crypto_identifier(value: &str) -> Result<(), validator::ValidationError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-' | b'/' | b'@')
        })
    {
        return Err(validator::ValidationError::new("invalid_crypto_identifier"));
    }

    Ok(())
}

fn validate_optional_binding_name(
    value: &Option<String>,
) -> Result<(), validator::ValidationError> {
    if let Some(value) = value {
        validate_crypto_identifier(value)?;
    }

    Ok(())
}

fn validate_encryption_payload_paths(fields: &[String]) -> Result<(), validator::ValidationError> {
    if fields.is_empty() {
        return Err(validator::ValidationError::new(
            "invalid_encryption_payload_paths",
        ));
    }

    for field in fields {
        if field.is_empty()
            || field.starts_with('.')
            || field.ends_with('.')
            || field.split('.').any(invalid_payload_encryption_path_part)
        {
            return Err(validator::ValidationError::new(
                "invalid_encryption_payload_paths",
            ));
        }
    }

    Ok(())
}

fn invalid_payload_encryption_path_part(part: &str) -> bool {
    part.is_empty()
        || matches!(
            part,
            "$qdrant_ckks" | "$qdrant_client_aead" | "$qdrant_ciphertext"
        )
        || part.contains('\0')
        || part.contains('[')
        || part.contains(']')
        || part.contains('*')
        || part.bytes().all(|byte| byte.is_ascii_digit())
}

fn validate_encryption_metadata_keys(keys: &[String]) -> Result<(), validator::ValidationError> {
    if keys.is_empty() {
        return Err(validator::ValidationError::new(
            "invalid_encryption_metadata_keys",
        ));
    }

    for key in keys {
        if key.is_empty() || key.contains('\0') {
            return Err(validator::ValidationError::new(
                "invalid_encryption_metadata_keys",
            ));
        }
    }

    Ok(())
}

fn validate_encryption_rules(
    rules: &[EncryptionRuleRef],
) -> Result<(), validator::ValidationError> {
    if rules.is_empty() {
        return Err(validator::ValidationError::new("invalid_encryption_rules"));
    }

    let mut ids = HashSet::new();
    let mut payload_paths = Vec::<&str>::new();
    let mut vector_names = HashSet::new();
    for rule in rules {
        if !ids.insert(rule.id.as_str()) {
            return Err(validator::ValidationError::new(
                "duplicate_encryption_rule_id",
            ));
        }
        if matches!(
            rule.selector,
            EncryptionSelector::MetadataKeys { .. } | EncryptionSelector::VectorNames { .. }
        ) {
            return Err(validator::ValidationError::new(
                "unsupported_encryption_selector",
            ));
        }
        match &rule.selector {
            EncryptionSelector::PayloadPaths { paths } => {
                for path in paths {
                    if payload_paths
                        .iter()
                        .any(|existing| encryption_paths_overlap(existing, path))
                    {
                        return Err(validator::ValidationError::new(
                            "overlapping_encryption_selector",
                        ));
                    }
                    payload_paths.push(path);
                }
            }
            EncryptionSelector::VectorNames { names } => {
                for name in names {
                    if !vector_names.insert(name.as_str()) {
                        return Err(validator::ValidationError::new(
                            "overlapping_encryption_selector",
                        ));
                    }
                }
            }
            EncryptionSelector::MetadataKeys { .. } => {}
        }
    }

    Ok(())
}

fn encryption_paths_overlap(left: &str, right: &str) -> bool {
    left == right
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with('.'))
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

fn validate_collection_encryption_sections(
    params: &CollectionParams,
) -> Result<(), validator::ValidationError> {
    if params.encryption.is_some() && params.ckks.is_some() {
        return Err(validator::ValidationError::new(
            "conflicting_collection_encryption_sections",
        ));
    }

    Ok(())
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate, Anonymize, Clone, PartialEq, Eq)]
#[validate(schema(function = "validate_collection_encryption_sections"))]
#[serde(rename_all = "snake_case")]
pub struct CollectionParams {
    /// Configuration of the vector storage
    #[validate(nested)]
    #[serde(default)]
    pub vectors: VectorsConfig,
    /// Number of shards the collection has
    #[serde(default = "default_shard_number")]
    #[anonymize(false)]
    pub shard_number: NonZeroU32,
    /// Sharding method
    /// Default is Auto - points are distributed across all available shards
    /// Custom - points are distributed across shards according to shard key
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sharding_method: Option<ShardingMethod>,
    /// Number of replicas for each shard
    #[serde(default = "default_replication_factor")]
    #[anonymize(false)]
    pub replication_factor: NonZeroU32,
    /// Defines how many replicas should apply the operation for us to consider it successful.
    /// Increasing this number will make the collection more resilient to inconsistencies, but will
    /// also make it fail if not enough replicas are available.
    /// Does not have any performance impact.
    #[serde(default = "default_write_consistency_factor")]
    #[anonymize(false)]
    pub write_consistency_factor: NonZeroU32,
    /// Defines how many additional replicas should be processing read request at the same time.
    /// Default value is Auto, which means that fan-out will be determined automatically based on
    /// the busyness of the local replica.
    /// Having more than 0 might be useful to smooth latency spikes of individual nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[anonymize(false)]
    pub read_fan_out_factor: Option<u32>,
    /// Define number of milliseconds to wait before attempting to read from another replica.
    /// This setting can help to reduce latency spikes in case of occasional slow replicas.
    /// Default is 0, which means delayed fan out request is disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[anonymize(false)]
    pub read_fan_out_delay_ms: Option<u64>,
    /// If true - point's payload will not be stored in memory.
    /// It will be read from the disk every time it is requested.
    /// This setting saves RAM by (slightly) increasing the response time.
    /// Note: those payload values that are involved in filtering and are indexed - remain in RAM.
    ///
    /// Default: true
    #[serde(default = "default_on_disk_payload")]
    pub on_disk_payload: bool,
    /// Configuration of the sparse vector storage
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub sparse_vectors: Option<BTreeMap<VectorNameBuf, SparseVectorParams>>,
    /// Capability-oriented collection encryption rules. Secret key material is never stored here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub encryption: Option<CollectionEncryptionConfig>,
    /// Collection-local encryption settings. Secret key material is never stored here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub ckks: Option<CkksCollectionConfig>,
}

impl CollectionParams {
    pub fn payload_storage_type(&self) -> PayloadStorageType {
        #[cfg(feature = "rocksdb")]
        if self.on_disk_payload {
            PayloadStorageType::Mmap
        } else if common::flags::feature_flags().payload_storage_skip_rocksdb {
            PayloadStorageType::InRamMmap
        } else {
            PayloadStorageType::InMemory
        }

        #[cfg(not(feature = "rocksdb"))]
        PayloadStorageType::from_on_disk_payload(self.on_disk_payload)
    }

    pub fn check_compatible(&self, other: &CollectionParams) -> CollectionResult<()> {
        let CollectionParams {
            vectors,
            shard_number: _, // Maybe be updated by resharding, assume local shards needs to be dropped
            sharding_method, // Not changeable
            replication_factor: _, // May be changed
            write_consistency_factor: _, // May be changed
            read_fan_out_factor: _, // May be changed
            read_fan_out_delay_ms: _, // May be changed,
            on_disk_payload: _, // May be changed
            sparse_vectors,  // Parameters may be changes, but not the structure
            encryption,
            ckks,
        } = other;

        self.vectors.check_compatible(vectors)?;

        if &self.encryption != encryption {
            return Err(CollectionError::bad_input(
                "collection encryption config is incompatible: encryption changes require a migration",
            ));
        }

        if &self.ckks != ckks {
            return Err(CollectionError::bad_input(
                "collection ckks config is incompatible: encryption changes require a migration",
            ));
        }

        let this_sparse_vectors: HashSet<_> = if let Some(sparse_vectors) = &self.sparse_vectors {
            sparse_vectors.keys().collect()
        } else {
            HashSet::new()
        };

        let other_sparse_vectors: HashSet<_> = if let Some(sparse_vectors) = sparse_vectors {
            sparse_vectors.keys().collect()
        } else {
            HashSet::new()
        };

        if this_sparse_vectors != other_sparse_vectors {
            return Err(CollectionError::bad_input(format!(
                "sparse vectors are incompatible: \
                 origin sparse vectors: {this_sparse_vectors:?}, \
                 while other sparse vectors: {other_sparse_vectors:?}",
            )));
        }

        let this_sharding_method = self.sharding_method.unwrap_or_default();
        let other_sharding_method = sharding_method.unwrap_or_default();

        if this_sharding_method != other_sharding_method {
            return Err(CollectionError::bad_input(format!(
                "sharding method is incompatible: \
                 origin sharding method: {this_sharding_method:?}, \
                 while other sharding method: {other_sharding_method:?}",
            )));
        }

        Ok(())
    }

    pub fn get_deferred_point_id(
        &self,
        hnsw_config: &HnswConfig,
        deferred_point_threshold_bytes: Option<NonZeroUsize>,
    ) -> Option<PointOffsetType> {
        let threshold_bytes = deferred_point_threshold_bytes?.get();

        // Because we cannot predict multivector size,
        // define here a constant-size inner vectors count for multivector.
        const MULTIVECTOR_SIZE: usize = 16;

        self.vectors
            .params_iter()
            // Skip vectors without HNSW indexing
            .filter_map(|(_name, params)| {
                // Merge HNSW config with vector config to get effective HNSW config for the vector.
                let effective_hnsw = hnsw_config.update_opt(params.hnsw_config.as_ref());
                (effective_hnsw.m > 0 || effective_hnsw.payload_m.unwrap_or_default() > 0)
                    .then_some(params)
            })
            .map(|params| {
                let element_bytes = match params.datatype {
                    Some(Datatype::Float16) => 2,
                    Some(Datatype::Uint8) => 1,
                    Some(Datatype::Float32) | None => 4,
                };

                let dim = params.size.get() as usize;

                let vector_bytes = if params.multivector_config.is_some() {
                    element_bytes * dim * MULTIVECTOR_SIZE
                } else {
                    element_bytes * dim
                };

                let deferred_from = threshold_bytes.div_ceil(vector_bytes);
                PointOffsetType::try_from(deferred_from).unwrap_or(PointOffsetType::MAX)
            })
            .min()
    }
}

pub fn default_shard_number() -> NonZeroU32 {
    NonZeroU32::new(1).unwrap()
}

pub fn default_replication_factor() -> NonZeroU32 {
    NonZeroU32::new(1).unwrap()
}

pub fn default_write_consistency_factor() -> NonZeroU32 {
    NonZeroU32::new(1).unwrap()
}

pub const fn default_on_disk_payload() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Validate, Clone, PartialEq)]
pub struct CollectionConfigInternal {
    #[validate(nested)]
    pub params: CollectionParams,
    #[validate(nested)]
    pub hnsw_config: HnswConfig,
    #[validate(nested)]
    pub optimizer_config: OptimizersConfig,
    #[validate(nested)]
    pub wal_config: WalConfig,
    #[serde(default)]
    #[validate(nested)]
    pub quantization_config: Option<QuantizationConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub strict_mode_config: Option<StrictModeConfig>,
    #[serde(default)]
    pub uuid: Option<Uuid>,
    /// Arbitrary JSON metadata for the collection
    /// This can be used to store application-specific information
    /// such as creation time, migration data, inference model info, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Payload>,
}

impl CollectionConfigInternal {
    pub fn to_bytes(&self) -> CollectionResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|err| CollectionError::service_error(err.to_string()))
    }

    pub fn save(&self, path: &Path) -> CollectionResult<()> {
        let config_path = path.join(COLLECTION_CONFIG_FILE);
        let af = AtomicFile::new(&config_path, AllowOverwrite);
        let state_bytes = serde_json::to_vec(self).unwrap();
        af.write(|f| f.write_all(&state_bytes)).map_err(|err| {
            CollectionError::service_error(format!("Can't write {config_path:?}, error: {err}"))
        })?;
        Ok(())
    }

    pub fn load(path: &Path) -> CollectionResult<Self> {
        let config_path = path.join(COLLECTION_CONFIG_FILE);
        let mut contents = String::new();
        let mut file = File::open(config_path)?;
        file.read_to_string(&mut contents)?;
        Ok(serde_json::from_str(&contents)?)
    }

    /// Check if collection config exists
    pub fn check(path: &Path) -> bool {
        let config_path = path.join(COLLECTION_CONFIG_FILE);
        config_path.exists()
    }

    pub fn validate_and_warn(&self) {
        if let Err(ref errs) = self.validate() {
            validation::warn_validation_errors("Collection configuration file", errs);
        }
    }

    /// Get warnings related to this configuration
    pub fn get_warnings(&self) -> Vec<CollectionWarning> {
        let mut warnings = Vec::new();

        for (vector_name, vector_config) in self.params.vectors.params_iter() {
            let vector_hnsw = self
                .hnsw_config
                .update_opt(vector_config.hnsw_config.as_ref());

            let vector_quantization =
                vector_config.quantization_config.is_some() || self.quantization_config.is_some();

            if vector_hnsw.inline_storage.unwrap_or_default() {
                if vector_config.multivector_config.is_some() {
                    warnings.push(CollectionWarning {
                        message: format!(
                            "The `hnsw_config.inline_storage` option for vector '{vector_name}' \
                             is not compatible with multivectors. This option will be ignored."
                        ),
                    });
                } else if !vector_quantization {
                    warnings.push(CollectionWarning {
                        message: format!(
                            "The `hnsw_config.inline_storage` option for vector '{vector_name}' \
                             requires quantization to be enabled. This option will be ignored."
                        ),
                    });
                }
            }
        }

        warnings
    }

    pub fn to_base_segment_config(&self) -> SegmentConfig {
        self.params
            .to_base_segment_config(self.quantization_config.as_ref())
    }
}

impl CollectionParams {
    pub fn empty() -> Self {
        CollectionParams {
            vectors: Default::default(),
            shard_number: default_shard_number(),
            sharding_method: None,
            replication_factor: default_replication_factor(),
            write_consistency_factor: default_write_consistency_factor(),
            read_fan_out_factor: None,
            read_fan_out_delay_ms: None,
            on_disk_payload: default_on_disk_payload(),
            sparse_vectors: None,
            encryption: None,
            ckks: None,
        }
    }

    pub fn effective_encryption(&self) -> Option<CollectionEncryptionConfig> {
        self.encryption.clone().or_else(|| {
            self.ckks
                .as_ref()
                .and_then(CollectionEncryptionConfig::from_legacy_ckks)
        })
    }

    fn missing_vector_error(&self, vector_name: &VectorName) -> CollectionError {
        let mut available_names = vec![];

        match &self.vectors {
            VectorsConfig::Single(_) => {
                available_names.push(DEFAULT_VECTOR_NAME.to_owned());
            }
            VectorsConfig::Multi(vectors) => {
                for name in vectors.keys() {
                    available_names.push(name.clone());
                }
            }
        }

        if let Some(sparse_vectors) = &self.sparse_vectors {
            for name in sparse_vectors.keys() {
                available_names.push(name.clone());
            }
        }

        if available_names.is_empty() {
            CollectionError::BadInput {
                description: "Vectors are not configured in this collection".into(),
            }
        } else if available_names == vec![DEFAULT_VECTOR_NAME] {
            CollectionError::BadInput {
                description: format!(
                    "Vector with name {vector_name} is not configured in this collection"
                ),
            }
        } else {
            let available_names = available_names.join(", ");
            if vector_name == DEFAULT_VECTOR_NAME {
                return CollectionError::BadInput {
                    description: format!(
                        "Collection requires specified vector name in the request, available names: {available_names}"
                    ),
                };
            }

            CollectionError::BadInput {
                description: format!(
                    "Vector with name `{vector_name}` is not configured in this collection, available names: {available_names}"
                ),
            }
        }
    }

    pub fn get_distance(&self, vector_name: &VectorName) -> CollectionResult<Distance> {
        match self.vectors.get_params(vector_name) {
            Some(params) => Ok(params.distance),
            None => {
                if let Some(sparse_vectors) = &self.sparse_vectors
                    && let Some(_params) = sparse_vectors.get(vector_name)
                {
                    return Ok(Distance::Dot);
                }
                Err(self.missing_vector_error(vector_name))
            }
        }
    }

    pub fn check_vector_exists(&self, vector_name: &VectorName) -> CollectionResult<()> {
        match self.vectors.get_params(vector_name) {
            Some(_params) => Ok(()),
            None => {
                if self
                    .sparse_vectors
                    .as_ref()
                    .map(|sparse_vectors| sparse_vectors.contains_key(vector_name))
                    .unwrap_or(false)
                {
                    return Ok(());
                }
                Err(self.missing_vector_error(vector_name))
            }
        }
    }

    fn get_vector_params_mut(
        &mut self,
        vector_name: &VectorName,
    ) -> CollectionResult<&mut VectorParams> {
        self.vectors
            .get_params_mut(vector_name)
            .ok_or_else(|| CollectionError::BadInput {
                description: if vector_name == DEFAULT_VECTOR_NAME {
                    "Default vector params are not specified in config".into()
                } else {
                    format!("Vector params for {vector_name} are not specified in config")
                },
            })
    }

    pub fn get_sparse_vector_params_opt(
        &self,
        vector_name: &VectorName,
    ) -> Option<&SparseVectorParams> {
        self.sparse_vectors
            .as_ref()
            .and_then(|sparse_vectors| sparse_vectors.get(vector_name))
    }

    pub fn get_sparse_vector_params_mut(
        &mut self,
        vector_name: &VectorName,
    ) -> CollectionResult<&mut SparseVectorParams> {
        self.sparse_vectors
            .as_mut()
            .ok_or_else(|| CollectionError::BadInput {
                description: format!(
                    "Sparse vector `{vector_name}` is not specified in collection config"
                ),
            })?
            .get_mut(vector_name)
            .ok_or_else(|| CollectionError::BadInput {
                description: format!(
                    "Sparse vector `{vector_name}` is not specified in collection config"
                ),
            })
    }

    /// Update collection vectors from the given update vectors config
    pub fn update_vectors_from_diff(
        &mut self,
        update_vectors_diff: &VectorsConfigDiff,
    ) -> CollectionResult<()> {
        for (vector_name, update_params) in update_vectors_diff.0.iter() {
            let vector_params = self.get_vector_params_mut(vector_name)?;
            let VectorParamsDiff {
                hnsw_config,
                quantization_config,
                on_disk,
            } = update_params.clone();

            if let Some(hnsw_diff) = hnsw_config {
                if let Some(existing_hnsw) = &vector_params.hnsw_config {
                    vector_params.hnsw_config = Some(existing_hnsw.update(&hnsw_diff));
                } else {
                    vector_params.hnsw_config = Some(hnsw_diff);
                }
            }

            if let Some(quantization_diff) = quantization_config {
                vector_params.quantization_config = match quantization_diff.clone() {
                    QuantizationConfigDiff::Scalar(scalar) => {
                        Some(QuantizationConfig::Scalar(scalar))
                    }
                    QuantizationConfigDiff::Product(product) => {
                        Some(QuantizationConfig::Product(product))
                    }
                    QuantizationConfigDiff::Binary(binary) => {
                        Some(QuantizationConfig::Binary(binary))
                    }
                    QuantizationConfigDiff::Disabled(_) => None,
                }
            }

            if let Some(on_disk) = on_disk {
                vector_params.on_disk = Some(on_disk);
            }
        }
        Ok(())
    }

    /// Update collection vectors from the given update vectors config
    pub fn update_sparse_vectors_from_other(
        &mut self,
        update_vectors: &SparseVectorsConfig,
    ) -> CollectionResult<()> {
        for (vector_name, update_params) in update_vectors.0.iter() {
            let sparse_vector_params = self.get_sparse_vector_params_mut(vector_name)?;
            let SparseVectorParams { index, modifier } = update_params.clone();

            if let Some(modifier) = modifier {
                sparse_vector_params.modifier = Some(modifier);
            }

            if let Some(index) = index {
                if let Some(existing_index) = &mut sparse_vector_params.index {
                    existing_index.update_from_other(index);
                } else {
                    sparse_vector_params.index.replace(index);
                }
            }
        }
        Ok(())
    }

    /// Convert into unoptimized named vector data configs
    ///
    /// It is the job of the segment optimizer to change this configuration with optimized settings
    /// based on threshold configurations.
    pub fn to_base_vector_data(
        &self,
        collection_quantization: Option<&QuantizationConfig>,
    ) -> HashMap<VectorNameBuf, VectorDataConfig> {
        let quantization_fn = |quantization_config: Option<&QuantizationConfig>| {
            quantization_config
                // Only if there is no `quantization_config` we may start using `collection_quantization` (to avoid mixing quantizations between segments)
                .or(collection_quantization)
                .filter(|c| c.supports_appendable())
                .cloned()
        };

        self.vectors
            .params_iter()
            .map(|(name, params)| {
                let VectorParams {
                    size,
                    distance,
                    hnsw_config: _,
                    quantization_config,
                    on_disk,
                    datatype,
                    multivector_config,
                } = params;

                (
                    name.into(),
                    VectorDataConfig {
                        size: size.get() as usize,
                        distance: *distance,
                        // Plain (disabled) index
                        index: Indexes::Plain {},
                        // Quantizaton config in appendable segment if runtime feature flag is set
                        quantization_config: common::flags::feature_flags()
                            .appendable_quantization
                            .then(|| quantization_fn(quantization_config.as_ref()))
                            .flatten(),
                        // Default to in memory storage
                        storage_type: if on_disk.unwrap_or_default() {
                            VectorStorageType::ChunkedMmap
                        } else {
                            VectorStorageType::InRamChunkedMmap
                        },
                        multivector_config: *multivector_config,
                        datatype: datatype.map(VectorStorageDatatype::from),
                    },
                )
            })
            .collect()
    }

    /// Convert into unoptimized sparse vector data configs
    ///
    /// It is the job of the segment optimizer to change this configuration with optimized settings
    /// based on threshold configurations.
    pub fn to_sparse_vector_data(&self) -> HashMap<VectorNameBuf, SparseVectorDataConfig> {
        if let Some(sparse_vectors) = &self.sparse_vectors {
            sparse_vectors
                .iter()
                .map(|(name, params)| {
                    (
                        name.clone(),
                        SparseVectorDataConfig {
                            index: SparseIndexConfig {
                                full_scan_threshold: params
                                    .index
                                    .and_then(|index| index.full_scan_threshold),
                                index_type: SparseIndexType::MutableRam,
                                datatype: params
                                    .index
                                    .and_then(|index| index.datatype)
                                    .map(VectorStorageDatatype::from),
                            },
                            storage_type: params.storage_type(),
                            modifier: params.modifier,
                        },
                    )
                })
                .collect()
        } else {
            Default::default()
        }
    }

    /// Convert into unoptimized segment config
    ///
    /// It is the job of the segment optimizer to change this configuration with optimized settings
    /// based on threshold configurations.
    pub fn to_base_segment_config(
        &self,
        collection_quantization: Option<&QuantizationConfig>,
    ) -> SegmentConfig {
        let vector_data = self.to_base_vector_data(collection_quantization);
        let sparse_vector_data = self.to_sparse_vector_data();
        let payload_storage_type = self.payload_storage_type();

        SegmentConfig {
            vector_data,
            sparse_vector_data,
            payload_storage_type,
        }
    }
}
