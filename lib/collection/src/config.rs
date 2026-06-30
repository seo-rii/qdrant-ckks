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
    VectorStorageDatatype, VectorStorageType, WithVector,
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
use crate::private_hnsw_oram_store::private_hnsw_oram_vector_name_is_safe_store_component;

pub const COLLECTION_CONFIG_FILE: &str = "config.json";
const PAYLOAD_FIELD_BINDING: &str = "payload-field/v1";
const CLIENT_PAYLOAD_ENVELOPE_BINDING: &str = "client-payload-envelope/v1";
pub const PRIVATE_RESULT_ORAM_BINDING: &str = qdrant_sec::PRIVATE_RESULT_ORAM_BINDING;
const VECTOR_ENVELOPE_BINDING: &str = "vector-envelope/v1";
pub const PRIVATE_HNSW_ORAM_BINDING: &str = qdrant_sec::PRIVATE_HNSW_ORAM_BINDING;
const METADATA_VALUE_BINDING: &str = "metadata-value/v1";
const METADATA_EXACT_MATCH_TOKEN_BINDING: &str = "metadata-exact-match-token/v1";

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
            retain_closed: NonZeroUsize::new(*wal_retain_closed).unwrap_or(NonZeroUsize::MIN),
        }
    }
}

#[cfg(test)]
mod ckks_tests {
    use validator::Validate;

    use super::*;

    #[test]
    fn collection_params_reject_legacy_ckks_field() {
        let raw = r#"{
            "ckks": {
                "enabled": true,
                "key_id": "tenant-a:docs",
                "payload_text_fields": ["body", "document.summary"]
            }
        }"#;
        let err = serde_json::from_str::<CollectionParams>(raw)
            .expect_err("legacy ckks collection config must be rejected at parse time");
        assert!(err.to_string().contains("unknown field `ckks`"));
    }

    #[test]
    fn encryption_config_round_trips() {
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
                encryption_epoch: 3,
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

        let missing_epoch = CollectionParams {
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

        let err = missing_epoch.validate().unwrap_err();
        assert!(format!("{err:?}").contains("client_payload_envelope_requires_rk_epoch"));

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
            "$qdrant_sec.body",
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
    fn encryption_config_allows_vector_names_for_sidecar_storage() {
        let params = CollectionParams {
            vectors: VectorsConfig::Multi(BTreeMap::from([(
                "embedding".into(),
                VectorParams {
                    size: std::num::NonZeroU64::new(4).unwrap(),
                    distance: Distance::Dot,
                    hnsw_config: None,
                    quantization_config: None,
                    on_disk: None,
                    datatype: None,
                    multivector_config: None,
                },
            )])),
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

        params.validate().unwrap();
    }

    #[test]
    fn encrypted_vector_return_guard_rejects_any_or_selected_encrypted_vectors() {
        let encryption = CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a:docs".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 3,
            migration_state: CryptoMigrationState::Active,
            rules: vec![EncryptionRuleRef {
                id: "embedding_conf".to_string(),
                selector: EncryptionSelector::VectorNames {
                    names: vec!["embedding".to_string()],
                },
                instance: "docs_vector_v1".to_string(),
                binding: Some("vector-envelope/v1".to_string()),
            }],
        };

        assert_eq!(
            encrypted_vector_return_request(&encryption, &WithVector::Bool(true)),
            Some(EncryptedVectorReturnRequest::Any {
                encrypted_name: "embedding"
            })
        );
        assert_eq!(
            encrypted_vector_return_request(
                &encryption,
                &WithVector::Selector(vec!["plain".to_string(), "embedding".to_string()])
            ),
            Some(EncryptedVectorReturnRequest::Named {
                vector_name: "embedding"
            })
        );
        assert_eq!(
            encrypted_vector_return_request(
                &encryption,
                &WithVector::Selector(vec!["plain".to_string()])
            ),
            None
        );
        assert_eq!(
            encrypted_vector_return_request(&encryption, &WithVector::Bool(false)),
            None
        );
    }

    #[test]
    fn encrypted_vector_return_request_debug_redacts_vector_names() {
        let any = EncryptedVectorReturnRequest::Any {
            encrypted_name: "CONFIG-ENCRYPTED-VECTOR-SENTINEL",
        };
        let named = EncryptedVectorReturnRequest::Named {
            vector_name: "CONFIG-REQUESTED-VECTOR-SENTINEL",
        };

        for rendered in [format!("{any:?}"), format!("{named:?}")] {
            assert!(rendered.contains("[redacted]"), "{rendered}");
            assert!(
                !rendered.contains("CONFIG-ENCRYPTED-VECTOR-SENTINEL"),
                "{rendered}"
            );
            assert!(
                !rendered.contains("CONFIG-REQUESTED-VECTOR-SENTINEL"),
                "{rendered}"
            );
        }

        assert_eq!(any.vector_name(), "CONFIG-ENCRYPTED-VECTOR-SENTINEL");
        assert_eq!(named.vector_name(), "CONFIG-REQUESTED-VECTOR-SENTINEL");
    }

    #[test]
    fn collection_encryption_config_debug_redacts_rules_and_selectors() {
        let encryption = CollectionEncryptionConfig {
            version: 1,
            key_id: Some("CONFIG-ENCRYPTION-KEY-SENTINEL".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 9,
            migration_state: CryptoMigrationState::Active,
            rules: vec![
                EncryptionRuleRef {
                    id: "CONFIG-PAYLOAD-RULE-SENTINEL".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["payload.secret.sentinel".to_string()],
                    },
                    instance: "CONFIG-PAYLOAD-INSTANCE-SENTINEL".to_string(),
                    binding: Some(CLIENT_PAYLOAD_ENVELOPE_BINDING.to_string()),
                },
                EncryptionRuleRef {
                    id: "CONFIG-VECTOR-RULE-SENTINEL".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["CONFIG-VECTOR-NAME-SENTINEL".to_string()],
                    },
                    instance: "CONFIG-VECTOR-INSTANCE-SENTINEL".to_string(),
                    binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
                },
                EncryptionRuleRef {
                    id: "CONFIG-METADATA-RULE-SENTINEL".to_string(),
                    selector: EncryptionSelector::MetadataKeys {
                        keys: vec!["metadata.secret.sentinel".to_string()],
                    },
                    instance: "CONFIG-METADATA-INSTANCE-SENTINEL".to_string(),
                    binding: Some(METADATA_EXACT_MATCH_TOKEN_BINDING.to_string()),
                },
            ],
        };

        for rendered in [
            format!("{encryption:?}"),
            format!("{:?}", encryption.rules[0]),
            format!("{:?}", encryption.rules[1]),
            format!("{:?}", encryption.rules[2]),
            format!("{:?}", encryption.rules[0].selector),
            format!("{:?}", encryption.rules[1].selector),
            format!("{:?}", encryption.rules[2].selector),
        ] {
            assert!(rendered.contains("[redacted]"), "{rendered}");
            for sentinel in [
                "CONFIG-ENCRYPTION-KEY-SENTINEL",
                "CONFIG-PAYLOAD-RULE-SENTINEL",
                "payload.secret.sentinel",
                "CONFIG-PAYLOAD-INSTANCE-SENTINEL",
                "CONFIG-VECTOR-RULE-SENTINEL",
                "CONFIG-VECTOR-NAME-SENTINEL",
                "CONFIG-VECTOR-INSTANCE-SENTINEL",
                "CONFIG-METADATA-RULE-SENTINEL",
                "metadata.secret.sentinel",
                "CONFIG-METADATA-INSTANCE-SENTINEL",
            ] {
                assert!(!rendered.contains(sentinel), "{rendered}");
            }
        }
    }

    #[test]
    fn collection_params_debug_redacts_vector_names() {
        let params = CollectionParams {
            vectors: VectorsConfig::Multi(BTreeMap::from([(
                "CONFIG-PARAMS-VECTOR-SENTINEL".into(),
                VectorParams {
                    size: std::num::NonZeroU64::new(4).unwrap(),
                    distance: Distance::Cosine,
                    hnsw_config: None,
                    quantization_config: None,
                    on_disk: None,
                    datatype: None,
                    multivector_config: None,
                },
            )])),
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("CONFIG-PARAMS-KEY-SENTINEL".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "CONFIG-PARAMS-RULE-SENTINEL".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["CONFIG-PARAMS-VECTOR-SENTINEL".to_string()],
                    },
                    instance: "CONFIG-PARAMS-INSTANCE-SENTINEL".to_string(),
                    binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let rendered = format!("{params:?}");

        assert!(rendered.contains("[redacted]"), "{rendered}");
        assert!(
            !rendered.contains("CONFIG-PARAMS-VECTOR-SENTINEL"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("CONFIG-PARAMS-KEY-SENTINEL"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("CONFIG-PARAMS-RULE-SENTINEL"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("CONFIG-PARAMS-INSTANCE-SENTINEL"),
            "{rendered}"
        );
    }

    #[test]
    fn private_hnsw_oram_vector_guard_message_uses_session_api() {
        let private_rule = EncryptionRuleRef {
            id: "embedding_private".to_string(),
            selector: EncryptionSelector::VectorNames {
                names: vec!["embedding".to_string()],
            },
            instance: "docs_text_private_hnsw".to_string(),
            binding: Some("private-hnsw-oram/v1".to_string()),
        };
        let opaque_rule = EncryptionRuleRef {
            id: "embedding_opaque".to_string(),
            selector: EncryptionSelector::VectorNames {
                names: vec!["opaque".to_string()],
            },
            instance: "docs_vector_v1".to_string(),
            binding: Some("vector-envelope/v1".to_string()),
        };

        assert!(encryption_rule_uses_private_hnsw_oram(&private_rule));
        assert!(!encryption_rule_uses_private_hnsw_oram(&opaque_rule));

        let message = private_hnsw_oram_api_required_message("embedding");
        assert!(message.contains(qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER));
        assert!(message.contains("/private-hnsw/{vector}/session"));
        assert!(message.contains("compatible SDK traversal APIs"));
        assert!(!message.contains("embedding"));

        for reflected_label in [
            "retrieve",
            "scroll",
            "search",
            "query",
            "recommend",
            "discover",
            "delete vectors",
            "sync points",
            "upsert points",
            "update vectors",
            "private-hnsw-vector-operation-sentinel",
        ] {
            assert!(!message.contains(reflected_label), "{message}");
        }

        for private_alias in [
            "clientStateBackup",
            "clientStateBackups",
            "client_state_backup",
            "clientStateSnapshot",
            "clientStateSnapshots",
            "client_state_snapshot",
            "client_state_snapshots",
            "clientStateCiphertext",
            "clientStateCiphertextHash",
            "clientStateCiphertextHashes",
            "clientStateCiphertextSha256",
            "clientStateCiphertextsSha256",
            "client_state_ciphertext",
            "client_state_ciphertext_hash",
            "client_state_ciphertext_hashes",
            "client_state_ciphertext_sha256",
            "client_state_ciphertexts_sha256",
            "encryptedClientStateBackup",
            "encryptedClientStateBackups",
            "encryptedClientStateSnapshot",
            "encryptedClientStateSnapshots",
            "encrypted_client_state",
            "encrypted_client_state_backup",
            "encrypted_client_state_backups",
            "encrypted_client_state_snapshot",
            "encrypted_client_state_snapshots",
            "encryptedClientStateCiphertext",
            "encrypted_client_state_ciphertext",
            "encryptedClientStateCiphertextHash",
            "encryptedClientStateCiphertextHashes",
            "encryptedClientStateCiphertextSha256",
            "encryptedClientStateCiphertextsSha256",
            "encrypted_client_state_ciphertext_hash",
            "encrypted_client_state_ciphertext_hashes",
            "encrypted_client_state_ciphertext_sha256",
            "encrypted_client_state_ciphertexts_sha256",
            "oramPositionMapBackups",
            "oram_position_map_backups",
            "positionMapBackups",
            "position_map_backups",
            "stashBackups",
            "stateCiphertext",
            "stateCiphertextHash",
            "stateCiphertextHashes",
            "stateCiphertextSha256",
            "stateCiphertextsSha256",
            "state_ciphertext",
            "state_ciphertext_hash",
            "state_ciphertext_hashes",
            "state_ciphertext_sha256",
            "state_ciphertexts_sha256",
            "tokenPositionMapBackups",
            "token_position_map_backups",
        ] {
            let message = private_hnsw_oram_api_required_message(private_alias);
            assert!(message.contains(qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER));
            assert!(message.contains("/private-hnsw/{vector}/session"));
            assert!(!message.contains(private_alias), "{message}");
        }
    }

    #[test]
    fn private_result_oram_payload_guard_message_uses_session_api() {
        let private_rule = EncryptionRuleRef {
            id: "body_private_result".to_string(),
            selector: EncryptionSelector::PayloadPaths {
                paths: vec!["document.body".to_string()],
            },
            instance: "docs_private_result_oram".to_string(),
            binding: Some("private-result-oram/v1".to_string()),
        };
        let payload_rule = EncryptionRuleRef {
            id: "body_payload".to_string(),
            selector: EncryptionSelector::PayloadPaths {
                paths: vec!["body".to_string()],
            },
            instance: "docs_payload_v1".to_string(),
            binding: Some("payload-field/v1".to_string()),
        };

        assert!(encryption_rule_uses_private_result_oram(&private_rule));
        assert!(!encryption_rule_uses_private_result_oram(&payload_rule));

        let message = private_result_oram_api_required_message("document.body");
        assert!(message.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER));
        assert!(message.contains("/private-result-oram/session"));
        assert!(message.contains("compatible SDK fetch APIs"));
        assert!(!message.contains("document.body"));

        for reflected_label in [
            "retrieve",
            "scroll",
            "search",
            "query",
            "recommend",
            "discover",
            "filter",
            "order by",
            "group by",
            "facet",
            "set payload",
            "overwrite payload",
            "delete payload",
            "clear payload",
            "private-result-payload-operation-sentinel",
        ] {
            assert!(!message.contains(reflected_label), "{message}");
        }

        for private_alias in [
            "clientStateBackup",
            "clientStateBackups",
            "client_state_backup",
            "clientStateSnapshot",
            "clientStateSnapshots",
            "client_state_snapshot",
            "client_state_snapshots",
            "clientStateCiphertext",
            "clientStateCiphertextHash",
            "clientStateCiphertextHashes",
            "clientStateCiphertextSha256",
            "clientStateCiphertextsSha256",
            "client_state_ciphertext",
            "client_state_ciphertext_hash",
            "client_state_ciphertext_hashes",
            "client_state_ciphertext_sha256",
            "client_state_ciphertexts_sha256",
            "encryptedClientStateBackup",
            "encryptedClientStateBackups",
            "encryptedClientStateSnapshot",
            "encryptedClientStateSnapshots",
            "encrypted_client_state",
            "encrypted_client_state_backup",
            "encrypted_client_state_backups",
            "encrypted_client_state_snapshot",
            "encrypted_client_state_snapshots",
            "encryptedClientStateCiphertext",
            "encrypted_client_state_ciphertext",
            "encryptedClientStateCiphertextHash",
            "encryptedClientStateCiphertextHashes",
            "encryptedClientStateCiphertextSha256",
            "encryptedClientStateCiphertextsSha256",
            "encrypted_client_state_ciphertext_hash",
            "encrypted_client_state_ciphertext_hashes",
            "encrypted_client_state_ciphertext_sha256",
            "encrypted_client_state_ciphertexts_sha256",
            "oramPositionMapBackups",
            "oram_position_map_backups",
            "positionMapBackups",
            "position_map_backups",
            "stashBackups",
            "stateCiphertext",
            "stateCiphertextHash",
            "stateCiphertextHashes",
            "stateCiphertextSha256",
            "stateCiphertextsSha256",
            "state_ciphertext",
            "state_ciphertext_hash",
            "state_ciphertext_hashes",
            "state_ciphertext_sha256",
            "state_ciphertexts_sha256",
            "tokenPositionMapBackups",
            "token_position_map_backups",
        ] {
            let message = private_result_oram_api_required_message(private_alias);
            assert!(message.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER));
            assert!(message.contains("/private-result-oram/session"));
            assert!(!message.contains(private_alias), "{message}");
        }
    }

    #[test]
    fn private_result_oram_payload_overlap_message_redacts_paths() {
        let message = private_result_oram_payload_selector_overlap_message(
            "document.body.lang",
            "document.body",
        );

        assert!(
            message.contains("cannot use private result ORAM payload field"),
            "{message}"
        );
        for reflected_label in [
            "filter on",
            "order by",
            "group by",
            "facet on",
            "create payload index on",
            "formula condition",
            "private-result-selector-operation-sentinel",
        ] {
            assert!(!message.contains(reflected_label), "{message}");
        }
        assert!(
            message.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER),
            "{message}"
        );
        assert!(
            message.contains("/private-result-oram/session"),
            "{message}"
        );
        assert!(!message.contains("document.body"), "{message}");
        assert!(!message.contains("document"), "{message}");
        assert!(!message.contains("body"), "{message}");
        assert!(!message.contains("lang"), "{message}");
        assert!(!message.contains("blind index"), "{message}");
    }

    #[test]
    fn encryption_config_rejects_sparse_only_encrypted_vector_selector() {
        let params = CollectionParams {
            sparse_vectors: Some(BTreeMap::from([(
                "embedding".into(),
                SparseVectorParams {
                    index: None,
                    modifier: None,
                },
            )])),
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
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

        let err = params
            .validate()
            .expect_err("encrypted vector selector must reject sparse-only vector names");
        assert!(
            err.to_string()
                .contains("encrypted_vector_sparse_unsupported")
        );
    }

    #[test]
    fn encryption_config_rejects_quantized_or_multi_vector_encrypted_vectors() {
        let encrypted_vector_rule = EncryptionRuleRef {
            id: "embedding_conf".to_string(),
            selector: EncryptionSelector::VectorNames {
                names: vec!["embedding".to_string()],
            },
            instance: "docs_vector_v1".to_string(),
            binding: Some("vector-envelope/v1".to_string()),
        };
        let base_vector = VectorParams {
            size: std::num::NonZeroU64::new(4).unwrap(),
            distance: Distance::Dot,
            hnsw_config: None,
            quantization_config: None,
            on_disk: None,
            datatype: None,
            multivector_config: None,
        };
        let encrypted_params = |vector: VectorParams| CollectionParams {
            vectors: VectorsConfig::Multi(BTreeMap::from([("embedding".into(), vector)])),
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state: CryptoMigrationState::Active,
                rules: vec![encrypted_vector_rule.clone()],
            }),
            ..CollectionParams::empty()
        };

        encrypted_params(base_vector.clone()).validate().unwrap();

        let mut quantized_vector = base_vector.clone();
        quantized_vector.quantization_config = Some(QuantizationConfig::Scalar(
            segment::types::ScalarQuantization {
                scalar: segment::types::ScalarQuantizationConfig {
                    r#type: segment::types::ScalarType::Int8,
                    quantile: Some(0.99),
                    always_ram: Some(true),
                },
            },
        ));
        let err = encrypted_params(quantized_vector)
            .validate()
            .expect_err("encrypted vector selector must reject quantized dense vector params");
        assert!(
            err.to_string()
                .contains("encrypted_vector_quantization_unsupported")
        );

        let mut multi_vector = base_vector;
        multi_vector.multivector_config = Some(Default::default());
        let err = encrypted_params(multi_vector)
            .validate()
            .expect_err("encrypted vector selector must reject multi-vector params");
        assert!(
            err.to_string()
                .contains("encrypted_vector_multivector_unsupported")
        );
    }

    #[test]
    fn collection_config_rejects_global_quantization_for_encrypted_vectors() {
        let mut config = CollectionConfigInternal {
            params: CollectionParams {
                vectors: VectorsConfig::Multi(BTreeMap::from([(
                    "embedding".into(),
                    VectorParams {
                        size: std::num::NonZeroU64::new(4).unwrap(),
                        distance: Distance::Dot,
                        hnsw_config: None,
                        quantization_config: None,
                        on_disk: None,
                        datatype: None,
                        multivector_config: None,
                    },
                )])),
                encryption: Some(CollectionEncryptionConfig {
                    version: 1,
                    key_id: Some("tenant-a:docs".to_string()),
                    crypto_schema_version: 1,
                    encryption_epoch: 3,
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
            },
            hnsw_config: HnswConfig::default(),
            optimizer_config: OptimizersConfig::fixture(),
            wal_config: WalConfig::default(),
            quantization_config: None,
            strict_mode_config: None,
            uuid: None,
            metadata: None,
        };

        config.validate().unwrap();
        config.quantization_config = Some(QuantizationConfig::Scalar(
            segment::types::ScalarQuantization {
                scalar: segment::types::ScalarQuantizationConfig {
                    r#type: segment::types::ScalarType::Int8,
                    quantile: Some(0.99),
                    always_ram: Some(true),
                },
            },
        ));
        let err = config
            .validate()
            .expect_err("encrypted vector config must reject global quantization");
        assert!(
            err.to_string()
                .contains("encrypted_vector_collection_quantization_unsupported")
        );
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
    fn disabled_crypto_migration_state_is_not_effective_encryption() {
        let mut params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
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

        assert!(params.effective_encryption().is_some());

        params.encryption.as_mut().unwrap().migration_state = CryptoMigrationState::Disabled;
        assert!(
            params.effective_encryption().is_none(),
            "completed decryption migrations must not leave encryption guards active",
        );
    }

    #[test]
    fn startup_crypto_state_rejects_in_flight_migration_states() {
        for migration_state in [
            CryptoMigrationState::Disabled,
            CryptoMigrationState::Encrypting,
            CryptoMigrationState::Rotating,
            CryptoMigrationState::Decrypting,
        ] {
            let config = CollectionConfigInternal {
                params: CollectionParams {
                    encryption: Some(CollectionEncryptionConfig {
                        version: 1,
                        key_id: Some("tenant-a:docs".to_string()),
                        crypto_schema_version: 1,
                        encryption_epoch: 3,
                        migration_state,
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
                },
                hnsw_config: HnswConfig::default(),
                optimizer_config: OptimizersConfig::fixture(),
                wal_config: WalConfig::default(),
                quantization_config: None,
                strict_mode_config: None,
                uuid: Some(Uuid::from_u128(0x1234567890abcdef1234567890abcdef)),
                metadata: None,
            };

            let err = config
                .validate_startup_crypto_state()
                .expect_err("startup must fail closed for non-active migration state");
            assert!(matches!(
                err,
                CollectionError::BadInput { description }
                    if description.contains("verified migration recovery manifest")
            ));
        }
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
        assert!(
            noop.validate().is_err(),
            "validator trait must reject the same unsafe plan as the admin migration path",
        );

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

        let unexpected_retired_rk = CryptoMigrationPlan {
            from: Disabled,
            to: Encrypting,
            target_epoch: 3,
            active_rk_id: Some("rk/docs/3".to_string()),
            retired_rk_id: Some("rk/docs/2".to_string()),
            dry_run: false,
            checkpoints: Vec::new(),
        };
        assert!(unexpected_retired_rk.validate_admin_plan().is_err());

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
        valid_start.validate().unwrap();

        let start_with_stale_checkpoint = CryptoMigrationPlan {
            checkpoints: vec![CryptoMigrationCheckpoint {
                shard_id: 0,
                total_points: 10,
                processed_points: 10,
                rewritten_points: 10,
                changed_points: 0,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
            ..valid_start.clone()
        };
        assert!(start_with_stale_checkpoint.validate_admin_plan().is_err());

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
                changed_points: 0,
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
                changed_points: 0,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        };
        assert!(
            missing_initial_completion_active_rk
                .validate_admin_plan()
                .is_err()
        );

        let dry_run_initial_completion = CryptoMigrationPlan {
            from: Encrypting,
            to: Active,
            target_epoch: 3,
            active_rk_id: Some("rk/docs/3".to_string()),
            retired_rk_id: None,
            dry_run: true,
            checkpoints: vec![CryptoMigrationCheckpoint {
                shard_id: 0,
                total_points: 10,
                processed_points: 10,
                rewritten_points: 10,
                changed_points: 0,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        };
        assert!(dry_run_initial_completion.validate_admin_plan().is_err());

        let missing_completion_epoch = CryptoMigrationPlan {
            from: Encrypting,
            to: Active,
            target_epoch: 0,
            active_rk_id: Some("rk/docs/3".to_string()),
            retired_rk_id: None,
            dry_run: false,
            checkpoints: vec![CryptoMigrationCheckpoint {
                shard_id: 0,
                total_points: 10,
                processed_points: 10,
                rewritten_points: 10,
                changed_points: 0,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        };
        assert!(missing_completion_epoch.validate_admin_plan().is_err());

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

        let identical_rotation_resource_keys = CryptoMigrationPlan {
            from: Active,
            to: Rotating,
            target_epoch: 4,
            active_rk_id: Some("rk/docs/4".to_string()),
            retired_rk_id: Some("rk/docs/4".to_string()),
            dry_run: false,
            checkpoints: Vec::new(),
        };
        assert!(
            identical_rotation_resource_keys
                .validate_admin_plan()
                .is_err()
        );

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
                changed_points: 0,
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
                changed_points: 0,
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
                changed_points: 0,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        };
        assert!(verified_but_incomplete.validate_admin_plan().is_err());

        let verified_without_rewrite_completion = CryptoMigrationPlan {
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
                rewritten_points: 9,
                changed_points: 0,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        };
        assert!(
            verified_without_rewrite_completion
                .validate_admin_plan()
                .is_err()
        );

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
                changed_points: 0,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        };
        assert!(invalid_counts.validate_admin_plan().is_err());

        let invalid_changed_count = CryptoMigrationPlan {
            from: Active,
            to: Rotating,
            target_epoch: 4,
            active_rk_id: Some("rk/docs/4".to_string()),
            retired_rk_id: Some("rk/docs/3".to_string()),
            dry_run: false,
            checkpoints: vec![CryptoMigrationCheckpoint {
                shard_id: 0,
                total_points: 10,
                processed_points: 10,
                rewritten_points: 5,
                changed_points: 6,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        };
        assert!(invalid_changed_count.validate_admin_plan().is_err());

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
                    changed_points: 0,
                    status: CryptoMigrationCheckpointStatus::Verified,
                },
                CryptoMigrationCheckpoint {
                    shard_id: 0,
                    total_points: 8,
                    processed_points: 8,
                    rewritten_points: 8,
                    changed_points: 0,
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
                changed_points: 0,
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
                changed_points: 0,
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
                changed_points: 0,
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
                changed_points: 0,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        };
        complete_decryption.validate_admin_plan().unwrap();
    }

    #[test]
    fn crypto_migration_plan_validates_against_current_config() {
        use CryptoMigrationState::{Active, Disabled, Rotating};

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
        let applied_rotation = valid_rotation.apply_to_config(&current).unwrap();
        assert_eq!(applied_rotation.migration_state, Rotating);
        assert_eq!(applied_rotation.encryption_epoch, 4);
        assert_eq!(applied_rotation.rules, current.rules);

        let dry_run_rotation = CryptoMigrationPlan {
            dry_run: true,
            ..valid_rotation.clone()
        };
        dry_run_rotation
            .validate_admin_plan_for_config(&current)
            .unwrap();
        assert_eq!(
            dry_run_rotation.apply_to_config(&current).unwrap(),
            current,
            "dry-run migration plans must validate without mutating collection config",
        );

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
        let applied_decryption_start = valid_decryption_start.apply_to_config(&current).unwrap();
        assert_eq!(
            applied_decryption_start.migration_state,
            CryptoMigrationState::Decrypting
        );
        assert_eq!(applied_decryption_start.encryption_epoch, 3);

        let dry_run_decryption_start = CryptoMigrationPlan {
            dry_run: true,
            ..valid_decryption_start
        };
        dry_run_decryption_start
            .validate_admin_plan_for_config(&current)
            .unwrap();
        assert_eq!(
            dry_run_decryption_start.apply_to_config(&current).unwrap(),
            current,
            "dry-run decryption migration plans must validate without mutating collection config",
        );

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
                changed_points: 0,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        };
        assert!(
            wrong_completion_epoch
                .validate_admin_plan_for_config(&rotating_current)
                .is_err()
        );
        assert!(
            wrong_completion_epoch
                .apply_to_config(&rotating_current)
                .is_err()
        );

        let complete_rotation = CryptoMigrationPlan {
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
                changed_points: 0,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        };
        let applied_completion = complete_rotation
            .apply_to_config(&rotating_current)
            .unwrap();
        assert_eq!(applied_completion.migration_state, Active);
        assert_eq!(applied_completion.encryption_epoch, 4);

        let mut decrypting_current = current.clone();
        decrypting_current.migration_state = CryptoMigrationState::Decrypting;
        decrypting_current.encryption_epoch = 3;
        let complete_decryption = CryptoMigrationPlan {
            from: CryptoMigrationState::Decrypting,
            to: Disabled,
            target_epoch: 3,
            active_rk_id: Some("rk/docs/3".to_string()),
            retired_rk_id: None,
            dry_run: false,
            checkpoints: vec![CryptoMigrationCheckpoint {
                shard_id: 0,
                total_points: 10,
                processed_points: 10,
                rewritten_points: 10,
                changed_points: 0,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        };
        let applied_decryption = complete_decryption
            .apply_to_config(&decrypting_current)
            .unwrap();
        assert_eq!(applied_decryption.migration_state, Disabled);
        assert_eq!(applied_decryption.encryption_epoch, 3);

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
                changed_points: 0,
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
    fn encryption_config_allows_exact_match_metadata_blind_index_selector() {
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_blind_eq".to_string(),
                    selector: EncryptionSelector::MetadataKeys {
                        keys: vec!["body__blind_eq".to_string()],
                    },
                    instance: "docs_meta_eq_v1".to_string(),
                    binding: Some("metadata-exact-match-token/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        params.validate().unwrap();

        let mut missing_key_id = params.clone();
        missing_key_id.encryption.as_mut().unwrap().key_id = None;
        let err = missing_key_id
            .validate()
            .expect_err("metadata blind-index token rule must require collection key id");
        assert!(
            err.to_string()
                .contains("metadata_blind_index_requires_key_id")
        );

        let mut missing_epoch = params;
        missing_epoch.encryption.as_mut().unwrap().encryption_epoch = 0;
        let err = missing_epoch
            .validate()
            .expect_err("metadata blind-index token rule must require RK epoch");
        assert!(
            err.to_string()
                .contains("metadata_blind_index_requires_rk_epoch")
        );
    }

    #[test]
    fn encryption_config_rejects_reserved_and_unsupported_metadata_keys() {
        for key in [
            "$qdrant_sec.body",
            "$qdrant_client_aead.body",
            "$qdrant_sec_vectors.embedding",
            "items[].name",
            "items.*.name",
            "items.0.name",
        ] {
            let params = CollectionParams {
                encryption: Some(CollectionEncryptionConfig {
                    version: 1,
                    key_id: Some("tenant-a:docs".to_string()),
                    crypto_schema_version: 1,
                    encryption_epoch: 3,
                    migration_state: CryptoMigrationState::Active,
                    rules: vec![EncryptionRuleRef {
                        id: "metadata_conf".to_string(),
                        selector: EncryptionSelector::MetadataKeys {
                            keys: vec![key.to_string()],
                        },
                        instance: "docs_metadata_v1".to_string(),
                        binding: Some("metadata-value/v1".to_string()),
                    }],
                }),
                ..CollectionParams::empty()
            };

            assert!(params.validate().is_err(), "{key} should be rejected");
        }
    }

    #[test]
    fn encryption_config_allows_metadata_value_binding_and_rejects_overlap() {
        let metadata_value_params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
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

        metadata_value_params.validate().unwrap();

        let mut missing_key_id = metadata_value_params.clone();
        missing_key_id.encryption.as_mut().unwrap().key_id = None;
        let err = missing_key_id
            .validate()
            .expect_err("metadata value encryption must require collection key id");
        assert!(err.to_string().contains("metadata_value_requires_key_id"));

        let mut missing_epoch = metadata_value_params;
        missing_epoch.encryption.as_mut().unwrap().encryption_epoch = 0;
        let err = missing_epoch
            .validate()
            .expect_err("metadata value encryption must require RK epoch");
        assert!(err.to_string().contains("metadata_value_requires_rk_epoch"));

        let overlapping_params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![
                    EncryptionRuleRef {
                        id: "body_conf".to_string(),
                        selector: EncryptionSelector::PayloadPaths {
                            paths: vec!["body".to_string()],
                        },
                        instance: "docs_payload_v1".to_string(),
                        binding: Some("payload-field/v1".to_string()),
                    },
                    EncryptionRuleRef {
                        id: "body_nested_index".to_string(),
                        selector: EncryptionSelector::MetadataKeys {
                            keys: vec!["body.blind_eq".to_string()],
                        },
                        instance: "docs_meta_eq_v1".to_string(),
                        binding: Some("metadata-exact-match-token/v1".to_string()),
                    },
                ],
            }),
            ..CollectionParams::empty()
        };

        assert!(overlapping_params.validate().is_err());
    }

    #[test]
    fn encryption_config_rejects_selector_binding_domain_mismatch() {
        let payload_with_metadata_binding = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("metadata-exact-match-token/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let err = payload_with_metadata_binding
            .validate()
            .expect_err("payload selector must reject metadata binding");
        assert!(
            err.to_string()
                .contains("unsupported_payload_encryption_binding")
        );

        let vector_with_payload_binding = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "embedding_conf".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["embedding".into()],
                    },
                    instance: "docs_vector_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let err = vector_with_payload_binding
            .validate()
            .expect_err("vector selector must reject payload binding");
        assert!(
            err.to_string()
                .contains("unsupported_vector_encryption_binding")
        );

        let hnsw_with_payload_selector = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "hnsw_wrong_selector".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["private_hnsw_payload_sentinel".to_string()],
                    },
                    instance: "docs_private_hnsw_v1".to_string(),
                    binding: Some("private-hnsw-oram/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let err = hnsw_with_payload_selector
            .validate()
            .expect_err("private HNSW binding must reject payload selectors");
        let rendered = err.to_string();
        assert!(rendered.contains("private_hnsw_oram_requires_vector_selector"));
        assert!(!rendered.contains("private_hnsw_payload_sentinel"));

        let result_with_vector_selector = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "result_wrong_selector".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["private-result-vector-sentinel".into()],
                    },
                    instance: "docs_private_result_v1".to_string(),
                    binding: Some("private-result-oram/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let err = result_with_vector_selector
            .validate()
            .expect_err("private result binding must reject vector selectors");
        let rendered = err.to_string();
        assert!(rendered.contains("private_result_oram_requires_payload_selector"));
        assert!(!rendered.contains("private-result-vector-sentinel"));
    }

    #[test]
    fn encryption_config_accepts_private_result_oram_payload_binding() {
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_private_result".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_private_result_oram_v1".to_string(),
                    binding: Some("private-result-oram/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        params
            .validate()
            .expect("private result ORAM payload binding should be schema-valid in E3");
    }

    #[test]
    fn encryption_config_rejects_duplicate_private_result_oram_payload_binding() {
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state: CryptoMigrationState::Active,
                rules: vec![
                    EncryptionRuleRef {
                        id: "body_private_result".to_string(),
                        selector: EncryptionSelector::PayloadPaths {
                            paths: vec!["private_result_path_sentinel.body".to_string()],
                        },
                        instance: "docs_private_result_oram_v1".to_string(),
                        binding: Some("private-result-oram/v1".to_string()),
                    },
                    EncryptionRuleRef {
                        id: "summary_private_result".to_string(),
                        selector: EncryptionSelector::PayloadPaths {
                            paths: vec!["summary".to_string()],
                        },
                        instance: "docs_private_result_oram_v1".to_string(),
                        binding: Some("private-result-oram/v1".to_string()),
                    },
                ],
            }),
            ..CollectionParams::empty()
        };

        let err = params
            .validate()
            .expect_err("private result ORAM has one collection-scoped payload binding in v1");
        assert!(
            err.to_string()
                .contains("duplicate_private_result_oram_binding")
        );
        assert!(!err.to_string().contains("private_result_path_sentinel"));
    }

    #[test]
    fn encryption_config_accepts_private_hnsw_oram_vector_binding() {
        let params = CollectionParams {
            vectors: VectorsConfig::Multi(BTreeMap::from([(
                "embedding".into(),
                VectorParams {
                    size: std::num::NonZeroU64::new(2).unwrap(),
                    distance: Distance::Cosine,
                    hnsw_config: None,
                    quantization_config: None,
                    on_disk: None,
                    datatype: None,
                    multivector_config: None,
                },
            )])),
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "embedding_private_hnsw".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["embedding".into()],
                    },
                    instance: "docs_private_hnsw_v1".to_string(),
                    binding: Some("private-hnsw-oram/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        params
            .validate()
            .expect("private HNSW ORAM vector binding should be accepted");
    }

    #[test]
    fn encryption_config_rejects_multi_vector_private_hnsw_oram_rule() {
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "embedding_private_hnsw".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["title".into(), "body".into()],
                    },
                    instance: "docs_private_hnsw_v1".to_string(),
                    binding: Some("private-hnsw-oram/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let err = params
            .validate()
            .expect_err("private HNSW ORAM v1 must bind exactly one vector");
        assert!(
            err.to_string()
                .contains("private_hnsw_oram_single_vector_selector")
        );
    }

    #[test]
    fn encryption_config_rejects_private_hnsw_oram_unsafe_vector_store_names() {
        for vector_name in [
            "stash",
            "stashBackups.json",
            "client.state",
            "clientStateBackup.json",
            "clientStateBackups.json",
            "client_state_backup.json",
            "clientStateSnapshot.json",
            "clientStateSnapshots.json",
            "client_state_snapshot.json",
            "client_state_snapshots.json",
            "client_state_ciphertext.json",
            "clientStateCiphertext.json",
            "client_state_ciphertext_hash.json",
            "clientStateCiphertextHash.json",
            "client_state_ciphertext_hashes.json",
            "clientStateCiphertextHashes.json",
            "client_state_ciphertext_sha256.json",
            "clientStateCiphertextSha256.json",
            "client_state_ciphertexts_sha256.json",
            "clientStateCiphertextsSha256.json",
            "encrypted_client_state.json",
            "encrypted_client_state_backup.json",
            "encryptedClientStateBackup.json",
            "encrypted_client_state_snapshot.json",
            "encrypted_client_state_snapshots.json",
            "encryptedClientStateSnapshot.json",
            "encryptedClientStateSnapshots.json",
            "encryptedClientStateBackups.json",
            "encrypted_client_state_ciphertext.json",
            "encryptedClientStateCiphertext.json",
            "encryptedClientStateCiphertextHash.json",
            "encrypted_client_state_ciphertext_hashes.json",
            "encryptedClientStateCiphertextHashes.json",
            "encrypted_client_state_ciphertext_hash.json",
            "encrypted_client_state_ciphertext_sha256.json",
            "encryptedClientStateCiphertextSha256.json",
            "encrypted_client_state_ciphertexts_sha256.json",
            "encryptedClientStateCiphertextsSha256.json",
            "position-map",
            "position_map_backups.json",
            "positionMapBackups.json",
            "oram_position_map_backups.json",
            "oramPositionMapBackups.json",
            "state_ciphertext.json",
            "stateCiphertext.json",
            "state_ciphertext_hash.json",
            "stateCiphertextHash.json",
            "state_ciphertext_hashes.json",
            "stateCiphertextHashes.json",
            "state_ciphertext_sha256.json",
            "stateCiphertextSha256.json",
            "state_ciphertexts_sha256.json",
            "stateCiphertextsSha256.json",
            "token_position_map_backups.json",
            "tokenPositionMapBackups.json",
            "tenant/private-vector-secret",
            "private vector secret",
        ] {
            let params = CollectionParams {
                vectors: VectorsConfig::Multi(BTreeMap::from([(
                    vector_name.into(),
                    VectorParams {
                        size: std::num::NonZeroU64::new(2).unwrap(),
                        distance: Distance::Cosine,
                        hnsw_config: None,
                        quantization_config: None,
                        on_disk: None,
                        datatype: None,
                        multivector_config: None,
                    },
                )])),
                encryption: Some(CollectionEncryptionConfig {
                    version: 1,
                    key_id: Some("tenant-a:docs".to_string()),
                    crypto_schema_version: 1,
                    encryption_epoch: 3,
                    migration_state: CryptoMigrationState::Active,
                    rules: vec![EncryptionRuleRef {
                        id: "embedding_private_hnsw".to_string(),
                        selector: EncryptionSelector::VectorNames {
                            names: vec![vector_name.into()],
                        },
                        instance: "docs_private_hnsw_v1".to_string(),
                        binding: Some("private-hnsw-oram/v1".to_string()),
                    }],
                }),
                ..CollectionParams::empty()
            };

            let err = params
                .validate()
                .expect_err("private HNSW ORAM vector store name must be safe");
            let rendered = err.to_string();
            assert!(
                rendered.contains("private_hnsw_oram_safe_vector_store_name"),
                "{rendered}"
            );
            for leaked in [
                "stashBackups",
                "clientStateBackup",
                "clientStateBackups",
                "client_state_backup",
                "clientStateSnapshot",
                "clientStateSnapshots",
                "client_state_snapshot",
                "client_state_snapshots",
                "client_state_ciphertext",
                "clientStateCiphertext",
                "client_state_ciphertext_hash",
                "clientStateCiphertextHash",
                "client_state_ciphertext_hashes",
                "clientStateCiphertextHashes",
                "client_state_ciphertext_sha256",
                "clientStateCiphertextSha256",
                "client_state_ciphertexts_sha256",
                "clientStateCiphertextsSha256",
                "encrypted_client_state",
                "encrypted_client_state_backup",
                "encryptedClientStateBackup",
                "encrypted_client_state_backups",
                "encrypted_client_state_snapshot",
                "encrypted_client_state_snapshots",
                "encryptedClientStateSnapshot",
                "encryptedClientStateSnapshots",
                "encryptedClientStateBackups",
                "encrypted_client_state_ciphertext",
                "encryptedClientStateCiphertext",
                "encryptedClientStateCiphertextHash",
                "encrypted_client_state_ciphertext_hashes",
                "encryptedClientStateCiphertextHashes",
                "encrypted_client_state_ciphertext_hash",
                "encrypted_client_state_ciphertext_sha256",
                "encryptedClientStateCiphertextSha256",
                "encrypted_client_state_ciphertexts_sha256",
                "encryptedClientStateCiphertextsSha256",
                "position_map_backups",
                "positionMapBackups",
                "oram_position_map_backups",
                "oramPositionMapBackups",
                "state_ciphertext",
                "stateCiphertext",
                "state_ciphertext_hash",
                "stateCiphertextHash",
                "state_ciphertext_hashes",
                "stateCiphertextHashes",
                "state_ciphertext_sha256",
                "stateCiphertextSha256",
                "state_ciphertexts_sha256",
                "stateCiphertextsSha256",
                "token_position_map_backups",
                "tokenPositionMapBackups",
            ] {
                assert!(!rendered.contains(leaked), "{rendered}");
            }
        }
    }

    #[test]
    fn encryption_config_rejects_private_hnsw_oram_vector_overlap() {
        let params = CollectionParams {
            vectors: VectorsConfig::Multi(BTreeMap::from([(
                "embedding".into(),
                VectorParams {
                    size: std::num::NonZeroU64::new(2).unwrap(),
                    distance: Distance::Cosine,
                    hnsw_config: None,
                    quantization_config: None,
                    on_disk: None,
                    datatype: None,
                    multivector_config: None,
                },
            )])),
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state: CryptoMigrationState::Active,
                rules: vec![
                    EncryptionRuleRef {
                        id: "embedding_private_hnsw".to_string(),
                        selector: EncryptionSelector::VectorNames {
                            names: vec!["embedding".into()],
                        },
                        instance: "docs_private_hnsw_v1".to_string(),
                        binding: Some("private-hnsw-oram/v1".to_string()),
                    },
                    EncryptionRuleRef {
                        id: "embedding_client_ckks".to_string(),
                        selector: EncryptionSelector::VectorNames {
                            names: vec!["embedding".into()],
                        },
                        instance: "docs_client_ckks_v1".to_string(),
                        binding: Some("vector-envelope/v1".to_string()),
                    },
                ],
            }),
            ..CollectionParams::empty()
        };

        let err = params
            .validate()
            .expect_err("private HNSW ORAM vector must not overlap another vector binding");
        assert!(
            err.to_string()
                .contains("private_hnsw_oram_overlapping_selector")
        );
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

#[derive(
    Debug, Deserialize, Serialize, JsonSchema, Validate, Anonymize, Clone, PartialEq, Eq, Hash,
)]
#[validate(schema(function = "validate_crypto_migration_plan"))]
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

fn validate_crypto_migration_plan(plan: &CryptoMigrationPlan) -> Result<(), ValidationError> {
    plan.validate_admin_plan()
}

impl CryptoMigrationPlan {
    pub fn requires_verified_completion(&self) -> bool {
        matches!(
            (self.from, self.to),
            (
                CryptoMigrationState::Encrypting,
                CryptoMigrationState::Active
            ) | (CryptoMigrationState::Rotating, CryptoMigrationState::Active)
                | (
                    CryptoMigrationState::Decrypting,
                    CryptoMigrationState::Disabled
                )
        )
    }

    pub fn validate_admin_plan(&self) -> Result<(), ValidationError> {
        if !self.from.is_job_transition_to(self.to) {
            return Err(ValidationError::new("invalid_crypto_migration_transition"));
        }

        if self.target_epoch == 0 {
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

        let is_rotation_transition = matches!(
            (self.from, self.to),
            (CryptoMigrationState::Active, CryptoMigrationState::Rotating)
                | (CryptoMigrationState::Rotating, CryptoMigrationState::Active)
        );
        if is_rotation_transition {
            if self.retired_rk_id.as_deref().is_none_or(str::is_empty) {
                return Err(ValidationError::new("missing_crypto_migration_retired_rk"));
            }
        } else if self.retired_rk_id.is_some() {
            return Err(ValidationError::new(
                "unexpected_crypto_migration_retired_rk",
            ));
        }

        let requires_verified_completion = self.requires_verified_completion();

        if self.dry_run && requires_verified_completion {
            return Err(ValidationError::new(
                "crypto_migration_completion_cannot_be_dry_run",
            ));
        }

        if !requires_verified_completion && !self.checkpoints.is_empty() {
            return Err(ValidationError::new(
                "unexpected_crypto_migration_checkpoints",
            ));
        }

        for rk_id in [&self.active_rk_id, &self.retired_rk_id]
            .into_iter()
            .flatten()
        {
            validate_crypto_identifier(rk_id)
                .map_err(|_| ValidationError::new("invalid_crypto_migration_resource_key"))?;
        }
        if self.active_rk_id.is_some()
            && self.retired_rk_id.is_some()
            && self.active_rk_id == self.retired_rk_id
        {
            return Err(ValidationError::new(
                "crypto_migration_resource_key_conflict",
            ));
        }

        for checkpoint in &self.checkpoints {
            if checkpoint.processed_points > checkpoint.total_points
                || checkpoint.rewritten_points > checkpoint.processed_points
                || checkpoint.changed_points > checkpoint.rewritten_points
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
                        || checkpoint.rewritten_points != checkpoint.total_points
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

    pub fn apply_to_config(
        &self,
        current: &CollectionEncryptionConfig,
    ) -> Result<CollectionEncryptionConfig, ValidationError> {
        self.validate_admin_plan_for_config(current)?;
        if self.dry_run {
            return Ok(current.clone());
        }

        let mut next = current.clone();
        next.migration_state = self.to;

        if matches!(
            (self.from, self.to),
            (
                CryptoMigrationState::Disabled,
                CryptoMigrationState::Encrypting
            ) | (CryptoMigrationState::Active, CryptoMigrationState::Rotating)
        ) {
            next.encryption_epoch = self.target_epoch;
        }

        Ok(next)
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
    /// Number of points whose payload bytes actually changed.
    ///
    /// `rewritten_points` is the verified coverage count used for completion
    /// proofs and may equal `total_points` on idempotent reruns. This field
    /// distinguishes already-current points from points that needed a rewrite.
    #[serde(default)]
    #[anonymize(false)]
    pub changed_points: u64,
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

/// Capability-oriented collection encryption rules.
///
/// Secret key material is never stored here. Metadata selectors support
/// server-side metadata value AEAD and client-generated exact-match
/// blind-index token fields; range, geo, and full-text filtering remain
/// unsupported over encrypted metadata values.
#[derive(Deserialize, Serialize, JsonSchema, Validate, Anonymize, Clone, PartialEq, Eq, Hash)]
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
    pub rules: Vec<EncryptionRuleRef>,
}

impl std::fmt::Debug for CollectionEncryptionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CollectionEncryptionConfig")
            .field("version", &self.version)
            .field("key_id", &self.key_id.as_ref().map(|_| "[redacted]"))
            .field("crypto_schema_version", &self.crypto_schema_version)
            .field("encryption_epoch", &self.encryption_epoch)
            .field("migration_state", &self.migration_state)
            .field("rule_count", &"[redacted]")
            .finish()
    }
}

const fn default_crypto_schema_version() -> u16 {
    1
}

fn validate_collection_encryption_config(
    config: &CollectionEncryptionConfig,
) -> Result<(), validator::ValidationError> {
    validate_encryption_rules(&config.rules)?;

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

    if config.rules.iter().any(|rule| {
        rule.binding.as_deref() == Some("client-payload-envelope/v1")
            && config.encryption_epoch == 0
    }) {
        return Err(validator::ValidationError::new(
            "client_payload_envelope_requires_rk_epoch",
        ));
    }

    if config.rules.iter().any(|rule| {
        rule.binding.as_deref() == Some(METADATA_VALUE_BINDING)
            && config.key_id.as_deref().is_none_or(str::is_empty)
    }) {
        return Err(validator::ValidationError::new(
            "metadata_value_requires_key_id",
        ));
    }

    if config.rules.iter().any(|rule| {
        rule.binding.as_deref() == Some(METADATA_VALUE_BINDING) && config.encryption_epoch == 0
    }) {
        return Err(validator::ValidationError::new(
            "metadata_value_requires_rk_epoch",
        ));
    }

    if config.rules.iter().any(|rule| {
        rule.binding.as_deref() == Some(METADATA_EXACT_MATCH_TOKEN_BINDING)
            && config.key_id.as_deref().is_none_or(str::is_empty)
    }) {
        return Err(validator::ValidationError::new(
            "metadata_blind_index_requires_key_id",
        ));
    }

    if config.rules.iter().any(|rule| {
        rule.binding.as_deref() == Some(METADATA_EXACT_MATCH_TOKEN_BINDING)
            && config.encryption_epoch == 0
    }) {
        return Err(validator::ValidationError::new(
            "metadata_blind_index_requires_rk_epoch",
        ));
    }

    Ok(())
}

#[derive(Deserialize, Serialize, JsonSchema, Anonymize, Clone, PartialEq, Eq, Hash)]
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

impl std::fmt::Debug for EncryptionRuleRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionRuleRef")
            .field("id", &"[redacted]")
            .field("selector", &self.selector)
            .field("instance", &"[redacted]")
            .field("binding", &self.binding)
            .finish()
    }
}

#[derive(Deserialize, Serialize, JsonSchema, Anonymize, Clone, PartialEq, Eq, Hash)]
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
    /// Client-generated exact-match blind-index token fields.
    ///
    /// These fields are ordinary searchable payload fields carrying opaque
    /// tokens. They must not overlap encrypted payload paths.
    MetadataKeys {
        #[validate(custom(function = "validate_encryption_metadata_keys"))]
        #[anonymize(true)]
        keys: Vec<String>,
    },
}

impl std::fmt::Debug for EncryptionSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadPaths { .. } => f
                .debug_struct("PayloadPaths")
                .field("path_count", &"[redacted]")
                .finish(),
            Self::VectorNames { .. } => f
                .debug_struct("VectorNames")
                .field("name_count", &"[redacted]")
                .finish(),
            Self::MetadataKeys { .. } => f
                .debug_struct("MetadataKeys")
                .field("key_count", &"[redacted]")
                .finish(),
        }
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EncryptedVectorReturnRequest<'a> {
    Any { encrypted_name: &'a str },
    Named { vector_name: &'a str },
}

impl std::fmt::Debug for EncryptedVectorReturnRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any { .. } => f
                .debug_struct("Any")
                .field("encrypted_name", &"[redacted]")
                .finish(),
            Self::Named { .. } => f
                .debug_struct("Named")
                .field("vector_name", &"[redacted]")
                .finish(),
        }
    }
}

impl<'a> EncryptedVectorReturnRequest<'a> {
    pub fn vector_name(self) -> &'a str {
        match self {
            Self::Any { encrypted_name } => encrypted_name,
            Self::Named { vector_name } => vector_name,
        }
    }
}

pub fn encrypted_vector_return_request<'a>(
    encryption: &'a CollectionEncryptionConfig,
    with_vector: &'a WithVector,
) -> Option<EncryptedVectorReturnRequest<'a>> {
    match with_vector {
        WithVector::Bool(false) => None,
        WithVector::Bool(true) => encryption.rules.iter().find_map(|rule| {
            let EncryptionSelector::VectorNames { names } = &rule.selector else {
                return None;
            };
            names
                .first()
                .map(String::as_str)
                .map(|encrypted_name| EncryptedVectorReturnRequest::Any { encrypted_name })
        }),
        WithVector::Selector(vector_names) => vector_names.iter().find_map(|requested_name| {
            encryption.rules.iter().find_map(|rule| {
                let EncryptionSelector::VectorNames { names } = &rule.selector else {
                    return None;
                };
                names.iter().any(|name| name == requested_name).then_some(
                    EncryptedVectorReturnRequest::Named {
                        vector_name: requested_name,
                    },
                )
            })
        }),
    }
}

pub fn encryption_rule_uses_private_hnsw_oram(rule: &EncryptionRuleRef) -> bool {
    rule.binding.as_deref() == Some(PRIVATE_HNSW_ORAM_BINDING)
}

pub fn encryption_rule_uses_private_result_oram(rule: &EncryptionRuleRef) -> bool {
    rule.binding.as_deref() == Some(PRIVATE_RESULT_ORAM_BINDING)
}

pub fn private_hnsw_oram_api_required_message(_vector_name: &str) -> String {
    format!(
        "{} requires client-led private ORAM sessions. Use /private-hnsw/{{vector}}/session and compatible SDK traversal APIs.",
        qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
    )
}

pub fn private_result_oram_api_required_message(_payload_path: &str) -> String {
    format!(
        "{} requires client-led private result ORAM sessions. Use /private-result-oram/session and compatible SDK fetch APIs.",
        qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
    )
}

pub fn private_result_oram_payload_selector_overlap_message(
    _requested_path: impl std::fmt::Display,
    payload_path: &str,
) -> String {
    format!(
        "cannot use private result ORAM payload field because it overlaps a private result ORAM path; {}",
        private_result_oram_api_required_message(payload_path),
    )
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
            "$qdrant_sec"
                | "$qdrant_client_aead"
                | "$qdrant_ciphertext"
                | "$qdrant_sec_vectors"
                | "$qdrant_sec_ckks_vector"
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
        if key.is_empty()
            || key.starts_with('.')
            || key.ends_with('.')
            || key.split('.').any(invalid_payload_encryption_path_part)
        {
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
    let mut payload_paths = Vec::<(&str, Option<&str>)>::new();
    let mut vector_names = HashMap::<&str, Option<&str>>::new();
    let mut metadata_keys = Vec::<(&str, Option<&str>)>::new();
    let mut has_private_result_oram_rule = false;
    for rule in rules {
        if !ids.insert(rule.id.as_str()) {
            return Err(validator::ValidationError::new(
                "duplicate_encryption_rule_id",
            ));
        }
        match &rule.selector {
            EncryptionSelector::PayloadPaths { paths } => {
                let binding = rule.binding.as_deref();
                if binding.is_some_and(|binding| {
                    binding != PAYLOAD_FIELD_BINDING
                        && binding != CLIENT_PAYLOAD_ENVELOPE_BINDING
                        && binding != PRIVATE_RESULT_ORAM_BINDING
                }) {
                    if binding == Some(PRIVATE_HNSW_ORAM_BINDING) {
                        return Err(validator::ValidationError::new(
                            "private_hnsw_oram_requires_vector_selector",
                        ));
                    }
                    return Err(validator::ValidationError::new(
                        "unsupported_payload_encryption_binding",
                    ));
                }
                if binding == Some(PRIVATE_RESULT_ORAM_BINDING)
                    && std::mem::replace(&mut has_private_result_oram_rule, true)
                {
                    return Err(validator::ValidationError::new(
                        "duplicate_private_result_oram_binding",
                    ));
                }
                for path in paths {
                    if let Some((_, existing_binding)) = payload_paths
                        .iter()
                        .find(|(existing, _)| encryption_paths_overlap(existing, path))
                    {
                        return Err(private_result_oram_overlap_validation_error(
                            binding,
                            *existing_binding,
                        ));
                    }
                    if metadata_keys
                        .iter()
                        .any(|(existing, _)| encryption_paths_overlap(existing, path))
                    {
                        return Err(private_result_oram_overlap_validation_error(binding, None));
                    }
                    payload_paths.push((path, binding));
                }
            }
            EncryptionSelector::VectorNames { names } => {
                let binding = rule.binding.as_deref();
                if binding.is_some_and(|binding| {
                    binding != VECTOR_ENVELOPE_BINDING && binding != PRIVATE_HNSW_ORAM_BINDING
                }) {
                    if binding == Some(PRIVATE_RESULT_ORAM_BINDING) {
                        return Err(validator::ValidationError::new(
                            "private_result_oram_requires_payload_selector",
                        ));
                    }
                    return Err(validator::ValidationError::new(
                        "unsupported_vector_encryption_binding",
                    ));
                }
                if binding == Some(PRIVATE_HNSW_ORAM_BINDING) && names.len() != 1 {
                    return Err(validator::ValidationError::new(
                        "private_hnsw_oram_single_vector_selector",
                    ));
                }
                if binding == Some(PRIVATE_HNSW_ORAM_BINDING)
                    && names
                        .iter()
                        .any(|name| !private_hnsw_oram_vector_name_is_safe_store_component(name))
                {
                    return Err(validator::ValidationError::new(
                        "private_hnsw_oram_safe_vector_store_name",
                    ));
                }
                for name in names {
                    if let Some(existing_binding) = vector_names.insert(name.as_str(), binding) {
                        return Err(private_hnsw_oram_overlap_validation_error(
                            binding,
                            existing_binding,
                        ));
                    }
                }
            }
            EncryptionSelector::MetadataKeys { keys } => {
                let binding = rule.binding.as_deref();
                if !matches!(
                    binding,
                    Some(METADATA_VALUE_BINDING | METADATA_EXACT_MATCH_TOKEN_BINDING)
                ) {
                    return Err(validator::ValidationError::new(
                        "unsupported_metadata_encryption_binding",
                    ));
                }
                for key in keys {
                    if let Some((_, existing_binding)) = payload_paths
                        .iter()
                        .find(|(existing, _)| encryption_paths_overlap(existing, key))
                    {
                        return Err(private_result_oram_overlap_validation_error(
                            binding,
                            *existing_binding,
                        ));
                    }
                    if metadata_keys
                        .iter()
                        .any(|(existing, _)| encryption_paths_overlap(existing, key))
                    {
                        return Err(validator::ValidationError::new(
                            "overlapping_encryption_selector",
                        ));
                    }
                    metadata_keys.push((key, binding));
                }
            }
        }
    }

    Ok(())
}

fn private_result_oram_overlap_validation_error(
    current_binding: Option<&str>,
    existing_binding: Option<&str>,
) -> validator::ValidationError {
    if current_binding == Some(PRIVATE_RESULT_ORAM_BINDING)
        || existing_binding == Some(PRIVATE_RESULT_ORAM_BINDING)
    {
        validator::ValidationError::new("private_result_oram_overlapping_selector")
    } else {
        validator::ValidationError::new("overlapping_encryption_selector")
    }
}

fn private_hnsw_oram_overlap_validation_error(
    current_binding: Option<&str>,
    existing_binding: Option<&str>,
) -> validator::ValidationError {
    if current_binding == Some(PRIVATE_HNSW_ORAM_BINDING)
        || existing_binding == Some(PRIVATE_HNSW_ORAM_BINDING)
    {
        validator::ValidationError::new("private_hnsw_oram_overlapping_selector")
    } else {
        validator::ValidationError::new("overlapping_encryption_selector")
    }
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
    if let Some(encryption) = &params.encryption {
        for rule in &encryption.rules {
            let EncryptionSelector::VectorNames { names } = &rule.selector else {
                continue;
            };
            for name in names {
                let Some(vector_params) = params.vectors.get_params(name.as_str()) else {
                    if params
                        .sparse_vectors
                        .as_ref()
                        .is_some_and(|sparse_vectors| sparse_vectors.contains_key(name.as_str()))
                    {
                        return Err(validator::ValidationError::new(
                            "encrypted_vector_sparse_unsupported",
                        ));
                    }
                    return Err(validator::ValidationError::new(
                        "encrypted_vector_dense_vector_required",
                    ));
                };
                if vector_params.quantization_config.is_some() {
                    return Err(validator::ValidationError::new(
                        "encrypted_vector_quantization_unsupported",
                    ));
                }
                if vector_params.multivector_config.is_some() {
                    return Err(validator::ValidationError::new(
                        "encrypted_vector_multivector_unsupported",
                    ));
                }
            }
        }
    }

    Ok(())
}

#[derive(Deserialize, Serialize, JsonSchema, Validate, Anonymize, Clone, PartialEq, Eq)]
#[validate(schema(function = "validate_collection_encryption_sections"))]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
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
}

impl std::fmt::Debug for CollectionParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CollectionParams")
            .field("vectors", &"[redacted]")
            .field("shard_number", &self.shard_number)
            .field("sharding_method", &self.sharding_method)
            .field("replication_factor", &self.replication_factor)
            .field("write_consistency_factor", &self.write_consistency_factor)
            .field("read_fan_out_factor", &self.read_fan_out_factor)
            .field("read_fan_out_delay_ms", &self.read_fan_out_delay_ms)
            .field("on_disk_payload", &self.on_disk_payload)
            .field(
                "sparse_vectors",
                &self.sparse_vectors.as_ref().map(|_| "[redacted]"),
            )
            .field("encryption", &self.encryption)
            .finish()
    }
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
        } = other;

        self.vectors.check_compatible(vectors)?;

        if &self.encryption != encryption {
            return Err(CollectionError::bad_input(
                "collection encryption config is incompatible: encryption changes require a migration",
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
#[validate(schema(function = "validate_collection_config_internal"))]
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

fn validate_collection_config_internal(
    config: &CollectionConfigInternal,
) -> Result<(), validator::ValidationError> {
    if config.quantization_config.is_some()
        && config.params.encryption.as_ref().is_some_and(|encryption| {
            encryption
                .rules
                .iter()
                .any(|rule| matches!(rule.selector, EncryptionSelector::VectorNames { .. }))
        })
    {
        return Err(validator::ValidationError::new(
            "encrypted_vector_collection_quantization_unsupported",
        ));
    }

    Ok(())
}

impl CollectionConfigInternal {
    pub fn stable_crypto_id(&self, collection_name: &str) -> CollectionResult<String> {
        if self.params.effective_encryption().is_none() {
            return Ok(collection_name.to_string());
        }

        self.uuid.map(|uuid| uuid.to_string()).ok_or_else(|| {
            CollectionError::bad_input(
                "encrypted collection is missing a stable UUID; encrypted payload/vector AAD \
                 cannot fall back to collection name",
            )
        })
    }

    pub fn to_bytes(&self) -> CollectionResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|err| CollectionError::service_error(err.to_string()))
    }

    pub fn save(&self, path: &Path) -> CollectionResult<()> {
        let config_path = path.join(COLLECTION_CONFIG_FILE);
        let af = AtomicFile::new(&config_path, AllowOverwrite);
        let state_bytes = self.to_bytes()?;
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

    pub fn validate_startup_crypto_state(&self) -> CollectionResult<()> {
        if let Some(encryption) = &self.params.encryption
            && encryption.migration_state != CryptoMigrationState::Active
        {
            return Err(CollectionError::bad_input(format!(
                "collection startup found in-flight or disabled crypto migration state {:?}; \
                 restart recovery requires migration_state=active, no encryption config, or a \
                 verified migration recovery manifest",
                encryption.migration_state,
            )));
        }

        Ok(())
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

#[cfg(test)]
mod stable_crypto_id_tests {
    use super::*;

    fn config_with_params(
        params: CollectionParams,
        uuid: Option<Uuid>,
    ) -> CollectionConfigInternal {
        CollectionConfigInternal {
            params,
            hnsw_config: HnswConfig::default(),
            optimizer_config: OptimizersConfig::fixture(),
            wal_config: WalConfig::default(),
            quantization_config: None,
            strict_mode_config: None,
            uuid,
            metadata: None,
        }
    }

    fn encrypted_params() -> CollectionParams {
        CollectionParams {
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
        }
    }

    #[test]
    fn plaintext_stable_crypto_id_keeps_collection_name() {
        let config = config_with_params(CollectionParams::empty(), None);

        assert_eq!(config.stable_crypto_id("docs").unwrap(), "docs");
    }

    #[test]
    fn encrypted_stable_crypto_id_requires_uuid() {
        let config = config_with_params(encrypted_params(), None);

        let err = config.stable_crypto_id("docs").unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("missing a stable UUID"));
        assert!(!rendered.contains("docs"));
    }

    #[test]
    fn encrypted_stable_crypto_id_uses_uuid() {
        let uuid = Uuid::from_u128(0x1234567890abcdef1234567890abcdef);
        let config = config_with_params(encrypted_params(), Some(uuid));

        assert_eq!(config.stable_crypto_id("docs").unwrap(), uuid.to_string());
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
        }
    }

    pub fn effective_encryption(&self) -> Option<CollectionEncryptionConfig> {
        self.encryption
            .as_ref()
            .filter(|encryption| encryption.migration_state != CryptoMigrationState::Disabled)
            .cloned()
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
