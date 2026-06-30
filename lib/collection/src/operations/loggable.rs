use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{self, Write};
use std::sync::Arc;

use segment::data_types::facets::FacetParams;
use serde::Serialize;
use serde_json::Value;
use shard::count::CountRequestInternal;
use shard::operations::CollectionUpdateOperations;
use shard::scroll::ScrollRequestInternal;

use crate::operations::generalizer::Generalizer;
use crate::operations::types::PointRequestInternal;
use crate::operations::universal_query::shard_query::ShardQueryRequest;

pub trait Loggable {
    fn to_log_value(&self) -> serde_json::Value;

    fn request_name(&self) -> &'static str;

    /// Hash of the query, which is going to be used for approximate deduplication and counting.
    fn request_hash(&self) -> u64;

    fn to_log_value_and_hash(&self) -> (serde_json::Value, u64) {
        let value = self.to_log_value();
        let hash = redacted_request_hash(self.request_name(), &value);
        (value, hash)
    }
}

impl Loggable for CollectionUpdateOperations {
    fn to_log_value(&self) -> Value {
        to_generalized_redacted_log_value(self)
    }

    fn request_name(&self) -> &'static str {
        "points-update"
    }

    fn request_hash(&self) -> u64 {
        redacted_request_hash(self.request_name(), &self.to_log_value())
    }
}

impl Loggable for Vec<ShardQueryRequest> {
    fn to_log_value(&self) -> Value {
        to_generalized_redacted_log_value(self)
    }

    fn request_name(&self) -> &'static str {
        "query"
    }

    fn request_hash(&self) -> u64 {
        redacted_request_hash(self.request_name(), &self.to_log_value())
    }
}

impl Loggable for ScrollRequestInternal {
    fn to_log_value(&self) -> Value {
        to_generalized_redacted_log_value(self)
    }

    fn request_name(&self) -> &'static str {
        "scroll"
    }

    fn request_hash(&self) -> u64 {
        redacted_request_hash(self.request_name(), &self.to_log_value())
    }
}

impl<T: Loggable> Loggable for Arc<T> {
    fn to_log_value(&self) -> Value {
        self.as_ref().to_log_value()
    }

    fn request_name(&self) -> &'static str {
        self.as_ref().request_name()
    }

    fn request_hash(&self) -> u64 {
        self.as_ref().request_hash()
    }
}

impl Loggable for FacetParams {
    fn to_log_value(&self) -> Value {
        to_generalized_redacted_log_value(self)
    }

    fn request_name(&self) -> &'static str {
        "facet"
    }

    fn request_hash(&self) -> u64 {
        redacted_request_hash(self.request_name(), &self.to_log_value())
    }
}

impl Loggable for CountRequestInternal {
    fn to_log_value(&self) -> Value {
        to_generalized_redacted_log_value(self)
    }

    fn request_name(&self) -> &'static str {
        "count"
    }

    fn request_hash(&self) -> u64 {
        redacted_request_hash(self.request_name(), &self.to_log_value())
    }
}

impl Loggable for PointRequestInternal {
    fn to_log_value(&self) -> Value {
        to_generalized_redacted_log_value(self)
    }

    fn request_name(&self) -> &'static str {
        "retrieve"
    }

    fn request_hash(&self) -> u64 {
        redacted_request_hash(self.request_name(), &self.to_log_value())
    }
}

fn to_redacted_log_value(value: &impl Serialize) -> Value {
    let mut value = serde_json::to_value(value).unwrap_or_default();
    redact_sensitive_log_fields(&mut value);
    value
}

fn to_generalized_redacted_log_value(value: &(impl Generalizer + Serialize)) -> Value {
    let generalized = value.remove_details();
    to_redacted_log_value(&generalized)
}

fn redact_sensitive_log_fields(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                let key = key.as_str();
                let key_lowercase;
                let key = if key.bytes().any(|byte| byte.is_ascii_uppercase()) {
                    key_lowercase = key.to_ascii_lowercase();
                    key_lowercase.as_str()
                } else {
                    key
                };
                let compact_key;
                let key_without_separators = if key.bytes().any(|byte| matches!(byte, b'_' | b'-'))
                {
                    compact_key = key.replace('_', "").replace('-', "");
                    compact_key.as_str()
                } else {
                    key
                };
                if matches!(
                    key,
                    "payload"
                        | "payloads"
                        | "vector"
                        | "vectors"
                        | "query_vector"
                        | "query_vectors"
                        | "query_embedding"
                        | "query_embeddings"
                        | "query_plaintext"
                        | "query_plaintexts"
                        | "value"
                        | "values"
                        | "match"
                        | "range"
                        | "geo_bounding_box"
                        | "geo_radius"
                        | "geo_polygon"
                        | "Vector"
                        | "Mmr"
                        | "score"
                        | "scores"
                        | "distance"
                        | "distances"
                        | "candidate_score"
                        | "candidate_scores"
                        | "candidate_distance"
                        | "candidate_distances"
                        | "distance_score"
                        | "distance_scores"
                        | "node_score"
                        | "node_scores"
                        | "node_distance"
                        | "node_distances"
                        | "plaintext_score"
                        | "plaintext_scores"
                        | "score_plaintext"
                        | "score_plaintexts"
                        | "ciphertext"
                        | "ciphertexts"
                        | "ciphertext_sha256"
                        | "ciphertexts_sha256"
                        | "ciphertext_b64"
                        | "ciphertexts_b64"
                        | "ciphertext_sha256_b64"
                        | "ciphertexts_sha256_b64"
                        | "encrypted_query"
                        | "encrypted_queries"
                        | "encrypted_query_b64"
                        | "encrypted_queries_b64"
                        | "nonce"
                        | "nonces"
                        | "nonce_b64"
                        | "nonces_b64"
                        | "signature"
                        | "signatures"
                        | "signature_b64"
                        | "signatures_b64"
                        | "sig"
                        | "sig_b64"
                        | "public_key"
                        | "public_keys"
                        | "public_key_b64"
                        | "signature_public_keys"
                        | "signature_public_key_b64"
                        | "crypto_context"
                        | "crypto_contexts"
                        | "context_digest"
                        | "context_digests"
                        | "wrapped_key"
                        | "wrapped_keys"
                        | "wrapped_key_b64"
                        | "wrapped_keys_b64"
                        | "value_b64"
                        | "values_b64"
                        | "secret"
                        | "secret_b64"
                        | "key_material"
                        | "key_material_b64"
                        | "master_key_b64"
                        | "master_key"
                        | "resource_key"
                        | "resource_key_b64"
                        | "wrapping_key"
                        | "wrapping_key_b64"
                        | "owner_signing_key_id"
                        | "owner_signing_key_ids"
                        | "signing_key_id"
                        | "signing_key_ids"
                        | "authorization"
                        | "api_key"
                        | "x_api_key"
                        | "x-api-key"
                        | "cookie"
                        | "set_cookie"
                        | "set-cookie"
                        | "token"
                        | "access_token"
                        | "refresh_token"
                        | "client_id"
                        | "session_id"
                        | "access_key_id"
                        | "secret_access_key"
                        | "bearer_token"
                        | "id_token"
                        | "jwt"
                        | "session"
                        | "session_token"
                        | "vault_token"
                        | "x_vault_token"
                        | "x-vault-token"
                        | "aws_security_token"
                        | "x_amz_security_token"
                        | "x-amz-security-token"
                        | "x_amz_credential"
                        | "x-amz-credential"
                        | "x_amz_signature"
                        | "x-amz-signature"
                        | "client_secret"
                        | "credential"
                        | "credentials"
                        | "password"
                        | "private_key"
                        | "private_key_b64"
                        | "secret_key"
                        | "secret_key_b64"
                        | "read_path"
                        | "read_path_label"
                        | "read_path_labels"
                        | "read_paths"
                        | "read_bucket"
                        | "read_bucket_id"
                        | "read_bucket_ids"
                        | "read_bucket_id_sequence"
                        | "read_bucket_id_sequences"
                        | "read_bucket_sequence"
                        | "read_bucket_sequences"
                        | "read_buckets"
                        | "read_bucket_count"
                        | "read_bucket_id_count"
                        | "read_bucket_id_counts"
                        | "read_bucket_counts"
                        | "paths"
                        | "path_count"
                        | "path_counts"
                        | "requested_paths"
                        | "requested_path_count"
                        | "requested_path_counts"
                        | "dummy_paths_included"
                        | "access_path"
                        | "access_paths"
                        | "access_count"
                        | "access_counts"
                        | "block_plaintext"
                        | "block_plaintexts"
                        | "bucket_commitment"
                        | "bucket_commitments"
                        | "bucket_plaintext"
                        | "bucket_plaintexts"
                        | "leaf_commitment"
                        | "leaf_commitments"
                        | "merkle_proof"
                        | "merkle_proofs"
                        | "proof"
                        | "proofs"
                        | "leaf"
                        | "leaves"
                        | "leaf_id"
                        | "leaf_ids"
                        | "old_leaf"
                        | "old_leaves"
                        | "old_leaf_id"
                        | "old_leaf_ids"
                        | "old_leaf_label"
                        | "old_leaf_labels"
                        | "new_leaf"
                        | "new_leaves"
                        | "new_leaf_id"
                        | "new_leaf_ids"
                        | "new_leaf_label"
                        | "new_leaf_labels"
                        | "leaf_hash"
                        | "leaf_hashes"
                        | "sibling"
                        | "siblings"
                        | "sibling_hash"
                        | "sibling_hashes"
                        | "bucket_id"
                        | "bucket_ids"
                        | "bucket_id_count"
                        | "bucket_id_counts"
                        | "bucket_id_sequence"
                        | "bucket_id_sequences"
                        | "bucket_sequence"
                        | "bucket_sequences"
                        | "requested_bucket_count"
                        | "requested_bucket_counts"
                        | "returned_bucket_count"
                        | "returned_bucket_counts"
                        | "updated_bucket"
                        | "updated_bucket_commitment"
                        | "updated_bucket_commitments"
                        | "updated_bucket_id"
                        | "updated_bucket_ids"
                        | "updated_bucket_count"
                        | "updated_bucket_counts"
                        | "updated_buckets"
                        | "writeback_bucket_count"
                        | "writeback_bucket_counts"
                        | "accessed_leaf_label"
                        | "accessed_leaf_labels"
                        | "oram_path"
                        | "oram_paths"
                        | "path_label"
                        | "path_labels"
                        | "leaf_label"
                        | "leaf_labels"
                        | "leaf_count"
                        | "leaf_counts"
                        | "sibling_count"
                        | "sibling_counts"
                        | "client_state"
                        | "client_state_backup"
                        | "client_state_backups"
                        | "client_state_snapshot"
                        | "client_state_snapshots"
                        | "client_state_ciphertext"
                        | "client_state_ciphertexts"
                        | "client_state_ciphertext_hash"
                        | "client_state_ciphertext_hashes"
                        | "client_state_ciphertext_sha256"
                        | "client_state_ciphertexts_sha256"
                        | "encrypted_client_state"
                        | "encrypted_client_states"
                        | "encrypted_client_state_backup"
                        | "encrypted_client_state_backups"
                        | "encrypted_client_state_snapshot"
                        | "encrypted_client_state_snapshots"
                        | "encrypted_client_state_ciphertext"
                        | "encrypted_client_state_ciphertexts"
                        | "encrypted_client_state_ciphertext_hash"
                        | "encrypted_client_state_ciphertext_hashes"
                        | "encrypted_client_state_ciphertext_sha256"
                        | "encrypted_client_state_ciphertexts_sha256"
                        | "position_map"
                        | "position_count"
                        | "position_counts"
                        | "position_map_len"
                        | "position_map_backup"
                        | "position_map_backups"
                        | "position_maps"
                        | "position_map_snapshot"
                        | "position_map_snapshots"
                        | "oram_position_map"
                        | "oram_position_map_backup"
                        | "oram_position_map_backups"
                        | "oram_position_maps"
                        | "oram_position_map_snapshot"
                        | "oram_position_map_snapshots"
                        | "token_position_map"
                        | "token_count"
                        | "token_counts"
                        | "token_position_map_backup"
                        | "token_position_map_backups"
                        | "token_position_maps"
                        | "token_position_map_snapshot"
                        | "token_position_map_snapshots"
                        | "stash"
                        | "stash_len"
                        | "stash_backup"
                        | "stash_backups"
                        | "stash_snapshot"
                        | "stash_snapshots"
                        | "entry_node_id"
                        | "entry_node_ids"
                        | "level_mask"
                        | "level_masks"
                        | "node_block"
                        | "node_blocks"
                        | "node_id"
                        | "node_ids"
                        | "node_plaintext"
                        | "node_plaintexts"
                        | "neighbor"
                        | "neighbor_count"
                        | "neighbor_counts"
                        | "neighbor_id"
                        | "neighbors"
                        | "neighbor_ids"
                        | "neighbor_level"
                        | "neighbor_levels"
                        | "candidate_id"
                        | "candidate_ids"
                        | "candidate_heap"
                        | "candidate_heaps"
                        | "candidate_node"
                        | "candidate_nodes"
                        | "client_signature"
                        | "client_signatures"
                        | "commit_signature"
                        | "commit_signatures"
                        | "manifest_signature"
                        | "manifest_signatures"
                        | "read_signature"
                        | "read_signatures"
                        | "request_signature"
                        | "request_signatures"
                        | "top_k"
                        | "top_ks"
                        | "topk"
                        | "result_id"
                        | "result_ids"
                        | "point_token"
                        | "point_tokens"
                        | "fetch_token"
                        | "fetch_tokens"
                        | "payload_len"
                        | "payload_bytes"
                        | "payload_fetch_token"
                        | "payload_fetch_tokens"
                        | "payload_oram_leaf"
                        | "payload_oram_leaves"
                        | "payload_plaintext"
                        | "payload_plaintexts"
                        | "plaintext_block"
                        | "plaintext_blocks"
                        | "plaintext_bucket"
                        | "plaintext_buckets"
                        | "plaintext_payload"
                        | "plaintext_payloads"
                        | "plaintext_vector"
                        | "plaintext_vectors"
                        | "root_hash"
                        | "root_hashes"
                        | "old_root_hash"
                        | "old_root_hashes"
                        | "new_root_hash"
                        | "new_root_hashes"
                        | "vector_bytes"
                        | "vector_plaintext"
                        | "vector_plaintexts"
                        | "visited_node"
                        | "visited_nodes"
                        | "visited_node_id"
                        | "visited_node_ids"
                        | "hit_count"
                        | "hit_counts"
                        | "result_count"
                        | "result_counts"
                        | "real_path_count"
                        | "real_path_counts"
                ) || matches!(
                    key_without_separators,
                    "xapikey"
                        | "setcookie"
                        | "accesstoken"
                        | "refreshtoken"
                        | "accesskeyid"
                        | "secretaccesskey"
                        | "bearertoken"
                        | "ownersigningkeyid"
                        | "ownersigningkeyids"
                        | "signingkeyid"
                        | "signingkeyids"
                        | "idtoken"
                        | "sessiontoken"
                        | "vaulttoken"
                        | "xvaulttoken"
                        | "awssecuritytoken"
                        | "xamzsecuritytoken"
                        | "xamzcredential"
                        | "xamzsignature"
                        | "clientid"
                        | "sessionid"
                        | "clientsecret"
                        | "clientstateciphertext"
                        | "clientstateciphertexts"
                        | "clientstateciphertexthash"
                        | "clientstateciphertexthashes"
                        | "clientstateciphertextsha256"
                        | "clientstateciphertextssha256"
                        | "privatekey"
                        | "privatekeyb64"
                        | "secretkey"
                        | "secretkeyb64"
                        | "publickey"
                        | "publickeys"
                        | "publickeyb64"
                        | "signaturepublickeys"
                        | "signaturepublickeyb64"
                        | "queryvector"
                        | "queryvectors"
                        | "queryembedding"
                        | "queryembeddings"
                        | "queryplaintext"
                        | "queryplaintexts"
                        | "score"
                        | "scores"
                        | "distance"
                        | "distances"
                        | "candidatescore"
                        | "candidatescores"
                        | "candidatedistance"
                        | "candidatedistances"
                        | "distancescore"
                        | "distancescores"
                        | "nodescore"
                        | "nodescores"
                        | "nodedistance"
                        | "nodedistances"
                        | "plaintextscore"
                        | "plaintextscores"
                        | "scoreplaintext"
                        | "scoreplaintexts"
                        | "ciphertextsha256"
                        | "ciphertextssha256"
                        | "ciphertextb64"
                        | "ciphertextsb64"
                        | "ciphertextsha256b64"
                        | "ciphertextssha256b64"
                        | "encryptedqueryb64"
                        | "encryptedqueriesb64"
                        | "nonceb64"
                        | "noncesb64"
                        | "signatureb64"
                        | "signaturesb64"
                        | "sigb64"
                        | "cryptocontext"
                        | "cryptocontexts"
                        | "contextdigest"
                        | "contextdigests"
                        | "encryptedquery"
                        | "encryptedqueries"
                        | "wrappedkey"
                        | "wrappedkeys"
                        | "wrappedkeyb64"
                        | "wrappedkeysb64"
                        | "valueb64"
                        | "valuesb64"
                        | "secretb64"
                        | "keymaterial"
                        | "keymaterialb64"
                        | "masterkey"
                        | "masterkeyb64"
                        | "resourcekey"
                        | "resourcekeyb64"
                        | "wrappingkey"
                        | "wrappingkeyb64"
                        | "pathlabel"
                        | "pathlabels"
                        | "readpathlabel"
                        | "readpathlabels"
                        | "readpath"
                        | "readpaths"
                        | "readbucket"
                        | "readbucketid"
                        | "readbucketids"
                        | "readbucketidsequence"
                        | "readbucketidsequences"
                        | "readbucketsequence"
                        | "readbucketsequences"
                        | "readbuckets"
                        | "readbucketcount"
                        | "readbucketidcount"
                        | "readbucketidcounts"
                        | "readbucketcounts"
                        | "pathcount"
                        | "pathcounts"
                        | "requestedpaths"
                        | "requestedpathcount"
                        | "requestedpathcounts"
                        | "dummypathsincluded"
                        | "accesspath"
                        | "accesspaths"
                        | "accesscount"
                        | "accesscounts"
                        | "blockplaintext"
                        | "blockplaintexts"
                        | "bucketcommitment"
                        | "bucketcommitments"
                        | "bucketplaintext"
                        | "bucketplaintexts"
                        | "leafcommitment"
                        | "leafcommitments"
                        | "merkleproof"
                        | "merkleproofs"
                        | "proof"
                        | "proofs"
                        | "leaf"
                        | "leaves"
                        | "leafid"
                        | "leafids"
                        | "oldleaf"
                        | "oldleaves"
                        | "oldleafid"
                        | "oldleafids"
                        | "oldleaflabel"
                        | "oldleaflabels"
                        | "newleaf"
                        | "newleaves"
                        | "newleafid"
                        | "newleafids"
                        | "newleaflabel"
                        | "newleaflabels"
                        | "leafhash"
                        | "leafhashes"
                        | "sibling"
                        | "siblings"
                        | "siblinghash"
                        | "siblinghashes"
                        | "bucketid"
                        | "bucketids"
                        | "bucketidcount"
                        | "bucketidcounts"
                        | "bucketidsequence"
                        | "bucketidsequences"
                        | "bucketsequence"
                        | "bucketsequences"
                        | "requestedbucketcount"
                        | "requestedbucketcounts"
                        | "returnedbucketcount"
                        | "returnedbucketcounts"
                        | "updatedbucket"
                        | "updatedbucketcommitment"
                        | "updatedbucketcommitments"
                        | "updatedbucketid"
                        | "updatedbucketids"
                        | "updatedbucketcount"
                        | "updatedbucketcounts"
                        | "updatedbuckets"
                        | "writebackbucketcount"
                        | "writebackbucketcounts"
                        | "accessedleaflabel"
                        | "accessedleaflabels"
                        | "orampath"
                        | "orampaths"
                        | "leaflabel"
                        | "leaflabels"
                        | "leafcount"
                        | "leafcounts"
                        | "siblingcount"
                        | "siblingcounts"
                        | "clientstate"
                        | "clientstatebackup"
                        | "clientstatebackups"
                        | "clientstatesnapshot"
                        | "clientstatesnapshots"
                        | "encryptedclientstate"
                        | "encryptedclientstates"
                        | "encryptedclientstatebackup"
                        | "encryptedclientstatebackups"
                        | "encryptedclientstatesnapshot"
                        | "encryptedclientstatesnapshots"
                        | "encryptedclientstateciphertext"
                        | "encryptedclientstateciphertexts"
                        | "encryptedclientstateciphertexthash"
                        | "encryptedclientstateciphertexthashes"
                        | "encryptedclientstateciphertextsha256"
                        | "encryptedclientstateciphertextssha256"
                        | "stateciphertext"
                        | "stateciphertexts"
                        | "stateciphertexthash"
                        | "stateciphertexthashes"
                        | "stateciphertextsha256"
                        | "stateciphertextssha256"
                        | "positionmap"
                        | "positioncount"
                        | "positioncounts"
                        | "positionmaplen"
                        | "positionmapbackup"
                        | "positionmapbackups"
                        | "positionmaps"
                        | "positionmapsnapshot"
                        | "positionmapsnapshots"
                        | "orampositionmap"
                        | "orampositionmapbackup"
                        | "orampositionmapbackups"
                        | "orampositionmaps"
                        | "orampositionmapsnapshot"
                        | "orampositionmapsnapshots"
                        | "tokenpositionmap"
                        | "tokencount"
                        | "tokencounts"
                        | "tokenpositionmapbackup"
                        | "tokenpositionmapbackups"
                        | "tokenpositionmaps"
                        | "tokenpositionmapsnapshot"
                        | "tokenpositionmapsnapshots"
                        | "stash"
                        | "stashlen"
                        | "stashbackup"
                        | "stashbackups"
                        | "stashsnapshot"
                        | "stashsnapshots"
                        | "entrynodeid"
                        | "entrynodeids"
                        | "levelmask"
                        | "levelmasks"
                        | "nodeblock"
                        | "nodeblocks"
                        | "nodeid"
                        | "nodeids"
                        | "nodeplaintext"
                        | "nodeplaintexts"
                        | "neighbor"
                        | "neighbors"
                        | "neighborcount"
                        | "neighborcounts"
                        | "neighborid"
                        | "neighborids"
                        | "neighborlevel"
                        | "neighborlevels"
                        | "candidateid"
                        | "candidateids"
                        | "candidateheap"
                        | "candidateheaps"
                        | "candidatenode"
                        | "candidatenodes"
                        | "clientsignature"
                        | "clientsignatures"
                        | "commitsignature"
                        | "commitsignatures"
                        | "manifestsignature"
                        | "manifestsignatures"
                        | "readsignature"
                        | "readsignatures"
                        | "requestsignature"
                        | "requestsignatures"
                        | "topk"
                        | "topks"
                        | "resultid"
                        | "resultids"
                        | "pointtoken"
                        | "pointtokens"
                        | "fetchtoken"
                        | "fetchtokens"
                        | "payloadlen"
                        | "payloadbytes"
                        | "payloadfetchtoken"
                        | "payloadfetchtokens"
                        | "payloadoramleaf"
                        | "payloadoramleaves"
                        | "payloadplaintext"
                        | "payloadplaintexts"
                        | "plaintextblock"
                        | "plaintextblocks"
                        | "plaintextbucket"
                        | "plaintextbuckets"
                        | "plaintextpayload"
                        | "plaintextpayloads"
                        | "plaintextvector"
                        | "plaintextvectors"
                        | "roothash"
                        | "roothashes"
                        | "oldroothash"
                        | "oldroothashes"
                        | "newroothash"
                        | "newroothashes"
                        | "vectorbytes"
                        | "vectorplaintext"
                        | "vectorplaintexts"
                        | "visitednode"
                        | "visitednodes"
                        | "visitednodeid"
                        | "visitednodeids"
                        | "hitcount"
                        | "hitcounts"
                        | "resultcount"
                        | "resultcounts"
                        | "realpathcount"
                        | "realpathcounts"
                        | "unknownfield"
                ) {
                    *value = Value::String("[redacted]".to_string());
                } else {
                    redact_sensitive_log_fields(value);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                redact_sensitive_log_fields(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn redacted_request_hash(request_name: &str, log_value: &Value) -> u64 {
    struct HashWriter<'a>(&'a mut DefaultHasher);

    impl Write for HashWriter<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut hasher = DefaultHasher::new();
    request_name.hash(&mut hasher);
    if serde_json::to_writer(HashWriter(&mut hasher), log_value).is_err() {
        "serde-json-hash-failed".hash(&mut hasher);
    }
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use segment::types::{
        Condition, FieldCondition, Filter, Payload, WithPayloadInterface, WithVector,
    };
    use serde::Serialize;
    use serde::ser::Serializer;
    use serde_json::{Value, json};
    use shard::count::CountRequestInternal;
    use shard::operations::point_ops::{
        PointInsertOperationsInternal, PointOperations, PointStructPersisted, VectorStructPersisted,
    };
    use shard::query::query_enum::QueryEnum;
    use shard::query::{MmrInternal, ScoringQuery, ShardQueryRequest};

    use super::*;

    #[derive(Clone)]
    struct SerializationProbe {
        secret: &'static str,
    }

    impl Generalizer for SerializationProbe {
        fn remove_details(&self) -> Self {
            Self {
                secret: "[redacted]",
            }
        }
    }

    impl Serialize for SerializationProbe {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            assert_ne!(
                self.secret, "qdrant-sec-serialization-probe-secret",
                "raw secret-bearing request must be generalized before serde_json materialization",
            );
            serializer.serialize_str(self.secret)
        }
    }

    fn insert_test_json_field(
        value: &mut Value,
        object_path: &[&str],
        key: &str,
        field_value: Value,
    ) {
        let mut cursor = value;
        for path in object_path {
            cursor = cursor.get_mut(*path).unwrap();
        }
        cursor
            .as_object_mut()
            .unwrap()
            .insert(key.to_string(), field_value);
    }

    #[test]
    fn generalized_log_projection_serializes_only_redacted_projection() {
        let value = to_generalized_redacted_log_value(&SerializationProbe {
            secret: "qdrant-sec-serialization-probe-secret",
        });

        assert_eq!(value, json!("[redacted]"));
    }

    #[test]
    fn update_log_value_redacts_payloads_and_vectors() {
        let operation = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::PointsList(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![12345.125, -23456.25]),
                payload: Some(Payload(
                    json!({ "body": "qdrant-sec-log-plaintext-sentinel" })
                        .as_object()
                        .unwrap()
                        .clone(),
                )),
            }]),
        ));

        let log_value = operation.to_log_value();
        let serialized = serde_json::to_string(&log_value).unwrap();

        assert!(!serialized.contains("qdrant-sec-log-plaintext-sentinel"));
        assert!(!serialized.contains("12345.125"));
        assert!(serialized.contains("[redacted]"));
    }

    #[test]
    fn update_request_hash_uses_redacted_payloads_and_vectors() {
        let update = |payload: &str, vector: Vec<f32>| {
            CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
                PointInsertOperationsInternal::PointsList(vec![PointStructPersisted {
                    id: 1.into(),
                    vector: VectorStructPersisted::from(vector),
                    payload: Some(Payload(
                        json!({ "body": payload }).as_object().unwrap().clone(),
                    )),
                }]),
            ))
        };
        let first = update("secret-a", vec![1.0, 2.0]);
        let second = update("secret-b", vec![3.0, 4.0]);

        assert_eq!(first.to_log_value(), second.to_log_value());
        assert_eq!(first.request_hash(), second.request_hash());
    }

    #[test]
    fn query_log_value_redacts_payload_filter_literals() {
        let request = CountRequestInternal {
            filter: Some(Filter::new_must(Condition::Field(
                FieldCondition::new_match(
                    "document.body".parse().unwrap(),
                    serde_json::from_value(json!({
                        "value": "qdrant-sec-filter-log-sentinel",
                    }))
                    .unwrap(),
                ),
            ))),
            exact: true,
        };

        let log_value = request.to_log_value();
        let serialized = serde_json::to_string(&log_value).unwrap();

        assert!(!serialized.contains("qdrant-sec-filter-log-sentinel"));
        assert!(serialized.contains("[redacted]"));
    }

    #[test]
    fn query_request_hash_uses_redacted_filter_literals() {
        let request = |literal: &str| CountRequestInternal {
            filter: Some(Filter::new_must(Condition::Field(
                FieldCondition::new_match(
                    "document.body".parse().unwrap(),
                    serde_json::from_value(json!({ "value": literal })).unwrap(),
                ),
            ))),
            exact: true,
        };
        let first = request("secret-a");
        let second = request("secret-b");

        assert_eq!(first.to_log_value(), second.to_log_value());
        assert_eq!(first.request_hash(), second.request_hash());
    }

    #[test]
    fn query_log_value_redacts_query_vectors() {
        let request = vec![ShardQueryRequest {
            prefetches: vec![],
            query: Some(ScoringQuery::Vector(QueryEnum::from(vec![
                98765.125, -87654.25,
            ]))),
            filter: None,
            score_threshold: None,
            limit: 10,
            offset: 0,
            params: None,
            with_vector: WithVector::Bool(false),
            with_payload: WithPayloadInterface::Bool(false),
        }];

        let log_value = request.to_log_value();
        let serialized = serde_json::to_string(&log_value).unwrap();

        assert!(!serialized.contains("98765.125"));
        assert!(!serialized.contains("-87654.25"));
        assert!(serialized.contains("[redacted]"));
    }

    #[test]
    fn query_request_hash_uses_redacted_query_vectors() {
        let request = |vector: Vec<f32>| {
            vec![ShardQueryRequest {
                prefetches: vec![],
                query: Some(ScoringQuery::Vector(QueryEnum::from(vector))),
                filter: None,
                score_threshold: None,
                limit: 10,
                offset: 0,
                params: None,
                with_vector: WithVector::Bool(false),
                with_payload: WithPayloadInterface::Bool(false),
            }]
        };
        let first = request(vec![1.0, 2.0]);
        let second = request(vec![3.0, 4.0]);

        assert_eq!(first.to_log_value(), second.to_log_value());
        assert_eq!(first.request_hash(), second.request_hash());
    }

    #[test]
    fn redaction_removes_encrypted_envelope_material() {
        let mut value = json!({
            "client_payload": {
                "$qdrant_client_aead": {
                    "key_id": "tenant-a/payload-rk",
                    "rk_id": "tenant-a/payload-rk",
                    "nonce": "qdrant-sec-log-nonce-sentinel",
                    "ciphertext": "qdrant-sec-log-ciphertext-sentinel",
                    "ciphertext_sha256": "qdrant-sec-log-ciphertext-sha256-sentinel",
                    "signature": {
                        "alg": "ed25519",
                        "key_id": "tenant-a/signing-key",
                        "sig": "qdrant-sec-log-signature-sentinel"
                    }
                }
            },
            "ckks_query": {
                "context_digest": "qdrant-sec-log-context-digest-sentinel",
                "encrypted_query": "qdrant-sec-log-encrypted-query-sentinel",
                "public_key": "qdrant-sec-log-public-key-sentinel",
                "crypto_context": "qdrant-sec-log-crypto-context-sentinel"
            }
        });

        redact_sensitive_log_fields(&mut value);
        let serialized = serde_json::to_string(&value).unwrap();

        assert!(!serialized.contains("qdrant-sec-log-nonce-sentinel"));
        assert!(!serialized.contains("qdrant-sec-log-ciphertext-sentinel"));
        assert!(!serialized.contains("qdrant-sec-log-ciphertext-sha256-sentinel"));
        assert!(!serialized.contains("qdrant-sec-log-signature-sentinel"));
        assert!(!serialized.contains("qdrant-sec-log-context-digest-sentinel"));
        assert!(!serialized.contains("qdrant-sec-log-encrypted-query-sentinel"));
        assert!(!serialized.contains("qdrant-sec-log-public-key-sentinel"));
        assert!(!serialized.contains("qdrant-sec-log-crypto-context-sentinel"));
        assert!(serialized.contains("tenant-a/payload-rk"));
    }

    #[test]
    fn encrypted_envelope_request_hash_uses_redacted_material() {
        let envelope = |nonce: &str, ciphertext: &str, ciphertext_sha256: &str, signature: &str| {
            let mut value = json!({
                "client_payload": {
                    "$qdrant_client_aead": {
                        "key_id": "tenant-a/payload-rk",
                        "rk_id": "tenant-a/payload-rk",
                        "nonce": nonce,
                        "ciphertext": ciphertext,
                        "ciphertext_sha256": ciphertext_sha256,
                        "signature": {
                            "alg": "ed25519",
                            "key_id": "tenant-a/signing-key",
                            "sig": signature
                        }
                    }
                }
            });
            redact_sensitive_log_fields(&mut value);
            value
        };

        let first = envelope(
            "nonce-a",
            "ciphertext-a",
            "ciphertext-sha256-a",
            "signature-a",
        );
        let second = envelope(
            "nonce-b",
            "ciphertext-b",
            "ciphertext-sha256-b",
            "signature-b",
        );

        assert_eq!(first, second);
        assert_eq!(
            redacted_request_hash("encrypted-envelope", &first),
            redacted_request_hash("encrypted-envelope", &second),
        );
    }

    #[test]
    fn mmr_query_log_value_redacts_query_vector() {
        let request = vec![ShardQueryRequest {
            prefetches: vec![],
            query: Some(ScoringQuery::Mmr(MmrInternal {
                vector: vec![54321.125, -12345.25].into(),
                using: "embedding".to_string(),
                lambda: ordered_float::OrderedFloat(0.5),
                candidates_limit: 20,
            })),
            filter: None,
            score_threshold: None,
            limit: 10,
            offset: 0,
            params: None,
            with_vector: WithVector::Bool(false),
            with_payload: WithPayloadInterface::Bool(false),
        }];

        let log_value = request.to_log_value();
        let serialized = serde_json::to_string(&log_value).unwrap();

        assert!(!serialized.contains("54321.125"));
        assert!(!serialized.contains("-12345.25"));
        assert!(serialized.contains("[redacted]"));
    }

    #[test]
    fn log_value_redacts_crypto_envelope_fields_recursively() {
        let mut value = json!({
            "outer": {
                "ciphertext": "qdrant-sec-ciphertext-log-sentinel",
                "ciphertexts": [
                    "qdrant-sec-ciphertexts-log-sentinel-a",
                    "qdrant-sec-ciphertexts-log-sentinel-b"
                ],
                "ciphertext_sha256": "qdrant-sec-ciphertext-sha256-log-sentinel",
                "ciphertexts_sha256": ["qdrant-sec-ciphertexts-sha256-log-sentinel"],
                "ciphertext_b64": "qdrant-sec-ciphertext-b64-log-sentinel",
                "ciphertexts_b64": ["qdrant-sec-ciphertexts-b64-log-sentinel"],
                "ciphertext_sha256_b64": "qdrant-sec-ciphertext-sha256-b64-log-sentinel",
                "ciphertexts_sha256_b64": ["qdrant-sec-ciphertexts-sha256-b64-log-sentinel"],
                "nonce": "qdrant-sec-nonce-log-sentinel",
                "nonces": ["qdrant-sec-nonces-log-sentinel"],
                "nonce_b64": "qdrant-sec-nonce-b64-log-sentinel",
                "nonces_b64": ["qdrant-sec-nonces-b64-log-sentinel"],
                "signature": {
                    "sig": "qdrant-sec-signature-log-sentinel",
                    "sig_b64": "qdrant-sec-signature-sig-b64-log-sentinel",
                    "public_key": "qdrant-sec-public-key-log-sentinel"
                },
                "signatures": ["qdrant-sec-signatures-log-sentinel"],
                "signature_b64": "qdrant-sec-signature-b64-log-sentinel",
                "signatures_b64": ["qdrant-sec-signatures-b64-log-sentinel"],
                "public_keys": ["qdrant-sec-public-keys-log-sentinel"],
                "signature_public_keys": [{
                    "key_id": "tenant-a/client-signing-v1",
                    "public_key_b64": "qdrant-sec-signature-public-keys-log-sentinel"
                }],
                "crypto_context": "qdrant-sec-context-log-sentinel",
                "crypto_contexts": ["qdrant-sec-contexts-log-sentinel"],
                "context_digest": "qdrant-sec-context-digest-log-sentinel",
                "context_digests": ["qdrant-sec-context-digests-log-sentinel"],
                "encrypted_query": "qdrant-sec-encrypted-query-log-sentinel",
                "encrypted_queries": ["qdrant-sec-encrypted-queries-log-sentinel"],
                "encrypted_query_b64": "qdrant-sec-encrypted-query-b64-log-sentinel",
                "encrypted_queries_b64": ["qdrant-sec-encrypted-queries-b64-log-sentinel"],
                "wrapped_key_b64": "qdrant-sec-wrapped-key-log-sentinel",
                "wrapped_keys_b64": ["qdrant-sec-wrapped-keys-log-sentinel"],
                "value_b64": "qdrant-sec-inline-key-log-sentinel",
                "values_b64": ["qdrant-sec-inline-keys-log-sentinel"]
            }
        });

        redact_sensitive_log_fields(&mut value);
        let serialized = serde_json::to_string(&value).unwrap();

        for sentinel in [
            "qdrant-sec-ciphertext-log-sentinel",
            "qdrant-sec-ciphertexts-log-sentinel-a",
            "qdrant-sec-ciphertexts-log-sentinel-b",
            "qdrant-sec-ciphertext-sha256-log-sentinel",
            "qdrant-sec-ciphertexts-sha256-log-sentinel",
            "qdrant-sec-ciphertext-b64-log-sentinel",
            "qdrant-sec-ciphertexts-b64-log-sentinel",
            "qdrant-sec-ciphertext-sha256-b64-log-sentinel",
            "qdrant-sec-ciphertexts-sha256-b64-log-sentinel",
            "qdrant-sec-nonce-log-sentinel",
            "qdrant-sec-nonces-log-sentinel",
            "qdrant-sec-nonce-b64-log-sentinel",
            "qdrant-sec-nonces-b64-log-sentinel",
            "qdrant-sec-signature-log-sentinel",
            "qdrant-sec-signature-sig-b64-log-sentinel",
            "qdrant-sec-signatures-log-sentinel",
            "qdrant-sec-signature-b64-log-sentinel",
            "qdrant-sec-signatures-b64-log-sentinel",
            "qdrant-sec-public-key-log-sentinel",
            "qdrant-sec-public-keys-log-sentinel",
            "qdrant-sec-signature-public-keys-log-sentinel",
            "qdrant-sec-context-log-sentinel",
            "qdrant-sec-contexts-log-sentinel",
            "qdrant-sec-context-digest-log-sentinel",
            "qdrant-sec-context-digests-log-sentinel",
            "qdrant-sec-encrypted-query-log-sentinel",
            "qdrant-sec-encrypted-queries-log-sentinel",
            "qdrant-sec-encrypted-query-b64-log-sentinel",
            "qdrant-sec-encrypted-queries-b64-log-sentinel",
            "qdrant-sec-wrapped-key-log-sentinel",
            "qdrant-sec-wrapped-keys-log-sentinel",
            "qdrant-sec-inline-key-log-sentinel",
            "qdrant-sec-inline-keys-log-sentinel",
        ] {
            assert!(!serialized.contains(sentinel));
        }
        assert!(serialized.contains("[redacted]"));
    }

    #[test]
    fn log_value_redacts_private_oram_access_pattern_fields() {
        let mut private_hnsw_oram_access = json!({
            "private_hnsw": {
                "client_id": "qdrant-sec-private-hnsw-client-id-log-sentinel",
                "session_id": "qdrant-sec-private-hnsw-session-id-log-sentinel",
                "paths": ["qdrant-sec-private-hnsw-path-log-sentinel"],
                "access_path": ["qdrant-sec-private-hnsw-access-path-log-sentinel"],
                "accessPaths": ["qdrant-sec-private-hnsw-camel-access-path-log-sentinel"],
                "root_hash": "qdrant-sec-private-hnsw-root-hash-log-sentinel",
                "rootHash": "qdrant-sec-private-hnsw-camel-root-hash-log-sentinel",
                "old_root_hash": "qdrant-sec-private-hnsw-old-root-hash-log-sentinel",
                "old_root_hashes": ["qdrant-sec-private-hnsw-old-root-hashes-log-sentinel"],
                "newRootHash": "qdrant-sec-private-hnsw-camel-new-root-hash-log-sentinel",
                "newRootHashes": ["qdrant-sec-private-hnsw-camel-new-root-hashes-log-sentinel"],
                "bucket_ids": ["qdrant-sec-private-oram-bucket-id-log-sentinel"],
                "bucketIds": ["qdrant-sec-private-oram-camel-bucket-id-log-sentinel"],
                "bucketId": "qdrant-sec-private-oram-camel-single-bucket-id-log-sentinel",
                "bucket_commitment": "qdrant-sec-private-oram-bucket-commitment-log-sentinel",
                "bucket_commitments": ["qdrant-sec-private-oram-bucket-commitments-log-sentinel"],
                "bucketCommitments": ["qdrant-sec-private-oram-camel-bucket-commitment-log-sentinel"],
                "bucketCommitment": "qdrant-sec-private-oram-camel-single-bucket-commitment-log-sentinel",
                "updated_buckets": [{
                    "bucket_id": "qdrant-sec-private-oram-nested-bucket-id-log-sentinel",
                    "bucket_commitment": "qdrant-sec-private-oram-nested-bucket-commitment-log-sentinel"
                }],
                "updated_bucket": {
                    "bucket_id": "qdrant-sec-private-oram-updated-single-bucket-id-log-sentinel",
                    "bucket_commitment": "qdrant-sec-private-oram-updated-single-bucket-commitment-log-sentinel"
                },
                "updatedBuckets": ["qdrant-sec-private-oram-camel-updated-bucket-log-sentinel"],
                "updatedBucket": {
                    "bucketId": "qdrant-sec-private-oram-camel-updated-single-bucket-id-log-sentinel",
                    "bucketCommitment": "qdrant-sec-private-oram-camel-updated-single-bucket-commitment-log-sentinel"
                },
                "proof": {
                    "leaves": [{
                        "bucket_id": "qdrant-sec-private-oram-proof-bucket-id-log-sentinel",
                        "leaf_hash": "qdrant-sec-private-oram-proof-leaf-hash-log-sentinel",
                        "siblings": [{
                            "hash": "qdrant-sec-private-oram-proof-sibling-hash-log-sentinel"
                        }]
                    }]
                },
                "merkleProof": {
                    "leafHash": "qdrant-sec-private-oram-camel-proof-leaf-hash-log-sentinel",
                    "siblings": ["qdrant-sec-private-oram-camel-proof-sibling-log-sentinel"]
                },
                "path_label": "qdrant-sec-private-hnsw-path-label-log-sentinel",
                "pathLabel": "qdrant-sec-private-hnsw-camel-single-path-label-log-sentinel",
                "pathLabels": ["qdrant-sec-private-hnsw-camel-path-label-log-sentinel"],
                "readPathLabels": ["qdrant-sec-private-hnsw-camel-read-path-label-log-sentinel"],
                "leaf_label": "qdrant-sec-private-hnsw-leaf-label-log-sentinel",
                "leafLabel": "qdrant-sec-private-hnsw-camel-single-leaf-label-log-sentinel",
                "leafLabels": ["qdrant-sec-private-hnsw-camel-leaf-label-log-sentinel"],
                "accessed_leaf_labels": ["qdrant-sec-private-hnsw-accessed-leaf-label-log-sentinel"],
                "accessedLeafLabels": ["qdrant-sec-private-hnsw-camel-accessed-leaf-label-log-sentinel"],
                "oram_path": ["qdrant-sec-private-hnsw-oram-path-log-sentinel"],
                "oramPaths": ["qdrant-sec-private-hnsw-camel-oram-path-log-sentinel"],
                "client_state": {
                    "position_map": "qdrant-sec-private-hnsw-position-map-log-sentinel",
                    "oram_position_map": "qdrant-sec-private-hnsw-oram-position-map-log-sentinel",
                    "stash": "qdrant-sec-private-hnsw-stash-log-sentinel"
                },
                "clientState": "qdrant-sec-private-hnsw-camel-client-state-log-sentinel",
                "unknown_field": "qdrant-sec-private-oram-unknown-field-log-sentinel",
                "unknownField": "qdrant-sec-private-oram-camel-unknown-field-log-sentinel"
            }
        });
        let mut private_hnsw_graph = json!({
            "private_hnsw": {
                "node_id": "qdrant-sec-private-hnsw-node-id-log-sentinel",
                "nodeId": "qdrant-sec-private-hnsw-camel-single-node-id-log-sentinel",
                "nodeIds": ["qdrant-sec-private-hnsw-camel-node-id-log-sentinel"],
                "entry_node_id": "qdrant-sec-private-hnsw-entry-node-id-log-sentinel",
                "entryNodeId": "qdrant-sec-private-hnsw-camel-entry-node-id-log-sentinel",
                "level_mask": "qdrant-sec-private-hnsw-level-mask-log-sentinel",
                "levelMask": "qdrant-sec-private-hnsw-camel-level-mask-log-sentinel",
                "visited_nodes": ["qdrant-sec-private-hnsw-visited-node-log-sentinel"],
                "visitedNodeIds": ["qdrant-sec-private-hnsw-camel-visited-node-id-log-sentinel"],
                "neighbors": ["qdrant-sec-private-hnsw-neighbor-log-sentinel"],
                "neighbor_id": "qdrant-sec-private-hnsw-neighbor-id-log-sentinel",
                "neighborId": "qdrant-sec-private-hnsw-camel-single-neighbor-id-log-sentinel",
                "neighborIds": ["qdrant-sec-private-hnsw-camel-neighbor-id-log-sentinel"],
                "neighbor_levels": ["qdrant-sec-private-hnsw-neighbor-level-log-sentinel"],
                "neighborLevels": ["qdrant-sec-private-hnsw-camel-neighbor-level-log-sentinel"],
                "candidate_heap": "qdrant-sec-private-hnsw-candidate-heap-log-sentinel",
                "candidateHeap": "qdrant-sec-private-hnsw-camel-candidate-heap-log-sentinel",
                "candidate_nodes": ["qdrant-sec-private-hnsw-candidate-node-log-sentinel"],
                "candidateNodes": ["qdrant-sec-private-hnsw-camel-candidate-node-log-sentinel"],
                "client_signature": "qdrant-sec-private-hnsw-client-signature-log-sentinel",
                "clientSignature": "qdrant-sec-private-hnsw-camel-client-signature-log-sentinel",
                "commit_signature": "qdrant-sec-private-hnsw-commit-signature-log-sentinel",
                "commitSignature": "qdrant-sec-private-hnsw-camel-commit-signature-log-sentinel",
                "manifest_signature": "qdrant-sec-private-hnsw-manifest-signature-log-sentinel",
                "manifestSignature": "qdrant-sec-private-hnsw-camel-manifest-signature-log-sentinel",
                "top_k": ["qdrant-sec-private-hnsw-top-k-log-sentinel"],
                "topK": ["qdrant-sec-private-hnsw-camel-top-k-log-sentinel"],
                "result_ids": ["qdrant-sec-private-hnsw-result-id-log-sentinel"],
                "resultIds": ["qdrant-sec-private-hnsw-camel-result-id-log-sentinel"],
                "resultId": "qdrant-sec-private-hnsw-camel-single-result-id-log-sentinel",
                "point_token": "qdrant-sec-private-hnsw-point-token-log-sentinel",
                "pointTokens": ["qdrant-sec-private-hnsw-camel-point-tokens-log-sentinel"],
                "pointToken": "qdrant-sec-private-hnsw-camel-point-token-log-sentinel",
                "payload_fetch_token": "qdrant-sec-private-hnsw-payload-token-log-sentinel",
                "payloadFetchToken": "qdrant-sec-private-hnsw-camel-payload-token-log-sentinel"
            }
        });
        let mut private_result_oram = json!({
            "private_result_oram": {
                "client_id": "qdrant-sec-private-result-client-id-log-sentinel",
                "clientId": "qdrant-sec-private-result-camel-client-id-log-sentinel",
                "session_id": "qdrant-sec-private-result-session-id-log-sentinel",
                "sessionId": "qdrant-sec-private-result-camel-session-id-log-sentinel",
                "root_hash": "qdrant-sec-private-result-root-hash-log-sentinel",
                "rootHashes": ["qdrant-sec-private-result-camel-root-hash-log-sentinel"],
                "oldRootHash": "qdrant-sec-private-result-camel-old-root-hash-log-sentinel",
                "new_root_hash": "qdrant-sec-private-result-new-root-hash-log-sentinel",
                "bucket_ids": ["qdrant-sec-private-result-bucket-id-log-sentinel"],
                "bucketIds": ["qdrant-sec-private-result-camel-bucket-id-log-sentinel"],
                "bucket_commitments": ["qdrant-sec-private-result-bucket-commitment-log-sentinel"],
                "bucketCommitments": ["qdrant-sec-private-result-camel-bucket-commitment-log-sentinel"],
                "read_signature": "qdrant-sec-private-result-read-signature-log-sentinel",
                "readSignature": "qdrant-sec-private-result-camel-read-signature-log-sentinel",
                "commit_signature": "qdrant-sec-private-result-commit-signature-log-sentinel",
                "commitSignature": "qdrant-sec-private-result-camel-commit-signature-log-sentinel",
                "requestSignature": "qdrant-sec-private-result-camel-request-signature-log-sentinel",
                "updated_buckets": [{
                    "bucket_id": "qdrant-sec-private-result-updated-bucket-id-log-sentinel",
                    "bucket_commitment": "qdrant-sec-private-result-updated-bucket-commitment-log-sentinel"
                }],
                "updated_bucket": {
                    "bucket_id": "qdrant-sec-private-result-updated-single-bucket-id-log-sentinel",
                    "bucket_commitment": "qdrant-sec-private-result-updated-single-bucket-commitment-log-sentinel"
                },
                "updatedBuckets": [{
                    "bucketId": "qdrant-sec-private-result-camel-updated-bucket-id-log-sentinel",
                    "bucketCommitment": "qdrant-sec-private-result-camel-updated-bucket-commitment-log-sentinel"
                }],
                "proofs": [{
                    "leaf_hash": "qdrant-sec-private-result-proof-leaf-hash-log-sentinel",
                    "siblings": [{
                        "hash": "qdrant-sec-private-result-proof-sibling-hash-log-sentinel"
                    }]
                }],
                "merkleProof": {
                    "leafHash": "qdrant-sec-private-result-camel-proof-leaf-hash-log-sentinel",
                    "siblingHash": "qdrant-sec-private-result-camel-proof-sibling-hash-log-sentinel"
                },
                "payload_fetch_tokens": ["qdrant-sec-private-result-payload-token-log-sentinel"],
                "payloadFetchToken": "qdrant-sec-private-result-camel-payload-token-log-sentinel",
                "fetch_tokens": ["qdrant-sec-private-result-fetch-token-log-sentinel"],
                "fetchToken": "qdrant-sec-private-result-camel-fetch-token-log-sentinel",
                "token_position_map": "qdrant-sec-private-result-token-position-map-log-sentinel",
                "tokenPositionMap": "qdrant-sec-private-result-camel-token-position-map-log-sentinel",
                "payload_oram_leaf": "qdrant-sec-private-result-payload-oram-leaf-log-sentinel",
                "payloadOramLeaves": ["qdrant-sec-private-result-camel-payload-oram-leaf-log-sentinel"],
                "result_ids": ["qdrant-sec-private-result-id-log-sentinel"],
                "client_state": {
                    "stash": "qdrant-sec-private-result-stash-log-sentinel"
                }
            }
        });
        for (key, field_value) in [
            (
                "owner_signing_key_id",
                json!("qdrant-sec-private-hnsw-owner-signing-key-id-log-sentinel"),
            ),
            (
                "ownerSigningKeyId",
                json!("qdrant-sec-private-hnsw-camel-owner-signing-key-id-log-sentinel"),
            ),
            (
                "signing_key_id",
                json!("qdrant-sec-private-hnsw-signing-key-id-log-sentinel"),
            ),
            (
                "signingKeyId",
                json!("qdrant-sec-private-hnsw-camel-signing-key-id-log-sentinel"),
            ),
            (
                "bucket_plaintext",
                json!("qdrant-sec-private-oram-bucket-plaintext-log-sentinel"),
            ),
            (
                "bucketPlaintext",
                json!("qdrant-sec-private-oram-camel-bucket-plaintext-log-sentinel"),
            ),
            (
                "plaintext_bucket",
                json!("qdrant-sec-private-oram-plaintext-bucket-log-sentinel"),
            ),
            (
                "plaintextBucket",
                json!("qdrant-sec-private-oram-camel-plaintext-bucket-log-sentinel"),
            ),
            (
                "bucket_sequence",
                json!(["qdrant-sec-private-oram-bucket-sequence-log-sentinel"]),
            ),
            (
                "bucketSequences",
                json!(["qdrant-sec-private-oram-camel-bucket-sequence-log-sentinel"]),
            ),
            (
                "updated_bucket_id",
                json!("qdrant-sec-private-oram-updated-bucket-id-flat-log-sentinel"),
            ),
            (
                "updatedBucketId",
                json!("qdrant-sec-private-oram-camel-updated-bucket-id-flat-log-sentinel"),
            ),
            (
                "updated_bucket_commitment",
                json!("qdrant-sec-private-oram-updated-bucket-commitment-flat-log-sentinel"),
            ),
            (
                "updatedBucketCommitment",
                json!("qdrant-sec-private-oram-camel-updated-bucket-commitment-flat-log-sentinel"),
            ),
        ] {
            insert_test_json_field(
                &mut private_hnsw_oram_access,
                &["private_hnsw"],
                key,
                field_value,
            );
        }
        for (key, field_value) in [
            (
                "node_block",
                json!("qdrant-sec-private-hnsw-node-block-log-sentinel"),
            ),
            (
                "nodeBlock",
                json!("qdrant-sec-private-hnsw-camel-node-block-log-sentinel"),
            ),
            (
                "node_plaintext",
                json!("qdrant-sec-private-hnsw-node-plaintext-log-sentinel"),
            ),
            (
                "nodePlaintext",
                json!("qdrant-sec-private-hnsw-camel-node-plaintext-log-sentinel"),
            ),
            (
                "block_plaintext",
                json!("qdrant-sec-private-hnsw-block-plaintext-log-sentinel"),
            ),
            (
                "blockPlaintext",
                json!("qdrant-sec-private-hnsw-camel-block-plaintext-log-sentinel"),
            ),
            (
                "plaintext_block",
                json!("qdrant-sec-private-hnsw-plaintext-block-log-sentinel"),
            ),
            (
                "plaintextBlock",
                json!("qdrant-sec-private-hnsw-camel-plaintext-block-log-sentinel"),
            ),
            (
                "vector_bytes",
                json!("qdrant-sec-private-hnsw-vector-bytes-log-sentinel"),
            ),
            (
                "vectorBytes",
                json!("qdrant-sec-private-hnsw-camel-vector-bytes-log-sentinel"),
            ),
            (
                "vector_plaintext",
                json!("qdrant-sec-private-hnsw-vector-plaintext-log-sentinel"),
            ),
            (
                "vectorPlaintext",
                json!("qdrant-sec-private-hnsw-camel-vector-plaintext-log-sentinel"),
            ),
            (
                "plaintext_vector",
                json!("qdrant-sec-private-hnsw-plaintext-vector-log-sentinel"),
            ),
            (
                "plaintextVector",
                json!("qdrant-sec-private-hnsw-camel-plaintext-vector-log-sentinel"),
            ),
        ] {
            insert_test_json_field(&mut private_hnsw_graph, &["private_hnsw"], key, field_value);
        }
        for (key, field_value) in [
            (
                "position_map_snapshot",
                json!("qdrant-sec-private-hnsw-position-map-snapshot-log-sentinel"),
            ),
            (
                "position_map_backup",
                json!("qdrant-sec-private-hnsw-position-map-backup-log-sentinel"),
            ),
            (
                "oramPositionMapSnapshot",
                json!("qdrant-sec-private-hnsw-camel-oram-position-map-snapshot-log-sentinel"),
            ),
            (
                "oramPositionMapBackup",
                json!("qdrant-sec-private-hnsw-camel-oram-position-map-backup-log-sentinel"),
            ),
            (
                "oramPositionMapBackups",
                json!(["qdrant-sec-private-hnsw-camel-oram-position-map-backups-log-sentinel"]),
            ),
            (
                "positionMapBackups",
                json!(["qdrant-sec-private-hnsw-camel-position-map-backups-log-sentinel"]),
            ),
            (
                "stashBackup",
                json!("qdrant-sec-private-hnsw-camel-stash-backup-log-sentinel"),
            ),
            (
                "stashBackups",
                json!(["qdrant-sec-private-hnsw-camel-stash-backups-log-sentinel"]),
            ),
        ] {
            insert_test_json_field(
                &mut private_hnsw_oram_access,
                &["private_hnsw", "client_state"],
                key,
                field_value,
            );
        }
        for (key, field_value) in [
            (
                "client_state_snapshot",
                json!("qdrant-sec-private-hnsw-client-state-snapshot-log-sentinel"),
            ),
            (
                "client_state_backup",
                json!("qdrant-sec-private-hnsw-client-state-backup-log-sentinel"),
            ),
            (
                "clientStateSnapshot",
                json!("qdrant-sec-private-hnsw-camel-client-state-snapshot-log-sentinel"),
            ),
            (
                "clientStateBackup",
                json!("qdrant-sec-private-hnsw-camel-client-state-backup-log-sentinel"),
            ),
            (
                "clientStateBackups",
                json!(["qdrant-sec-private-hnsw-camel-client-state-backups-log-sentinel"]),
            ),
            (
                "encrypted_client_state",
                json!("qdrant-sec-private-hnsw-encrypted-client-state-log-sentinel"),
            ),
            (
                "encryptedClientState",
                json!("qdrant-sec-private-hnsw-camel-encrypted-client-state-log-sentinel"),
            ),
            (
                "encrypted_client_state_snapshot",
                json!("qdrant-sec-private-hnsw-encrypted-client-state-snapshot-log-sentinel"),
            ),
            (
                "encrypted_client_state_backup",
                json!("qdrant-sec-private-hnsw-encrypted-client-state-backup-log-sentinel"),
            ),
            (
                "encryptedClientStateSnapshot",
                json!("qdrant-sec-private-hnsw-camel-encrypted-client-state-snapshot-log-sentinel"),
            ),
            (
                "encryptedClientStateBackup",
                json!("qdrant-sec-private-hnsw-camel-encrypted-client-state-backup-log-sentinel"),
            ),
            (
                "encryptedClientStateBackups",
                json!([
                    "qdrant-sec-private-hnsw-camel-encrypted-client-state-backups-log-sentinel"
                ]),
            ),
            (
                "stashSnapshot",
                json!("qdrant-sec-private-hnsw-camel-stash-snapshot-log-sentinel"),
            ),
            (
                "read_bucket_id",
                json!("qdrant-sec-private-oram-single-read-bucket-log-sentinel"),
            ),
            (
                "readBucketId",
                json!("qdrant-sec-private-oram-camel-single-read-bucket-log-sentinel"),
            ),
            (
                "read_bucket_ids",
                json!(["qdrant-sec-private-oram-read-bucket-id-log-sentinel"]),
            ),
            (
                "readBucketIds",
                json!(["qdrant-sec-private-oram-camel-read-bucket-id-log-sentinel"]),
            ),
            (
                "bucket_id_sequence",
                json!(["qdrant-sec-private-oram-bucket-id-sequence-log-sentinel"]),
            ),
            (
                "bucketIdSequence",
                json!(["qdrant-sec-private-oram-camel-bucket-id-sequence-log-sentinel"]),
            ),
            (
                "bucket_id_sequences",
                json!(["qdrant-sec-private-oram-bucket-sequences-log-sentinel"]),
            ),
            (
                "bucketIdSequences",
                json!(["qdrant-sec-private-oram-camel-bucket-sequences-log-sentinel"]),
            ),
            (
                "leaf_commitment",
                json!("qdrant-sec-private-oram-single-leaf-commitment-log-sentinel"),
            ),
            (
                "leafCommitment",
                json!("qdrant-sec-private-oram-camel-single-leaf-commitment-log-sentinel"),
            ),
            (
                "leaf_commitments",
                json!(["qdrant-sec-private-oram-leaf-commitment-log-sentinel"]),
            ),
            (
                "leafCommitments",
                json!(["qdrant-sec-private-oram-camel-leaf-commitment-log-sentinel"]),
            ),
        ] {
            insert_test_json_field(
                &mut private_hnsw_oram_access,
                &["private_hnsw"],
                key,
                field_value,
            );
        }
        for (key, field_value) in [
            (
                "owner_signing_key_id",
                json!("qdrant-sec-private-result-owner-signing-key-id-log-sentinel"),
            ),
            (
                "ownerSigningKeyId",
                json!("qdrant-sec-private-result-camel-owner-signing-key-id-log-sentinel"),
            ),
            (
                "signing_key_id",
                json!("qdrant-sec-private-result-signing-key-id-log-sentinel"),
            ),
            (
                "signingKeyId",
                json!("qdrant-sec-private-result-camel-signing-key-id-log-sentinel"),
            ),
            (
                "payload_bytes",
                json!("qdrant-sec-private-result-payload-bytes-log-sentinel"),
            ),
            (
                "payloadBytes",
                json!("qdrant-sec-private-result-camel-payload-bytes-log-sentinel"),
            ),
            (
                "payload_plaintext",
                json!("qdrant-sec-private-result-payload-plaintext-log-sentinel"),
            ),
            (
                "payloadPlaintext",
                json!("qdrant-sec-private-result-camel-payload-plaintext-log-sentinel"),
            ),
            (
                "plaintext_payload",
                json!("qdrant-sec-private-result-plaintext-payload-log-sentinel"),
            ),
            (
                "plaintextPayload",
                json!("qdrant-sec-private-result-camel-plaintext-payload-log-sentinel"),
            ),
            (
                "token_position_map_snapshot",
                json!("qdrant-sec-private-result-token-position-map-snapshot-log-sentinel"),
            ),
            (
                "token_position_map_backup",
                json!("qdrant-sec-private-result-token-position-map-backup-log-sentinel"),
            ),
            (
                "tokenPositionMapSnapshot",
                json!("qdrant-sec-private-result-camel-token-position-map-snapshot-log-sentinel"),
            ),
            (
                "tokenPositionMapBackup",
                json!("qdrant-sec-private-result-camel-token-position-map-backup-log-sentinel"),
            ),
            (
                "tokenPositionMapBackups",
                json!(["qdrant-sec-private-result-camel-token-position-map-backups-log-sentinel"]),
            ),
            (
                "clientStateBackups",
                json!(["qdrant-sec-private-result-camel-client-state-backups-log-sentinel"]),
            ),
            (
                "clientStateSnapshots",
                json!(["qdrant-sec-private-result-camel-client-state-snapshots-log-sentinel"]),
            ),
            (
                "encryptedClientStateBackups",
                json!([
                    "qdrant-sec-private-result-camel-encrypted-client-state-backups-log-sentinel"
                ]),
            ),
            (
                "encryptedClientStates",
                json!(["qdrant-sec-private-result-camel-encrypted-client-states-log-sentinel"]),
            ),
            (
                "encryptedClientStateSnapshots",
                json!([
                    "qdrant-sec-private-result-camel-encrypted-client-state-snapshots-log-sentinel"
                ]),
            ),
            (
                "stash_snapshots",
                json!(["qdrant-sec-private-result-stash-snapshots-log-sentinel"]),
            ),
            (
                "stash_backups",
                json!(["qdrant-sec-private-result-stash-backups-log-sentinel"]),
            ),
            (
                "stashBackups",
                json!(["qdrant-sec-private-result-camel-stash-backups-log-sentinel"]),
            ),
            (
                "read_bucket_id",
                json!("qdrant-sec-private-result-single-read-bucket-log-sentinel"),
            ),
            (
                "readBucketId",
                json!("qdrant-sec-private-result-camel-single-read-bucket-log-sentinel"),
            ),
            (
                "read_bucket_ids",
                json!(["qdrant-sec-private-result-read-bucket-id-log-sentinel"]),
            ),
            (
                "readBucketIds",
                json!(["qdrant-sec-private-result-camel-read-bucket-id-log-sentinel"]),
            ),
            (
                "read_bucket_id_sequence",
                json!(["qdrant-sec-private-result-read-bucket-id-sequence-log-sentinel"]),
            ),
            (
                "readBucketIdSequence",
                json!(["qdrant-sec-private-result-camel-read-bucket-id-sequence-log-sentinel"]),
            ),
            (
                "read_bucket_sequence",
                json!(["qdrant-sec-private-result-read-bucket-sequence-log-sentinel"]),
            ),
            (
                "readBucketSequence",
                json!(["qdrant-sec-private-result-camel-read-bucket-sequence-log-sentinel"]),
            ),
            (
                "read_bucket_sequences",
                json!(["qdrant-sec-private-result-read-bucket-sequences-log-sentinel"]),
            ),
            (
                "bucket_id_sequence",
                json!(["qdrant-sec-private-result-bucket-id-sequence-log-sentinel"]),
            ),
            (
                "bucketIdSequence",
                json!(["qdrant-sec-private-result-camel-bucket-id-sequence-log-sentinel"]),
            ),
            (
                "bucket_id_sequences",
                json!(["qdrant-sec-private-result-bucket-sequences-log-sentinel"]),
            ),
            (
                "bucketIdSequences",
                json!(["qdrant-sec-private-result-camel-bucket-sequences-log-sentinel"]),
            ),
            (
                "bucket_sequence",
                json!(["qdrant-sec-private-result-short-bucket-sequence-log-sentinel"]),
            ),
            (
                "bucketSequence",
                json!(["qdrant-sec-private-result-camel-short-bucket-sequence-log-sentinel"]),
            ),
            (
                "bucket_sequences",
                json!(["qdrant-sec-private-result-short-bucket-sequences-log-sentinel"]),
            ),
            (
                "leaf_commitment",
                json!("qdrant-sec-private-result-leaf-commitment-log-sentinel"),
            ),
            (
                "leafCommitment",
                json!("qdrant-sec-private-result-camel-leaf-commitment-log-sentinel"),
            ),
            (
                "leaf_commitments",
                json!(["qdrant-sec-private-result-leaf-commitments-log-sentinel"]),
            ),
            (
                "leafCommitments",
                json!(["qdrant-sec-private-result-camel-leaf-commitments-log-sentinel"]),
            ),
        ] {
            insert_test_json_field(
                &mut private_result_oram,
                &["private_result_oram"],
                key,
                field_value,
            );
        }
        for (key, field_value) in [
            (
                "path_count",
                json!("qdrant-sec-private-oram-count-log-sentinel-path-count"),
            ),
            (
                "pathCount",
                json!("qdrant-sec-private-oram-count-log-sentinel-camel-path-count"),
            ),
            (
                "pathCounts",
                json!(["qdrant-sec-private-oram-count-log-sentinel-camel-path-counts"]),
            ),
            (
                "requested_paths",
                json!("qdrant-sec-private-oram-count-log-sentinel-requested-paths"),
            ),
            (
                "bucketIdCounts",
                json!(["qdrant-sec-private-oram-count-log-sentinel-bucket-id-counts"]),
            ),
            (
                "readBucketIdCounts",
                json!(["qdrant-sec-private-oram-count-log-sentinel-read-bucket-id-counts"]),
            ),
            (
                "requestedPathCounts",
                json!(["qdrant-sec-private-oram-count-log-sentinel-requested-path-counts"]),
            ),
            (
                "requestedBucketCounts",
                json!(["qdrant-sec-private-oram-count-log-sentinel-requested-bucket-counts"]),
            ),
            (
                "dummyPathsIncluded",
                json!("qdrant-sec-private-oram-count-log-sentinel-dummy-paths-included"),
            ),
            (
                "returned_bucket_count",
                json!("qdrant-sec-private-oram-count-log-sentinel-returned-bucket-count"),
            ),
            (
                "returnedBucketCounts",
                json!(["qdrant-sec-private-oram-count-log-sentinel-returned-bucket-counts"]),
            ),
            (
                "updatedBucketCount",
                json!("qdrant-sec-private-oram-count-log-sentinel-updated-bucket-count"),
            ),
            (
                "updatedBucketCounts",
                json!(["qdrant-sec-private-oram-count-log-sentinel-updated-bucket-counts"]),
            ),
            (
                "writeback_bucket_count",
                json!("qdrant-sec-private-oram-count-log-sentinel-writeback-bucket-count"),
            ),
            (
                "writebackBucketCounts",
                json!(["qdrant-sec-private-oram-count-log-sentinel-writeback-bucket-counts"]),
            ),
            (
                "leafCount",
                json!("qdrant-sec-private-oram-count-log-sentinel-leaf-count"),
            ),
            (
                "sibling_count",
                json!("qdrant-sec-private-oram-count-log-sentinel-sibling-count"),
            ),
            (
                "position_map_len",
                json!("qdrant-sec-private-oram-count-log-sentinel-position-map-len"),
            ),
            (
                "stashLen",
                json!("qdrant-sec-private-oram-count-log-sentinel-stash-len"),
            ),
        ] {
            insert_test_json_field(
                &mut private_hnsw_oram_access,
                &["private_hnsw"],
                key,
                field_value,
            );
        }
        for (key, field_value) in [
            (
                "bucket_id_count",
                json!("qdrant-sec-private-oram-count-log-sentinel-bucket-id-count"),
            ),
            (
                "requestedBucketCount",
                json!("qdrant-sec-private-oram-count-log-sentinel-requested-bucket-count"),
            ),
            (
                "access_count",
                json!("qdrant-sec-private-oram-count-log-sentinel-access-count"),
            ),
            (
                "tokenCount",
                json!("qdrant-sec-private-oram-count-log-sentinel-token-count"),
            ),
            (
                "payload_len",
                json!("qdrant-sec-private-oram-count-log-sentinel-payload-len"),
            ),
            (
                "resultCount",
                json!("qdrant-sec-private-oram-count-log-sentinel-result-count"),
            ),
            (
                "real_path_count",
                json!("qdrant-sec-private-oram-count-log-sentinel-real-path-count"),
            ),
        ] {
            insert_test_json_field(
                &mut private_result_oram,
                &["private_result_oram"],
                key,
                field_value,
            );
        }

        redact_sensitive_log_fields(&mut private_hnsw_oram_access);
        redact_sensitive_log_fields(&mut private_hnsw_graph);
        redact_sensitive_log_fields(&mut private_result_oram);
        let serialized = format!(
            "{}{}{}",
            serde_json::to_string(&private_hnsw_oram_access).unwrap(),
            serde_json::to_string(&private_hnsw_graph).unwrap(),
            serde_json::to_string(&private_result_oram).unwrap()
        );

        for sentinel in [
            "qdrant-sec-private-hnsw-client-id-log-sentinel",
            "qdrant-sec-private-hnsw-session-id-log-sentinel",
            "qdrant-sec-private-oram-count-log-sentinel",
            "qdrant-sec-private-hnsw-owner-signing-key-id-log-sentinel",
            "qdrant-sec-private-hnsw-camel-owner-signing-key-id-log-sentinel",
            "qdrant-sec-private-hnsw-signing-key-id-log-sentinel",
            "qdrant-sec-private-hnsw-camel-signing-key-id-log-sentinel",
            "qdrant-sec-private-hnsw-path-log-sentinel",
            "qdrant-sec-private-hnsw-access-path-log-sentinel",
            "qdrant-sec-private-hnsw-camel-access-path-log-sentinel",
            "qdrant-sec-private-hnsw-root-hash-log-sentinel",
            "qdrant-sec-private-hnsw-camel-root-hash-log-sentinel",
            "qdrant-sec-private-hnsw-old-root-hash-log-sentinel",
            "qdrant-sec-private-hnsw-old-root-hashes-log-sentinel",
            "qdrant-sec-private-hnsw-camel-new-root-hash-log-sentinel",
            "qdrant-sec-private-hnsw-camel-new-root-hashes-log-sentinel",
            "qdrant-sec-private-oram-bucket-id-log-sentinel",
            "qdrant-sec-private-oram-camel-bucket-id-log-sentinel",
            "qdrant-sec-private-oram-camel-single-bucket-id-log-sentinel",
            "qdrant-sec-private-oram-bucket-plaintext-log-sentinel",
            "qdrant-sec-private-oram-camel-bucket-plaintext-log-sentinel",
            "qdrant-sec-private-oram-plaintext-bucket-log-sentinel",
            "qdrant-sec-private-oram-camel-plaintext-bucket-log-sentinel",
            "qdrant-sec-private-oram-bucket-sequence-log-sentinel",
            "qdrant-sec-private-oram-camel-bucket-sequence-log-sentinel",
            "qdrant-sec-private-oram-single-read-bucket-log-sentinel",
            "qdrant-sec-private-oram-camel-single-read-bucket-log-sentinel",
            "qdrant-sec-private-oram-read-bucket-id-log-sentinel",
            "qdrant-sec-private-oram-camel-read-bucket-id-log-sentinel",
            "qdrant-sec-private-oram-bucket-id-sequence-log-sentinel",
            "qdrant-sec-private-oram-camel-bucket-id-sequence-log-sentinel",
            "qdrant-sec-private-oram-bucket-sequences-log-sentinel",
            "qdrant-sec-private-oram-camel-bucket-sequences-log-sentinel",
            "qdrant-sec-private-oram-bucket-commitment-log-sentinel",
            "qdrant-sec-private-oram-bucket-commitments-log-sentinel",
            "qdrant-sec-private-oram-camel-bucket-commitment-log-sentinel",
            "qdrant-sec-private-oram-camel-single-bucket-commitment-log-sentinel",
            "qdrant-sec-private-oram-single-leaf-commitment-log-sentinel",
            "qdrant-sec-private-oram-camel-single-leaf-commitment-log-sentinel",
            "qdrant-sec-private-oram-leaf-commitment-log-sentinel",
            "qdrant-sec-private-oram-camel-leaf-commitment-log-sentinel",
            "qdrant-sec-private-oram-nested-bucket-id-log-sentinel",
            "qdrant-sec-private-oram-nested-bucket-commitment-log-sentinel",
            "qdrant-sec-private-oram-updated-single-bucket-id-log-sentinel",
            "qdrant-sec-private-oram-updated-single-bucket-commitment-log-sentinel",
            "qdrant-sec-private-oram-camel-updated-bucket-log-sentinel",
            "qdrant-sec-private-oram-updated-bucket-id-flat-log-sentinel",
            "qdrant-sec-private-oram-camel-updated-bucket-id-flat-log-sentinel",
            "qdrant-sec-private-oram-updated-bucket-commitment-flat-log-sentinel",
            "qdrant-sec-private-oram-camel-updated-bucket-commitment-flat-log-sentinel",
            "qdrant-sec-private-oram-camel-updated-single-bucket-id-log-sentinel",
            "qdrant-sec-private-oram-camel-updated-single-bucket-commitment-log-sentinel",
            "qdrant-sec-private-oram-proof-bucket-id-log-sentinel",
            "qdrant-sec-private-oram-proof-leaf-hash-log-sentinel",
            "qdrant-sec-private-oram-proof-sibling-hash-log-sentinel",
            "qdrant-sec-private-oram-camel-proof-leaf-hash-log-sentinel",
            "qdrant-sec-private-oram-camel-proof-sibling-log-sentinel",
            "qdrant-sec-private-hnsw-path-label-log-sentinel",
            "qdrant-sec-private-hnsw-camel-single-path-label-log-sentinel",
            "qdrant-sec-private-hnsw-camel-path-label-log-sentinel",
            "qdrant-sec-private-hnsw-camel-read-path-label-log-sentinel",
            "qdrant-sec-private-hnsw-leaf-label-log-sentinel",
            "qdrant-sec-private-hnsw-camel-single-leaf-label-log-sentinel",
            "qdrant-sec-private-hnsw-camel-leaf-label-log-sentinel",
            "qdrant-sec-private-hnsw-accessed-leaf-label-log-sentinel",
            "qdrant-sec-private-hnsw-camel-accessed-leaf-label-log-sentinel",
            "qdrant-sec-private-hnsw-oram-path-log-sentinel",
            "qdrant-sec-private-hnsw-camel-oram-path-log-sentinel",
            "qdrant-sec-private-hnsw-position-map-log-sentinel",
            "qdrant-sec-private-hnsw-position-map-snapshot-log-sentinel",
            "qdrant-sec-private-hnsw-position-map-backup-log-sentinel",
            "qdrant-sec-private-hnsw-oram-position-map-log-sentinel",
            "qdrant-sec-private-hnsw-camel-oram-position-map-snapshot-log-sentinel",
            "qdrant-sec-private-hnsw-camel-oram-position-map-backup-log-sentinel",
            "qdrant-sec-private-hnsw-camel-oram-position-map-backups-log-sentinel",
            "qdrant-sec-private-hnsw-camel-position-map-backups-log-sentinel",
            "qdrant-sec-private-hnsw-stash-log-sentinel",
            "qdrant-sec-private-hnsw-camel-stash-backup-log-sentinel",
            "qdrant-sec-private-hnsw-camel-stash-backups-log-sentinel",
            "qdrant-sec-private-hnsw-camel-client-state-log-sentinel",
            "qdrant-sec-private-hnsw-client-state-snapshot-log-sentinel",
            "qdrant-sec-private-hnsw-client-state-backup-log-sentinel",
            "qdrant-sec-private-hnsw-camel-client-state-snapshot-log-sentinel",
            "qdrant-sec-private-hnsw-camel-client-state-backup-log-sentinel",
            "qdrant-sec-private-hnsw-camel-client-state-backups-log-sentinel",
            "qdrant-sec-private-hnsw-encrypted-client-state-log-sentinel",
            "qdrant-sec-private-hnsw-camel-encrypted-client-state-log-sentinel",
            "qdrant-sec-private-hnsw-encrypted-client-state-snapshot-log-sentinel",
            "qdrant-sec-private-hnsw-encrypted-client-state-backup-log-sentinel",
            "qdrant-sec-private-hnsw-camel-encrypted-client-state-snapshot-log-sentinel",
            "qdrant-sec-private-hnsw-camel-encrypted-client-state-backup-log-sentinel",
            "qdrant-sec-private-hnsw-camel-encrypted-client-state-backups-log-sentinel",
            "qdrant-sec-private-hnsw-camel-stash-snapshot-log-sentinel",
            "qdrant-sec-private-hnsw-node-id-log-sentinel",
            "qdrant-sec-private-hnsw-camel-single-node-id-log-sentinel",
            "qdrant-sec-private-hnsw-camel-node-id-log-sentinel",
            "qdrant-sec-private-hnsw-node-block-log-sentinel",
            "qdrant-sec-private-hnsw-camel-node-block-log-sentinel",
            "qdrant-sec-private-hnsw-node-plaintext-log-sentinel",
            "qdrant-sec-private-hnsw-camel-node-plaintext-log-sentinel",
            "qdrant-sec-private-hnsw-block-plaintext-log-sentinel",
            "qdrant-sec-private-hnsw-camel-block-plaintext-log-sentinel",
            "qdrant-sec-private-hnsw-plaintext-block-log-sentinel",
            "qdrant-sec-private-hnsw-camel-plaintext-block-log-sentinel",
            "qdrant-sec-private-hnsw-vector-bytes-log-sentinel",
            "qdrant-sec-private-hnsw-camel-vector-bytes-log-sentinel",
            "qdrant-sec-private-hnsw-vector-plaintext-log-sentinel",
            "qdrant-sec-private-hnsw-camel-vector-plaintext-log-sentinel",
            "qdrant-sec-private-hnsw-plaintext-vector-log-sentinel",
            "qdrant-sec-private-hnsw-camel-plaintext-vector-log-sentinel",
            "qdrant-sec-private-hnsw-entry-node-id-log-sentinel",
            "qdrant-sec-private-hnsw-camel-entry-node-id-log-sentinel",
            "qdrant-sec-private-hnsw-level-mask-log-sentinel",
            "qdrant-sec-private-hnsw-camel-level-mask-log-sentinel",
            "qdrant-sec-private-hnsw-visited-node-log-sentinel",
            "qdrant-sec-private-hnsw-camel-visited-node-id-log-sentinel",
            "qdrant-sec-private-hnsw-neighbor-log-sentinel",
            "qdrant-sec-private-hnsw-neighbor-id-log-sentinel",
            "qdrant-sec-private-hnsw-camel-single-neighbor-id-log-sentinel",
            "qdrant-sec-private-hnsw-camel-neighbor-id-log-sentinel",
            "qdrant-sec-private-hnsw-neighbor-level-log-sentinel",
            "qdrant-sec-private-hnsw-camel-neighbor-level-log-sentinel",
            "qdrant-sec-private-hnsw-candidate-heap-log-sentinel",
            "qdrant-sec-private-hnsw-camel-candidate-heap-log-sentinel",
            "qdrant-sec-private-hnsw-candidate-node-log-sentinel",
            "qdrant-sec-private-hnsw-camel-candidate-node-log-sentinel",
            "qdrant-sec-private-hnsw-client-signature-log-sentinel",
            "qdrant-sec-private-hnsw-camel-client-signature-log-sentinel",
            "qdrant-sec-private-hnsw-commit-signature-log-sentinel",
            "qdrant-sec-private-hnsw-camel-commit-signature-log-sentinel",
            "qdrant-sec-private-hnsw-manifest-signature-log-sentinel",
            "qdrant-sec-private-hnsw-camel-manifest-signature-log-sentinel",
            "qdrant-sec-private-hnsw-top-k-log-sentinel",
            "qdrant-sec-private-hnsw-camel-top-k-log-sentinel",
            "qdrant-sec-private-hnsw-result-id-log-sentinel",
            "qdrant-sec-private-hnsw-camel-result-id-log-sentinel",
            "qdrant-sec-private-hnsw-camel-single-result-id-log-sentinel",
            "qdrant-sec-private-hnsw-point-token-log-sentinel",
            "qdrant-sec-private-hnsw-camel-point-tokens-log-sentinel",
            "qdrant-sec-private-hnsw-camel-point-token-log-sentinel",
            "qdrant-sec-private-hnsw-payload-token-log-sentinel",
            "qdrant-sec-private-hnsw-camel-payload-token-log-sentinel",
            "qdrant-sec-private-oram-unknown-field-log-sentinel",
            "qdrant-sec-private-oram-camel-unknown-field-log-sentinel",
            "qdrant-sec-private-result-client-id-log-sentinel",
            "qdrant-sec-private-result-camel-client-id-log-sentinel",
            "qdrant-sec-private-result-session-id-log-sentinel",
            "qdrant-sec-private-result-camel-session-id-log-sentinel",
            "qdrant-sec-private-result-owner-signing-key-id-log-sentinel",
            "qdrant-sec-private-result-camel-owner-signing-key-id-log-sentinel",
            "qdrant-sec-private-result-signing-key-id-log-sentinel",
            "qdrant-sec-private-result-camel-signing-key-id-log-sentinel",
            "qdrant-sec-private-result-root-hash-log-sentinel",
            "qdrant-sec-private-result-camel-root-hash-log-sentinel",
            "qdrant-sec-private-result-camel-old-root-hash-log-sentinel",
            "qdrant-sec-private-result-new-root-hash-log-sentinel",
            "qdrant-sec-private-result-bucket-id-log-sentinel",
            "qdrant-sec-private-result-camel-bucket-id-log-sentinel",
            "qdrant-sec-private-result-single-read-bucket-log-sentinel",
            "qdrant-sec-private-result-camel-single-read-bucket-log-sentinel",
            "qdrant-sec-private-result-read-bucket-id-log-sentinel",
            "qdrant-sec-private-result-camel-read-bucket-id-log-sentinel",
            "qdrant-sec-private-result-read-bucket-id-sequence-log-sentinel",
            "qdrant-sec-private-result-camel-read-bucket-id-sequence-log-sentinel",
            "qdrant-sec-private-result-read-bucket-sequence-log-sentinel",
            "qdrant-sec-private-result-camel-read-bucket-sequence-log-sentinel",
            "qdrant-sec-private-result-read-bucket-sequences-log-sentinel",
            "qdrant-sec-private-result-bucket-id-sequence-log-sentinel",
            "qdrant-sec-private-result-camel-bucket-id-sequence-log-sentinel",
            "qdrant-sec-private-result-bucket-sequences-log-sentinel",
            "qdrant-sec-private-result-camel-bucket-sequences-log-sentinel",
            "qdrant-sec-private-result-short-bucket-sequence-log-sentinel",
            "qdrant-sec-private-result-camel-short-bucket-sequence-log-sentinel",
            "qdrant-sec-private-result-short-bucket-sequences-log-sentinel",
            "qdrant-sec-private-result-bucket-commitment-log-sentinel",
            "qdrant-sec-private-result-camel-bucket-commitment-log-sentinel",
            "qdrant-sec-private-result-leaf-commitment-log-sentinel",
            "qdrant-sec-private-result-camel-leaf-commitment-log-sentinel",
            "qdrant-sec-private-result-leaf-commitments-log-sentinel",
            "qdrant-sec-private-result-camel-leaf-commitments-log-sentinel",
            "qdrant-sec-private-result-read-signature-log-sentinel",
            "qdrant-sec-private-result-camel-read-signature-log-sentinel",
            "qdrant-sec-private-result-commit-signature-log-sentinel",
            "qdrant-sec-private-result-camel-commit-signature-log-sentinel",
            "qdrant-sec-private-result-camel-request-signature-log-sentinel",
            "qdrant-sec-private-result-updated-bucket-id-log-sentinel",
            "qdrant-sec-private-result-updated-bucket-commitment-log-sentinel",
            "qdrant-sec-private-result-updated-single-bucket-id-log-sentinel",
            "qdrant-sec-private-result-updated-single-bucket-commitment-log-sentinel",
            "qdrant-sec-private-result-camel-updated-bucket-id-log-sentinel",
            "qdrant-sec-private-result-camel-updated-bucket-commitment-log-sentinel",
            "qdrant-sec-private-result-proof-leaf-hash-log-sentinel",
            "qdrant-sec-private-result-proof-sibling-hash-log-sentinel",
            "qdrant-sec-private-result-camel-proof-leaf-hash-log-sentinel",
            "qdrant-sec-private-result-camel-proof-sibling-hash-log-sentinel",
            "qdrant-sec-private-result-payload-token-log-sentinel",
            "qdrant-sec-private-result-camel-payload-token-log-sentinel",
            "qdrant-sec-private-result-payload-bytes-log-sentinel",
            "qdrant-sec-private-result-camel-payload-bytes-log-sentinel",
            "qdrant-sec-private-result-payload-plaintext-log-sentinel",
            "qdrant-sec-private-result-camel-payload-plaintext-log-sentinel",
            "qdrant-sec-private-result-plaintext-payload-log-sentinel",
            "qdrant-sec-private-result-camel-plaintext-payload-log-sentinel",
            "qdrant-sec-private-result-fetch-token-log-sentinel",
            "qdrant-sec-private-result-camel-fetch-token-log-sentinel",
            "qdrant-sec-private-result-token-position-map-log-sentinel",
            "qdrant-sec-private-result-camel-token-position-map-log-sentinel",
            "qdrant-sec-private-result-token-position-map-snapshot-log-sentinel",
            "qdrant-sec-private-result-token-position-map-backup-log-sentinel",
            "qdrant-sec-private-result-camel-token-position-map-snapshot-log-sentinel",
            "qdrant-sec-private-result-camel-token-position-map-backup-log-sentinel",
            "qdrant-sec-private-result-camel-token-position-map-backups-log-sentinel",
            "qdrant-sec-private-result-payload-oram-leaf-log-sentinel",
            "qdrant-sec-private-result-camel-payload-oram-leaf-log-sentinel",
            "qdrant-sec-private-result-id-log-sentinel",
            "qdrant-sec-private-result-stash-log-sentinel",
            "qdrant-sec-private-result-camel-client-state-backups-log-sentinel",
            "qdrant-sec-private-result-camel-client-state-snapshots-log-sentinel",
            "qdrant-sec-private-result-camel-encrypted-client-state-backups-log-sentinel",
            "qdrant-sec-private-result-camel-encrypted-client-states-log-sentinel",
            "qdrant-sec-private-result-camel-encrypted-client-state-snapshots-log-sentinel",
            "qdrant-sec-private-result-stash-snapshots-log-sentinel",
            "qdrant-sec-private-result-stash-backups-log-sentinel",
            "qdrant-sec-private-result-camel-stash-backups-log-sentinel",
        ] {
            assert!(!serialized.contains(sentinel));
        }
        assert!(serialized.contains("[redacted]"));

        let mut read_paths_aliases = json!({
            "read_path": ["qdrant-sec-private-hnsw-single-read-path-log-sentinel"],
            "readPath": ["qdrant-sec-private-hnsw-camel-single-read-path-log-sentinel"],
            "read_paths": ["qdrant-sec-private-hnsw-read-path-log-sentinel"],
            "readPaths": ["qdrant-sec-private-hnsw-camel-read-path-log-sentinel"],
            "read_path_label": "qdrant-sec-private-hnsw-read-path-label-log-sentinel",
            "readPathLabel": "qdrant-sec-private-hnsw-camel-single-read-path-label-log-sentinel",
            "read_path_labels": ["qdrant-sec-private-hnsw-read-path-labels-log-sentinel"],
            "read_bucket": "qdrant-sec-private-result-read-bucket-log-sentinel",
            "read_bucket_id": "qdrant-sec-private-result-single-read-bucket-alias-log-sentinel",
            "read_bucket_ids": ["qdrant-sec-private-result-read-bucket-id-alias-log-sentinel"],
            "read_buckets": ["qdrant-sec-private-result-read-buckets-log-sentinel"],
            "readBucket": "qdrant-sec-private-result-camel-read-bucket-log-sentinel",
            "readBucketId": "qdrant-sec-private-result-camel-single-read-bucket-alias-log-sentinel",
            "readBucketIds": ["qdrant-sec-private-result-camel-read-bucket-id-alias-log-sentinel"],
            "readBuckets": ["qdrant-sec-private-result-camel-read-buckets-log-sentinel"],
            "read_bucket_sequence": ["qdrant-sec-private-result-read-bucket-sequence-alias-log-sentinel"],
            "readBucketSequence": ["qdrant-sec-private-result-camel-read-bucket-sequence-alias-log-sentinel"],
            "readBucketSequences": ["qdrant-sec-private-result-camel-read-bucket-sequences-alias-log-sentinel"],
            "bucket_sequence": ["qdrant-sec-private-result-short-bucket-sequence-alias-log-sentinel"],
            "bucketSequence": ["qdrant-sec-private-result-camel-short-bucket-sequence-alias-log-sentinel"],
            "bucketSequences": ["qdrant-sec-private-result-camel-short-bucket-sequences-alias-log-sentinel"],
            "bucket_id_sequences": ["qdrant-sec-private-result-bucket-sequences-alias-log-sentinel"],
            "bucketIdSequences": ["qdrant-sec-private-result-camel-bucket-sequences-alias-log-sentinel"],
            "leaf_commitment": "qdrant-sec-private-result-leaf-commitment-alias-log-sentinel",
            "leaf_commitments": ["qdrant-sec-private-result-leaf-commitments-alias-log-sentinel"],
            "leafCommitment": "qdrant-sec-private-result-camel-leaf-commitment-alias-log-sentinel",
            "leafCommitments": ["qdrant-sec-private-result-camel-leaf-commitments-alias-log-sentinel"],
        });
        redact_sensitive_log_fields(&mut read_paths_aliases);
        let read_paths_serialized = serde_json::to_string(&read_paths_aliases).unwrap();
        assert!(
            !read_paths_serialized
                .contains("qdrant-sec-private-hnsw-single-read-path-log-sentinel")
        );
        assert!(
            !read_paths_serialized
                .contains("qdrant-sec-private-hnsw-camel-single-read-path-log-sentinel")
        );
        assert!(!read_paths_serialized.contains("qdrant-sec-private-hnsw-read-path-log-sentinel"));
        assert!(
            !read_paths_serialized.contains("qdrant-sec-private-hnsw-camel-read-path-log-sentinel")
        );
        assert!(
            !read_paths_serialized.contains("qdrant-sec-private-hnsw-read-path-label-log-sentinel")
        );
        assert!(
            !read_paths_serialized
                .contains("qdrant-sec-private-hnsw-camel-single-read-path-label-log-sentinel")
        );
        assert!(
            !read_paths_serialized
                .contains("qdrant-sec-private-hnsw-read-path-labels-log-sentinel")
        );
        assert!(
            !read_paths_serialized.contains("qdrant-sec-private-result-read-bucket-log-sentinel")
        );
        assert!(
            !read_paths_serialized.contains("qdrant-sec-private-result-read-buckets-log-sentinel")
        );
        assert!(
            !read_paths_serialized
                .contains("qdrant-sec-private-result-camel-read-bucket-log-sentinel")
        );
        assert!(
            !read_paths_serialized
                .contains("qdrant-sec-private-result-camel-read-buckets-log-sentinel")
        );
        assert!(
            !read_paths_serialized
                .contains("qdrant-sec-private-result-read-bucket-id-alias-log-sentinel")
        );
        assert!(
            !read_paths_serialized
                .contains("qdrant-sec-private-result-single-read-bucket-alias-log-sentinel")
        );
        assert!(
            !read_paths_serialized
                .contains("qdrant-sec-private-result-camel-read-bucket-id-alias-log-sentinel")
        );
        assert!(
            !read_paths_serialized
                .contains("qdrant-sec-private-result-camel-single-read-bucket-alias-log-sentinel")
        );
        for leaked in [
            "qdrant-sec-private-result-read-bucket-sequence-alias-log-sentinel",
            "qdrant-sec-private-result-camel-read-bucket-sequence-alias-log-sentinel",
            "qdrant-sec-private-result-camel-read-bucket-sequences-alias-log-sentinel",
            "qdrant-sec-private-result-short-bucket-sequence-alias-log-sentinel",
            "qdrant-sec-private-result-camel-short-bucket-sequence-alias-log-sentinel",
            "qdrant-sec-private-result-camel-short-bucket-sequences-alias-log-sentinel",
        ] {
            assert!(!read_paths_serialized.contains(leaked));
        }
        assert!(
            !read_paths_serialized
                .contains("qdrant-sec-private-result-bucket-sequences-alias-log-sentinel")
        );
        assert!(
            !read_paths_serialized
                .contains("qdrant-sec-private-result-camel-bucket-sequences-alias-log-sentinel")
        );
        assert!(
            !read_paths_serialized
                .contains("qdrant-sec-private-result-leaf-commitment-alias-log-sentinel")
        );
        assert!(
            !read_paths_serialized
                .contains("qdrant-sec-private-result-leaf-commitments-alias-log-sentinel")
        );
        assert!(
            !read_paths_serialized
                .contains("qdrant-sec-private-result-camel-leaf-commitment-alias-log-sentinel")
        );
        assert!(
            !read_paths_serialized
                .contains("qdrant-sec-private-result-camel-leaf-commitments-alias-log-sentinel")
        );

        let mut position_map_aliases = json!({
            "position_map": "qdrant-sec-private-oram-position-map-alias-log-sentinel",
            "position_maps": ["qdrant-sec-private-oram-position-maps-alias-log-sentinel"],
            "positionMap": "qdrant-sec-private-oram-camel-position-map-alias-log-sentinel",
            "positionMaps": ["qdrant-sec-private-oram-camel-position-maps-alias-log-sentinel"],
            "client_state_ciphertext": "qdrant-sec-private-oram-client-state-ciphertext-alias-log-sentinel",
            "client_state_ciphertext_hash": "qdrant-sec-private-oram-client-state-ciphertext-hash-alias-log-sentinel",
            "client_state_ciphertext_hashes": ["qdrant-sec-private-oram-client-state-ciphertext-hashes-alias-log-sentinel"],
            "clientStateCiphertext": "qdrant-sec-private-oram-camel-client-state-ciphertext-alias-log-sentinel",
            "clientStateCiphertextHash": "qdrant-sec-private-oram-camel-client-state-ciphertext-hash-alias-log-sentinel",
            "clientStateCiphertextHashes": ["qdrant-sec-private-oram-camel-client-state-ciphertext-hashes-alias-log-sentinel"],
            "encrypted_client_state": "qdrant-sec-private-oram-encrypted-client-state-alias-log-sentinel",
            "encrypted_client_state_backup": "qdrant-sec-private-oram-encrypted-client-state-backup-alias-log-sentinel",
            "encrypted_client_state_snapshot": "qdrant-sec-private-oram-encrypted-client-state-snapshot-alias-log-sentinel",
            "encrypted_client_state_ciphertext": "qdrant-sec-private-oram-encrypted-client-state-ciphertext-alias-log-sentinel",
            "encryptedClientStateCiphertext": "qdrant-sec-private-oram-camel-encrypted-client-state-ciphertext-alias-log-sentinel",
            "encrypted_client_state_ciphertext_hash": "qdrant-sec-private-oram-encrypted-client-state-ciphertext-hash-alias-log-sentinel",
            "encrypted_client_state_ciphertext_hashes": ["qdrant-sec-private-oram-encrypted-client-state-ciphertext-hashes-alias-log-sentinel"],
            "encryptedClientStateCiphertextHash": "qdrant-sec-private-oram-camel-encrypted-client-state-ciphertext-hash-alias-log-sentinel",
            "encryptedClientStateCiphertextHashes": ["qdrant-sec-private-oram-camel-encrypted-client-state-ciphertext-hashes-alias-log-sentinel"],
            "state_ciphertext": "qdrant-sec-private-oram-state-ciphertext-alias-log-sentinel",
            "state_ciphertext_hash": "qdrant-sec-private-oram-state-ciphertext-hash-alias-log-sentinel",
            "state_ciphertext_hashes": ["qdrant-sec-private-oram-state-ciphertext-hashes-alias-log-sentinel"],
            "stateCiphertext": "qdrant-sec-private-oram-camel-state-ciphertext-alias-log-sentinel",
            "stateCiphertextHash": "qdrant-sec-private-oram-camel-state-ciphertext-hash-alias-log-sentinel",
            "stateCiphertextHashes": ["qdrant-sec-private-oram-camel-state-ciphertext-hashes-alias-log-sentinel"],
            "oram_position_maps": ["qdrant-sec-private-oram-oram-position-maps-alias-log-sentinel"],
            "oram_position_map_backups": ["qdrant-sec-private-oram-oram-position-map-backups-alias-log-sentinel"],
            "oramPositionMaps": ["qdrant-sec-private-oram-camel-oram-position-maps-alias-log-sentinel"],
            "token_position_maps": ["qdrant-sec-private-oram-token-position-maps-alias-log-sentinel"],
            "token_position_map_backups": ["qdrant-sec-private-oram-token-position-map-backups-alias-log-sentinel"],
            "tokenPositionMapSnapshots": ["qdrant-sec-private-oram-camel-token-position-map-snapshots-alias-log-sentinel"],
            "stashSnapshot": "qdrant-sec-private-oram-camel-stash-snapshot-alias-log-sentinel",
            "stash": "qdrant-sec-private-oram-stash-alias-log-sentinel"
        });
        redact_sensitive_log_fields(&mut position_map_aliases);
        let position_map_aliases_serialized = serde_json::to_string(&position_map_aliases).unwrap();
        for leaked in [
            "qdrant-sec-private-oram-position-map-alias-log-sentinel",
            "qdrant-sec-private-oram-position-maps-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-position-map-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-position-maps-alias-log-sentinel",
            "qdrant-sec-private-oram-client-state-ciphertext-alias-log-sentinel",
            "qdrant-sec-private-oram-client-state-ciphertext-hash-alias-log-sentinel",
            "qdrant-sec-private-oram-client-state-ciphertext-hashes-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-client-state-ciphertext-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-client-state-ciphertext-hash-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-client-state-ciphertext-hashes-alias-log-sentinel",
            "qdrant-sec-private-oram-encrypted-client-state-alias-log-sentinel",
            "qdrant-sec-private-oram-encrypted-client-state-backup-alias-log-sentinel",
            "qdrant-sec-private-oram-encrypted-client-state-snapshot-alias-log-sentinel",
            "qdrant-sec-private-oram-encrypted-client-state-ciphertext-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-encrypted-client-state-ciphertext-alias-log-sentinel",
            "qdrant-sec-private-oram-encrypted-client-state-ciphertext-hash-alias-log-sentinel",
            "qdrant-sec-private-oram-encrypted-client-state-ciphertext-hashes-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-encrypted-client-state-ciphertext-hash-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-encrypted-client-state-ciphertext-hashes-alias-log-sentinel",
            "qdrant-sec-private-oram-state-ciphertext-alias-log-sentinel",
            "qdrant-sec-private-oram-state-ciphertext-hash-alias-log-sentinel",
            "qdrant-sec-private-oram-state-ciphertext-hashes-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-state-ciphertext-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-state-ciphertext-hash-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-state-ciphertext-hashes-alias-log-sentinel",
            "qdrant-sec-private-oram-oram-position-maps-alias-log-sentinel",
            "qdrant-sec-private-oram-oram-position-map-backups-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-oram-position-maps-alias-log-sentinel",
            "qdrant-sec-private-oram-token-position-maps-alias-log-sentinel",
            "qdrant-sec-private-oram-token-position-map-backups-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-token-position-map-snapshots-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-stash-snapshot-alias-log-sentinel",
            "qdrant-sec-private-oram-stash-alias-log-sentinel",
        ] {
            assert!(!position_map_aliases_serialized.contains(leaked));
        }

        let mut client_state_sha256_aliases = json!({
            "client_state_ciphertext_sha256": "qdrant-sec-private-oram-client-state-ciphertext-sha256-alias-log-sentinel",
            "client_state_ciphertexts_sha256": ["qdrant-sec-private-oram-client-state-ciphertexts-sha256-alias-log-sentinel"],
            "clientStateCiphertextSha256": "qdrant-sec-private-oram-camel-client-state-ciphertext-sha256-alias-log-sentinel",
            "clientStateCiphertextsSha256": ["qdrant-sec-private-oram-camel-client-state-ciphertexts-sha256-alias-log-sentinel"],
            "encrypted_client_state_ciphertext_sha256": "qdrant-sec-private-oram-encrypted-client-state-ciphertext-sha256-alias-log-sentinel",
            "encrypted_client_state_ciphertexts_sha256": ["qdrant-sec-private-oram-encrypted-client-state-ciphertexts-sha256-alias-log-sentinel"],
            "encryptedClientStateCiphertextSha256": "qdrant-sec-private-oram-camel-encrypted-client-state-ciphertext-sha256-alias-log-sentinel",
            "encryptedClientStateCiphertextsSha256": ["qdrant-sec-private-oram-camel-encrypted-client-state-ciphertexts-sha256-alias-log-sentinel"],
            "state_ciphertext_sha256": "qdrant-sec-private-oram-state-ciphertext-sha256-alias-log-sentinel",
            "state_ciphertexts_sha256": ["qdrant-sec-private-oram-state-ciphertexts-sha256-alias-log-sentinel"],
            "stateCiphertextSha256": "qdrant-sec-private-oram-camel-state-ciphertext-sha256-alias-log-sentinel",
            "stateCiphertextsSha256": ["qdrant-sec-private-oram-camel-state-ciphertexts-sha256-alias-log-sentinel"],
        });
        redact_sensitive_log_fields(&mut client_state_sha256_aliases);
        let client_state_sha256_aliases_serialized =
            serde_json::to_string(&client_state_sha256_aliases).unwrap();
        for leaked in [
            "qdrant-sec-private-oram-client-state-ciphertext-sha256-alias-log-sentinel",
            "qdrant-sec-private-oram-client-state-ciphertexts-sha256-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-client-state-ciphertext-sha256-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-client-state-ciphertexts-sha256-alias-log-sentinel",
            "qdrant-sec-private-oram-encrypted-client-state-ciphertext-sha256-alias-log-sentinel",
            "qdrant-sec-private-oram-encrypted-client-state-ciphertexts-sha256-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-encrypted-client-state-ciphertext-sha256-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-encrypted-client-state-ciphertexts-sha256-alias-log-sentinel",
            "qdrant-sec-private-oram-state-ciphertext-sha256-alias-log-sentinel",
            "qdrant-sec-private-oram-state-ciphertexts-sha256-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-state-ciphertext-sha256-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-state-ciphertexts-sha256-alias-log-sentinel",
        ] {
            assert!(!client_state_sha256_aliases_serialized.contains(leaked));
        }

        let mut plural_sensitive_aliases = json!({
            "candidate_heaps": ["qdrant-sec-private-oram-candidate-heaps-alias-log-sentinel"],
            "candidateHeaps": ["qdrant-sec-private-oram-camel-candidate-heaps-alias-log-sentinel"],
            "client_signatures": ["qdrant-sec-private-oram-client-signatures-alias-log-sentinel"],
            "clientSignatures": ["qdrant-sec-private-oram-camel-client-signatures-alias-log-sentinel"],
            "commit_signatures": ["qdrant-sec-private-oram-commit-signatures-alias-log-sentinel"],
            "commitSignatures": ["qdrant-sec-private-oram-camel-commit-signatures-alias-log-sentinel"],
            "manifest_signatures": ["qdrant-sec-private-oram-manifest-signatures-alias-log-sentinel"],
            "manifestSignatures": ["qdrant-sec-private-oram-camel-manifest-signatures-alias-log-sentinel"],
            "read_signatures": ["qdrant-sec-private-oram-read-signatures-alias-log-sentinel"],
            "readSignatures": ["qdrant-sec-private-oram-camel-read-signatures-alias-log-sentinel"],
            "request_signatures": ["qdrant-sec-private-oram-request-signatures-alias-log-sentinel"],
            "requestSignatures": ["qdrant-sec-private-oram-camel-request-signatures-alias-log-sentinel"],
            "top_ks": ["qdrant-sec-private-oram-top-ks-alias-log-sentinel"],
            "topKs": ["qdrant-sec-private-oram-camel-top-ks-alias-log-sentinel"]
        });
        redact_sensitive_log_fields(&mut plural_sensitive_aliases);
        let plural_sensitive_aliases_serialized =
            serde_json::to_string(&plural_sensitive_aliases).unwrap();
        for leaked in [
            "qdrant-sec-private-oram-candidate-heaps-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-candidate-heaps-alias-log-sentinel",
            "qdrant-sec-private-oram-client-signatures-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-client-signatures-alias-log-sentinel",
            "qdrant-sec-private-oram-commit-signatures-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-commit-signatures-alias-log-sentinel",
            "qdrant-sec-private-oram-manifest-signatures-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-manifest-signatures-alias-log-sentinel",
            "qdrant-sec-private-oram-read-signatures-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-read-signatures-alias-log-sentinel",
            "qdrant-sec-private-oram-request-signatures-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-request-signatures-alias-log-sentinel",
            "qdrant-sec-private-oram-top-ks-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-top-ks-alias-log-sentinel",
        ] {
            assert!(!plural_sensitive_aliases_serialized.contains(leaked));
        }

        let mut query_and_score_aliases = json!({
            "query_vector": ["qdrant-sec-private-oram-query-vector-alias-log-sentinel"],
            "queryVector": ["qdrant-sec-private-oram-camel-query-vector-alias-log-sentinel"],
            "query_embedding": ["qdrant-sec-private-oram-query-embedding-alias-log-sentinel"],
            "queryEmbeddings": ["qdrant-sec-private-oram-camel-query-embeddings-alias-log-sentinel"],
            "query_plaintext": "qdrant-sec-private-oram-query-plaintext-alias-log-sentinel",
            "queryPlaintext": "qdrant-sec-private-oram-camel-query-plaintext-alias-log-sentinel",
            "score": "qdrant-sec-private-oram-score-alias-log-sentinel",
            "scores": ["qdrant-sec-private-oram-scores-alias-log-sentinel"],
            "distance": "qdrant-sec-private-oram-distance-alias-log-sentinel",
            "distances": ["qdrant-sec-private-oram-distances-alias-log-sentinel"],
            "candidate_score": "qdrant-sec-private-oram-candidate-score-alias-log-sentinel",
            "candidateScores": ["qdrant-sec-private-oram-camel-candidate-scores-alias-log-sentinel"],
            "candidate_distance": "qdrant-sec-private-oram-candidate-distance-alias-log-sentinel",
            "candidateDistances": ["qdrant-sec-private-oram-camel-candidate-distances-alias-log-sentinel"],
            "distance_score": "qdrant-sec-private-oram-distance-score-alias-log-sentinel",
            "distanceScores": ["qdrant-sec-private-oram-camel-distance-scores-alias-log-sentinel"],
            "node_score": "qdrant-sec-private-oram-node-score-alias-log-sentinel",
            "nodeScores": ["qdrant-sec-private-oram-camel-node-scores-alias-log-sentinel"],
            "node_distance": "qdrant-sec-private-oram-node-distance-alias-log-sentinel",
            "nodeDistances": ["qdrant-sec-private-oram-camel-node-distances-alias-log-sentinel"]
        });
        redact_sensitive_log_fields(&mut query_and_score_aliases);
        let query_and_score_aliases_serialized =
            serde_json::to_string(&query_and_score_aliases).unwrap();
        for leaked in [
            "qdrant-sec-private-oram-query-vector-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-query-vector-alias-log-sentinel",
            "qdrant-sec-private-oram-query-embedding-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-query-embeddings-alias-log-sentinel",
            "qdrant-sec-private-oram-query-plaintext-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-query-plaintext-alias-log-sentinel",
            "qdrant-sec-private-oram-score-alias-log-sentinel",
            "qdrant-sec-private-oram-scores-alias-log-sentinel",
            "qdrant-sec-private-oram-distance-alias-log-sentinel",
            "qdrant-sec-private-oram-distances-alias-log-sentinel",
            "qdrant-sec-private-oram-candidate-score-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-candidate-scores-alias-log-sentinel",
            "qdrant-sec-private-oram-candidate-distance-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-candidate-distances-alias-log-sentinel",
            "qdrant-sec-private-oram-distance-score-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-distance-scores-alias-log-sentinel",
            "qdrant-sec-private-oram-node-score-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-node-scores-alias-log-sentinel",
            "qdrant-sec-private-oram-node-distance-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-node-distances-alias-log-sentinel",
        ] {
            assert!(!query_and_score_aliases_serialized.contains(leaked));
        }

        let mut leaf_aliases = json!({
            "leaf": "qdrant-sec-private-oram-leaf-alias-log-sentinel",
            "leaves": ["qdrant-sec-private-oram-leaves-alias-log-sentinel"],
            "leaf_id": "qdrant-sec-private-oram-leaf-id-alias-log-sentinel",
            "leafIds": ["qdrant-sec-private-oram-camel-leaf-ids-alias-log-sentinel"],
            "old_leaf": "qdrant-sec-private-oram-old-leaf-alias-log-sentinel",
            "oldLeaf": "qdrant-sec-private-oram-camel-old-leaf-alias-log-sentinel",
            "old_leaf_id": "qdrant-sec-private-oram-old-leaf-id-alias-log-sentinel",
            "oldLeafLabels": ["qdrant-sec-private-oram-camel-old-leaf-labels-alias-log-sentinel"],
            "new_leaf": "qdrant-sec-private-oram-new-leaf-alias-log-sentinel",
            "newLeaf": "qdrant-sec-private-oram-camel-new-leaf-alias-log-sentinel",
            "new_leaf_id": "qdrant-sec-private-oram-new-leaf-id-alias-log-sentinel",
            "newLeafLabels": ["qdrant-sec-private-oram-camel-new-leaf-labels-alias-log-sentinel"],
        });
        redact_sensitive_log_fields(&mut leaf_aliases);
        let leaf_aliases_serialized = serde_json::to_string(&leaf_aliases).unwrap();
        for leaked in [
            "qdrant-sec-private-oram-leaf-alias-log-sentinel",
            "qdrant-sec-private-oram-leaves-alias-log-sentinel",
            "qdrant-sec-private-oram-leaf-id-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-leaf-ids-alias-log-sentinel",
            "qdrant-sec-private-oram-old-leaf-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-old-leaf-alias-log-sentinel",
            "qdrant-sec-private-oram-old-leaf-id-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-old-leaf-labels-alias-log-sentinel",
            "qdrant-sec-private-oram-new-leaf-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-new-leaf-alias-log-sentinel",
            "qdrant-sec-private-oram-new-leaf-id-alias-log-sentinel",
            "qdrant-sec-private-oram-camel-new-leaf-labels-alias-log-sentinel",
        ] {
            assert!(!leaf_aliases_serialized.contains(leaked));
        }

        let mut first = json!({
            "read_buckets": {
                "session_id": "private-oram-session-a",
                "root_hash": "private-oram-root-a",
                "old_root_hash": "private-oram-old-root-a",
                "new_root_hash": "private-oram-new-root-a",
                "read_paths": ["read-path-a"],
                "access_paths": ["access-path-a"],
                "accessed_leaf_labels": ["accessed-leaf-a"],
                "oram_paths": ["oram-path-a"],
                "bucket_ids": [1, 2, 3],
                "bucket_sequence": [3, 2, 1],
                "read_bucket_sequence": [10, 11],
                "bucket_commitments": ["bucket-commitment-a"],
                "visited_node_ids": ["visited-node-a"],
                "neighbor_id": "neighbor-a",
                "candidate_nodes": ["candidate-a"],
                "read_signature": "read-signature-a",
                "commit_signature": "commit-signature-a",
                "unknown_field": "unknown-field-a",
                "updated_buckets": [
                    { "bucket_id": 7, "bucket_commitment": "updated-bucket-a" },
                    { "bucket_id": 8, "bucket_commitment": "updated-bucket-b" }
                ],
                "proof": {
                    "leaf_hash": "leaf-hash-a",
                    "siblings": [{ "hash": "sibling-hash-a" }]
                },
                "client_state_ciphertext": "client-state-ciphertext-a",
                "state_ciphertext_hash": "client-state-ciphertext-hash-a",
                "client_state_ciphertext_sha256": "client-state-ciphertext-sha256-a",
                "client_state_ciphertexts_sha256": ["client-state-ciphertexts-sha256-a"],
                "encrypted_client_state_ciphertext_sha256": "encrypted-client-state-ciphertext-sha256-a",
                "encrypted_client_state_ciphertexts_sha256": ["encrypted-client-state-ciphertexts-sha256-a"],
                "state_ciphertext_sha256": "state-ciphertext-sha256-a",
                "state_ciphertexts_sha256": ["state-ciphertexts-sha256-a"],
                "token_position_map": { "fetch-token-a": 99 },
                "position_maps": [{ "node-a": 1 }]
            }
        });
        let mut second = json!({
            "read_buckets": {
                "session_id": "private-oram-session-b",
                "root_hash": "private-oram-root-b",
                "old_root_hash": "private-oram-old-root-b",
                "new_root_hash": "private-oram-new-root-b",
                "read_paths": ["read-path-b"],
                "access_paths": ["access-path-b"],
                "accessed_leaf_labels": ["accessed-leaf-b"],
                "oram_paths": ["oram-path-b"],
                "bucket_ids": [9, 10, 11],
                "bucket_sequence": [11, 10, 9],
                "read_bucket_sequence": [12, 13],
                "bucket_commitments": ["bucket-commitment-b", "bucket-commitment-c"],
                "visited_node_ids": ["visited-node-b"],
                "neighbor_id": "neighbor-b",
                "candidate_nodes": ["candidate-b"],
                "read_signature": "read-signature-b",
                "commit_signature": "commit-signature-b",
                "unknown_field": "unknown-field-b",
                "updated_buckets": [{ "bucket_id": 12, "bucket_commitment": "updated-bucket-c" }],
                "proof": {
                    "leaf_hash": "leaf-hash-b",
                    "siblings": [{ "hash": "sibling-hash-b" }]
                },
                "client_state_ciphertext": "client-state-ciphertext-b",
                "state_ciphertext_hash": "client-state-ciphertext-hash-b",
                "client_state_ciphertext_sha256": "client-state-ciphertext-sha256-b",
                "client_state_ciphertexts_sha256": ["client-state-ciphertexts-sha256-b"],
                "encrypted_client_state_ciphertext_sha256": "encrypted-client-state-ciphertext-sha256-b",
                "encrypted_client_state_ciphertexts_sha256": ["encrypted-client-state-ciphertexts-sha256-b"],
                "state_ciphertext_sha256": "state-ciphertext-sha256-b",
                "state_ciphertexts_sha256": ["state-ciphertexts-sha256-b"],
                "token_position_map": { "fetch-token-b": 17 },
                "position_maps": [{ "node-b": 2 }]
            }
        });
        insert_test_json_field(
            &mut first,
            &["read_buckets"],
            "read_path",
            json!(["single-read-path-a"]),
        );
        insert_test_json_field(
            &mut first,
            &["read_buckets"],
            "read_path_label",
            json!("single-read-path-label-a"),
        );
        insert_test_json_field(
            &mut second,
            &["read_buckets"],
            "read_path",
            json!(["single-read-path-b"]),
        );
        insert_test_json_field(
            &mut second,
            &["read_buckets"],
            "read_path_label",
            json!("single-read-path-label-b"),
        );
        redact_sensitive_log_fields(&mut first);
        redact_sensitive_log_fields(&mut second);
        assert_eq!(first, second);
        assert_eq!(
            redacted_request_hash("private-oram", &first),
            redacted_request_hash("private-oram", &second)
        );

        let mut camel_first = json!({
            "readBuckets": {
                "sessionId": "private-oram-camel-session-a",
                "rootHash": "private-oram-camel-root-a",
                "oldRootHash": "private-oram-camel-old-root-a",
                "newRootHash": "private-oram-camel-new-root-a",
                "bucketIds": [1, 2, 3],
                "bucketSequence": [3, 2, 1],
                "readBucketSequence": [10, 11],
                "accessPaths": ["private-oram-camel-access-path-a"],
                "accessedLeafLabels": ["private-oram-camel-accessed-leaf-a"],
                "oramPaths": ["private-oram-camel-oram-path-a"],
                "bucketCommitments": ["private-oram-camel-bucket-commitment-a"],
                "visitedNodeIds": ["private-oram-camel-visited-node-a"],
                "neighborId": "private-oram-camel-neighbor-a",
                "candidateNodes": ["private-oram-camel-candidate-a"],
                "readSignature": "private-oram-camel-read-signature-a",
                "commitSignature": "private-oram-camel-commit-signature-a",
                "unknownField": "private-oram-camel-unknown-field-a",
                "updatedBuckets": [
                    { "bucketId": 7, "bucketCommitment": "private-oram-camel-updated-bucket-a" },
                    { "bucketId": 8, "bucketCommitment": "private-oram-camel-updated-bucket-b" }
                ],
                "merkleProof": {
                    "leafHash": "private-oram-camel-leaf-hash-a",
                    "siblings": [{ "hash": "private-oram-camel-sibling-hash-a" }]
                },
                "clientStateCiphertext": "private-oram-camel-client-state-ciphertext-a",
                "clientStateCiphertextHash": "private-oram-camel-client-state-ciphertext-hash-a",
                "clientStateCiphertextHashes": ["private-oram-camel-client-state-ciphertext-hashes-a"],
                "encryptedClientStateCiphertext": "private-oram-camel-encrypted-client-state-ciphertext-a",
                "encrypted_client_state_ciphertext_hash": "private-oram-encrypted-client-state-ciphertext-hash-a",
                "encryptedClientStateCiphertextHash": "private-oram-camel-encrypted-client-state-ciphertext-hash-a",
                "encryptedClientStateCiphertextHashes": ["private-oram-camel-encrypted-client-state-ciphertext-hashes-a"],
                "stateCiphertext": "private-oram-camel-state-ciphertext-a",
                "stateCiphertextHash": "private-oram-camel-state-ciphertext-hash-a",
                "stateCiphertextHashes": ["private-oram-camel-state-ciphertext-hashes-a"],
                "payloadFetchToken": "private-oram-camel-payload-fetch-token-a",
                "positionMap": { "private-oram-camel-node-a": 31 },
                "positionMaps": [{ "private-oram-camel-node-a": 32 }],
                "tokenPositionMap": { "private-oram-camel-fetch-token-a": 99 },
                "payloadOramLeaf": "private-oram-camel-payload-leaf-a"
            }
        });
        let mut camel_second = json!({
            "readBuckets": {
                "sessionId": "private-oram-camel-session-b",
                "rootHash": "private-oram-camel-root-b",
                "oldRootHash": "private-oram-camel-old-root-b",
                "newRootHash": "private-oram-camel-new-root-b",
                "bucketIds": [9, 10, 11],
                "bucketSequence": [11, 10, 9],
                "readBucketSequence": [12, 13],
                "accessPaths": ["private-oram-camel-access-path-b"],
                "accessedLeafLabels": ["private-oram-camel-accessed-leaf-b"],
                "oramPaths": ["private-oram-camel-oram-path-b"],
                "bucketCommitments": [
                    "private-oram-camel-bucket-commitment-b",
                    "private-oram-camel-bucket-commitment-c"
                ],
                "visitedNodeIds": ["private-oram-camel-visited-node-b"],
                "neighborId": "private-oram-camel-neighbor-b",
                "candidateNodes": ["private-oram-camel-candidate-b"],
                "readSignature": "private-oram-camel-read-signature-b",
                "commitSignature": "private-oram-camel-commit-signature-b",
                "unknownField": "private-oram-camel-unknown-field-b",
                "updatedBuckets": [
                    { "bucketId": 12, "bucketCommitment": "private-oram-camel-updated-bucket-c" }
                ],
                "merkleProof": {
                    "leafHash": "private-oram-camel-leaf-hash-b",
                    "siblings": [{ "hash": "private-oram-camel-sibling-hash-b" }]
                },
                "clientStateCiphertext": "private-oram-camel-client-state-ciphertext-b",
                "clientStateCiphertextHash": "private-oram-camel-client-state-ciphertext-hash-b",
                "clientStateCiphertextHashes": ["private-oram-camel-client-state-ciphertext-hashes-b"],
                "encryptedClientStateCiphertext": "private-oram-camel-encrypted-client-state-ciphertext-b",
                "encrypted_client_state_ciphertext_hash": "private-oram-encrypted-client-state-ciphertext-hash-b",
                "encryptedClientStateCiphertextHash": "private-oram-camel-encrypted-client-state-ciphertext-hash-b",
                "encryptedClientStateCiphertextHashes": ["private-oram-camel-encrypted-client-state-ciphertext-hashes-b"],
                "stateCiphertext": "private-oram-camel-state-ciphertext-b",
                "stateCiphertextHash": "private-oram-camel-state-ciphertext-hash-b",
                "stateCiphertextHashes": ["private-oram-camel-state-ciphertext-hashes-b"],
                "payloadFetchToken": "private-oram-camel-payload-fetch-token-b",
                "positionMap": { "private-oram-camel-node-b": 41 },
                "positionMaps": [{ "private-oram-camel-node-b": 42 }],
                "tokenPositionMap": { "private-oram-camel-fetch-token-b": 17 },
                "payloadOramLeaf": "private-oram-camel-payload-leaf-b"
            }
        });
        insert_test_json_field(
            &mut camel_first,
            &["readBuckets"],
            "clientStateCiphertextSha256",
            json!("private-oram-camel-client-state-ciphertext-sha256-a"),
        );
        insert_test_json_field(
            &mut camel_first,
            &["readBuckets"],
            "clientStateCiphertextsSha256",
            json!(["private-oram-camel-client-state-ciphertexts-sha256-a"]),
        );
        insert_test_json_field(
            &mut camel_first,
            &["readBuckets"],
            "encryptedClientStateCiphertextSha256",
            json!("private-oram-camel-encrypted-client-state-ciphertext-sha256-a"),
        );
        insert_test_json_field(
            &mut camel_first,
            &["readBuckets"],
            "encryptedClientStateCiphertextsSha256",
            json!(["private-oram-camel-encrypted-client-state-ciphertexts-sha256-a"]),
        );
        insert_test_json_field(
            &mut camel_first,
            &["readBuckets"],
            "stateCiphertextSha256",
            json!("private-oram-camel-state-ciphertext-sha256-a"),
        );
        insert_test_json_field(
            &mut camel_first,
            &["readBuckets"],
            "stateCiphertextsSha256",
            json!(["private-oram-camel-state-ciphertexts-sha256-a"]),
        );
        insert_test_json_field(
            &mut camel_second,
            &["readBuckets"],
            "clientStateCiphertextSha256",
            json!("private-oram-camel-client-state-ciphertext-sha256-b"),
        );
        insert_test_json_field(
            &mut camel_second,
            &["readBuckets"],
            "clientStateCiphertextsSha256",
            json!(["private-oram-camel-client-state-ciphertexts-sha256-b"]),
        );
        insert_test_json_field(
            &mut camel_second,
            &["readBuckets"],
            "encryptedClientStateCiphertextSha256",
            json!("private-oram-camel-encrypted-client-state-ciphertext-sha256-b"),
        );
        insert_test_json_field(
            &mut camel_second,
            &["readBuckets"],
            "encryptedClientStateCiphertextsSha256",
            json!(["private-oram-camel-encrypted-client-state-ciphertexts-sha256-b"]),
        );
        insert_test_json_field(
            &mut camel_second,
            &["readBuckets"],
            "stateCiphertextSha256",
            json!("private-oram-camel-state-ciphertext-sha256-b"),
        );
        insert_test_json_field(
            &mut camel_second,
            &["readBuckets"],
            "stateCiphertextsSha256",
            json!(["private-oram-camel-state-ciphertexts-sha256-b"]),
        );
        insert_test_json_field(
            &mut camel_first,
            &["readBuckets"],
            "readPath",
            json!(["private-oram-camel-single-read-path-a"]),
        );
        insert_test_json_field(
            &mut camel_first,
            &["readBuckets"],
            "readPathLabel",
            json!("private-oram-camel-single-read-path-label-a"),
        );
        insert_test_json_field(
            &mut camel_second,
            &["readBuckets"],
            "readPath",
            json!(["private-oram-camel-single-read-path-b"]),
        );
        insert_test_json_field(
            &mut camel_second,
            &["readBuckets"],
            "readPathLabel",
            json!("private-oram-camel-single-read-path-label-b"),
        );
        redact_sensitive_log_fields(&mut camel_first);
        redact_sensitive_log_fields(&mut camel_second);
        assert_eq!(camel_first, camel_second);
        assert_eq!(
            redacted_request_hash("private-oram", &camel_first),
            redacted_request_hash("private-oram", &camel_second)
        );
    }

    #[test]
    fn log_value_redacts_ckks_plaintext_score_fields() {
        let mut value = json!({
            "bridge_response": {
                "score": "qdrant-sec-ckks-score-log-sentinel",
                "scores": ["qdrant-sec-ckks-scores-log-sentinel"],
                "plaintext_score": "qdrant-sec-ckks-plaintext-score-log-sentinel",
                "plaintext_scores": ["qdrant-sec-ckks-plaintext-scores-log-sentinel"],
                "score_plaintext": "qdrant-sec-ckks-score-plaintext-log-sentinel",
                "score_plaintexts": ["qdrant-sec-ckks-score-plaintexts-log-sentinel"]
            }
        });

        redact_sensitive_log_fields(&mut value);
        let serialized = serde_json::to_string(&value).unwrap();

        for sentinel in [
            "qdrant-sec-ckks-score-log-sentinel",
            "qdrant-sec-ckks-scores-log-sentinel",
            "qdrant-sec-ckks-plaintext-score-log-sentinel",
            "qdrant-sec-ckks-plaintext-scores-log-sentinel",
            "qdrant-sec-ckks-score-plaintext-log-sentinel",
            "qdrant-sec-ckks-score-plaintexts-log-sentinel",
        ] {
            assert!(!serialized.contains(sentinel));
        }
        assert!(serialized.contains("[redacted]"));
    }

    #[test]
    fn log_value_redacts_sensitive_camel_and_kebab_case_fields() {
        let mut value = json!({
            "bridgeRequest": {
                "encryptedQuery": "qdrant-sec-camel-encrypted-query-log-sentinel",
                "encryptedQueryB64": "qdrant-sec-camel-encrypted-query-b64-log-sentinel",
                "cryptoContext": "qdrant-sec-camel-crypto-context-log-sentinel",
                "contextDigest": "qdrant-sec-camel-context-digest-log-sentinel",
                "publicKeyB64": "qdrant-sec-camel-public-key-log-sentinel",
                "wrappedKeyB64": "qdrant-sec-camel-wrapped-key-log-sentinel",
                "valueB64": "qdrant-sec-camel-value-log-sentinel",
                "nonceB64": "qdrant-sec-camel-nonce-b64-log-sentinel",
                "ciphertextB64": "qdrant-sec-camel-ciphertext-b64-log-sentinel",
                "ciphertextSha256": "qdrant-sec-camel-ciphertext-sha256-log-sentinel",
                "ciphertextSha256B64": "qdrant-sec-camel-ciphertext-sha256-b64-log-sentinel",
                "signatureB64": "qdrant-sec-camel-signature-b64-log-sentinel",
                "signaturePublicKeys": [{
                    "keyId": "tenant-a/client-signing-v1",
                    "publicKeyB64": "qdrant-sec-camel-signature-public-keys-log-sentinel"
                }]
            },
            "headers": {
                "xApiKey": "qdrant-sec-camel-api-key-log-sentinel",
                "set-cookie": "qdrant-sec-kebab-set-cookie-log-sentinel",
                "x-vault-token": "qdrant-sec-kebab-vault-token-log-sentinel"
            },
            "tls": {
                "privateKeyB64": "qdrant-sec-camel-private-key-log-sentinel"
            }
        });

        redact_sensitive_log_fields(&mut value);
        let serialized = serde_json::to_string(&value).unwrap();

        for sentinel in [
            "qdrant-sec-camel-encrypted-query-log-sentinel",
            "qdrant-sec-camel-encrypted-query-b64-log-sentinel",
            "qdrant-sec-camel-crypto-context-log-sentinel",
            "qdrant-sec-camel-context-digest-log-sentinel",
            "qdrant-sec-camel-public-key-log-sentinel",
            "qdrant-sec-camel-wrapped-key-log-sentinel",
            "qdrant-sec-camel-value-log-sentinel",
            "qdrant-sec-camel-nonce-b64-log-sentinel",
            "qdrant-sec-camel-ciphertext-b64-log-sentinel",
            "qdrant-sec-camel-ciphertext-sha256-log-sentinel",
            "qdrant-sec-camel-ciphertext-sha256-b64-log-sentinel",
            "qdrant-sec-camel-signature-b64-log-sentinel",
            "qdrant-sec-camel-signature-public-keys-log-sentinel",
            "qdrant-sec-camel-api-key-log-sentinel",
            "qdrant-sec-kebab-set-cookie-log-sentinel",
            "qdrant-sec-kebab-vault-token-log-sentinel",
            "qdrant-sec-camel-private-key-log-sentinel",
        ] {
            assert!(!serialized.contains(sentinel));
        }
        assert!(serialized.contains("[redacted]"));
    }

    #[test]
    fn log_value_redacts_generic_secret_fields_recursively() {
        let mut value = json!({
            "headers": {
                "authorization": "Bearer qdrant-sec-authorization-log-sentinel",
                "x-api-key": "qdrant-sec-x-api-key-log-sentinel",
                "cookie": "qdrant-sec-cookie-log-sentinel",
                "set-cookie": "qdrant-sec-set-cookie-log-sentinel",
                "Authorization": "Bearer qdrant-sec-title-authorization-log-sentinel",
                "X-API-Key": "qdrant-sec-title-api-key-log-sentinel",
                "Cookie": "qdrant-sec-title-cookie-log-sentinel",
                "Set-Cookie": "qdrant-sec-title-set-cookie-log-sentinel"
            },
            "snapshot": {
                "api_key": "qdrant-sec-api-key-log-sentinel",
                "token": "qdrant-sec-token-log-sentinel",
                "access_token": "qdrant-sec-access-token-log-sentinel",
                "refresh_token": "qdrant-sec-refresh-token-log-sentinel",
                "access_key_id": "qdrant-sec-access-key-id-log-sentinel",
                "secret_access_key": "qdrant-sec-secret-access-key-log-sentinel",
                "bearer_token": "qdrant-sec-bearer-token-log-sentinel",
                "id_token": "qdrant-sec-id-token-log-sentinel",
                "jwt": "qdrant-sec-jwt-log-sentinel",
                "session": "qdrant-sec-session-log-sentinel",
                "session_token": "qdrant-sec-session-token-log-sentinel",
                "vault_token": "qdrant-sec-vault-token-log-sentinel",
                "x-vault-token": "qdrant-sec-x-vault-token-log-sentinel",
                "aws_security_token": "qdrant-sec-aws-security-token-log-sentinel",
                "X-Amz-Security-Token": "qdrant-sec-x-amz-security-token-log-sentinel",
                "X-Amz-Credential": "qdrant-sec-x-amz-credential-log-sentinel",
                "X-Amz-Signature": "qdrant-sec-x-amz-signature-log-sentinel",
                "client_secret": "qdrant-sec-client-secret-log-sentinel",
                "credential": "qdrant-sec-credential-log-sentinel",
                "credentials": "qdrant-sec-credentials-log-sentinel",
                "password": "qdrant-sec-password-log-sentinel"
            },
            "tls": {
                "private_key": "qdrant-sec-private-key-log-sentinel",
                "private_key_b64": "qdrant-sec-private-key-b64-log-sentinel"
            },
            "crypto": {
                "secret": "qdrant-sec-generic-secret-log-sentinel",
                "secret_b64": "qdrant-sec-generic-secret-b64-log-sentinel",
                "key_material": "qdrant-sec-key-material-log-sentinel",
                "key_material_b64": "qdrant-sec-key-material-b64-log-sentinel",
                "master_key": "qdrant-sec-master-key-log-sentinel",
                "master_key_b64": "qdrant-sec-master-key-b64-log-sentinel",
                "resource_key": "qdrant-sec-resource-key-log-sentinel",
                "resource_key_b64": "qdrant-sec-resource-key-b64-log-sentinel",
                "wrapping_key": "qdrant-sec-wrapping-key-log-sentinel",
                "wrapping_key_b64": "qdrant-sec-wrapping-key-b64-log-sentinel",
                "secret_key": "qdrant-sec-secret-key-log-sentinel",
                "secret_key_b64": "qdrant-sec-secret-key-b64-log-sentinel",
                "public_key_b64": "qdrant-sec-public-key-b64-log-sentinel",
                "signature_public_key_b64": "qdrant-sec-signature-public-key-log-sentinel"
            }
        });

        redact_sensitive_log_fields(&mut value);
        let serialized = serde_json::to_string(&value).unwrap();

        for sentinel in [
            "qdrant-sec-authorization-log-sentinel",
            "qdrant-sec-x-api-key-log-sentinel",
            "qdrant-sec-cookie-log-sentinel",
            "qdrant-sec-set-cookie-log-sentinel",
            "qdrant-sec-title-authorization-log-sentinel",
            "qdrant-sec-title-api-key-log-sentinel",
            "qdrant-sec-title-cookie-log-sentinel",
            "qdrant-sec-title-set-cookie-log-sentinel",
            "qdrant-sec-api-key-log-sentinel",
            "qdrant-sec-token-log-sentinel",
            "qdrant-sec-access-token-log-sentinel",
            "qdrant-sec-refresh-token-log-sentinel",
            "qdrant-sec-access-key-id-log-sentinel",
            "qdrant-sec-secret-access-key-log-sentinel",
            "qdrant-sec-bearer-token-log-sentinel",
            "qdrant-sec-id-token-log-sentinel",
            "qdrant-sec-jwt-log-sentinel",
            "qdrant-sec-session-log-sentinel",
            "qdrant-sec-session-token-log-sentinel",
            "qdrant-sec-vault-token-log-sentinel",
            "qdrant-sec-x-vault-token-log-sentinel",
            "qdrant-sec-aws-security-token-log-sentinel",
            "qdrant-sec-x-amz-security-token-log-sentinel",
            "qdrant-sec-x-amz-credential-log-sentinel",
            "qdrant-sec-x-amz-signature-log-sentinel",
            "qdrant-sec-client-secret-log-sentinel",
            "qdrant-sec-credential-log-sentinel",
            "qdrant-sec-credentials-log-sentinel",
            "qdrant-sec-password-log-sentinel",
            "qdrant-sec-private-key-log-sentinel",
            "qdrant-sec-private-key-b64-log-sentinel",
            "qdrant-sec-generic-secret-log-sentinel",
            "qdrant-sec-generic-secret-b64-log-sentinel",
            "qdrant-sec-key-material-log-sentinel",
            "qdrant-sec-key-material-b64-log-sentinel",
            "qdrant-sec-master-key-log-sentinel",
            "qdrant-sec-master-key-b64-log-sentinel",
            "qdrant-sec-resource-key-log-sentinel",
            "qdrant-sec-resource-key-b64-log-sentinel",
            "qdrant-sec-wrapping-key-log-sentinel",
            "qdrant-sec-wrapping-key-b64-log-sentinel",
            "qdrant-sec-secret-key-log-sentinel",
            "qdrant-sec-secret-key-b64-log-sentinel",
            "qdrant-sec-public-key-b64-log-sentinel",
            "qdrant-sec-signature-public-key-log-sentinel",
        ] {
            assert!(!serialized.contains(sentinel));
        }
        assert!(serialized.contains("[redacted]"));
    }

    #[test]
    fn generic_secret_request_hash_uses_redacted_material() {
        let mut first = json!({
            "headers": {
                "authorization": "Bearer secret-a",
                "x-api-key": "api-secret-a",
                "Authorization": "Bearer title-secret-a",
                "X-API-Key": "title-api-secret-a",
                "cookie": "cookie-secret-a",
                "set-cookie": "set-cookie-secret-a",
                "Cookie": "title-cookie-secret-a",
                "Set-Cookie": "title-set-cookie-secret-a"
            },
            "oauth": {
                "access_token": "access-secret-a",
                "refresh_token": "refresh-secret-a",
                "access_key_id": "access-key-id-secret-a",
                "secret_access_key": "secret-access-key-a",
                "id_token": "id-token-secret-a",
                "jwt": "jwt-secret-a",
                "client_secret": "client-secret-a"
            },
            "vault": {
                "x-vault-token": "vault-secret-a"
            },
            "aws": {
                "X-Amz-Security-Token": "amz-security-token-a",
                "X-Amz-Credential": "amz-credential-a",
                "X-Amz-Signature": "amz-signature-a",
                "aws_security_token": "aws-security-token-a"
            },
            "session": {
                "session_token": "session-secret-a",
                "credentials": "credentials-secret-a"
            },
            "crypto": {
                "secret": "generic-secret-a",
                "secret_b64": "generic-secret-b64-a",
                "key_material": "material-secret-a",
                "key_material_b64": "material-secret-b64-a",
                "master_key": "master-secret-a",
                "master_key_b64": "master-secret-b64-a",
                "resource_key": "resource-secret-a",
                "resource_key_b64": "resource-secret-b64-a",
                "wrapping_key": "wrapping-secret-a",
                "wrapping_key_b64": "wrapping-secret-b64-a"
            }
        });
        let mut second = json!({
            "headers": {
                "authorization": "Bearer secret-b",
                "x-api-key": "api-secret-b",
                "Authorization": "Bearer title-secret-b",
                "X-API-Key": "title-api-secret-b",
                "cookie": "cookie-secret-b",
                "set-cookie": "set-cookie-secret-b",
                "Cookie": "title-cookie-secret-b",
                "Set-Cookie": "title-set-cookie-secret-b"
            },
            "oauth": {
                "access_token": "access-secret-b",
                "refresh_token": "refresh-secret-b",
                "access_key_id": "access-key-id-secret-b",
                "secret_access_key": "secret-access-key-b",
                "id_token": "id-token-secret-b",
                "jwt": "jwt-secret-b",
                "client_secret": "client-secret-b"
            },
            "vault": {
                "x-vault-token": "vault-secret-b"
            },
            "aws": {
                "X-Amz-Security-Token": "amz-security-token-b",
                "X-Amz-Credential": "amz-credential-b",
                "X-Amz-Signature": "amz-signature-b",
                "aws_security_token": "aws-security-token-b"
            },
            "session": {
                "session_token": "session-secret-b",
                "credentials": "credentials-secret-b"
            },
            "crypto": {
                "secret": "generic-secret-b",
                "secret_b64": "generic-secret-b64-b",
                "key_material": "material-secret-b",
                "key_material_b64": "material-secret-b64-b",
                "master_key": "master-secret-b",
                "master_key_b64": "master-secret-b64-b",
                "resource_key": "resource-secret-b",
                "resource_key_b64": "resource-secret-b64-b",
                "wrapping_key": "wrapping-secret-b",
                "wrapping_key_b64": "wrapping-secret-b64-b"
            }
        });

        redact_sensitive_log_fields(&mut first);
        redact_sensitive_log_fields(&mut second);

        assert_eq!(first, second);
        assert_eq!(
            redacted_request_hash("secret-bearing-request", &first),
            redacted_request_hash("secret-bearing-request", &second),
        );
    }
}
