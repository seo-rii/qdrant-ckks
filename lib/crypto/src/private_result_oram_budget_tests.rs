//! The private result ORAM seal keys observe the AES-GCM random-nonce invocation budget.

use super::*;
use crate::aead::AES_GCM_RANDOM_NONCE_INVOCATION_LIMIT;

fn keys() -> PrivateResultOramClientKeys {
    PrivateResultOramClientKeys::derive_from_resource_key_with_context(
        &SecretKey::from_bytes([9; 32]),
        "collection-uuid-1",
        "tenant-a/rk",
        1,
    )
    .unwrap()
}

fn bucket_context() -> PrivateResultOramBucketAeadContext<'static> {
    PrivateResultOramBucketAeadContext {
        collection_id: "collection-uuid-1",
        key_id: "tenant-a:key",
        rk_id: "tenant-a/rk",
        rk_epoch: 1,
        bucket_id: 0,
        index_epoch: 1,
    }
}

#[test]
fn bucket_seals_stop_at_the_invocation_budget() {
    let keys = keys();
    keys.bucket_seals
        .set_for_test(AES_GCM_RANDOM_NONCE_INVOCATION_LIMIT - 2);
    seal_private_result_oram_bucket(&keys, bucket_context(), b"a").unwrap();
    let last = seal_private_result_oram_bucket(&keys, bucket_context(), b"b").unwrap();
    assert_eq!(
        keys.bucket_seal_invocations(),
        AES_GCM_RANDOM_NONCE_INVOCATION_LIMIT
    );
    assert!(matches!(
        seal_private_result_oram_bucket(&keys, bucket_context(), b"c"),
        Err(PrivateResultOramError::Encryption(
            EncryptionError::KeyUsageExhausted
        ))
    ));
    // Opening never consumes budget and still works for earlier seals.
    assert_eq!(
        open_private_result_oram_bucket(&keys, bucket_context(), &last).unwrap(),
        b"b"
    );
    assert_eq!(
        keys.bucket_seal_invocations(),
        AES_GCM_RANDOM_NONCE_INVOCATION_LIMIT
    );
    // The client-state key keeps its own budget.
    assert_eq!(keys.client_state_seal_invocations(), 0);
}

#[test]
fn client_state_seals_stop_at_the_invocation_budget() {
    let keys = keys();
    keys.client_state_seals
        .set_for_test(AES_GCM_RANDOM_NONCE_INVOCATION_LIMIT - 1);
    let snapshot = PrivateResultOramClientState::new().to_snapshot(2).unwrap();
    let root = BASE64URL_NOPAD.encode(&[7u8; 32]);
    let context = PrivateResultOramClientStateAeadContext {
        collection_id: "collection-uuid-1",
        key_id: "tenant-a:key",
        rk_id: "tenant-a/rk",
        rk_epoch: 1,
        index_epoch: 1,
        root_hash: &root,
    };
    seal_private_result_oram_client_state_snapshot(&keys, context, &snapshot).unwrap();
    assert!(matches!(
        seal_private_result_oram_client_state_snapshot(&keys, context, &snapshot),
        Err(PrivateResultOramError::Encryption(
            EncryptionError::KeyUsageExhausted
        ))
    ));
    assert_eq!(
        keys.client_state_seal_invocations(),
        AES_GCM_RANDOM_NONCE_INVOCATION_LIMIT
    );
    assert_eq!(keys.bucket_seal_invocations(), 0);
}
