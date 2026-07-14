import json
import pathlib
import subprocess

import requests

from .assertions import assert_http_ok
from .utils import (
    PROJECT_ROOT,
    make_peer_folders,
    start_first_peer,
    start_peer,
    wait_collection_exists_and_active_on_all_peers,
    wait_for_uniform_cluster_status,
    wait_peer_added,
)


COLLECTION = "docs"
VECTOR = "text"
BASE_EPOCH = 42
NEXT_EPOCH = 43
FIXTURE_EXAMPLE = "private_oram_cluster_fixture"
PLACEHOLDER_COLLECTION_ID = "12345678-90ab-cdef-1234-567890abcdef"


def _private_oram_fixture(collection_id: str) -> dict:
    completed = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "qdrant-sec",
            "--example",
            FIXTURE_EXAMPLE,
            "--",
            collection_id,
        ],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
    )
    return json.loads(completed.stdout)


def _write_private_oram_runtime_config(
    peer_dir: pathlib.Path, hnsw_public_key: str, result_public_key: str
) -> None:
    local_config = f"""
crypto:
  zero_trust_profile: strict
  instances:
    docs_private_hnsw_v1:
      provider: vector/private-hnsw-oram@v1
      materials: {{}}
      options:
        key_id: tenant-a/vector-private-rk
        expected_rk_id: tenant-a/vector-private-rk
        min_rk_epoch: 7
        max_rk_epoch: 7
        search_execution: client_led
        search_mode: private_hnsw_oram
        result_privacy: private_payload_oram_required
        distance: euclid
        dim: 2
        hnsw:
          m: 2
          ef_construction: 4
          max_layers: 3
          fixed_neighbor_slots: 4
        oram:
          kind: path_oram
          bucket_size: 2
          block_size_bytes: 4096
          tree_height: 2
          path_batch_size: 1
        fixed_budget:
          enabled: true
          upper_layer_steps: 1
          base_layer_steps: 3
          paths_per_round: 1
          fixed_result_k: 1
        integrity:
          manifest_signature_required: true
          commit_signature_required: true
          merkle_root_required: true
        signature_public_keys:
          tenant-a/private-hnsw-signing-v1: {hnsw_public_key}
    docs_private_result_oram_v1:
      provider: payload/private-result-oram@v1
      materials: {{}}
      options:
        key_id: tenant-a/vector-private-rk
        expected_rk_id: tenant-a/vector-private-rk
        min_rk_epoch: 7
        max_rk_epoch: 7
        oram:
          kind: path_oram
          bucket_size: 2
          block_size_bytes: 1024
          tree_height: 2
          path_batch_size: 1
        integrity:
          manifest_signature_required: true
          commit_signature_required: true
          merkle_root_required: true
        signature_public_keys:
          tenant-a/private-result-signing-v1: {result_public_key}
"""
    (peer_dir / "config" / "local.yaml").write_text(local_config)


def _post_result(url: str, body: dict) -> dict:
    response = requests.post(url, json=body, timeout=30)
    assert_http_ok(response)
    return response.json()["result"]


def _collection_uuid(peer_url: str) -> str:
    response = requests.get(
        f"{peer_url}/telemetry", params={"details_level": 2}, timeout=30
    )
    assert_http_ok(response)
    collections = response.json()["result"]["collections"]["collections"]
    collection = next(item for item in collections if item["id"] == COLLECTION)
    return collection["config"]["uuid"]


def _upload_hnsw(peer_url: str, fixture: dict) -> None:
    hnsw = fixture["hnsw"]
    _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/manifest",
        {
            "manifest": hnsw["manifest"],
            "signature": hnsw["manifest_signature"],
        },
    )
    _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/buckets",
        {
            "index_epoch": BASE_EPOCH,
            "root_hash": hnsw["manifest"]["root_hash"],
            "buckets": hnsw["buckets"],
        },
    )


def _exercise_hnsw_owner_session(peer_url: str, fixture: dict) -> None:
    hnsw = fixture["hnsw"]
    session = _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session",
        {
            "client_id": "tenant-a/multi-peer-hnsw-sdk",
            "desired_epoch": BASE_EPOCH,
            "fixed_budget": True,
            "result_privacy": "private_payload_oram_required",
        },
    )
    read = _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/oram/read_paths",
        {
            "session_id": session["session_id"],
            "index_epoch": BASE_EPOCH,
            "root_hash": session["root_hash"],
            "paths": hnsw["read"]["paths"],
            "padding": {"requested_paths": 1, "dummy_paths_included": True},
            "client_signature": hnsw["read"]["signature"],
        },
    )
    assert read["index_epoch"] == BASE_EPOCH
    assert read["root_hash"] == session["root_hash"]
    assert len(read["buckets"]) == 3

    commit = hnsw["commit"]
    committed = _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/oram/commit",
        {
            "session_id": session["session_id"],
            "old_epoch": commit["old_epoch"],
            "new_epoch": commit["new_epoch"],
            "old_root_hash": commit["old_root_hash"],
            "new_root_hash": commit["new_root_hash"],
            "updated_buckets": commit["updated_buckets"],
            "commit_signature": commit["signature"],
        },
    )
    assert committed["index_epoch"] == NEXT_EPOCH
    assert committed["root_hash"] == commit["new_root_hash"]

    closed = _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session/{session['session_id']}/close",
        {},
    )
    assert closed is True


def _upload_result_oram(peer_url: str, fixture: dict) -> None:
    result = fixture["result"]
    _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-result-oram/manifest",
        {
            "manifest": result["manifest"],
            "signature": result["manifest_signature"],
        },
    )
    _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-result-oram/buckets",
        {
            "index_epoch": BASE_EPOCH,
            "root_hash": result["manifest"]["root_hash"],
            "buckets": result["buckets"],
        },
    )


def _exercise_result_owner_session(peer_url: str, fixture: dict) -> None:
    result = fixture["result"]
    session = _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-result-oram/session",
        {
            "client_id": "tenant-a/multi-peer-result-sdk",
            "desired_epoch": BASE_EPOCH,
            "fixed_budget": True,
        },
    )
    read = _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-result-oram/oram/read_buckets",
        {
            "session_id": session["session_id"],
            "index_epoch": BASE_EPOCH,
            "root_hash": session["root_hash"],
            "bucket_ids": result["read"]["bucket_ids"],
            "read_signature": result["read"]["signature"],
        },
    )
    assert read["index_epoch"] == BASE_EPOCH
    assert read["root_hash"] == session["root_hash"]
    assert len(read["buckets"]) == 3

    commit = result["commit"]
    committed = _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-result-oram/oram/commit",
        {
            "session_id": session["session_id"],
            "old_epoch": commit["old_epoch"],
            "new_epoch": commit["new_epoch"],
            "old_root_hash": commit["old_root_hash"],
            "new_root_hash": commit["new_root_hash"],
            "updated_buckets": commit["updated_buckets"],
            "commit_signature": commit["signature"],
        },
    )
    assert committed["index_epoch"] == NEXT_EPOCH
    assert committed["root_hash"] == commit["new_root_hash"]

    closed = _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-result-oram/session/{session['session_id']}/close",
        {},
    )
    assert closed is True


def _assert_replica_can_open_current_sessions(peer_url: str, fixture: dict) -> None:
    for endpoint, body in [
        (
            f"private-hnsw/{VECTOR}",
            {
                "client_id": "tenant-a/replica-hnsw-sdk",
                "desired_epoch": NEXT_EPOCH,
                "fixed_budget": True,
                "result_privacy": "private_payload_oram_required",
            },
        ),
        (
            "private-result-oram",
            {
                "client_id": "tenant-a/replica-result-sdk",
                "desired_epoch": NEXT_EPOCH,
                "fixed_budget": True,
            },
        ),
    ]:
        session = _post_result(
            f"{peer_url}/collections/{COLLECTION}/{endpoint}/session", body
        )
        assert session["index_epoch"] == NEXT_EPOCH
        close_endpoint = (
            f"private-hnsw/{VECTOR}"
            if endpoint.startswith("private-hnsw")
            else "private-result-oram"
        )
        assert (
            _post_result(
                f"{peer_url}/collections/{COLLECTION}/{close_endpoint}/session/{session['session_id']}/close",
                {},
            )
            is True
        )


def test_private_oram_sessions_replicate_through_public_routes(tmp_path: pathlib.Path):
    bootstrap_fixture = _private_oram_fixture(PLACEHOLDER_COLLECTION_ID)
    peer_dirs = make_peer_folders(tmp_path, 2)
    for peer_dir in peer_dirs:
        _write_private_oram_runtime_config(
            peer_dir,
            bootstrap_fixture["hnsw_public_key"],
            bootstrap_fixture["result_public_key"],
        )

    bootstrap_api, bootstrap_uri = start_first_peer(
        peer_dirs[0], "private_oram_peer_0.log"
    )
    leader = wait_peer_added(bootstrap_api)
    replica_api = start_peer(
        peer_dirs[1], "private_oram_peer_1.log", bootstrap_uri
    )
    peer_urls = [bootstrap_api, replica_api]
    wait_for_uniform_cluster_status(peer_urls, leader)

    create = requests.put(
        f"{bootstrap_api}/collections/{COLLECTION}",
        json={
            "vectors": {VECTOR: {"size": 2, "distance": "Euclid"}},
            "shard_number": 1,
            "replication_factor": 2,
            "write_consistency_factor": 2,
            "encryption": {
                "version": 1,
                "key_id": "tenant-a/vector-private-rk",
                "crypto_schema_version": 1,
                "encryption_epoch": 7,
                "migration_state": "active",
                "rules": [
                    {
                        "id": "text_private_hnsw",
                        "selector": {"kind": "vector_names", "names": [VECTOR]},
                        "instance": "docs_private_hnsw_v1",
                        "binding": "private-hnsw-oram/v1",
                    },
                    {
                        "id": "payload_private_result_oram",
                        "selector": {"kind": "payload_paths", "paths": ["body"]},
                        "instance": "docs_private_result_oram_v1",
                        "binding": "private-result-oram/v1",
                    },
                ],
            },
        },
        timeout=30,
    )
    assert_http_ok(create)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)

    collection_id = _collection_uuid(bootstrap_api)
    fixture = _private_oram_fixture(collection_id)
    assert fixture["hnsw_public_key"] == bootstrap_fixture["hnsw_public_key"]
    assert fixture["result_public_key"] == bootstrap_fixture["result_public_key"]

    _upload_hnsw(bootstrap_api, fixture)
    _exercise_hnsw_owner_session(bootstrap_api, fixture)
    _upload_result_oram(bootstrap_api, fixture)
    _exercise_result_owner_session(bootstrap_api, fixture)
    _assert_replica_can_open_current_sessions(replica_api, fixture)
