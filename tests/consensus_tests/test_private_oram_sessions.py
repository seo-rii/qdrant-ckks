import json
import pathlib
import stat
import subprocess

import pytest
import requests

from .assertions import assert_http_ok
from .utils import (
    PROJECT_ROOT,
    get_cluster_info,
    get_collection_cluster_info,
    get_uri,
    kill_all_processes,
    make_peer_folders,
    processes,
    start_first_peer,
    start_peer,
    wait_collection_exists_and_active_on_all_peers,
    wait_for_collection_local_shards_count,
    wait_for_collection_shard_transfers_count,
    wait_for_uniform_cluster_status,
    wait_peer_added,
    wait_for_peer_online,
)


COLLECTION = "docs"
VECTOR = "text"
BASE_EPOCH = 42
NEXT_EPOCH = 43
FIXTURE_EXAMPLE = "private_oram_cluster_fixture"
PLACEHOLDER_COLLECTION_ID = "12345678-90ab-cdef-1234-567890abcdef"


@pytest.fixture(autouse=True)
def cleanup_private_oram_peers():
    yield
    kill_all_processes()


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


def _start_private_oram_cluster(
    tmp_path: pathlib.Path, peer_count: int, replication_factor: int
) -> tuple[list[str], list[pathlib.Path], dict, int, str]:
    bootstrap_fixture = _private_oram_fixture(PLACEHOLDER_COLLECTION_ID)
    peer_dirs = make_peer_folders(tmp_path, peer_count)
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
    peer_urls = [bootstrap_api]
    for peer_index, peer_dir in enumerate(peer_dirs[1:], start=1):
        peer_urls.append(
            start_peer(
                peer_dir,
                f"private_oram_peer_{peer_index}.log",
                bootstrap_uri,
            )
        )
    wait_for_uniform_cluster_status(peer_urls, leader)

    create = requests.put(
        f"{bootstrap_api}/collections/{COLLECTION}",
        json={
            "vectors": {VECTOR: {"size": 2, "distance": "Euclid"}},
            "shard_number": 1,
            "replication_factor": replication_factor,
            "write_consistency_factor": replication_factor,
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

    fixture = _private_oram_fixture(_collection_uuid(bootstrap_api))
    assert fixture["hnsw_public_key"] == bootstrap_fixture["hnsw_public_key"]
    assert fixture["result_public_key"] == bootstrap_fixture["result_public_key"]
    return peer_urls, peer_dirs, fixture, leader, bootstrap_uri


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


def _open_hnsw_owner_session(peer_url: str, desired_epoch: int) -> dict:
    return _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session",
        {
            "client_id": "tenant-a/multi-peer-hnsw-sdk",
            "desired_epoch": desired_epoch,
            "fixed_budget": True,
            "result_privacy": "private_payload_oram_required",
        },
    )


def _read_hnsw_owner_session(peer_url: str, fixture: dict, session: dict) -> None:
    hnsw = fixture["hnsw"]
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


def _exercise_hnsw_owner_session(peer_url: str, fixture: dict) -> None:
    hnsw = fixture["hnsw"]
    session = _open_hnsw_owner_session(peer_url, BASE_EPOCH)
    _read_hnsw_owner_session(peer_url, fixture, session)

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


def _open_result_owner_session(peer_url: str, desired_epoch: int) -> dict:
    return _post_result(
        f"{peer_url}/collections/{COLLECTION}/private-result-oram/session",
        {
            "client_id": "tenant-a/multi-peer-result-sdk",
            "desired_epoch": desired_epoch,
            "fixed_budget": True,
        },
    )


def _read_result_owner_session(peer_url: str, fixture: dict, session: dict) -> None:
    result = fixture["result"]
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


def _exercise_result_owner_session(peer_url: str, fixture: dict) -> None:
    result = fixture["result"]
    session = _open_result_owner_session(peer_url, BASE_EPOCH)
    _read_result_owner_session(peer_url, fixture, session)

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


def _assert_replica_can_open_current_sessions(peer_url: str) -> None:
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
    peer_urls, _, fixture, _, _ = _start_private_oram_cluster(tmp_path, 2, 2)
    bootstrap_api, replica_api = peer_urls

    _upload_hnsw(bootstrap_api, fixture)
    _exercise_hnsw_owner_session(bootstrap_api, fixture)
    _upload_result_oram(bootstrap_api, fixture)
    _exercise_result_owner_session(bootstrap_api, fixture)
    _assert_replica_can_open_current_sessions(replica_api)


@pytest.mark.parametrize("transfer_operation", ["replicate_shard", "move_shard"])
def test_private_oram_shard_transfer_preinstalls_live_store(
    tmp_path: pathlib.Path, transfer_operation: str
):
    peer_urls, _, fixture, _, _ = _start_private_oram_cluster(tmp_path, 2, 1)
    cluster_infos = [
        get_collection_cluster_info(peer_url, COLLECTION) for peer_url in peer_urls
    ]
    source_indices = [
        index for index, info in enumerate(cluster_infos) if info["local_shards"]
    ]
    assert len(source_indices) == 1
    source_index = source_indices[0]
    target_index = 1 - source_index
    source_url = peer_urls[source_index]
    target_url = peer_urls[target_index]
    source_info = cluster_infos[source_index]
    target_info = cluster_infos[target_index]

    assert not target_info["local_shards"]
    shard_id = source_info["local_shards"][0]["shard_id"]

    _upload_hnsw(source_url, fixture)
    _exercise_hnsw_owner_session(source_url, fixture)
    _upload_result_oram(source_url, fixture)
    _exercise_result_owner_session(source_url, fixture)

    replicate = requests.post(
        f"{source_url}/collections/{COLLECTION}/cluster",
        json={
            transfer_operation: {
                "shard_id": shard_id,
                "from_peer_id": source_info["peer_id"],
                "to_peer_id": target_info["peer_id"],
                "method": "stream_records",
            }
        },
        timeout=60,
    )
    assert_http_ok(replicate)

    wait_for_collection_local_shards_count(target_url, COLLECTION, 1)
    wait_for_collection_local_shards_count(
        source_url,
        COLLECTION,
        1 if transfer_operation == "replicate_shard" else 0,
    )
    wait_for_collection_shard_transfers_count(source_url, COLLECTION, 0)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)
    _assert_replica_can_open_current_sessions(target_url)


@pytest.mark.parametrize("index_kind", ["hnsw", "result"])
def test_private_oram_replica_prepare_failure_preserves_epoch(
    tmp_path: pathlib.Path, index_kind: str
):
    peer_urls, _, fixture, leader, _ = _start_private_oram_cluster(tmp_path, 3, 3)
    peer_ids = [get_cluster_info(peer_url)["peer_id"] for peer_url in peer_urls]
    coordinator_index = peer_ids.index(leader)
    coordinator_url = peer_urls[coordinator_index]
    failed_replica_index = next(
        index for index, peer_id in enumerate(peer_ids) if peer_id != leader
    )

    if index_kind == "hnsw":
        _upload_hnsw(coordinator_url, fixture)
        session = _open_hnsw_owner_session(coordinator_url, BASE_EPOCH)
        _read_hnsw_owner_session(coordinator_url, fixture, session)
        commit = fixture["hnsw"]["commit"]
        commit_url = f"{coordinator_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/oram/commit"
        commit_body = {
            "session_id": session["session_id"],
            "old_epoch": commit["old_epoch"],
            "new_epoch": commit["new_epoch"],
            "old_root_hash": commit["old_root_hash"],
            "new_root_hash": commit["new_root_hash"],
            "updated_buckets": commit["updated_buckets"],
            "commit_signature": commit["signature"],
        }
    else:
        _upload_result_oram(coordinator_url, fixture)
        session = _open_result_owner_session(coordinator_url, BASE_EPOCH)
        _read_result_owner_session(coordinator_url, fixture, session)
        commit = fixture["result"]["commit"]
        commit_url = f"{coordinator_url}/collections/{COLLECTION}/private-result-oram/oram/commit"
        commit_body = {
            "session_id": session["session_id"],
            "old_epoch": commit["old_epoch"],
            "new_epoch": commit["new_epoch"],
            "old_root_hash": commit["old_root_hash"],
            "new_root_hash": commit["new_root_hash"],
            "updated_buckets": commit["updated_buckets"],
            "commit_signature": commit["signature"],
        }

    processes.pop(failed_replica_index).kill()
    response = requests.post(commit_url, json=commit_body, timeout=60)
    assert 500 <= response.status_code < 600
    for secret in [
        session["session_id"],
        commit["old_root_hash"],
        commit["new_root_hash"],
        commit["signature"]["sig"],
        commit["updated_buckets"][0]["ciphertext"],
    ]:
        assert secret not in response.text

    if index_kind == "hnsw":
        _read_hnsw_owner_session(coordinator_url, fixture, session)
        close_url = f"{coordinator_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session/{session['session_id']}/close"
        assert _post_result(close_url, {}) is True
        reopened = _open_hnsw_owner_session(coordinator_url, BASE_EPOCH)
        reopened_close_url = f"{coordinator_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session/{reopened['session_id']}/close"
    else:
        _read_result_owner_session(coordinator_url, fixture, session)
        close_url = f"{coordinator_url}/collections/{COLLECTION}/private-result-oram/session/{session['session_id']}/close"
        assert _post_result(close_url, {}) is True
        reopened = _open_result_owner_session(coordinator_url, BASE_EPOCH)
        reopened_close_url = f"{coordinator_url}/collections/{COLLECTION}/private-result-oram/session/{reopened['session_id']}/close"

    assert reopened["index_epoch"] == BASE_EPOCH
    assert _post_result(reopened_close_url, {}) is True


def _private_oram_buckets_dir(peer_dir: pathlib.Path, index_kind: str) -> pathlib.Path:
    pattern = (
        f"private_hnsw_oram/{VECTOR}/buckets"
        if index_kind == "hnsw"
        else "private_result_oram/buckets"
    )
    matches = list(peer_dir.rglob(pattern))
    assert len(matches) == 1
    return matches[0]


@pytest.mark.parametrize("index_kind", ["hnsw", "result"])
def test_private_oram_partial_finalize_recovers_after_coordinator_restart(
    tmp_path: pathlib.Path, index_kind: str
):
    peer_urls, peer_dirs, fixture, leader, _ = _start_private_oram_cluster(
        tmp_path, 3, 2
    )
    peer_ids = [get_cluster_info(peer_url)["peer_id"] for peer_url in peer_urls]
    replica_indices = [
        index
        for index, peer_url in enumerate(peer_urls)
        if get_collection_cluster_info(peer_url, COLLECTION)["local_shards"]
    ]
    assert len(replica_indices) == 2
    coordinator_index = next(
        index for index in replica_indices if peer_ids[index] != leader
    )
    finalize_failure_index = next(
        index for index in replica_indices if index != coordinator_index
    )
    coordinator_url = peer_urls[coordinator_index]

    if index_kind == "hnsw":
        _upload_hnsw(coordinator_url, fixture)
        session = _open_hnsw_owner_session(coordinator_url, BASE_EPOCH)
        _read_hnsw_owner_session(coordinator_url, fixture, session)
        commit = fixture["hnsw"]["commit"]
        commit_url = f"{coordinator_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/oram/commit"
        commit_body = {
            "session_id": session["session_id"],
            "old_epoch": commit["old_epoch"],
            "new_epoch": commit["new_epoch"],
            "old_root_hash": commit["old_root_hash"],
            "new_root_hash": commit["new_root_hash"],
            "updated_buckets": commit["updated_buckets"],
            "commit_signature": commit["signature"],
        }
    else:
        _upload_result_oram(coordinator_url, fixture)
        session = _open_result_owner_session(coordinator_url, BASE_EPOCH)
        _read_result_owner_session(coordinator_url, fixture, session)
        commit = fixture["result"]["commit"]
        commit_url = f"{coordinator_url}/collections/{COLLECTION}/private-result-oram/oram/commit"
        commit_body = {
            "session_id": session["session_id"],
            "old_epoch": commit["old_epoch"],
            "new_epoch": commit["new_epoch"],
            "old_root_hash": commit["old_root_hash"],
            "new_root_hash": commit["new_root_hash"],
            "updated_buckets": commit["updated_buckets"],
            "commit_signature": commit["signature"],
        }

    buckets_dir = _private_oram_buckets_dir(
        peer_dirs[finalize_failure_index], index_kind
    )
    original_mode = stat.S_IMODE(buckets_dir.stat().st_mode)
    buckets_dir.chmod(0o500)
    try:
        response = requests.post(commit_url, json=commit_body, timeout=60)
    finally:
        buckets_dir.chmod(original_mode)

    assert 500 <= response.status_code < 600
    for secret in [
        session["session_id"],
        commit["old_root_hash"],
        commit["new_root_hash"],
        commit["signature"]["sig"],
        commit["updated_buckets"][0]["ciphertext"],
    ]:
        assert secret not in response.text
    survivor_index = next(
        index for index in range(len(peer_urls)) if index != coordinator_index
    )
    restart_bootstrap_uri = get_uri(processes[survivor_index].p2p_port)
    processes.pop(coordinator_index).kill()
    restarted_url = start_peer(
        peer_dirs[coordinator_index],
        f"private_oram_{index_kind}_coordinator_restarted.log",
        restart_bootstrap_uri,
    )
    peer_urls[coordinator_index] = restarted_url
    wait_for_peer_online(restarted_url, path="/cluster")
    wait_for_uniform_cluster_status(peer_urls, leader)
    wait_collection_exists_and_active_on_all_peers(COLLECTION, peer_urls)

    if index_kind == "hnsw":
        recovered = _open_hnsw_owner_session(restarted_url, NEXT_EPOCH)
        recovered_close_url = f"{restarted_url}/collections/{COLLECTION}/private-hnsw/{VECTOR}/session/{recovered['session_id']}/close"
    else:
        recovered = _open_result_owner_session(restarted_url, NEXT_EPOCH)
        recovered_close_url = f"{restarted_url}/collections/{COLLECTION}/private-result-oram/session/{recovered['session_id']}/close"
    assert recovered["index_epoch"] == NEXT_EPOCH
    assert recovered["root_hash"] == commit["new_root_hash"]
    assert _post_result(recovered_close_url, {}) is True
