# qdrant-sec Large Work Plan

이 문서는 `RISK_REGISTER.md`의 대형 작업을 구현 순서대로 정리한다. 작은 방어 패치는 이미 별도 커밋으로 일부 처리됐고, 여기서는 설계, migration, 테스트 인프라, 구조 변경이 필요한 작업만 다룬다.

기준 브랜치: `sec`
최종 갱신: 2026-07-19

## 작업 원칙

- 각 단계는 독립 커밋 또는 작은 PR 단위로 끝낸다.
- 보안 기능은 fail-closed 테스트를 먼저 추가하고 구현한다.
- collection config 변경, key lifecycle, snapshot/replication 동작은 문서와 테스트 없이 코드만 바꾸지 않는다.
- legacy `params.ckks`는 더 이상 호환성 표면으로 유지하지 않고, collection config는 canonical `params.encryption`만 허용한다.
- `RISK_REGISTER.md`는 추적 문서이고 커밋 대상이 아니다.

## 현재 상태 요약

완료되었거나 현재 브랜치에서 fail-closed로 고정된 영역:

- Payload server-side encrypt-before-storage는 public upsert/set/overwrite/batch ingress에 연결되어 있다.
- Client-side zero-trust payload insert는 `$qdrant_client_aead`, mandatory Ed25519 signature, stable crypto identity, RK id/epoch/kdf-domain policy, request/process/collection-local persisted nonce replay cache를 사용한다.
- Server/client payload envelope provenance는 direct enum variant 조립 없이 safe constructor와 runtime-verified envelope key proof를 통해 collection write guard로 전달된다.
- Generic MK/RK material, wrapped RK, explicit opaque `material_fingerprint_id`, `rk_id`/`rk_epoch` envelope metadata, retired-material decrypt path, MK rewrap primitive가 들어가 있다.
- Public params diff와 direct config validation은 encryption/ckks mutation을 migration path 밖에서 거부한다.
- `ApplyCryptoMigration` meta operation과 migration plan validation/apply primitive가 있으며, dry-run은 config를 변경하지 않는다.
- Payload index/filter/order/group/formula/facet은 encrypted content에 대해 fail-closed 된다.
- CKKS encrypted vector dense ingest/update는 payload sidecar storage로 연결되어 있고, plaintext vector는 dense vector storage에서 제거된다.
- REST/gRPC legacy `search`, root direct `query`, raw-dense recommend/discover/context는 CKKS sidecar scoring으로 연결되어 있다. Nearest-neighbor `hnsw_ef` 요청은 segment-level CKKS ciphertext HNSW index primitive를 사용하며, graph cache는 in-memory와 collection-local disk cache로 보존된다.
- Quantization/ACORN/indexed-only search params와 plaintext-vector `HNSWIndex` file-format reuse는 아직 unsupported 상태에서 fail-closed 된다. Client-supplied encrypted CKKS query ciphertext, search matrix, prefetch/fusion/MMR, point-id recommend/discover/context examples, grouped variants는 문서화된 범위에서 sidecar scoring으로 라우팅된다.
- Snapshot/restore preflight, shard-transfer/replication/resharding start, dead-replica recovery source selection, readiness gate는 encrypted collection의 runtime crypto parity mismatch를 fail-closed 한다.
- OpenFHE bridge path/hash validation, parent-dir checks, env secret stripping, timeout/stdout/stderr malicious-behavior coverage, worker crash retry, worker pool, batch protocol, Linux Landlock write-deny and optional network-namespace egress-deny backend kinds가 들어가 있다.
- CKKS parameter allowlist는 정적 profile registry를 통해 관리하며, 현재 registry에는 `ckks-128-n16384-d4-scale50`만 포함한다.
- Encrypted payload read policy는 raw/redacted/decrypted 모드로 연결되어 있다. `decrypted`는 server-side `$qdrant_sec` payload text와 metadata value AEAD markers에만 적용되고 runtime settings와 global manage 또는 collection-scoped `payload_decrypt` 권한이 필요하며, client-side `$qdrant_client_aead`는 계속 raw/redacted만 지원한다.
- Metadata value AEAD와 client-generated blind-index token field는 canonical provider로 들어갔다. Blind-index token은 exact-match 전용이고 range/geo/full-text searchable encryption은 계속 unsupported다.
- `vector/private-hnsw-oram@v1`와 `payload/private-result-oram@v1`는 Phase 11 provider/API/store/SDK helper surface까지 연결되어 있다. Qdrant는 private HNSW ORAM에서 encrypted bucket store, manifest/signature validation, non-empty verifier registry validation, session lease, fixed-budget read/commit, epoch/root CAS만 수행하고, client SDK가 HNSW traversal, distance 계산, top-k, result payload ORAM fetch planning을 수행한다.
- Private ORAM REST/gRPC surface, OpenAPI Beta paths, metrics endpoint labels, snapshot/restore preflight, active-session snapshot/recovery/update/delete guard, ordinary search/upsert/payload read fail-closed guard, redaction/leakage tests가 들어가 있다.

남은 대형 작업:

- CKKS encrypted vector production-grade indexing: sidecar storage/search, segment-level ciphertext HNSW graph primitive, and client-supplied encrypted query ciphertext scoring are implemented, but plaintext-vector `HNSWIndex` file-format reuse, score decryption, and broader distributed rebuild/recovery coverage are still not implemented.
- OpenFHE checked bridge execution is Linux-only: runtime construction requires SHA-256 pinning and fd-backed `/proc/self/fd` execution, while non-Linux builds fail closed instead of using path-based validation/hash/exec.
- Crypto migration workflow: admin plan/rewrite/decrypt endpoints, point scan, verified checkpoint, decrypt completion, and re-encrypt primitive are implemented. 남은 범위는 background orchestration, persisted resume scheduling, rollback automation, and old-key disable/destroy retirement gate다.
- Cluster-wide client nonce replay ledger: request/process/collection-local/reload cache는 있지만 consensus-backed global ledger는 없다. Clustered client payload writes와 client-supplied CKKS encrypted query envelopes는 ledger가 구현될 때까지 fail-closed 된다.
- Metadata encryption: server-side metadata value AEAD와 client-generated exact-match blind-index token field provider/query integration은 들어갔다. Metadata value AEAD는 `encrypted_payload=decrypted` read mode와 `payload_decrypt` 권한을 공유한다. Server-computed tokens, range/geo/full-text searchable encryption, and dedicated metadata RBAC는 아직 없다.
- Encrypted payload read policy: raw envelope 반환은 기본값이고, REST/gRPC redacted/decrypted modes와 collection-scoped `payload_decrypt` capability는 연결되어 있다. 남은 범위는 export/read dump 정책과 SDK-side client envelope decrypt flow다.
- KMS/Vault key providers: local/env/file/fd/`unix_socket`/`vault_kv2`/wrapped material 기반은 있지만 external KMS lifecycle은 future work다.
- Broader distributed integration: current unit/integration coverage는 많지만 multi-node parity/restore/replay ledger e2e는 남아 있다.
- Private HNSW ORAM productionization: read-only bulk-built consensus-backed single-writer MVP, result ORAM fetch path, fixed multi-shard owner-union replication, per-shard manual/automatic `stream_records` preinstall, ReplicateShard/MoveShard/automatic recovery process E2E, partial live-preinstall failure/retry, active transfer abort/retry, exact active marked fixed-layout 및 reshard transfer restart/repreinstall, active reshard source hard-crash 상태 보존과 explicit exact-restart recovery, existing-peer active-reshard Raft snapshot topology recovery, chunked internal full-store transport, 63-bucket large-bundle process benchmark, durable collection-level layout CAS, typed scale-up/scale-down reshard start/progress/finish, exact active `resharding_stream_records` preinstall, HNSW-only 및 HNSW+result process E2E 기반은 들어갔다. 남은 범위는 dynamic online HNSW insertion, multi-writer ownership, active-reshard automatic task resume/new-peer snapshot bootstrap, shard-key layout mutation이다.

## Phase 0: 기준선 고정

목표: 이후 대형 변경이 현재 보안 계약을 깨뜨리지 않도록 최소 regression suite를 고정한다.

작업:

- `cargo test -p qdrant-ckks --test aead_security --test payload_security --test vector_security`를 기본 crypto regression으로 고정한다.
- `cargo test -p collection ckks`를 collection config regression으로 고정한다.
- 현재 문서화된 미지원 범위가 실제 API/schema와 어긋나지 않는지 확인한다.
- `RISK_REGISTER.md`의 이미 처리된 항목은 별도 후속 정리에서 상태를 `완료`로 바꾼다.

완료 조건:

- 기준 테스트 명령이 로컬에서 통과한다.
- 향후 phase별 PR 설명에서 이 기준 테스트를 재사용할 수 있다.

## Phase 1: Crypto Schema와 Migration State Machine

대상 리스크: `CONF-001`, `SEC-003`, `TEST-001`

목표: encryption rule 변경을 일반 config update가 아니라 명시적 migration workflow로 모델링한다.

작업 순서:

- collection config에 `crypto_schema_version` 또는 `encryption_epoch`를 추가한다.
- encrypted payload marker와 CKKS vector envelope에 schema/epoch를 기록한다.
- migration 상태를 `Disabled`, `Encrypting`, `Active`, `Rotating`, `Decrypting`으로 정의한다.
- 일반 collection update에서는 encryption enable/disable/rule 변경을 계속 거부한다.
- admin-only migration plan/rewrite/decrypt command를 유지하고, point scan과 verified checkpoint를 completion gate로 사용한다.
- completion checkpoint는 모든 shard id를 커버해야 하며, local shard가 있는 node에서는 checkpoint `total_points`가 실제 local shard point count와 일치해야 한다.
- migration dry-run이 변경 대상 point 수, selector 충돌, key availability를 보고하도록 유지한다.
- disable/decrypt migration은 client-side opaque envelope와 blind-index token을 건드리지 않으며, server-side decrypt completion은 verified checkpoint를 요구한다.
- 남은 작업은 migration run을 background task로 예약/재개하고, 실패 rollback과 old-key disable/destroy retirement gate를 운영 API로 묶는 것이다.

테스트:

- migration 없이 encryption config 변경 시 실패한다.
- migration 시작 후 collection 상태가 `Encrypting` 또는 `Rotating`으로 저장된다.
- rewrite/decrypt endpoint가 verified checkpoint를 반환하고 completion plan이 shard coverage와 local shard point count를 검증한다.
- 중단 후 재시작 시 background scheduler가 저장된 checkpoint부터 재개한다.
- 잘못된 key/runtime instance가 있으면 migration 시작 전에 실패한다.

완료 조건:

- 동일 collection 안에서 plaintext/ciphertext schema가 silent mixing되지 않는다.
- migration 없는 enable, disable, selector 변경, key 변경이 모두 fail-closed다.

## Phase 2: Key Lifecycle, Versions, and Rotation

대상 리스크: `SEC-003`

목표: active/retired key를 구분하고, rotation과 old key retirement를 안전한 상태 전이로 만든다.

작업 순서:

- runtime crypto material에 `key_version` 또는 `material_fingerprint`를 추가한다.
- AEAD envelope와 CKKS vector metadata에 `key_version` 또는 `material_fingerprint`를 기록한다.
- decrypt path는 active key와 retired key를 허용하되, encrypt path는 active key만 사용한다.
- re-encrypt primitive를 Phase 1 migration framework 위에 유지하고, endpoint가 stale envelope를 active RK로 reseal한다.
- old key retirement 전 full scan verification과 verified checkpoint를 요구한다.
- inline key material은 production/security mode에서 거부하거나 warning/audit event를 남긴다.
- KMS/Vault key source는 interface만 먼저 고정하고 구현은 provider별로 분리한다. File descriptor, Unix socket, Vault KV v2 direct material source는 운영용 fallback으로 유지한다.

테스트:

- old key로 암호화된 payload/vector envelope를 retired key로 복호화할 수 있다.
- 새 write는 active key로만 암호화된다.
- old key 제거 전 검증 실패 시 retirement가 중단된다.
- wrong key, wrong key_id, wrong key_version은 fail-closed다.

완료 조건:

- rotation 중 read/write가 어느 key를 쓰는지 문서와 코드에서 명확하다.
- key retirement는 검증 없이는 성공할 수 없다.

## Phase 3: Storage Path Threat Model and Plaintext Leakage Tests

대상 리스크: `SEC-004`, `TEST-001`

목표: WAL, segment, payload index, snapshot, shard transfer 경로에서 plaintext 노출 여부를 테스트로 증명한다.

작업 순서:

- `docs/ckks.md`에 ingress, WAL, segment, payload index, HNSW, snapshot, shard transfer, telemetry/log 경로별 plaintext/ciphertext 표를 추가한다.
- encrypted payload collection에 sentinel string을 upsert하는 integration fixture를 만든다.
- WAL, segment files, optimizer temp segment, snapshot archive에서 sentinel string이 검색되지 않는 테스트를 추가한다.
- vector plaintext byte pattern 또는 deterministic fixture vector가 segment/snapshot에 남지 않는지 검사한다.
- payload index 생성 시 encrypted field는 거부하거나 blind index 요구로 fail-closed한다.
- telemetry/log/audit output에 plaintext embedding/request body가 들어가지 않는지 smoke test를 추가한다.

테스트:

- plaintext string leakage scan.
- embedding byte pattern leakage scan.
- encrypted field index creation reject.
- snapshot archive scan.
- optimizer temp path scan.

완료 조건:

- `encrypt before storage` 주장이 테스트로 방어된다.
- plaintext가 남는 경로가 발견되면 해당 경로는 코드 수정 전까지 문서상 unsupported로 표시된다.

## Phase 4: Snapshot, Restore, Replication, and Cluster Fail-Closed

대상 리스크: `SEC-004`, `TEST-001`

목표: snapshot restore, shard transfer, replica sync에서 key/context 불일치가 silent partial success로 끝나지 않게 한다.

작업 순서:

- snapshot metadata에 필요한 crypto schema, key id/version, CKKS context digest summary를 기록한다.
- restore preflight에서 runtime key registry와 OpenFHE context availability를 검증한다.
- missing key, wrong key, wrong key_id, wrong context 정책을 정의한다.
- partial restore 허용 여부를 명시하고 기본은 fail-closed로 둔다.
- cluster node별 crypto instance registry health check를 추가한다.
- shard transfer 전 송신/수신 node의 crypto capability parity를 확인한다.

테스트:

- snapshot restore with missing key 실패.
- snapshot restore with wrong key 실패.
- snapshot restore with wrong CKKS context 실패.
- node A has key, node B missing key 상태에서 write/read/shard transfer 실패.
- replica join 전에 crypto registry mismatch가 health check에 노출된다.

완료 조건:

- key/context가 맞지 않는 cluster operation이 데이터 일부만 살리고 성공하지 않는다.
- 운영자가 restore 전에 어떤 runtime material이 필요한지 알 수 있다.

## Phase 5: OpenFHE Bridge Pool, Backpressure, and Protocol Efficiency

대상 리스크: `SEC-002`, `PERF-001`

목표: bridge worker를 단일 mutex 직렬 처리에서 process pool로 바꾸고, timeout/restart 경로를 검증한다.

작업 순서:

- `CryptoBackendConfig.size`가 실제 process pool size로 동작하도록 backend factory를 연결한다.
- worker pool abstraction을 추가한다.
- pool saturation은 caller를 무제한 queue에 쌓지 않고 worker request lock/timeout 경로에서 fail-closed 또는 backpressure semantics를 유지한다.
- worker별 stdin/stdout reader lifecycle을 독립 관리한다.
- timeout, EOF, invalid JSON, huge stdout/stderr, process exit 후 worker 재시작을 pool 단위로 처리한다.
- batch encrypt request/response protocol을 추가한다.
- successful first request 이후 같은 worker/context에서는 context/public key를 재전송하지 않는 cache protocol을 유지한다.
- binary framing 또는 MessagePack/CBOR 전환은 batch protocol 안정화 후 별도 단계로 진행한다.

테스트:

- concurrent encrypt N개가 pool size만큼 병렬 처리된다.
- queue 초과 시 bounded error가 반환된다.
- timeout worker만 재시작되고 다른 worker는 유지된다.
- no newline, huge stdout, huge stderr, invalid JSON, exit-after-write가 모두 fail-closed다.
- batch encrypt가 point-by-point 결과와 같은 envelope semantics를 유지한다.

완료 조건:

- bridge throughput이 단일 worker mutex에 의해 전역 직렬화되지 않는다.
- malicious bridge behavior가 pool 전체를 고착시키지 않는다.

## Phase 6: CKKS Parameter Profiles and OpenFHE Security Verification

대상 리스크: `SEC-005`

목표: 임의 raw parameter가 아니라 검증된 profile 중심으로 CKKS parameter를 받는다.

작업 순서:

- `ckks-128-d4` 같은 allowlisted profile enum을 정의한다.
- 기존 raw params는 `experimental_raw_params` 또는 feature flag 뒤로 이동한다.
- OpenFHE bridge가 security level, chain depth, scale/noise budget 검증 결과를 response에 포함하도록 protocol을 확장한다.
- Qdrant 쪽은 bridge 검증 결과가 없거나 mismatch면 collection create/update를 거부한다.
- known-safe profile table을 문서화한다.

테스트:

- allowlisted profile은 통과한다.
- raw params는 experimental flag 없이는 실패한다.
- OpenFHE security level mismatch는 실패한다.
- depth/scale/profile mismatch는 context digest와 validation에서 동시에 잡힌다.

완료 조건:

- 사용자가 임의 범위값만으로 unsafe CKKS context를 만들 수 없다.
- profile과 OpenFHE 검증 결과가 collection config에 명확히 남는다.

## Phase 7: Metadata Encryption and Blind Index Design

대상 리스크: `DOC-001`, `TEST-001`

목표: metadata encryption을 값 암호화와 exact-match 검색용 blind index로 분리해서 구현한다.

작업 순서:

- `metadata/aes-256-gcm@v1` metadata value AEAD와 `metadata/blind-index-hmac@v1` exact-match token provider contract를 분리한다. Exact-match blind-index token field는 `metadata/blind-index-hmac@v1` + `metadata-exact-match-token/v1`로 구현되어 있고, Qdrant는 token을 계산하지 않는다.
- metadata value envelope schema는 server-side `$qdrant_sec` AEAD marker를 사용하며 payload text와 동일한 write-provenance/fail-closed guard와 `encrypted_payload=decrypted` read policy를 탄다.
- exact-match token은 client/SDK가 deterministic HMAC/HKDF subkey로 만들고 원문 값을 저장하지 않는다.
- payload filter planner가 encrypted metadata field에 range/geo/full-text filter를 요청하면 거부한다.
- exact-match filter는 별도 blind-index token field를 대상으로 할 때만 허용한다.
- API docs에 지원/비지원 filter matrix를 추가한다.

테스트:

- metadata value는 retrieve/search/scroll에서 기본 raw marker로 반환되고, `encrypted_payload=decrypted`와 collection `payload_decrypt` 권한이 함께 있을 때 서버가 복호화해 반환한다.
- exact-match filter는 blind index token으로 동작한다.
- range/geo/full-text filter는 실패한다.
- metadata value selector는 `metadata-value/v1` binding과 `metadata/aes-256-gcm@v1` provider일 때만 허용하고, unsupported metadata bindings/providers는 계속 fail-closed 한다.

완료 조건:

- "metadata encryption 지원"이라는 문구가 실제 API 동작과 일치한다.
- AEAD-only metadata field가 검색 가능한 것처럼 보이지 않는다.

## Phase 8: Search Semantics Decision and Executor

대상 리스크: `ARCH-001`, `DOC-002`

목표: encrypted vector collection이 어떤 검색 모델을 지원하는지 타입과 API로 강제한다.

선택지:

- A안: at-rest encryption only. 검색은 plaintext vector 또는 별도 surrogate vector만 사용한다.
- B안: similarity-preserving/searchable encryption. 별도 보안 모델과 leakage profile을 문서화한다.
- C안: CKKS sidecar scoring. Qdrant dense vector storage에는 plaintext를 남기지 않고 `$qdrant_sec_vectors` sidecar ciphertext를 score한다.
- D안: native segment CKKS ciphertext HNSW index. Segment-level graph/index primitive는 들어갔지만, plaintext-vector `HNSWIndex` file format 재사용과 full collection optimizer lifecycle 통합은 별도 작업이다.

작업 순서:

- C안 sidecar storage/search는 현재 canonical 구현으로 선택됐다.
- `VectorCryptoBackend` capability는 encrypt, batch encrypt, encrypted-query scoring, stored-ciphertext scoring을 제공한다.
- collection create/update path는 encrypted dense vectors를 payload sidecar envelope로 저장하고 plaintext vector write를 제거한다. Sparse/multi-dense vector는 fail-closed 한다.
- query API는 plaintext dense query vectors를 bridge에서 encrypted query ciphertext로 변환할 수 있고, client-supplied encrypted CKKS query ciphertext도 sidecar scoring path로 받는다.
- Nearest-neighbor `search`/root direct `query`는 brute-force sidecar scoring 또는 `hnsw_ef` 기반 segment-level CKKS ciphertext HNSW graph를 사용한다. Serving records는 payload sidecar에서 읽고, graph primitive는 segment index type으로 관리한다.
- retrieve with/without decrypt, query failure modes, unsupported Qdrant flows는 `docs/ckks.md` 지원 matrix에 맞춰 계속 유지한다.

테스트:

- encrypted vector collection에서 unsupported search path는 명확한 error를 반환한다.
- Sidecar ingest/search/query/recommend/discover/context는 raw sidecar payload 반환, `with_vector` fail-closed, score threshold, wrong OpenFHE context fail-closed, plaintext vector leakage scan으로 검증된다.
- Segment-level CKKS ciphertext HNSW graph cache는 build, in-memory cache, disk persistence, pruning, hardening, stale/asymmetric cache ignore, and segment index file exposure tests로 검증된다.
- Plaintext-vector `HNSWIndex` file-format reuse와 score decrypt lifecycle은 아직 unsupported contract로 남긴다.

완료 조건:

- 사용자가 sidecar HNSW graph cache를 native Qdrant segment `HNSWIndex`로 오해할 수 없다.
- 지원되는 검색 모델과 unsupported 모델이 API validation, runtime capability, docs matrix, regression tests로 강제된다.

## Phase 9: Internal Crypto Module Split

대상 리스크: `ARCH-002`, `CONF-003`

목표: CKKS 중심 crypto layer를 `lib/crypto`의 공통 crypto layer와 provider-specific layer로 나눈다.

작업 순서:

- 내부 canonical type을 generic crypto plan으로 고정한다.
- legacy `params.ckks` REST/gRPC/schema 표면을 제거하고, canonical `params.encryption`만 받아들인다.
- 공통 AEAD envelope, key derivation, runtime registry를 `lib/crypto` 또는 equivalent module로 이동한다.
- CKKS vector provider를 `crypto-openfhe-ckks` 성격으로 분리한다.
- payload AEAD provider와 blind-index provider를 독립 모듈로 둔다.
- public exports와 docs를 새 경계에 맞춘다.

테스트:

- legacy config와 generic config가 같은 compiled plan으로 normalize된다.
- legacy projection은 key_id를 잃지 않는다.
- provider별 tests가 공통 crypto tests와 분리된다.

완료 조건:

- CKKS 고유 코드와 공통 crypto 코드의 책임 경계가 명확하다.
- 새 provider 추가가 CKKS 전용 모듈 경계에 계속 결합되지 않는다.

## Phase 10: User-Facing Examples and Release Gate

대상 리스크: `DOC-002`, `TEST-001`

목표: 운영자가 실제로 collection 생성부터 query/retrieve/failure mode까지 따라 할 수 있게 한다.

작업 순서:

- runtime config 예제를 generic `crypto.instances/materials/backends` 기준으로 갱신한다.
- collection create 예제를 legacy와 generic 중 canonical 하나로 정리한다.
- point upsert, retrieve, decrypt, query 예제를 작성한다.
- unsupported 기능 목록을 API docs와 `docs/ckks.md`에 맞춘다.
- PR 전 release gate checklist를 추가한다.

테스트:

- 문서 예제 JSON/YAML이 schema validation을 통과한다.
- smoke test가 예제 collection create/upsert/retrieve 경로를 실행한다.

완료 조건:

- 문서만 보고도 현재 지원 범위와 실패 모드를 이해할 수 있다.
- release gate가 security tests, migration tests, cluster tests, bridge tests를 모두 요구한다.

## Phase 11: Strict Zero-Trust Search with Private HNSW ORAM

목표: `vector/private-hnsw-oram@v1` provider를 추가해 strict zero-trust profile에서 검색 가능한 server-blind ANN path를 제공한다. Qdrant는 encrypted ORAM bucket store와 epoch/root CAS만 수행하고, client SDK가 HNSW traversal, distance 계산, top-k 결정을 수행한다.

작업 순서:

- Phase A: control-plane provider/binding const, runtime allowlist, strict-profile validation, collection binding validation, normal vector write/search fail-closed guard를 추가한다.
- Phase B: `PrivateHnswOramManifest` 타입, manifest signature format, collection-local `private_hnsw_oram/{vector}` store, bucket read/write primitive, epoch `current.json` CAS primitive를 추가한다.
- Phase C: REST/gRPC manifest, session open/close, ORAM `read_paths`, `commit`, session lease, single-writer lock, fixed request-size validation을 추가한다.
- Phase D: Rust 또는 Python reference SDK로 read-only bulk build, Path ORAM client, client-led HNSW traversal, known-answer fixtures를 제공한다.
- 현재 Rust helper는 f32 reference neighbor graph build, explicit-level f32 layered graph build, deterministic node-id level assignment, HNSW-style redundant-neighbor pruning, prebuilt node-block ORAM packing, encrypted bucket sealing/Merkle root generation, signed upload bundle packaging/preflight, manifest-aware writeback commit planning, verified encrypted traversal wrapper, optional post-commit signed manifest refresh, client state snapshot export/import, RK-derived encrypted client-state backup을 제공한다. Bulk build는 duplicate node id뿐 아니라 duplicate point token과 duplicate payload fetch token도 fail closed 하고, HNSW node block codec은 empty/non-contiguous level mask, out-of-mask neighbor level, self-neighbor, duplicate same-level neighbor, malformed/empty/non-finite `f32_le` vector bytes를 fail closed 하며, plaintext bucket codec과 client Path ORAM access도 decrypted path block을 stash에 흡수하기 전에 duplicate point/payload fetch token을 거부한다. 서버 테스트는 SDK-packaged manifest/bucket bundle이 REST/gRPC bucket upload와 같은 manifest epoch/root, fixed ciphertext size, Merkle commitment 계약을 만족하는지도 검증하고, crypto crate와 collection store fixture는 context-bound client key derivation으로 SDK upload/read_paths/verified-search/writeback-commit round trip을 검증한다. REST JSON DTO와 gRPC protobuf DTO fixture도 context-bound SDK-built manifest/buckets/session/read_paths/commit wire package를 round trip하고, gRPC fixture는 Merkle proof가 포함된 read response를 SDK verifier에 통과시킨다. REST/gRPC live route fixtures는 Dispatcher-backed collection에서 manifest upload, bucket upload, session open, `read_paths`, SDK proof verification, commit, close, manifest refresh 없이 committed epoch session reopen과 live epoch/root `read_paths`를 통과한다. SDK distribution packaging은 serde-compatible `PrivateHnswOramUploadBundle` API와 `validate_private_hnsw_oram_upload_bundle` preflight로 완료했다.
- Phase E: `ids_visible` result privacy를 문서화하고, `private_payload_oram_required` payload/result fetch 설계를 별도 provider 또는 index-token 확장으로 구체화한다.
  - 현재 working MVP는 `ids_visible`과 `private_payload_oram_required` private HNSW result mode를 구분하고, manifest/session policy도 runtime result privacy와 불일치하는 manifest를 거부한다. Runtime schema와 server-side HNSW manifest upload, bucket upload, session open, snapshot restore preflight는 `private_payload_oram_required`를 collection의 `private-result-oram/v1` payload rule이 `payload/private-result-oram@v1` provider에 함께 묶인 경우에만 허용하고, binding이 없으면 fail closed 한다. HNSW snapshot restore preflight도 paired result ORAM snapshot manifest의 `oram.path_batch_size`가 private HNSW `fixed_budget.fixed_result_k`를 나누는지 확인해 restored index가 partial final `read_buckets` batch를 만들지 못하게 한다. 일반 Qdrant search/query API는 계속 client-led private session 요구 오류를 반환한다.
  - HNSW SDK search hit은 node block의 `payload_fetch_token`을 전달하기 시작했고, `validate_private_hnsw_search_result_privacy` helper는 `private_payload_oram_required`에서 token 없는 hit을 fail closed 한다. SDK fetch-plan helper는 hit token을 정확히 `fixed_result_k`개 payload/result ORAM fetch token batch로 패딩하되 distinct dummy-token pool을 요구해 중복 logical fetch token, duplicate hit node/point, non-finite hit distance를 거부한다. Collection runtime은 `private_payload_oram_required`에서 result ORAM `oram.path_batch_size`가 private HNSW `fixed_budget.fixed_result_k`를 나누지 못하면 거부해 SDK가 partial final `read_buckets` batch를 만들 수 없게 한다. result ORAM client fetch planner와 verified fetch wrapper도 token batch 길이가 `oram.path_batch_size`의 정확한 배수가 아니면 fail closed 한다. private result ORAM fetch planner는 이 token batch와 client-held token-position map을 session `read_buckets` bucket-id sequence로 바꾸며, shared path bucket 중복을 제거하지 않고 보존해 fixed ORAM path volume이 overlap에 따라 줄어들지 않도록 한다. 서버 read validator도 duplicate bucket id를 허용하되 non-empty, whole-path-shaped, canonical Path ORAM heap path, 정확한 fixed-budget batch만 받는다. crypto crate는 collection/key lineage, index epoch, root hash, bucket count, exact padded bucket-id sequence를 묶는 canonical `read_buckets` message/sign/verify helper도 제공하고, REST/gRPC `read_buckets` API는 이 signed read request를 필수로 검증한 뒤 encrypted bucket read 또는 detailed path-shape error로 진행한다. planner는 missing position, duplicate token, duplicate position entry, out-of-range leaf를 fail closed 한다. private result ORAM client-only payload block/plaintext bucket codec도 추가되어 payload bytes, payload fetch token, point token, generation, deletion state를 fixed-size encrypted bucket body 안에 넣을 수 있다. bucket AEAD seal/open helper는 collection/key/epoch AAD, context-bound bucket commitment, ciphertext hash check, Merkle-proof-before-open read batch 검증까지 제공한다. SDK-side result ORAM state/access helper는 token position map/stash로 payload fetch token을 Path ORAM path에서 꺼내고 새 leaf로 remap한 뒤 commit용 plaintext writeback bucket을 만들며, duplicate payload fetch token과 duplicate point token은 plaintext bucket codec과 stash 흡수 경계에서 fail closed 한다. Verified token-fetch helper는 client position map에서 expected bucket path sequence를 재구성해 read plan과 일치해야만 planned encrypted bucket batches를 열고, fetched payload block의 duplicate point token을 token-fetch result 생성 전에 거부하며, batched Path ORAM access 사이의 local writeback overlay를 적용하고 payload blocks와 result ORAM commit planner용 unique resealed writeback buckets를 반환한다. REST/gRPC result ORAM commit guard는 owner-signed `updated_buckets`를 `oram.path_batch_size * (oram.tree_height + 1)` fixed writeback budget으로 제한해 commit volume이 manifest `bucket_count`까지 확장되지 않게 하고, multi-batch result fetch는 반복 fixed-size read/commit window로 처리한다. empty/duplicate/stale/malformed/invalid-signature commit은 계속 fail closed 한다. HNSW SDK finalizer는 real HNSW hit만 fetched payload block에 매핑하고 fetched token set, point-token binding, deleted payload rejection을 검증한다. HNSW padded fetch-token plan이 result ORAM ordered read planner의 fixed-size batch로 들어간 뒤 reordered fetch 결과를 finalizer가 real hit 순서로 복원하는 연결 테스트도 고정했다. result ORAM client-state plaintext snapshot shape도 추가해 token position map/stash backup shape를 검증하고, duplicate stash payload token과 duplicate stash point token을 import 경계에서 거부한다. encrypted snapshot helper는 client-derived state key와 collection/key/epoch/root AAD로 backup ciphertext를 seal/open한다.
  - Result ORAM `read_buckets` SDK ordered planner `plan_private_result_oram_ordered_read_bucket_batches_for_fetch_tokens`는 token-position leaf collision을 가능한 다른 fixed batch로 분산하고, configured batch count로 수용할 수 없는 repeated full ORAM path만 fail closed 한다. Verified fetch wrapper, server request validator, crypto message builder는 shared prefix bucket 중복은 보존하되 같은 fixed batch 안의 repeated full ORAM path는 fail closed 한다. 이 invariant는 unschedulable token-position leaf collision이나 stale/malicious read plan이 서버 `read_buckets` 요청으로 나가기 전에 잡히도록 한다.
  - Ordered planner는 작은 Path ORAM fixture의 모든 feasible leaf-count 분포를 스케줄할 수 있는지도 회귀 테스트로 고정해, 대표 collision 케이스뿐 아니라 greedy batch distribution invariant를 폭넓게 검증한다.
  - Ordered result ORAM read plan Debug 표면도 payload fetch token list와 token count를 반사하지 않는 redaction fixture에 포함했다.
  - Result ORAM `read_buckets` crypto message builder/signer/validator는 signed `bucket_count`에서 canonical Path ORAM tree height를 역산하고, non-canonical tree size, partial path, invalid root-to-leaf bucket sequence를 signature acceptance 전에 거부한다.
  - REST/gRPC result ORAM `read_buckets` route fixtures now also assert that signed malformed path-shape errors and out-of-range bucket-id signature failures do not reflect submitted root hashes, session ids, read signatures, or bucket ciphertext bodies.
  - REST/gRPC result ORAM `read_buckets`와 `commit` request signature key id도 session manifest의 `owner_signing_key_id`와 달라도 fail closed 한다. Runtime `signature_public_keys`에 등록된 다른 key id만으로는 해당 private result index의 read/writeback request를 authorize하지 않는다.
- `payload/private-result-oram@v1` runtime provider validation은 초기 E2에서 열렸고 현재 REST/gRPC session/read/commit 표면까지 연결됐다. runtime instance는 server materials/backend 없이 `key_id`, `expected_rk_id`, pinned RK epoch, Path ORAM shape, integrity booleans, signature public key registry만 허용한다. `private-result-oram/v1` collection binding validation은 provider `payload/private-result-oram@v1`만 허용하며 ordinary point upsert/sync/delete/delete-by-filter/payload write/delete/clear plan과 payload index/schema plan에는 들어가지 않는다. 그런 요청은 private result ORAM session API 안내와 함께 fail closed 한다. Ordinary point upsert/sync는 payload 내용이 public-looking이더라도 private result ORAM epoch contract 밖에서 point payload state를 만들거나 교체할 수 있으므로 binding이 있으면 닫고, key-less `overwrite_payload`는 full payload replacement로 취급한다. key-less `set_payload`도 protected path의 parent/child key overlap을 건드리면 fail closed 하며, exact child-only public payload merges만 일반 경로에서 허용한다. Ordinary retrieve/scroll/search/query raw payload reads도 `with_payload`가 private result ORAM payload path를 반환하려 하면 같은 session API 안내와 함께 fail closed 하고, payload 생략 또는 redacted encrypted payload output만 일반 read 경로에서 허용한다. Trusted-bridge CKKS sidecar fallback, point-id resolution, grouped sidecar search, CKKS search matrix는 이제 full raw payload 대신 reserved vector sidecar와 필요한 group key만 요청해 private result ORAM payload path를 실수로 건드리지 않는다. Filter/order-by/group-by/facet/formula selector가 private result ORAM payload path를 inspect하려는 경우도 blind-index 안내 대신 private result ORAM session API 안내로 fail closed 한다. REST/gRPC manifest/bucket upload API, session open/close, signed session-bound `read_buckets`, signed writeback `commit` API도 열었고, live route fixtures는 manifest refresh 없이 committed epoch session reopen과 live epoch/root `read_buckets`를 통과한다.
  - `PrivateResultOramManifest`, `PrivateResultOramBucket`, `PrivateResultOramSignature`, canonical manifest/commit signature message, Ed25519 signature verification/signing helpers, collection/key/epoch/capacity context validation, Path ORAM tree_height/bucket_count validation, encrypted bucket shape/hash validation, context-bound bucket commitment validation, bucket commitment Merkle root/proof verifier, client writeback commit planning helper, manifest-aware writeback commit planning helper, signed upload bundle packaging/preflight, optional post-commit signed manifest refresh helper는 crypto crate에 contract surface로 들어갔다. collection-local `PrivateResultOramStore` 구현은 `private_result_oram/manifest.json`, `manifest.sig`, encrypted buckets, Merkle commitment metadata, epoch `current.json` CAS, canonical `merkle_path_batch/v1` read proof DTO, initial upload bundle ingest, signed initial upload bundle ingest, writeback commit helper를 private HNSW ORAM store와 같은 fail-closed hardening으로 다룬다. initial upload bundle ingest는 crypto crate의 같은 preflight helper를 사용한 뒤 store runtime ciphertext size cap을 추가로 적용하고, signed ingest entrypoint는 owner Ed25519 manifest signature를 검증한 뒤에만 layout/bucket/current epoch 파일을 쓴다. writeback commit helper는 stale current epoch, bucket count, bucket commitment context를 bucket/Merkle writeback 전에 preflight하고, updated bucket commitment가 ciphertext hash와 collection/key lineage/bucket epoch context에 묶여 있는지 Merkle prepare 전에 검증해 실패한 stale/tampered commit이 저장 파일을 먼저 바꾸지 않도록 한다. collection snapshot은 configured `private-result-oram/v1` binding이 있을 때만 `private_result_oram/`을 포함하고, collection restore와 CLI/REST/storage recovery preflight는 manifest/current epoch, buckets, Merkle metadata, runtime Ed25519 signature를 fail-closed로 검증한다. runtime session은 single-writer lock과 active snapshot/upload guard를 사용하며, read/commit은 active session epoch/root와 current store epoch/root가 맞을 때만 수행된다.
  - Phase E rollout은 네 단계로 나눈다. E1은 provider/binding/result privacy enum을 예약하고 store/crypto contract를 fail-closed contract로 고정했다. E2는 runtime provider validation만 열되 collection binding과 API는 계속 닫아 provider options, signature registry, RK pinning, ORAM capacity, ciphertext cap 정책을 먼저 고정했다. E3는 collection binding, snapshot/restore preflight, manifest/bucket upload/read API를 열되 private HNSW `private_payload_oram_required`와 연결하지 않았다. E4는 private result ORAM session/read/commit API와 HNSW result fetch-token SDK linkage를 열었고, HNSW manifest/session/snapshot policy는 collection에 result ORAM binding이 있을 때만 `private_payload_oram_required`를 허용한다.
  - OpenAPI Beta surface는 private HNSW ORAM과 private result ORAM manifest upload/read, bucket upload, session open/close, read, commit REST paths를 노출하고 `docs/redoc/master/openapi.json` 생성물과 consistency endpoint count를 갱신했다. Consistency check는 14개 private ORAM REST method/path/operationId와 14개 generated gRPC method path도 직접 고정한다. REST/gRPC request metrics whitelist도 같은 private ORAM fixed endpoint labels를 포함하되 path labels, bucket ids, session ids, ciphertext, client-state fields는 metric labels에 넣지 않는다. gRPC metrics canonicalization fixture는 HNSW/result manifest get/upload, HNSW bucket upload, read, commit, close-session의 동적 suffix도 fixed method label로만 축약되는지 검증한다.
- Phase F: upper-layer client cache, speculative neighbor prefetch, neighbor clustering, graph-tailored ORAM 실험을 benchmark와 함께 추가한다.
  - upper-layer client cache는 `PrivateHnswClientNodeCache`와 `*_with_cache` search helper로 시작했다. 캐시 hit는 local node copy로 traversal/distance를 수행하되 `padding_node_id` ORAM access를 소비해 fixed-step request volume을 유지한다. Client traversal pending queue도 `VecDeque` 기반 FIFO로 유지해 fixed-step search hot path가 queue pop마다 앞쪽 원소를 shift하지 않는다.
  - search access metrics는 `PrivateHnswSearchResult::access_metrics`와 `PrivateHnswSearchAccessMetrics`로 시작했다. SDK benchmark가 fixed-budget ORAM search의 path access 수, unique leaf 수, budget exhaustion 여부를 plaintext 노출 없이 기록할 수 있다. zero-step params나 malformed access leaf-label이 있는 결과는 빈도/길이가 맞아도 exhausted로 보고하지 않는다. Strict SDK caller용 `validate_private_hnsw_strict_search_result` helper도 추가해 result privacy, canonical access leaf-label shape, finite hit distance, duplicate hit node/point, fixed-step budget exhaustion을 함께 fail-closed로 검증한다. Private result ORAM fetch planner와 payload finalizer도 같은 hit-shape 검증을 반복한다.
  - layered f32 builder는 u64 `level_mask` 경계를 fail-closed로 다룬다. level 63은 `u64::MAX` mask로 표현하고, level 64 이상은 panic/overflow 없이 invalid `levels` config로 거부한다.
  - benchmark harness는 `cargo bench -p qdrant-sec --bench private_hnsw_oram_bench`로 시작했다. 현재는 64x32 f32 fixture의 plaintext index build, fixed-budget plaintext ORAM-HNSW traversal, upper-layer client-cache traversal, client-AEAD encrypted bucket traversal, speculative prefetch planning, neighbor-clustered leaf planning, directional neighbor filtering, graph-traversal path batch planning with retained/path stats를 잰다. Benchmark fixture도 collection/vector/RK epoch context-bound client key derivation을 사용한다.
  - speculative neighbor prefetch는 `plan_private_hnsw_oram_speculative_prefetch` helper로 시작했다. SDK가 client position map에서 후보 node leaf를 deduplicate하고 고정 path 수까지 server `read_paths` duplicate-label guard와 호환되는 unique dummy leaf로 padding한 label 묶음을 만들 수 있다. Leaf-label bucket-path helper도 duplicate label을 bucket sequence 생성 전에 거부한다.
  - neighbor clustering은 `plan_private_hnsw_oram_neighbor_clustered_leaves` helper로 시작했다. bulk build 전에 entry에서 graph-order BFS를 수행해 관련 node chain을 인접 leaf에 배정하는 실험용 leaf planner이며, entry node id가 build block set에 없으면 fallback하지 않고 fail closed 한다. BFS queue는 `VecDeque` 기반이라 planner 자체가 fixture 규모 증가에 따라 불필요한 O(n²) queue shift 비용을 내지 않는다.
  - directional neighbor filtering은 `plan_private_hnsw_oram_directional_neighbor_filter` helper로 시작했다. client가 현재 노드/neighbor block/query vector를 로컬에서 해독한 뒤 query 방향으로 진행하는 neighbor만 거리순으로 고르는 실험용 planner다.
  - graph-traversal tailored ORAM은 `plan_private_hnsw_oram_graph_traversal_path_batch` helper로 시작했다. directional neighbor filter 결과를 client position map과 speculative prefetch padding에 연결해 fixed-size `read_paths` batch를 만든다. `*_with_stats` variant는 directional filter retained count와 실제 position-map-backed path count를 분리해 benchmark가 graph-filter selectivity와 ORAM path volume을 따로 기록할 수 있게 한다.
  - graph traversal/prefetch planner는 real candidate가 0개이거나 directional filter가 모든 neighbor를 버리는 경우에도 dummy leaf로 정확한 fixed-size path batch를 만들고, padding leaf도 중복 없이 순환하는지 회귀 테스트로 고정한다.
  - Strict SDK search result validator는 `ids_visible` result mode에서도 fixed-budget exhaustion을 요구하고, zero-step budget을 invalid config로 거부한다.
- Phase G: cluster parity fingerprint, private-ORAM transfer fail-closed, shard-local epoch ownership, consensus-backed epoch/root CAS를 설계하고 e2e 테스트한다.
  - cluster parity fingerprint는 기존 crypto runtime capability fingerprint에 private HNSW ORAM과 private result ORAM options/signing verifier policy가 포함되는 테스트로 고정했다. ORAM tree shape, private HNSW signing verifier drift, private result ORAM signing verifier drift는 peer parity mismatch로 실패한다. mismatch 오류, `/readyz` readiness mismatch 출력, distributed telemetry mismatch summary는 peer id만 남기고 local/peer fingerprint 문자열이나 private ORAM verifier key sentinel을 반사하지 않는다.
  - App telemetry와 anonymized app telemetry는 private HNSW ORAM과 private result ORAM `signature_public_keys` registry 원문을 직렬화하지 않고 non-secret runtime capability fingerprint만 내보내며, anonymized telemetry에서는 fingerprint도 제거한다. private ORAM verifier public key sentinel fixture로 회귀를 고정한다.
  - private-ORAM cluster gate는 고정 layout의 수동 `move_shard`/`replicate_shard`, automatic dead-replica recovery, exact active fixed-layout/reshard restart, reserved single-`Active` replica removal을 지원한다. Typed scale-up/down resharding은 별도 start/finish Raft operation과 active `ReshardState`에 정확히 대응하는 source-coordinated `ReplicateShard(resharding_stream_records)`만 연다. 모든 경로는 configured HNSW/result index의 동일 consensus reservation 아래 target에 current epoch/root/writeback digest와 전체 encrypted bucket bundle을 설치한 뒤 `private_oram_preinstalled` marker를 제출한다. 미표시·filtered·wrong-stage·wrong-endpoint·wrong-method transfer/restart, `replicate_points`, snapshot/WAL transfer, shard-key layout 변경, dead/transitional/batch/final replica removal은 fail closed 한다.
  - replica-state update guard는 private ORAM collection에서 active `MigratingPoints` reshard와 정확히 일치하는 scale-up target `Resharding -> Active` 또는 scale-down receiver `ReshardingScaleDown -> Active`만 허용한다. 그 밖의 resharding transition은 fail closed 하고, unrelated non-resharding state-only transition은 기존 동작을 유지한다.
  - consensus snapshot apply도 private ORAM bucket store collection에서는 exact supported shape와 `private_oram_preinstalled` marker를 가진 transfer state만 허용한다. Unmarked/unsupported transfer, non-empty resharding state, shard layout config 변경, unrelated shard id set/shard-key mapping/replica membership 변경, resharding replica-state 주입은 fail closed 한다. Empty transfer/resharding cleanup state와 non-resharding replica state-only sync는 허용하고, `Dead`/`Partial`/`Initializing`/`Listener`/`PartialSnapshot`/`Recovery`/`ActiveRead`/`ManualRecovery` 상태 적용이 guard에 막히지 않는지 테스트로 고정했다.
  - Storage consensus apply guard 오류도 private HNSW/result ORAM collection id/name, runtime key id, rule id, instance id, binding id, collection-local store directory name 같은 config sentinel을 반사하지 않는지 transfer/resharding/shard-key/replica-remove fixture로 고정한다. Cluster submit guard 오류도 같은 store directory sentinel을 반사하지 않는지 검증한다.
  - Private ORAM resharding/shard-key guards는 consensus submit과 collection-local layout 변경 경계 모두에서 호출자가 넘긴 operation label을 오류에 반사하지 않고 고정 resharding/shard-key layout 메시지만 반환한다.
  - 수동 shard snapshot 생성/stream/download/recovery와 partial snapshot manifest 조회도 private ORAM bucket store collection에서는 fail closed 한다. partial snapshot recovery는 recovery lock 상태를 관찰하기 전에 같은 guard로 먼저 닫는다. guard 오류는 호출자가 넘긴 operation label, private ORAM key id, rule id, instance id, binding id, collection-local store directory name을 반사하지 않는다. 현재 private index는 collection-local `private_hnsw_oram/` 또는 `private_result_oram/` bucket store이므로 shard snapshot만으로는 epoch/root parity를 보존할 수 없다.
  - distributed private ORAM session open/read/commit/close는 Dispatcher consensus coordinator가 있을 때 recovery, per-index hashed lease CAS, all-replica encrypted writeback, digest-bound epoch/root CAS를 거친다. Consensus coordinator가 없는 distributed REST/gRPC fixture와 common direct 호출은 기존 consensus-backed CAS guard에서 계속 fail closed 한다.
  - Raft persistent state에는 private HNSW/result ORAM index identity를 domain-separated digest로 키잉한 internal epoch/root CAS record가 추가됐다. CAS operation은 initial ownership 등록, exact old epoch/root precondition, monotonic epoch, canonical root hash를 검증하고, optional writeback digest로 provider-domain canonical signed commit message 전체의 SHA-256을 새 epoch에 결합한다. 이 digest는 lineage, old/new epoch/root, ordered encrypted bucket hash를 묶되 bucket id와 ciphertext 자체는 Raft에 저장하지 않는다. Initial ownership과 구형 persisted/Raft snapshot state는 digest `None`으로 호환된다. 이미 current state가 digest까지 정확히 requested new state인 동일 old→new replay는 no-op success로 처리하되, 같은 epoch/root라도 digest가 다른 writeback과 다른 new state를 가진 conflicting stale replay는 거부한다. 따라서 consensus apply 직후 응답 전에 중단된 coordinator가 같은 CAS를 안전하게 재제출할 수 있으며, state는 restart와 Raft snapshot apply를 통과한다. Dispatcher에는 local Raft apply 결과까지 기다리는 internal CAS submit/read bridge와 durable local prepare → awaited Raft CAS → idempotent local finalize 순서를 강제하는 internal writeback coordinator가 있다. CAS가 거부되면 coordinator는 abort callback을 호출하고, HNSW/result store abort는 owner-signed journal을 재검증한 뒤 local epoch, old Merkle tree, 모든 target bucket이 old view와 일치할 때만 journal을 삭제한다. 일부 bucket/Merkle/final epoch 반영이 시작된 상태에서는 abort가 journal을 보존하고 fail closed 한다. 실제 Raft loop fixture는 prepare 실패 시 consensus/finalize 미실행, conflicting stale CAS 시 abort 실행/finalize 미실행, consensus apply 뒤 local finalize 실패, 동일 operation retry가 exact CAS no-op을 거쳐 finalize를 다시 수행하는 경로를 검증하며, persistent/raft-snapshot fixture도 exact replay idempotence와 digest mismatch를 포함한 conflicting stale rejection을 고정한다. 이 internal state/coordinator만으로 encrypted bucket ownership/movement가 해결되는 것은 아니므로 distributed manifest/upload/session/read/commit guard는 bucket replication과 API commit 연동이 완료될 때까지 계속 닫혀 있다.
  - HNSW/result collection store는 owner-signed durable journal에서 old/new epoch, encrypted bucket batch, bucket count, commit signature만 담은 replication batch와 canonical consensus transition을 export할 수 있다. Receiver prepare primitive는 manifest-derived fixed writeback budget을 먼저 강제하고, canonical digest가 expected consensus transition과 정확히 일치하는지 journal 생성 전에 확인한 뒤, receiver 자신의 old Merkle tree에서 new tree를 재계산해 durable pending journal을 만든다. Merkle tree 파일은 transport payload로 신뢰하거나 복사하지 않는다. Dispatcher provider-specific CAS builder는 현재 Raft record를 읽어 local transition의 old epoch/root와 대조하고, 이전 writeback digest를 expected state에 그대로 보존하면서 새 digest를 new state에 넣는다. Source/replica fixture는 consensus mismatch가 receiver journal 생성 전에 거부되고 valid encrypted batch가 양쪽에서 같은 transition과 final bucket을 만드는지 검증하며, 연속 Raft writeback fixture는 이전 digest 보존을 고정한다. 아직 peer fan-out/ack, owner assignment, restart recovery orchestration, network transport는 연결되지 않았으므로 distributed API guard는 계속 닫혀 있다.
  - Dispatcher replicated-writeback coordinator는 required replica peer set과 정확히 일치하고 canonical writeback digest가 같은 prepare ACK를 모두 받은 뒤에만 Raft CAS를 제출한다. Remote prepare 실패, missing/duplicate/extra ACK, digest mismatch, CAS rejection은 remote/local abort를 모두 시도한다. Raft apply 뒤에는 remote finalize를 먼저 수행하고 local owner finalize를 마지막에 수행해 remote retry가 필요한 동안 owner journal을 보존한다. ACK Debug와 오류는 digest를 반사하지 않는다. 실제 Raft fixture는 incomplete ACK가 abort 후 consensus를 유지하는 경로와 exact ACK set이 remote-before-local finalize 순서로 다음 digest를 commit하는 경로를 고정한다. Collection-local ORAM store의 v1 peer set은 모든 shard가 동일한 non-empty `Active` replica membership을 가지며 current peer를 포함하고 모든 remote internal address가 알려진 경우에만 Dispatcher가 derive한다. Transitional replica state, shard별 membership 차이, local ownership 누락, unknown remote address는 fan-out 전에 fail closed 한다. HNSW/result receiver finalize/abort primitive는 expected old/new epoch/root와 writeback digest가 owner-signed pending journal의 canonical transition과 정확히 같아야 하며 mismatch 시 journal과 old state를 보존한다. 별도 consensus-backed private-ORAM ownership record와 owner-side ChannelService fan-out 연결은 아직 없으므로 distributed route guard는 계속 닫혀 있다.
  - Internal protobuf에는 HNSW/result index kind, collection identity, exact old/new epoch/root와 canonical digest, typed encrypted bucket batch, owner commit signature를 분리한 private ORAM prepare/completion wire DTO를 추가했다. Opaque JSON payload는 사용하지 않는다. QdrantInternal prepare/finalize/abort RPC는 stable collection identity, runtime binding, manifest/owner signature, fixed writeback budget, bucket hash/commitment, Merkle transition, canonical digest를 receiver에서 재검증하고 node-local service lock으로 journal mutation을 직렬화한다. Finalize/abort는 exact pending transition만 처리한다. Finalize 응답 유실 후 prepare 재시도는 current epoch/root, Merkle tree, 모든 updated encrypted bucket이 signed batch와 정확히 같을 때만 digest ACK를 재전송하고 새 journal을 만들지 않는다. Wire bound 오류는 ciphertext/digest/signing-key를 반사하지 않는다. Owner-side ChannelService fan-out과 multi-peer e2e 전까지 distributed route guard를 유지한다.
  - ChannelService는 단일 peer private ORAM prepare/finalize/abort RPC를 호출하고 transport/server 오류를 peer id만 남기는 고정 메시지로 sanitize한다. Dispatcher provider-specific request builder는 encrypted batch old/new와 canonical transition의 exact match를 serialization 전에 강제한다. High-level HNSW/result coordinator wrapper는 collection shard layout에서 exact remote peer set을 derive하고 prepare를 병렬 전송한 뒤 모든 future를 끝까지 수집하며, exact peer/digest ACK 검증 → Raft CAS → remote-before-local finalize 순서를 기존 coordinator에 연결한다. Abort/finalize fan-out도 한 peer 실패로 다른 peer 호출을 취소하지 않는다. Finalize는 `completed=true`를 요구하고 abort no-op은 idempotent하게 허용한다. Public client commit route 연결과 multi-peer e2e 전까지 distributed route guard를 유지한다.
  - HNSW/result collection store는 persisted current epoch/root가 signed manifest epoch/root와 같은 initial state이고 durable pending writeback이 없을 때만 complete encrypted upload bundle을 export한다. Export는 manifest ORAM tree에서 canonical bucket count를 재계산하고 caller-provided aggregate memory budget을 allocation 전에 강제한 뒤 모든 bucket과 full upload bundle, persisted Merkle leaf set을 다시 검증한다. Writeback으로 epoch가 진행된 store, manifest epoch에 남아 있어도 pending journal이 있는 store, oversized bundle은 initial export와 exact idempotent install에서 root/digest/ciphertext를 반사하지 않고 fail closed 한다.
  - QdrantInternal initial install RPC는 existing typed HNSW/result manifest/signature/bucket protobuf를 provider-discriminated oneof로 전달한다. Receiver는 decode/aggregate bounds, provider kind/oneof/vector convention, stable collection identity, runtime binding, manifest owner signature, full upload bundle을 node-local mutation lock 아래 재검증하고 exact existing bundle만 idempotent success로 인정한다. ChannelService install 오류는 peer id만 남긴다. Dispatcher initial coordinator는 derived remote replica 전체에 병렬 install을 보내고 실패 뒤에도 모든 future를 수집하며, 모든 ACK epoch/root가 expected state와 같을 때만 `expected=None`, digest-free initial ownership CAS를 Raft에 제출한다. CAS 실패 시 validated encrypted bundle은 exact retry를 위해 유지한다.
  - Public REST/gRPC initial manifest route는 Dispatcher consensus state가 있을 때만 coordinator-local staging helper를 사용한다. Complete bucket route는 persisted manifest/current epoch, 전체 canonical bucket set, Merkle leaves를 bounded export로 다시 검증하고 typed initial install을 모든 derived active replica에 fan-out한 뒤 initial ownership CAS가 apply되어야 성공을 반환한다. Consensus coordinator가 없는 distributed TOC와 common upload 직접 호출은 기존 single-node guard에서 계속 fail closed 한다. Manifest staging은 initial CAS 전까지 node-local이므로 client는 manifest와 bucket request를 같은 coordinator node에 보내고 불확정 응답에는 exact signed bundle을 재시도해야 한다. Session/read/writeback route guard는 유지한다.
  - Provider-neutral distributed recovery classifier는 local current state, optional signed pending transition, Raft ownership epoch/root/writeback digest를 비교한다. Pending이 없으면 local과 consensus exact epoch/root만 clean으로 인정하고, pending이 있으면 local+consensus가 old일 때만 abort, consensus가 exact new epoch/root/digest일 때만 finalize를 허용한다. Missing ownership, unrelated state, digest drift, local new/consensus old rollback 상태는 root/digest를 반사하지 않고 fail closed 한다. 다음 단계는 HNSW/result pending journal validation과 remote/local completion fan-out을 이 결정에 연결하는 것이다.
  - HNSW/result recovery context는 runtime/manifest owner/current epoch/signed pending replication batch를 재검증하고 context lifetime 동안 existing upload/session mutation reservation을 유지한다. Internal recovery orchestrator는 Raft classifier 결과에 따라 active replica set 전체에 exact abort/finalize completion을 remote-first로 fan-out한 뒤 같은 transition을 local에 적용한다. Clean initial context inspection은 두 provider route fixture로 고정했다.
  - Signed finalize는 pending journal을 제거하기 전에 canonical epoch commit file에 epoch/root/writeback digest completion record를 durable하게 기록한다. Pending이 없는 finalize replay는 current epoch/root, validated Merkle epoch/root, completion record의 exact digest가 모두 일치할 때만 idempotent success이고, same epoch/root의 conflicting digest는 fail closed 한다. Legacy digest-less commit은 signed pending journal과 최종 bucket/Merkle 상태를 재검증한 crash recovery에서만 exact digest record로 승격한다. Snapshot source/restore preflight는 canonical digest-bearing commit을 허용하지만 `current.json` digest와 malformed digest를 redacted 오류로 거부한다. 이로써 partial remote-finalize recovery 재시도 경계는 해소됐고, 다음 단계는 consensus-backed session ownership과 public commit route 연결이다.
  - Raft persistent/snapshot state에는 epoch map과 분리된 per-index private ORAM session lease map을 추가했다. Lease는 owner peer, opaque lease id의 SHA-256 hash, bounded issued/expires time만 저장하고 index identity는 기존 domain-separated key digest 뒤에 숨긴다. Exact CAS는 initial acquire, same-owner renewal, exact release, `new.issued_at >= old.expires_at`인 deterministic expired takeover만 허용하며 early takeover/stale release/overlong lease/malformed hash를 fail closed 한다. Restart와 Raft snapshot restore, legacy snapshot default, debug/log redaction 테스트를 추가했고 Dispatcher에 awaited apply 및 current lease 조회 bridge를 연결했다. Public session open/renew/close와 replicated commit은 이 lease hash를 사용한다.
  - Resharding용 collection-level private ORAM layout 합의 레코드 기반을 추가했다. Stable collection identity는 별도 domain-separated SHA-256 map key로만 persistent/Raft snapshot에 저장되고, 값은 generation, canonical sorted owner-peer union, shard-layout digest, layout transition 시점의 전체 private ORAM index epoch/root/writeback-completion-set digest를 보존한다. Initial generation 1과 이후 정확한 `+1` CAS만 허용하고 exact replay는 idempotent하며, empty/unsorted/duplicate/oversized owner set과 malformed digest, stale precondition, generation skip을 fail closed 한다. Persistent reload, legacy/new snapshot restore, 실제 single-peer Raft proposal/apply, Dispatcher bridge, raw/redacted Debug 비노출 회귀가 들어갔다. Shard-layout/index-state digest는 각각 별도 domain 아래 stable collection id, sharding mode, sorted shard/typed shard-key/per-shard active owners와 sorted provider kind/name/epoch/root/optional writeback digest를 length-prefixed 및 fixed big-endian encoding으로 묶고 KAT로 고정했다. Replica-removal coordinator는 모든 configured index의 동일한 live consensus reservation을 전후로 재확인하고, record가 없으면 stable pre-layout을 generation 1로 bootstrap한다. 이후 exact lease/current index-state 검증, generation `+1` layout CAS, reserved single-replica metadata 제거, post-layout 검증을 하나의 Raft operation apply 경계로 묶었다. Pure pre/post classifier와 persistent/ConsensusManager replay 테스트는 이미 제거된 topology의 exact replay를 허용하고 shard/owner/digest/lease drift를 redacted fail-closed로 고정한다. 일반 ORAM writeback 뒤 기존 record의 index-state digest가 오래된 것은 허용하되 topology exact match와 새 generation의 current index-state binding을 요구한다. Fixed-layout `stream_records` Move/Replicate도 같은 record를 사용한다. 모든 index reservation 아래 exact current state와 pre/post topology를 capture하고, record가 없으면 generation 1을 bootstrap한 뒤 expected/new layout과 sorted index-state checkpoint를 typed transfer metadata로 영속화한다. 전용 start Raft operation은 exact lease/state를 검증해 marker를 등록하고, 전용 finish operation은 captured state를 재검증해 layout CAS를 먼저 적용한 뒤 target activation/source removal과 post-layout 검증을 수행한다. Start/finish의 pre/post classifier와 CAS는 post-apply 오류 및 exact replay에 안전하고, restart는 metadata를 보존하며 abort는 layout을 진행하지 않는다. Transfer bootstrap 이후 임시 차단은 제거했다. 일반 untyped start/finish apply guard는 유지하고, public cluster route는 검증된 typed private-ORAM reshard operation만 제출한다.
  - Qdrant lease coordinator는 node-local session id를 별도 domain의 SHA-256 hash로 변환하고, absent/expired lease acquire, current owner/hash/expiry 검증, monotonic renewal, exact release를 Dispatcher awaited CAS에 연결한다. Public REST/gRPC open은 recovery와 local session 생성 뒤 consensus epoch/root를 재확인하고 lease 획득 실패 시 local writer를 정리한다. Read와 close는 exact live lease를 요구하고, commit은 write 권한/owner signature/budget 검증으로 local session을 busy 상태에 고정한 뒤에만 lease를 갱신한다. Coordinator가 old consensus에서 실패하면 remote/local journal을 abort하고 busy를 해제하며, exact new epoch/root/digest까지 진행됐으면 remote/local finalize를 재시도한다. 그 외 상태는 fail closed 한다. Oversized lease id, mismatch, recovery 오류는 session id/root/digest를 반사하지 않는다.
  - 실제 single-peer Raft proposal/apply 루프를 사용하는 HNSW/result ORAM 통합 테스트는 분산 create가 생성한 stable collection UUID로 client key/bucket/manifest를 다시 바인딩한 뒤 각 index의 initial ownership CAS, session lease acquire, signed fixed-path read, digest-bound commit, consensus epoch 확인, close lease release를 순서대로 검증한다. Dispatcher의 별도 replicated-writeback fixture가 exact remote ACK set과 remote-before-local finalize를 검증한다.
  - 실제 2-peer Qdrant process E2E는 SDK primitive로 생성한 context-bound encrypted fixture를 public REST route에 업로드하고, HNSW/result ORAM 각각 session open, owner-signed fixed-volume read, replicated digest-bound commit, close를 수행한 뒤 다른 replica에서 committed epoch session을 재개방한다. 별도 RF=1 process E2E는 source에서 두 store를 epoch 43으로 진행한 뒤 public `ReplicateShard(stream_records)`와 `MoveShard(stream_records)`를 각각 호출해 live bundle preinstall, marked target `SyncPoints`, shard activation을 완료하고 target에서 두 committed session을 재개방한다. 각 테스트는 source/target local shard ownership도 최종 operation 의미와 일치하는지 검증한다. Partial-preinstall E2E는 target result ORAM current state를 malformed로 만들어 HNSW install 뒤 result install만 실패시키고, transfer 미등록, 오류 root/signature/ciphertext redaction, source reservation 해제, malformed target 제거 뒤 exact idempotent retry 성공을 검증한다. Post-submit abort E2E는 staging transfer delay로 marked transfer를 active 상태에 유지하고 source session 차단을 확인한 뒤 abort한다. Abort가 transfer marker를 제거하고 target replica를 `Dead`로 남기며 preinstalled encrypted stores를 보존하는지, source session이 즉시 재개방되는지, 동일 ReplicateShard exact retry가 target activation과 session 재개방까지 완료하는지를 검증한다. Exact restart E2E는 같은 marked transfer가 active인 동안 target의 HNSW/result store를 제거하고 source에서 same-key `RestartTransfer(stream_records)`를 호출해 fresh reservation 기반 full-store reinstall, replacement marker의 session 차단, target activation과 두 committed session 재개방을 검증한다. Runtime capability fingerprint는 중첩 JSON object key를 canonical sort해 같은 설정을 읽은 별도 process가 map insertion order 때문에 parity mismatch를 내지 않도록 고정했다. 3-peer/RF=3 장애 E2E는 HNSW/result ORAM 각각 비리더 replica를 prepare 직전에 종료하고 commit이 fail closed 되는지, 오류가 session/root/signature/ciphertext를 반사하지 않는지, 기존 signed read와 old epoch session 재개방이 유지되는지를 검증한다. 3-peer/RF=2 partial-finalize E2E는 remote bucket finalize만 filesystem permission으로 실패시켜 Raft CAS 이후 owner/replica journal이 남은 상태를 만들고, coordinator process 재시작 뒤 remote-first/local finalize와 completed pending recovery 뒤 current-peer orphan consensus lease의 즉시 exact release를 거쳐 epoch 43 session을 재개방한다. Opt-in 2-peer large-bundle E2E는 tree height 5의 63-bucket HNSW/result store와 각각 10.504/5.254 MiB base64 ciphertext fields를 epoch 43까지 진행해 ReplicateShard target에서 session을 재개방한다. 별도 3-peer/2-shard/RF=1 owner-union E2E는 initial upload와 epoch-43 writeback이 서로 다른 두 shard owner에만 복제되는지 확인하고, non-owner target으로 한 shard를 ReplicateShard한 뒤 두 private ORAM session을 재개방한다. 3-peer/2-shard/RF=2 automatic recovery E2E는 비리더 target을 중단하고 일반 point write로 replica를 `Dead` 처리한 뒤 target의 HNSW ORAM store를 제거하고 같은 peer로 재시작한다. Target의 background recovery request, source-side signed full-store preinstall, marked per-shard transfer를 거쳐 replica들이 다시 `Active`가 되고 committed epoch 43 session이 target에서 재개방되는지 검증한다. 추가 2-peer HNSW-only 및 HNSW+result process E2E는 public typed scale-up과 scale-down을 각각 실행해 active reshard 동안 session이 닫히고, exact `resharding_stream_records` migration 뒤 layout generation 2와 최종 owner union이 모든 peer에 남으며, committed epoch session과 일반 point retrieval이 유지되는지 검증한다. 별도 source hard-crash E2E는 marked scale-up migration 중 source process를 종료/재기동해 startup abort와 missing-task abort가 모두 억제되는지 확인하고, target 두 store를 제거한 뒤 explicit exact restart의 fresh preinstall과 정상 finish를 검증한다. 추가 3-peer scale-up E2E는 stable pre-state follower가 compacted Raft snapshot으로 active topology를 복원하고 target shard 생성과 정상 finish까지 진행하는지 검증하며, 4-peer/RF=3 scale-down E2E는 같은 active reshard snapshot의 replay와 final owner session 재개방을 검증한다. Fixed-layout multi-shard ownership, exact restart, scale-up/down, paired result-ORAM reshard, source hard-crash explicit recovery, bounded existing-peer active-reshard Raft snapshot recovery 공백은 닫혔다. Active transfer task 자동 resume와 new-peer active snapshot bootstrap은 남아 있다.
  - Scale-up/down process E2E는 후속으로 HNSW-only와 paired HNSW+result 구성을 각각 실행하도록 매개변수화했다. Paired case는 두 index를 epoch 43까지 commit한 뒤 active reshard 동안 HNSW/result session이 모두 닫히는지, exact `resharding_stream_records` migration과 layout generation 2 이후 모든 final owner에서 두 root가 재개방되는지, 두 encrypted bucket store가 남는지 검증한다. Reshard batch가 사용하는 `UpsertPoints`는 exact marked active reshard transfer에만 blanket guard를 통과하며, 이후 per-field peer validation은 private HNSW vector와 private-result payload path를 계속 거부한다. HNSW-only case는 일반 point record 보존 검증을 유지한다.
  - Exact active reshard restart는 유일한 marked `resharding_stream_records` transfer의 key, source/target shard, peers, method와 `MigratingPoints` state가 모두 일치할 때만 source coordinator에서 허용한다. Fresh consensus reservation으로 target의 HNSW/result full store를 먼저 재설치하고, Raft apply는 old transfer task만 중단해 active reshard를 보존한 채 `to_shard_id`와 marker를 유지한 replacement transfer를 시작한다. 2-peer scale-up process E2E는 active migration 중 target의 두 store를 제거한 뒤 exact restart로 재설치하고, session 차단, 정상 reshard finish, layout generation 2와 두 committed session 재개방을 검증한다. Staging transfer delay는 `stream_records`와 `resharding_stream_records` 양쪽 batch에 같은 테스트 전용 cfg로 적용된다.
  - Fixed-layout transfer E2E는 모든 peer의 persisted private ORAM layout record도 직접 확인한다. 정상 Replicate/Move 완료는 generation 2와 최종 owner union을 요구하고, post-submit abort는 generation 1/pre-owner를 유지한 뒤 exact `Dead` target만 pre-layout에서 제외하는 동일 transfer retry로 generation 2까지 진행해야 한다. Exact restart는 active replacement 전후 generation 1을 유지하고 최종 activation에서 generation 2/두 owner로 진행해야 한다. 별도 3-peer/RF=3 E2E는 replica 제거로 existing layout을 generation 2로 만든 뒤 제거된 peer에 `ReplicateShard(stream_records)`를 수행해 generation 3과 전체 owner union, target HNSW/result session 재개방을 검증한다.
  - 별도 2-peer/RF=2 replica-removal E2E는 active HNSW session이 consensus reservation을 막는지, close 뒤 exact single remove가 성공하는지, 제거 peer에 ciphertext store가 남아도 HNSW/result session이 모두 거부되는지, 남은 owner에서는 committed session이 계속 열리는지를 검증한다.
  - HNSW/result collection store에는 signed manifest lineage와 현재 epoch/root/consensus writeback digest, 전체 encrypted bucket set을 묶는 live-replication bundle export/install primitive가 추가됐다. Export는 pending journal을 거부하고 mixed bucket epoch를 current 이하로 제한하며 각 bucket commitment와 persisted Merkle tree를 재검증한다. 따라서 manifest가 live epoch로 refresh된 뒤에도 untouched old-epoch bucket을 안전하게 이동할 수 있다. Install은 owner manifest signature와 expected Raft epoch/root/digest를 exact-match로 확인하고 전체 commitment에서 Merkle root를 재계산한 뒤 completion record와 `current.json`을 마지막에 기록한다. Exact existing store 재설치는 idempotent하고 다른 current state 교체는 fail closed 한다. Store fixture는 writeback으로 epoch 43까지 진행한 HNSW/result index를 빈 replica에 설치하고 untouched old-epoch bucket과 updated bucket이 같은 current root를 구성하는지 고정한다. Initial/live peer install은 최대 512 MiB의 완성된 typed protobuf request를 결정적인 1 MiB 이하 프레임으로 나눠 client-streaming internal RPC로 전송한다. Receiver는 frame version, exact sequence/count, aggregate length, request SHA-256을 bounded decoder에서 검증하고 완전한 request만 기존 install validator에 넘긴다. Chunked full-store receiver permit은 하나이며 atomic install 완료까지 유지되고, 30초 inter-frame idle timeout과 5분 permit-wait/전체-decode timeout을 적용하므로 partial/reordered/stalled/corrupt stream은 mutation 전 fail-closed되고 aggregate decode buffer가 여러 개 누적되지 않는다. Full-store install은 전용 5분 internal RPC deadline과 1회 retry를 사용하고, receiver의 signature/full-store hash/filesystem/fsync 작업은 blocking worker에서 수행해 Tokio health check와 Raft heartbeat를 막지 않는다.
  - 별도 typed `InstallPrivateOramLiveReplica` internal RPC와 ChannelService source transport가 HNSW/result live bundle에 연결됐다. Receiver는 wire aggregate bound, local Raft ownership epoch/root/digest exact match를 확인하고, active consensus lease가 있으면 shard-transfer coordinator가 보낸 canonical reservation hash와 정확히 일치할 때만 node-local private-ORAM mutation lock 아래 provider signature/full-store install을 수행한다. Target의 local Raft apply가 source보다 늦을 수 있으므로 receiver는 exact reservation의 적용만 bounded-wait하고, 누락되거나 다른 reservation은 그대로 거부한다. Source helper도 export 결과와 local Raft record를 대조하고 target ACK의 epoch/root/digest exact match를 요구하며 transport/ACK 오류는 peer id 외 root/digest/ciphertext를 반사하지 않는다. Public cluster update는 지원되는 fixed-layout per-shard Move/Replicate에서 이 helper를 호출해 preinstall ACK 뒤 marked transfer를 제출한다.
  - Automatic dead-replica recovery는 typed `RequestPrivateOramShardRecovery` internal RPC로 source peer에 위임한다. Target scheduler는 collection sync lock 밖의 background task에서 요청해 source의 reservation proposal이 target에 apply될 수 있게 하고, shard별 pending set으로 중복 요청을 합친다. Source는 configured shard count와 실제 fixed layout의 일치, local source `Active`, target `Dead`, no resharding/competing transfer를 검증하며, exact marked retry는 idempotent하게 인정하고 그 외에는 full-store preinstall 뒤 marked `ReplicateShard(stream_records)`를 제출한다.
  - Resharding layout foundation은 stable pre-layout과 `ReshardKey`에서 scale-up/scale-down 이후 canonical shard-layout digest와 owner union을 계산하는 fail-closed helper로 시작했다. Scale-up의 기존 shard id 재사용, scale-down의 missing shard/wrong owner/shard-key mismatch, 마지막 auto shard 또는 custom shard-key의 마지막 shard 제거는 거부한다. `PrivateOramReshardingLayoutTransition`은 exact reshard key, expected/new generation과 digest, target shard owner set, index epoch/root/writeback state를 묶고 scale-up/down pre/post topology를 replay-safe하게 분류하며 Debug에서는 collection/index/root/shard-key를 redaction한다. Persistent validator는 typed start/finish envelope의 모든 index에 동일한 exact consensus lease가 잡혀 있고 canonical 순서의 epoch/root/writeback state와 layout index-state digest가 현재 Raft state에 일치하는지 검증한다. Start는 expected layout에서만, finish는 expected 또는 idempotently applied new layout에서만 허용된다. 전용 `StartPrivateOramResharding`/`FinishPrivateOramResharding` Raft operation과 collection topology classifier도 연결되어 start는 layout을 바꾸지 않고 reshard meta만 적용하며, finish는 layout generation CAS 뒤 meta를 적용하고 두 단계 모두 post-apply failure에서 idempotent하게 replay된다. Scale-up target의 `Resharding` transitional replica와 scale-down의 `ReshardingScaleDown` owner는 start replay에서만 제한적으로 인정하며 finish 전에는 모든 replica와 hash-ring stage가 finalizable 상태여야 한다. Start coordinator는 fully-active stable layout에서 모든 index의 동일 reservation을 잡고 exact expected/new transition을 생성하며, scale-up은 기존 live-replica RPC로 target full-store를 먼저 설치하고 scale-down은 existing owner recovery를 완료한다. Finish coordinator는 `WriteHashRingCommitted` 상태와 exact reshard key, fully-active replica topology를 요구하고 모든 index를 다시 예약한다. Scale-up은 target full-store를 idempotently 재설치하며 self-target은 로컬 recovery로 검증하고, scale-down은 surviving coordinator의 로컬 recovery를 마친 뒤 pre/post layout과 generation CAS를 생성한다. 두 coordinator 모두 reshard 전후 owner union에 남아야 한다. Public cluster start/finish는 이 typed coordinator에 연결됐으며 일반 untyped meta-op은 계속 거부된다.
  - Typed private-ORAM resharding apply authority는 persistent lease/layout/index-state 검증과 topology classification을 통과한 `PrivateOramReshardingOperation`만 전용 `CollectionContainer` 경로로 전달한다. 실제 collection mutation은 private ORAM binding을 다시 확인하는 start/finish 메서드로 분리했고, 일반 `CollectionMetaOperations::Resharding(Start/Finish)`는 TOC와 collection 양쪽의 기존 guard에서 계속 거부된다. Typed authority는 commit/abort나 일반 collection에는 사용할 수 없도록 단위 테스트로 고정했다.
  - Private ORAM resharding의 중간 단계는 ORAM layout을 바꾸지 않는 exact transition만 허용한다. `CommitRead`/`CommitWrite`는 collection의 active reshard key와 stage 검사를 그대로 거치며, replica promotion은 `MigratingPoints`에서 scale-up exact target의 `Resharding -> Active` 또는 같은 shard-key scale-down receiver의 `ReshardingScaleDown -> Active`만 허용한다. Point migration transfer는 source coordinator가 active reshard key, same shard key, source/destination replica state, `sync=true`, no filter, no layout transition, `ReshardingStreamRecords`를 모두 만족할 때만 전체 ORAM store를 preinstall하고 marker를 붙인다. Wrong peer/shard/stage/current-state와 그 밖의 transitional state 변경은 collection 계층에서 fail closed다. Active resharding이나 shard transfer가 하나라도 있으면 새 HNSW/result ORAM session coordinator를 거부하므로 start부터 finish까지 consensus epoch/root와 layout index-state digest가 고정된다.
  - Phase G의 현재 gate는 다음과 같다. Dispatcher consensus state와 모든 shard가 fully active인 고정 layout의 owner-peer union이 있는 REST/gRPC 경로에서는 initial upload와 session open/read/commit/close가 열려 있다. 각 shard의 수동 `stream_records` Move/Replicate, source-coordinated automatic dead-replica recovery, 남는 owner/replica를 보장하는 reserved exact single-`Active` replica removal, typed scale-up/down start/progress/finish, exact marked `resharding_stream_records` point migration과 same-method active restart가 열려 있다. Exact marked active reshard의 source restart는 transfer/reshard를 보존하되 자동 resume하지 않으며, explicit exact restart가 fresh preinstall을 거쳐 복구한다. Existing-peer active-reshard Raft snapshot topology apply는 stable crypto identity, configured index epoch/root, canonical pre-layout, exact reshard key, monotonic stage/replica state를 모두 검증한 bounded 경로에서만 열린다. Consensus coordinator가 없는 distributed TOC, unsupported/unmarked/method-changing transfer restart, new-peer active-reshard snapshot bootstrap, shard-key 생성/삭제, dead/transitional/batch/final replica removal은 계속 fail closed 한다. 위의 “distributed route guard 유지” 문구들은 각 하위 primitive 구현 당시의 단계 기록이며 이 현재 gate가 최종 상태를 정의한다.
  - Private HNSW/result ORAM active-session epoch/root mismatch guard는 `read_paths`/`read_buckets`/`commit` 같은 operation label을 오류에 반사하지 않고 고정 active-session mismatch 메시지만 반환한다.
  - Private HNSW/result ORAM initial upload epoch mismatch guard는 store helper에 전달되는 `upload bundle` operation label을 오류에 반사하지 않고 고정 initial-epoch mismatch 메시지만 반환한다.
  - Private HNSW ORAM initial upload bucket commitment context guard는 `initial upload` operation label을 오류에 반사하지 않고 고정 bucket commitment mismatch 메시지만 반환한다.
  - Private result ORAM ordinary payload read guards는 retrieve/search/query/group lookup 같은 operation label을 오류에 반사하지 않고 고정 payload-read mismatch 메시지만 반환한다.
  - Private result ORAM payload selector overlap guards는 filter/order/group/facet/index/formula 같은 operation label을 오류에 반사하지 않고 고정 selector-overlap 메시지만 반환한다.
  - Private result ORAM payload write guards는 upsert/set/overwrite/delete/clear 같은 operation label을 오류에 반사하지 않고 고정 payload-write mismatch 메시지만 반환한다.
  - Private HNSW ORAM read-only vector write guards는 delete/sync 같은 operation label을 오류에 반사하지 않고 고정 read-only vector write 메시지만 반환한다.
  - Private HNSW ORAM point-level vector read guards는 retrieve/scroll 같은 operation label을 오류에 반사하지 않고 고정 point-level vector read 메시지만 반환한다.
  - Collection-level private HNSW ORAM fail-closed integration helper도 retrieve/scroll/search/query/recommend/discover/delete/sync/upsert/update-vectors 같은 ordinary operation label을 공통으로 금지한다.

테스트:

- runtime strict mode에서 private HNSW/result ORAM provider는 허용되고 server materials/backend, unsupported top-level/nested options, non-client-led search, loose fixed budget, unpinned RK id/epoch은 거부된다. unsupported option 값 자체는 validation error에 반사되지 않는다.
- runtime과 signed manifest는 `oram.path_batch_size`가 Path ORAM leaf count를 넘거나 `fixed_budget.paths_per_round`와 다르면 duplicate-label-free `read_paths` budget을 만들 수 없으므로 fail closed 한다.
- SDK Path ORAM leaf/bucket helper도 HNSW와 result ORAM 모두에서 `tree_height = 0` degenerate tree를 거부해 manifest/runtime validation과 같은 하한을 유지한다.
- runtime은 현재 MVP의 bounded JSON Merkle metadata store가 감당할 수 있는 범위로 private HNSW/result ORAM `tree_height`를 20 이하로 제한해, 지원 불가능한 대형 tree가 manifest/session/restore 경계까지 내려가지 않게 한다.
- runtime은 `path_batch_size * (tree_height + 1)`와 fixed bucket ciphertext size에서 계산한 단일 fixed ORAM read batch decoded ciphertext 총량도 제한해, 과도한 `read_paths`/`read_buckets` 응답을 만드는 private HNSW/result ORAM 정책을 거부한다.
- runtime과 signed manifest는 `dim`, `hnsw.fixed_neighbor_slots`, `oram.block_size_bytes` 조합이 fixed-size f32 node block을 담을 수 없는 경우도 fail closed 한다.
- manifest upload는 `hnsw`, `oram`, `fixed_budget` signed policy가 runtime instance policy와 다르면 fail closed 한다.
- collection config와 runtime validation은 `private-hnsw-oram/v1` binding과 rule당 단일 vector name만 허용하고, 같은 vector name에 대한 다른 vector binding overlap, provider/binding mismatch, vector dim/distance와 runtime options mismatch를 거부한다.
- private HNSW ORAM collection config, manifest, read/commit signature context는 vector name을 collection-local store path component로도 안전한 형태로 제한해 `/`, `:`, `.`, `..`, 128바이트 초과 이름이 bucket-store path construction까지 내려가지 않게 한다.
- normal `upsert`/`update_vectors` plaintext write, `delete_points`, `delete_vectors`, server-side search/scoring은 private ORAM session API 안내 메시지로 fail closed 된다. 실제 `do_upsert_points`/`do_update_vectors`/`do_delete_points`, runtime settings가 없는 vector write fallback, inference-derived vector write, collection peer/internal write guard, peer `SyncPoints`, `delete_vectors` point/filter targets, legacy search/batch search, root `do_query_points`, universal query prefetch/fusion/context/MMR, `lookup_from`/point-id reference-vector resolution, recommend/discover, grouped search/query, 그리고 search matrix 경계도 같은 fail-closed 메시지로 고정했다.
- private HNSW ORAM vector에 대한 `retrieve`/`scroll` `with_vector` 요청은 CKKS sidecar payload 안내가 아니라 private HNSW ORAM session API 안내로 fail closed 된다.
- REST payload export의 `with_vector` 거절 메시지는 private HNSW ORAM 사용자를 일반 read API로 안내하지 않고 provider-appropriate vector read/private session API만 안내한다.
- private HNSW/result ORAM gRPC telemetry wrapper는 collection label만 붙이고 vector name, session id, path label, bucket id/root hash sentinel을 telemetry extension으로 복사하지 않는 회귀 테스트를 둔다.
- REST close-session path의 session id 길이/문자 검증은 actix path validator가 아니라 공통 private ORAM session validator를 타게 해서 129/257바이트 oversized sentinel과 malformed id 모두 redacted `session_id is invalid` 오류로 고정한다.
- Common/gRPC read fixtures는 private HNSW ORAM collection에서도 vector를 요청하지 않는 허용 경로를 열어 두어, no-vector retrieve/scroll 요청이 private HNSW session을 요구하지 않는지도 고정한다.
- runtime crypto settings가 없는 ordinary query/search/recommend/discover/group/search-matrix fallback도 private HNSW ORAM vector에서는 CKKS/OpenFHE runtime 안내가 아니라 private HNSW ORAM session API 안내로 fail closed 된다.
- collection 내부 direct query/search/search-matrix entrypoint도 `private-hnsw-oram/v1` binding을 CKKS sidecar runtime 안내와 구분해 private HNSW ORAM session API 안내로 fail closed 한다.
- private ORAM bucket store는 missing canonical layout을 `NotFound`로 fail-closed 처리하고, directory chmod 전에 symlink/type을 검사하며, symlink bucket과 Unix group/world-accessible bucket directory/file을 fail-closed로 거부한다.
- private ORAM initial epoch upload는 같은 epoch/root 재업로드만 idempotent하게 허용하고, mismatched manifest epoch/root 재업로드는 기존 `current.json`을 덮지 않고 fail closed 한다.
- initial signed manifest upload는 manifest/signature write가 성공한 뒤에만 initial `current.json`을 publish하므로, manifest write 실패가 current epoch만 남기는 부분 상태를 만들지 않는다.
- current epoch/root와 stored manifest가 이미 일치하는 manifest 재업로드는 byte-identical no-op만 허용하고, commit 후 `current.json`이 stored manifest보다 앞선 refresh window에서는 새 signed manifest upload를 허용한다.
- crash window에서 bucket/Merkle writeback이 epoch CAS보다 먼저 보이더라도 old current epoch와 new bucket/root를 섞어 serving하지 않고 fail closed 한다.
- collection snapshot은 client-sealed private HNSW bucket ciphertext를 포함하되 private ORAM snapshot source root/nested symlink, client-owned ORAM state files, non-empty temp write state, bucket plaintext sentinel bytes를 archive에 허용하지 않고, empty temp subtree도 archive에서 제외한다. Client-owned state detection은 snake_case/camelCase/kebab-case/dot-separated alias를 포함한다. Restore preflight는 result privacy, collection/vector context, vector dim/distance, manifest signature key id, Path ORAM tree_height/bucket_count mismatch, current epoch/root, manifest-derived fixed bucket ciphertext size mismatch, collection/vector/key lineage에 묶이지 않은 bucket commitment, bucket commitments로 재계산한 manifest root mismatch, manifest bucket range 전체의 bucket presence mismatch, bucket symlink, weak bucket file mode를 fail-closed로 거부한다.
- REST/gRPC ORAM commit fixture는 non-increasing new_epoch, invalid Ed25519 commit signature, successful commit 이후 stale old_epoch replay를 모두 fail-closed로 검증한다. Read path와 commit path는 bucket read 또는 bucket/Merkle writeback 전에 store current epoch/root도 active session의 epoch/root와 일치하는지 preflight한다.
- REST/gRPC ORAM bucket upload/commit path는 encoded bucket ciphertext 길이를 decode 전에 제한하고, decoded bucket ciphertext 길이가 manifest의 `oram.bucket_size`와 `oram.block_size_bytes`에서 계산한 fixed bucket ciphertext 크기와 정확히 일치하는지 확인한다. commit path는 updated bucket writeback도 bucket `ciphertext_sha256`와 collection/vector/key lineage/bucket epoch context에 묶인 commitment인지 Merkle prepare/write 전에 검증한다.
- REST/gRPC ORAM session fixture는 strict mode `fixed_budget=false`, non-current desired epoch, result privacy mismatch를 session open에서 거부한다.
- REST/gRPC manifest upload fixture는 route settings가 `private_payload_oram_required` runtime mode로 drift되면 collection-level result ORAM binding requirement 또는 HNSW manifest policy에서 fail closed 되는지 검증한다.
- REST/gRPC ORAM session fixture는 active session이 있는 같은 private index에 대해 두 번째 session open을 `ConcurrentWriter`로 거부한다.
- session open은 registry에 active session을 등록한 뒤 stored manifest/signature/current epoch가 open 중 바뀌지 않았는지 다시 확인하고, drift가 있으면 방금 연 session을 닫은 뒤 fail closed 한다. Private HNSW ORAM과 private result ORAM common tests 모두 epoch drift, manifest drift, missing Merkle metadata, and missing bucket files를 sanitized error로 고정한다.
- REST/gRPC session open은 signed manifest/current epoch만 있고 encrypted bucket/Merkle upload가 아직 완료되지 않은 상태도 fail closed 한다.
- session registry는 lease가 만료된 session을 제거하면서 같은 private index의 single-writer lock도 해제하고, 만료된 session id 재사용은 read/commit/close 모두에서 fail closed 한다.
- session registry는 failed session action이나 wrong collection/vector close 요청 이후에도 active session과 single-writer lock을 보존한다. private HNSW와 private result ORAM 모두 잘못된 close가 session id를 제거하거나 writer lock을 고아 상태로 남기지 않는지 회귀 테스트로 고정했고, registry guard 오류가 session id, client id, key id, root hash, collection-local path sentinel을 반사하지 않는지도 검증한다.
- REST/gRPC ORAM session fixture는 active session이 있는 같은 private index에 대해 signed manifest upload와 initial encrypted bucket upload도 거부하고, active-session upload guard 오류가 session id, root hash, bucket ciphertext를 반사하지 않는지 검증한다.
- session registry는 signed manifest upload와 initial encrypted bucket upload가 write window를 잡는 동안 같은 private index의 새 session open과 중복 upload도 거부한다.
- collection snapshot guard는 private HNSW 또는 private result ORAM manifest/bucket upload write window가 열린 collection에서도 fail closed 한다.
- collection snapshot recovery도 기존 private ORAM collection의 active session/upload window와 동시에 진행되지 않도록 recovery 시작 전에 같은 guard를 잡고, guard 오류는 manifest root/signature/binding 값을 반사하지 않는다.
- collection update/delete도 private ORAM lifecycle guard를 잡아 active session/upload/snapshot window가 있는 collection 설정 변경이나 삭제를 fail closed 하고, update/delete 중 새 private ORAM session/upload 또는 collection/full snapshot이 열리지 않게 한다.
- REST/gRPC ORAM session fixture는 active private HNSW ORAM session이 있는 collection의 collection/full snapshot 생성도 거부하고, collection/full snapshot guard가 잡힌 동안 새 session open과 manifest/bucket upload도 거부한다. 오류는 session id, root hash, bucket ciphertext sentinel, collection-local `private_hnsw_oram` path를 반사하지 않는지 검증한다. Registry-level active-session/upload/snapshot guards는 collection id suffix/prefix 또는 다른 vector upload와 충돌 없이 exact collection/vector index marker만 막는지도 회귀 테스트로 고정한다.
- REST/gRPC private result ORAM live fixture도 collection/full snapshot guard가 잡힌 동안 session open, manifest upload, bucket upload를 거부하고, active result ORAM session이 있는 collection의 collection/full snapshot 생성도 거부한다. 오류는 session id, result root hash, bucket ciphertext, collection-local `private_result_oram` path를 반사하지 않는지 검증한다. Registry-level upload/snapshot guards는 collection id suffix/prefix 충돌 없이 exact collection marker만 막는지도 회귀 테스트로 고정한다.
- REST/gRPC snapshot route fixture는 collection/full snapshot creation과 active lifecycle window 및 active private HNSW/result ORAM session의 상호배제, shard snapshot list/create/stream/download/delete/recover, partial snapshot manifest, partial recover_from route가 private ORAM bucket store collection에서 fail closed 되는지도 고정한다. REST collection recovery route fixture는 active private ORAM snapshot/upload window 및 active private HNSW/result ORAM session과 recovery의 상호배제를 고정한다. 오류는 submitted snapshot location, operation label, root hash, bucket ciphertext, collection-local private ORAM store path를 반사하지 않는다.
- SDK/client state, upload bundles, REST/common wire DTO, canonical signature input/context, bucket validation context, AEAD/commitment context, verifier public key, collection-local private ORAM store의 Rust `Debug` surface도 session id, root hash, decoded epoch root hash, path label, bucket id, ORAM epoch, ciphertext length/body, signature key id/body, RK id, client position/stash, client ORAM tree/ciphertext sizing config, manifest-build HNSW/ORAM/fixed-budget policy internals, node deleted/generation/token-presence state, build-point vector length, upload/build/batch/proof/read-signature/store-Merkle bucket counts, search access metrics, common session bucket/tree/path-batch/ciphertext-budget values and embedded manifests, payload bytes, collection-local filesystem path를 반사하지 않도록 수동 redaction으로 바꿨고, qdrant-sec/qdrant/collection unit tests가 client-state/client-states, position-map, stash, ciphertext/hash/sha256 alias family의 sentinel leak absence를 검증한다.
- collection snapshot 생성은 archive 작성 전에 private HNSW ORAM manifest/current epoch/bucket/Merkle restore-layout parity를 preflight하고, 누락 bucket 같은 layout 오류를 collection-local path나 root hash 반사 없이 fail closed 한다.
- collection snapshot 생성은 private result ORAM store도 archive 작성 전에 manifest/current epoch/bucket/Merkle restore-layout parity를 preflight하고, configured binding 없는 orphan store나 누락 bucket 같은 layout 오류를 collection-local path나 root hash 반사 없이 fail closed 한다.
- private HNSW ORAM과 private result ORAM restore preflight는 manifest bucket range 전체를 검사하며 first/middle/last bucket 누락과 storage-level restore 경로를 bucket filename, collection-local path, root hash, signature/ciphertext-like base64url token 반사 없이 fail closed 한다.
- private ORAM snapshot source preflight와 archive append도 canonical store layout 외 파일을 거부한다. restore preflight는 추가 bucket/layout 파일, malformed current/epoch commit file, missing temp directory archive 형태를 회귀 테스트로 고정했고, current/epoch commit file은 bounded JSON epoch/root shape와 canonical root hash를 요구하며 commit file은 filename epoch 일치도 요구한다.
- REST/gRPC ORAM session fixture는 writeback commit 이후 manifest 재업로드 없이 새 epoch session을 열고 그 live epoch/root로 `read_paths`/`read_buckets`를 수행할 수 있으며, closed session id는 `read_paths`와 `commit`에 재사용할 수 없음을 검증한다.
- REST/gRPC `read_paths`와 `commit` 오류 응답은 unknown session id sentinel을 반사하지 않는다.
- REST/gRPC session close 오류 응답은 unknown session id sentinel을 반사하지 않는다.
- REST/gRPC `read_paths`, `commit`, `close`는 oversized/malformed session id를 registry lookup 전에 거부하고 submitted session id를 반사하지 않는다. well-shaped unknown session id는 기존 missing/expired-session 오류로 fail closed 된다.
- REST access log와 JSON/path validation boundary도 private ORAM 경로를 별도 sanitize한다. Access log는 session id, read path label, bucket/manifest/read/commit tail, private ORAM query string을 redaction하고 exact marker lookalike는 일반 경로로 유지한다. Marker detection is segment-position aware (`/collections/{collection}/private-hnsw...` or `/private-result-oram...` only), so ordinary collections named `private-hnsw` or `private-result-oram` do not get private-ORAM log/query/body-error handling. Private ORAM JSON body validation/deserialization 오류는 unknown field와 malformed body sentinel을 반사하지 않으며, REST path parameter validation도 vector/session-like path segment sentinel을 반사하지 않는다. gRPC route parameter validation도 oversized collection/vector 값과 malformed private ORAM collection-name sentinel을 오류 메시지에 넣지 않는다.
- REST/gRPC private HNSW/result ORAM route의 missing-encryption guard도 collection name을 반사하지 않는 고정 메시지로 fail closed 한다.
- REST/gRPC bucket upload, `read_paths`, `commit`은 submitted root hash를 canonical 32-byte base64url shape로 먼저 검증하고 malformed root hash를 registry/storage epoch 비교 전에 값 반사 없이 거부한다.
- REST/gRPC `read_paths`, `commit` client signature는 fixed 64-byte Ed25519 base64url 길이를 decode/verification 전에 검증하고 oversized/malformed signature body를 반사하지 않는다.
- private HNSW runtime verifier public key도 fixed 32-byte Ed25519 base64url 길이를 decode/verification 전에 검증하고 malformed public key body를 반사하지 않는다.
- REST/gRPC manifest read fixture는 uploaded manifest/signature를 runtime policy와 Ed25519 검증을 거쳐 반환하고, 이후 runtime `hnsw`, `oram`, `fixed_budget` 또는 private-result `result_privacy` policy가 drift된 settings에서도 fail closed 되는지 검증한다. Manifest upload 전 manifest read, bucket upload, session open은 sanitized `NotFound`로 fail closed 되고, manifest/bucket upload fixture는 signed manifest collection/vector/key lineage/vector metadata context mismatch, Path ORAM tree_height/bucket_count mismatch, invalid manifest Ed25519 signature, bucket `ciphertext_sha256` mismatch, incomplete bucket set, duplicated bucket id를 upload 경계에서 fail closed로 거부한다. Bucket upload도 manifest upload 이후 runtime `hnsw`, `oram`, `fixed_budget` 또는 private-result `result_privacy` policy가 drift된 settings를 fail closed로 거부하고, 정상 runtime settings로는 계속 upload를 완료할 수 있음을 검증한다.
- private HNSW initial bucket upload는 manifest Merkle root뿐 아니라 각 bucket commitment가 collection/vector/key lineage/bucket epoch context와 `ciphertext_sha256`에 묶여 있는지도 서버 validation에서 확인한다.
- REST/gRPC manifest upload, `read_paths`, `commit` signature key id lookup 오류 응답은 submitted key id sentinel을 반사하지 않는다.
- REST/gRPC manifest upload unsupported signature algorithm 오류 응답은 submitted algorithm sentinel을 반사하지 않는다.
- REST/gRPC manifest upload malformed signature 오류 응답은 submitted signature sentinel을 반사하지 않는다.
- REST/gRPC private ORAM manifest upload unsupported/malformed/tampered signature 오류 응답은 submitted signature key/body와 manifest root도 반사하지 않는다.
- REST/gRPC private HNSW ORAM `read_paths`와 `commit`의 unsupported request signature algorithm 오류 응답도 submitted algorithm, session/root/path, signature key/body, bucket ciphertext sentinel을 반사하지 않는다.
- REST/gRPC private result ORAM `read_buckets`와 `commit`의 unsupported request signature algorithm 오류 응답도 submitted algorithm, session/root, signature key/body, bucket ciphertext sentinel을 반사하지 않는다.
- REST/gRPC manifest upload는 signature key lookup 전에 unsupported algorithm과 malformed signature body를 먼저 검증해 malformed signed request가 registry lookup 경계까지 가지 않는다. Crypto manifest signature validators도 manifest shape를 canonical message construction 전에 검증한다.
- REST/gRPC private HNSW manifest upload/read, bucket upload, session open, snapshot restore preflight는 stored manifest signature shape와 `owner_signing_key_id` 일치를 runtime `signature_public_keys` lookup 전에 검증하므로, non-owner manifest signature key id는 configured 여부와 무관하게 owner-mismatch 오류로 fail closed 되고 submitted key id를 반사하지 않는다.
- REST/gRPC private result ORAM manifest upload/read, bucket upload, session open, snapshot restore preflight는 stored manifest signature shape와 `owner_signing_key_id` 일치를 runtime `signature_public_keys` lookup 전에 검증하므로, non-owner manifest signature key id는 configured 여부와 무관하게 owner-mismatch 오류로 fail closed 되고 submitted key id를 반사하지 않는다.
- runtime `signature_public_keys` registry는 동일 Ed25519 public key를 여러 key id alias로 등록하는 설정을 거부해 private HNSW v1 manifest의 `owner_signing_key_id` authorization이 verifier alias로 재바인딩되지 않도록 한다. 같은 registry validator를 쓰는 private result ORAM과 client envelope provider도 동일한 key-id uniqueness invariant를 공유한다.
- REST/gRPC private result ORAM manifest upload/read, bucket upload, session open은 runtime ORAM tree policy drift도 fail closed 하며 drifted option name이나 submitted bucket ciphertext를 반사하지 않는다.
- SDK manifest/read_paths/read_buckets/commit signing helpers와 read_paths/read_buckets/commit message builders는 malformed manifest, empty 또는 zero-budget read_paths, empty read_buckets, path-count mismatch, malformed 또는 duplicate read path label/root/hash, partial result ORAM bucket path, unsupported request signature algorithm, malformed signature key id, non-advancing commit epoch, empty commit을 canonical message construction 전에 거부한다.
- `qdrant-sec` crypto tests는 private HNSW manifest/read_paths/commit과 private result manifest/read_buckets/commit의 canonical message SHA-256 digest 및 deterministic Ed25519 known-answer signature를 고정하고, `docs/qdrant-sec-private-*-oram-signature-test-vector.json` fixture와의 SDK 호환성도 검증한다.
- REST/gRPC manifest upload store layout 오류 응답은 collection-local `private_hnsw_oram` filesystem path를 반사하지 않는다.
- REST/gRPC manifest read corrupt store 오류 응답은 collection-local `private_hnsw_oram` filesystem path를 반사하지 않는다.
- REST/gRPC private HNSW `read_paths`/`commit`과 private result ORAM `read_buckets`/`commit` client signature key id는 registry lookup 전에 shape validation을 통과해야 하며 invalid key id 오류는 submitted key id sentinel을 반사하지 않는다.
- REST/gRPC private HNSW `read_paths`와 `commit`은 active session manifest의 `owner_signing_key_id`를 확인한 뒤 verifier public key를 lookup하므로 non-owner key id 요청은 registry lookup 경계까지 가지 않는다.
- REST/gRPC private result ORAM `read_buckets`와 `commit`도 active session manifest의 `owner_signing_key_id`를 확인한 뒤 verifier public key를 lookup하므로 non-owner key id 요청은 registry lookup 경계까지 가지 않는다.
- REST/gRPC private HNSW `read_paths`와 `commit`은 malformed/duplicate path label, malformed root, empty/oversized/duplicate updated bucket 같은 request-shape 오류를 signature verification 전에 fail closed 하고, shape-valid 요청만 client signature 검증 뒤 bucket path derivation 또는 Merkle/writeback 준비로 진행한다.
- REST/gRPC private result ORAM `read_buckets`는 session owner-key preflight 이후 canonical signed bucket-id sequence를 detailed path-shape 또는 bucket-range 검증보다 먼저 확인하므로, unauthenticated malformed read batch는 generic signature-failure path에서 멈춘다.
- REST/gRPC bucket upload epoch/root 오류 응답은 submitted root hash sentinel을 반사하지 않는다.
- REST/gRPC bucket upload Merkle root mismatch 오류 응답은 computed Merkle root를 반사하지 않는다.
- REST/gRPC bucket upload 오류 응답은 malformed bucket ciphertext sentinel을 반사하지 않는다.
- REST/gRPC bucket upload ordering/fixed-size 검증 오류는 bucket id, bucket epoch, bucket ciphertext 값을 반사하지 않는다.
- REST/gRPC bucket upload store layout 오류 응답은 collection-local `private_hnsw_oram` filesystem path를 반사하지 않는다.
- REST/gRPC bucket upload/session open current epoch store 오류 응답은 collection-local `private_hnsw_oram` filesystem path를 반사하지 않는다.
- Common private HNSW/result ORAM store error mappers도 collection-originated path, bucket filename, bucket ciphertext sentinel을 generic 오류로 치환한다.
- collection-local private HNSW ORAM store의 bucket read/proof/commit 오류도 bucket id나 bucket epoch 값을 반사하지 않도록 일반화한다.
- collection-local private HNSW ORAM store의 current epoch, Merkle tree context, bucket shape 오류도 stored/requested epoch, bucket_count, bucket id, unsupported version 값을 반사하지 않도록 일반화한다.
- collection-local private HNSW ORAM store의 file/directory hardening 오류도 collection-local path, temp filename, symlink target, OS error 문자열을 반사하지 않도록 고정 메시지화한다.
- REST/gRPC session open client_id는 길이 제한과 safe ASCII resource-id 문자셋을 먼저 검증하고, oversized/malformed client id 오류 응답은 submitted client id sentinel을 반사하지 않는다.
- SDK helper는 commit plan의 old epoch/root가 해당 signed manifest와 맞을 때만 refreshed manifest/signature를 만들고, stale old root는 client-side에서 거부한다. Refresh 없이 post-commit epoch에서 계속 진행하는 클라이언트는 signed upload-anchor manifest가 아니라 live epoch/root와 leaf commitments를 `plan_private_hnsw_oram_commit_for_manifest_context`/`plan_private_result_oram_commit_for_manifest_context`에 넘겨 manifest lineage 검증과 current CAS context를 함께 유지한다.
- SDK upload bundle preflight는 manifest shape, manifest signature shape/owner key id, bucket ciphertext hash, bucket commitment, manifest root hash를 먼저 검증하고, bucket ciphertext hash와 context-bound commitment가 self-consistent하더라도 decoded ciphertext 길이가 manifest-derived fixed bucket ciphertext size와 다르면 client-side에서 거부한다. `validate_private_hnsw_oram_upload_bundle_with_signature`와 bundle method `validate_initial_upload_contract_with_signature`는 같은 preflight에 runtime manifest validation context와 Ed25519 verification을 묶어 호출할 수 있게 한다. `PrivateHnswOramStore::write_initial_upload_bundle_with_signature`도 이 helper를 호출한 뒤에만 layout/bucket/current epoch 파일을 쓰므로 owner signature 실패는 저장 상태를 만들지 않는다.
- manifest-aware `sign_private_hnsw_oram_read_paths_for_manifest_context` helper는 live epoch/root와 manifest key lineage/owner signing key, `oram.path_batch_size`, tree-bounded unique leaf label을 읽기 서명 context로 사용해 fixed read batch 수, leaf range, duplicate path label이 맞지 않으면 SDK에서 서명 전에 fail closed 한다. `sign_private_hnsw_oram_read_paths_for_manifest`는 manifest epoch/root가 live read context인 first-read 또는 refreshed-manifest convenience wrapper로 남긴다.
- SDK/reference commit planning helper는 live old epoch/root와 current leaf commitments를 old commit context로 사용하고, updated bucket commitment가 ciphertext hash와 collection/vector/key lineage/bucket epoch context에 묶여 있지 않으면 commit 서명 전에 fail closed 한다. `plan_private_hnsw_oram_commit_for_manifest_context`는 manifest lineage와 live old epoch/root를 함께 받으며, first commit 또는 optional manifest refresh 직후처럼 manifest epoch/root가 live old context와 같을 때는 `plan_private_hnsw_oram_commit_for_manifest` convenience wrapper도 같은 검증을 수행한다. 두 manifest-aware helper는 서버 commit guard와 같은 `oram.path_batch_size * (oram.tree_height + 1)` fixed writeback budget도 강제한다.
- SDK verified encrypted search/fetch helper도 writeback epoch가 read/session epoch보다 전진하지 않으면 첫 ORAM read 또는 local access remap 전에 fail closed 한다. HNSW verified search와 cached verified search는 `InvalidCommitEpoch`로 닫고, private result ORAM verified token fetch는 `new_epoch` manifest-field 오류로 닫아 서버 commit CAS와 같은 non-advancing epoch 불변식을 client boundary에서도 유지한다. Public HNSW plaintext/encrypted/verified search와 private result ORAM multi-batch verified fetch는 작업용 client state에만 remap/writeback을 누적하고 모든 proof/open/reseal 또는 plaintext validation이 성공한 뒤 원본 state를 갱신한다. HNSW search wrapper는 pending writeback overlay를 subsequent reads에 적용하되 caller writeback callback은 full search success 후 한 번만 호출하므로, 뒤 batch proof 실패나 post-access decode 실패가 앞 remap/writeback을 남기지 않는다.
- `PrivateHnswOramStore::commit_writeback_with_signature`와 `PrivateResultOramStore::commit_writeback_with_signature`는 runtime REST/gRPC commit 경로에 연결되어 canonical Ed25519 commit signature를 저장 manifest lineage로 검증한 뒤 durable pending-writeback journal을 fsync하고 fixed ciphertext size, context-bound bucket commitment, Merkle update, bucket writes, epoch/root CAS를 적용한다. 같은 signed commit 재시도는 prepare 직후, bucket/Merkle 반영 중, epoch CAS 직후에 남은 journal을 다시 검증하고 bucket/Merkle write와 CAS를 idempotent하게 완료한 뒤 journal을 삭제/fsync한다. 프로세스 재시작으로 기존 in-memory lease가 사라진 경우 새 session open은 pending journal을 발견해 index write reservation을 잡고 owner signature를 재검증한 뒤 복구를 완료하며, 같은 registry lock 안에서 reservation을 새 session writer lease로 전환한다. REST e2e는 HNSW와 result ORAM 모두 이 43→44 restart-style recovery를 고정한다. 변조 journal은 active state 변경 전에 fail closed 되고, pending journal이 남은 store는 temp-directory snapshot preflight를 통과하지 못한다. Commit CAS는 stored manifest epoch/root가 아니라 current epoch/root와 맞아야 하고, stored manifest는 lineage와 bucket_count 검증에 사용한다. invalid signature, malformed ciphertext, stale root, commitment-context mismatch, bucket ciphertext hash mismatch, short/oversized fixed ciphertext, wrong new Merkle root는 active bucket/Merkle/epoch 상태를 바꾸기 전에 fail closed 하며, runtime 오류 응답은 ciphertext 범주 같은 안전한 힌트만 보존하고 ciphertext body, bucket id, root hash는 반사하지 않는다. Consensus CAS, owner-union encrypted bucket replication, partial-finalize process fault recovery, fixed-layout manual/automatic bucket preinstall transfer, exact active marked transfer restart, typed scale-up/down reshard orchestration, bounded existing-peer active-reshard Raft snapshot topology recovery는 public/consensus 경로에 연결됐다. Active transfer task 자동 resume, new-peer active snapshot bootstrap, shard-key layout mutation은 계속 남아 있다.
- Paired HNSW/result scale-up/down, exact active reshard restart/repreinstall, source hard-crash 상태 보존/explicit restart, scale-up stable-to-active 및 scale-down active-to-active Raft snapshot E2E가 추가되어 위의 result-ORAM reshard, reshard transfer restart, source-crash fail-closed recovery, bounded existing-peer active-reshard snapshot recovery 잔여 항목은 닫혔다. Active transfer task 자동 resume, new-peer active snapshot bootstrap, shard-key layout mutation은 계속 남아 있다.
- SDK encrypted client-state backup helper는 ORAM position map/stash snapshot shape를 seal 전에 검증하고, open 전에 ciphertext hash shape와 encoded ciphertext 길이를 제한해 malformed/oversized backup ciphertext를 거부하며, duplicate position/stash, duplicate stash point/payload fetch token, malformed node/token id, malformed leaf label, malformed stash node block/vector/neighbor/level mask, stash map-key/node-id mismatch를 snapshot export/import 경계에서 fail closed 한다. HNSW bucket/client-state AAD와 manifest-build/read-path-signature/commit-signature context의 collection/key ids도 safe ASCII shape로 제한하고, vector name은 slash/path-like 값과 client-state alias를 거부하며, encrypted backup DTO가 position entries, leaf labels, stash blocks, node ids, point/payload fetch tokens, vector bytes, neighbor ids를 plaintext로 직렬화하지 않는지도 검증한다.
- private result ORAM encrypted client-state backup open도 HNSW client-state backup과 같은 epoch/root context binding, malformed ciphertext, short ciphertext, malformed hash, tampered ciphertext fail-closed 회귀를 갖고, duplicate stash point token, malformed stash payload block version/payload length, stash map-key/token mismatch를 snapshot export/import 경계에서 fail closed 하며, client-state AAD 및 read/commit signature collection/key context ids도 safe ASCII shape로 제한한다. encrypted backup DTO가 position tokens, leaf labels, stash payload fetch tokens, point tokens, payload bytes를 plaintext로 직렬화하지 않는지 검증한다.
- manifest-aware `sign_private_result_oram_read_buckets_for_manifest_context` helper는 live epoch/root와 manifest key lineage/owner signing key, `oram.path_batch_size * (oram.tree_height + 1)` fixed bucket-id volume 및 canonical Path ORAM heap path shape를 읽기 서명 context로 사용해 fixed read batch 수나 path shape가 맞지 않으면 SDK에서 서명 전에 fail closed 한다. `sign_private_result_oram_read_buckets_for_manifest`는 manifest epoch/root가 live read context인 convenience wrapper로 남긴다.
- private result ORAM도 동일하게 `plan_private_result_oram_commit_for_manifest_context`는 live old epoch/root와 signed manifest lineage를 함께 사용하고, manifest-aware refresh helper는 first commit 또는 optional manifest refresh 직후처럼 commit plan의 old epoch/root와 signed manifest가 같은 경우에만 refreshed manifest/signature를 만든다. stale old root는 client-side에서 거부한다. manifest-aware SDK commit planner는 서버 commit guard와 같은 `oram.path_batch_size * (oram.tree_height + 1)` fixed writeback budget을 강제해 oversized aggregate writeback plan을 로컬에서 fail closed 한다.
- private result ORAM upload bundle preflight도 manifest signature shape와 owner key id를 먼저 검증한다. `validate_private_result_oram_upload_bundle_with_signature`와 bundle method `validate_initial_upload_contract_with_signature`는 upload API가 shape/bucket/root preflight와 owner Ed25519 verification을 하나의 helper로 호출할 수 있게 한다. `PrivateResultOramStore::write_initial_upload_bundle_with_signature`도 이 helper를 호출한 뒤에만 layout/bucket/current epoch 파일을 쓰므로 owner signature 실패는 저장 상태를 만들지 않는다. `PrivateResultOramStore::commit_writeback_with_signature`는 canonical Ed25519 commit signature를 store manifest lineage로 검증한 뒤에만 기존 bucket/Merkle/epoch writeback 경로로 들어가므로 invalid signature는 저장 상태를 바꾸지 않는다. REST/gRPC commit handler도 canonical commit signature validator가 duplicate bucket refs 같은 malformed writeback shape를 generic signature-failure path에서 먼저 닫은 뒤에만 Merkle/writeback 검증으로 진행한다. manifest-aware commit planning/signature helper도 empty commit, malformed updated bucket ciphertext hash, updated bucket commitment가 ciphertext hash와 collection/key lineage/bucket epoch context에 묶여 있지 않은 commit을 서명/검증 전에 fail closed 한다.
- private result ORAM store의 upload bundle, commit, stored Merkle tree root mismatch 오류는 computed Merkle root를 반사하지 않는다. Bucket read/proof/commit 오류도 bucket id나 bucket epoch 값을 반사하지 않도록 일반화한다.
- private result ORAM store의 current epoch와 Merkle tree context 오류도 stored/requested epoch, bucket_count, unsupported version 값을 반사하지 않도록 일반화한다.
- private result ORAM store의 file/directory hardening 오류도 collection-local path, temp filename, symlink target, OS error 문자열을 반사하지 않도록 고정 메시지화한다.
- private HNSW/result ORAM manifest-only upload helper는 manifest/signature write가 성공한 뒤에만 initial current epoch를 publish하고, current manifest 재업로드는 저장 manifest/signature와 byte-identical일 때만 허용하며, writeback 이후 current epoch가 새 manifest epoch/root로 이미 전진한 post-commit refresh는 허용한다. Session open과 commit CAS는 refresh를 요구하지 않고 `epochs/current.json`의 live epoch/root를 따른다. Private HNSW/result ORAM current manifest reupload mismatch 오류도 제출/저장 signature와 root hash를 반사하지 않도록 테스트로 고정했다.
- private result ORAM store의 bucket shape 검증은 encoded ciphertext 길이를 decode 전에 제한한다. writeback commit도 empty update와 non-advancing epoch를 거부하고 current epoch/root CAS와 manifest bucket_count/lineage를 먼저 확인하며, updated bucket commitment가 ciphertext hash와 collection/key lineage/bucket epoch context에 묶여 있지 않으면 bucket/Merkle write 전에 fail closed 한다.
- private HNSW와 private result ORAM store의 bucket JSON read cap은 decoded ciphertext cap에 고정 여유분만 더하지 않고 base64url encoded 길이와 bounded JSON metadata overhead를 합산한다. 따라서 allowlist의 큰 bucket/block 조합도 정상 read되면서 oversized file은 계속 fail closed 된다.
- private HNSW와 private result ORAM의 client/server boundary arithmetic은 bucket plaintext codec length, canonical signature field length, Path ORAM path batch capacity, session lease expiry, registry refcount, Merkle bucket count, Merkle proof sibling count/level, request length, bucket id conversion을 checked conversion으로 처리해 overflow나 platform-width mismatch가 silent wrap 대신 fail closed 되도록 고정했다.
- private result ORAM initial epoch helper도 같은 epoch/root 재업로드만 idempotent하게 허용하고 mismatched manifest epoch/root 재업로드는 기존 `current.json`을 덮지 않는다. 같은 epoch/root의 initial upload bundle 재업로드도 저장된 manifest/signature, Merkle tree, bucket set과 byte-identical일 때만 no-op으로 허용하며, 각각의 mismatch를 별도 fail-closed 테스트로 고정했다.
- private HNSW ORAM initial upload bundle도 private result ORAM과 같은 parity를 갖는다. manifest Merkle root mismatch는 layout을 만들기 전에 거부하고, existing current epoch/root mismatch는 manifest/bucket/Merkle write 전에 fail closed 하며, 같은 epoch/root 재업로드는 저장된 manifest/signature, Merkle tree, bucket set이 byte-identical일 때만 no-op으로 허용한다. 두 store의 existing manifest/Merkle/bucket-set mismatch 오류도 제출되거나 저장된 root hash, signature, bucket commitment, ciphertext body를 반사하지 않도록 테스트로 고정했다.
- private result ORAM read-batch helper는 encrypted bucket read 전에 current epoch/root를 preflight하고, 반환 bucket과 Merkle proof leaf commitment가 서로 맞지 않으면 ciphertext, bucket id, root 값을 반사하지 않고 fail closed 한다.
- private ORAM bucket의 `index_epoch`는 해당 bucket이 마지막으로 쓰인 epoch를 뜻한다. writeback commit 후 변경되지 않은 bucket은 current index epoch보다 낮은 bucket epoch를 유지할 수 있으며, current Merkle root가 그 기존 bucket commitment를 포함할 때만 read proof로 반환된다. requested session epoch보다 미래인 bucket은 read/proof verifier에서 fail closed 한다.
- private result ORAM store는 directory chmod 전에 symlink/type을 검사하고, bucket symlink와 group/world-accessible bucket directory/file을 fail-closed로 거부한다. Snapshot source/restore preflight도 private HNSW/result ORAM root/nested symlink, unsupported file type, restore inspection error, client-state/position-map/stash alias를 fail closed로 거부하면서 symlink target path, bucket filename, collection-local path, OS error 문자열을 오류에 반사하지 않는다.
- collection-facing private HNSW ORAM runtime validation 오류는 내부 setup error detail을 붙이지 않고 고정 메시지로 반환해 unsupported option 이름, option 값, reason 문자열이 collection runtime BadInput에 반사되지 않는다.
- private HNSW와 private result ORAM Merkle proof store generator는 empty bucket batch를 거부하고, store-level Merkle commit prepare도 empty updated bucket set을 거부한다. SDK JSON verifier도 proof body를 파싱 전에 크기 제한하고, empty proof/bucket set을 거부하며, fixed-size path batch를 위해 반복 bucket/proof entry가 byte-identical인 경우만 허용하고 conflicting duplicate는 fail-closed로 거부한다. Store fixture는 HNSW와 result ORAM 모두 store-emitted duplicate proof JSON이 SDK verifier를 통과하는지 고정한다.
- private HNSW ORAM Merkle proof serialization failure도 serde error detail 없이 고정 service error로 반환한다.
- SDK verified encrypted search는 upper-layer client cache hit 경로에서도 Merkle proof를 bucket decrypt, state remap, ORAM writeback보다 먼저 검증한다.
- private HNSW ORAM commit fixed writeback budget 오류는 실제 max writeback bucket 수를 API 응답에 반사하지 않고 고정 문구로 반환한다. REST/gRPC oversized writeback fixtures가 `1..=N` 형태의 budget range 비노출을 고정한다.
- Common private HNSW/result ORAM session `Debug` fixtures는 bucket count, tree height, path batch size, derived ciphertext byte budget과 embedded manifest를 그대로 반사하지 않는지 고정한다.
- REST access log와 denied-auth audit path는 private ORAM close-session URL의 session id를 템플릿으로 치환하고 private ORAM read/commit query string과 비정상 private ORAM endpoint tail segment를 redacted 처리한다. malformed private result ORAM close-session path도 session id를 반사하지 않는다. Access log와 slow request log/request hash redaction은 private HNSW ORAM path/read/access/visited-node traversal aliases, query vector/embedding/plaintext aliases, score/distance aliases, candidate heap/score/distance aliases, node score/distance aliases, request/commit/read/manifest signature aliases, private result ORAM bucket ids, read bucket ids, bucket id sequences, bucket/leaf commitments, proof/proof_value aliases, updated bucket writebacks, leaf id/remap aliases, access-volume count aliases, session ids, client-state/ciphertext/hash/sha256 aliases, point/payload fetch tokens를 숨기며 snake_case/camelCase 단수·복수와 `payload.fetch.token` dotted alias fixture로 회귀를 고정한다.
- Snapshot/client-state, collection config validation, collection internal transfer/resharding/state/update guards, collection/common store and registry error mapping, slow-log/request-hash redaction, panic/error-reporting/audit redaction, metrics label, REST/gRPC route, receiving-shard, replica-priority recovery, collection cluster guards, and consensus transfer guards now treat `client_state_backup`, `client_state_snapshot`, `clientStateSnapshot(s)`, `encrypted_client_state`/`encryptedClientState`, encrypted client-state backup/snapshot, `*_ciphertext_sha256`, position-map/ORAM-position-map backup, token-position-map backup, and stash backup variants like other client-owned ORAM state aliases, so client state backup/snapshot material cannot be snapshotted as server-owned ORAM files or leak through config/search/update/cluster validation errors, slow/error/status logs, request hashes, metrics labels, route errors, or storage-level recovery/transfer errors.
- REST private HNSW/result ORAM DTO `Debug` fixtures도 manifest signature key/body와 encrypted bucket ciphertext, `ciphertext_sha256`, bucket commitment, upload/read bucket counts가 upload/read response wrapper에서 반사되지 않는지 직접 고정한다. REST/gRPC guard redaction fixtures는 plain/plural client-state, encrypted-client-state, position-map, ORAM-position-map, token-position-map, stash, state ciphertext/hash aliases와 `payload_fetch_token`/`payloadFetchToken(s)`/`payload.fetch.token` aliases까지 같은 금지 목록으로 유지한다.
- denied-auth audit error redaction도 private ORAM path/root/bucket/node/vector/token aliases와 query vector/embedding/plaintext, score/distance, candidate/node score/distance aliases를 숨기며 sentinel fixture로 회귀를 고정한다.
- private result ORAM nested request 객체 안의 `session_id`/`sessionId`, `bucket_ids`/`bucketIds`, `bucket_commitments`/`bucketCommitments`, `updated_buckets`/`updatedBuckets`, client-state ciphertext/hash aliases도 slow-request log와 request hash에서 redacted projection으로 동일화한다.
- panic telemetry와 gRPC status logging redaction도 private ORAM session/client id/path/raw read_paths/access path/read bucket id/bucket sequence/bucket or leaf commitment/leaf id/remap/proof_value/entry node/level mask/visited node/neighbor/query vector/score/distance/candidate score/distance/node score/distance/result/token/client-state/client-state ciphertext/hash/sha256/position-map/stash/update bucket/signature, owner/signing key id, signature-public-key registry, access-volume count/length snake_case·camelCase alias sentinel을 반사하지 않는지 검증한다.
- private result ORAM ordinary payload write/read guards는 configured protected payload path 파싱 실패 시 parser debug detail이나 submitted path token을 반사하지 않고 고정 오류로 fail closed 한다.
- Common/REST/gRPC update fixtures도 private HNSW ORAM `Upsert`/`Delete`/legacy `DeleteDeprecated`/`DeleteVectors`/internal `SyncPoints`와 private result ORAM `Upsert`/`SetPayload`/`OverwritePayload`/`DeletePayload`/`ClearPayload`/legacy `ClearPayloadDeprecated`/`Delete`/legacy `DeleteDeprecated`가 direct ordinary update guard와 같은 session API 안내로 fail closed 되는지 고정한다.
- Common/internal/gRPC create/delete-field-index fixtures도 `private-result-oram/v1` payload path의 payload index/schema creation/deletion이 같은 private result ORAM session API 안내로 fail closed 되는지 고정한다.
- Public create/delete-field-index guard는 private result ORAM payload-path 검증 전에 `write().extras()` 권한을 먼저 확인해 unauthorized caller에게 provider/session/path detail을 드러내지 않는지도 고정한다.
- gRPC `GetPoints`/`ScrollPoints`/`SearchPoints`/batch search/`SearchPointGroups`/`RecommendPoints`/batch recommend/`RecommendPointGroups`/`DiscoverPoints`/batch discover/`QueryPoints`/batch query/`QueryPointGroups` ordinary payload read wrappers도 `private-result-oram/v1` payload path를 반환하려 하면 common read guard와 같은 private result ORAM session API 안내로 fail closed 되는지 고정한다.
- Common/gRPC `encrypted_payload=decrypted` read requests와 REST group lookup preflight도 `private-result-oram/v1` payload path에 대해 generic decrypt-runtime 오류로 빠지지 않고 같은 private result ORAM session API 안내로 fail closed 되는지 고정한다.
- Common/gRPC read fixtures는 private result ORAM collection에서도 payload를 요청하지 않는 허용 경로를 열어 두어, payload-omitted retrieve/scroll/search 요청이 private result ORAM session을 요구하지 않는지도 고정한다.
- collection-level private result ORAM read/write/selector helper도 retrieve/search/query/recommend/discover/group lookup/filter/order/facet/group-by/update payload operation label 전체가 고정 session API 안내에 반사되지 않는지 공통 assertion으로 고정한다.
- gRPC grouped `with_lookup` payload requests도 lookup collection이 `private-result-oram/v1` payload path를 반환하려 하면 main hit payload가 꺼져 있어도 같은 private result ORAM session API 안내로 fail closed 되는지 고정한다.
- gRPC facet, count filter, scroll filter/order-by, formula query, grouped search, grouped query selector wrappers도 `private-result-oram/v1` payload path를 inspect하려 하면 common selector guard와 같은 private result ORAM session API 안내로 fail closed 되는지 고정한다.
- gRPC `PointsSelector` filter variant도 private HNSW ORAM `delete`/`delete_vectors`와 private result ORAM `set_payload`/`overwrite_payload`/`delete_payload`/`clear_payload`/`delete`에서 point-id selector와 같은 private session API 안내로 fail closed 되는지 고정한다.
- REST/gRPC request metrics fixtures도 private result ORAM `read_buckets`와 close-session endpoint에서 fixed endpoint label만 방출하고 dynamic bucket id/session id sentinel을 방출하지 않는지 검증한다. Metrics/OpenAPI surface checks use exact private ORAM route-shape matching, strip query strings only for otherwise fixed routes, and include malformed/lookalike path negatives so partial, similar, or extra-tail path names do not become fixed labels. gRPC private HNSW/result ORAM services are wrapped with the collection telemetry adapter as well, but the wrapper attaches only `collection_name` and never vector names, session ids, path labels, bucket ids, roots, ciphertext, client-state fields, or `*_ciphertext_sha256` client-state aliases.
- REST/gRPC private HNSW와 private result ORAM bucket upload/commit request-shape preflight는 collection, manifest, session lookup 전에 empty upload/writeback, duplicate upload bucket id, malformed `ciphertext_sha256`/`bucket_commitment`를 거부하며 submitted root hash, bucket ciphertext, commit signature body, collection-local store path를 반사하지 않는다.
- REST/gRPC private result ORAM bucket upload preflight도 mismatched 또는 malformed root hash를 submitted root hash와 bucket ciphertext 반사 없이 fail closed 한다.
- REST/gRPC private result ORAM bucket upload ciphertext/hash mismatch 오류도 submitted bucket ciphertext body를 반사하지 않고 generic ciphertext validation failure로 멈춘다.
- REST/gRPC private result ORAM `read_buckets`와 `commit`은 mismatched 또는 malformed root hash를 fail closed 하면서 submitted root hash, commit signature body, updated bucket ciphertext를 오류에 반사하지 않는다.
- REST/gRPC private result ORAM commit fixed writeback budget 오류도 실제 max writeback bucket 수를 API 응답에 반사하지 않고 고정 문구로 반환한다.
- REST/gRPC `read_paths` 오류 응답은 mismatched root hash sentinel, malformed path label sentinel, stored bucket ciphertext를 반사하지 않는다. path-to-bucket derivation helper도 하위 leaf-label decode 오류를 그대로 반사하지 않는다.
- REST/gRPC `read_paths` missing encrypted bucket/proof 오류 응답은 collection-local `private_hnsw_oram` filesystem path를 반사하지 않는다.
- REST/gRPC `read_paths`는 store current epoch/root가 active session과 맞지 않으면 bucket을 읽기 전에 fail closed 하고 stale root, stored bucket ciphertext, collection-local `private_hnsw_oram` path를 반사하지 않는다.
- REST/gRPC `read_paths`는 collection store의 batch+proof helper로 bucket을 읽어 current epoch/root를 store layer에서도 재확인하고, 응답 직전에 각 bucket commitment가 같은 순서의 Merkle proof leaf와 일치하는지 검증하며, mismatch가 있으면 ciphertext나 store path를 반사하지 않고 fail closed 한다.
- REST/gRPC `read_paths`와 `commit` malformed client signature shape 오류 응답은 submitted signature sentinel을 반사하지 않는다. Crypto signature message builders/validators도 collection/vector/key lineage, root hash, read path label, duplicate path label, `requested_paths`/path count 일치성, non-advancing commit epoch, updated bucket ciphertext hash shape를 signature body parsing/message construction 전에 검증한다.
- REST/gRPC `read_paths` 성공 응답은 bucket id를 unique set으로 축약하지 않고 요청된 ORAM path별 bucket sequence를 보존해 `requested_paths * (tree_height + 1)` 크기를 유지하며, SDK verifier는 반복 bucket/proof가 byte-identical일 때만 허용한다. Collection store fixture도 duplicate Merkle proof JSON이 SDK verifier를 통과하는지 고정한다.
- REST/gRPC `commit` old epoch/root mismatch 오류 응답은 submitted old root hash sentinel을 반사하지 않는다.
- REST/gRPC `commit` fixture는 empty 또는 oversized `updated_buckets`를 fixed writeback request-size validation에서 거부하고, crypto commit signature message builders/validators도 empty bucket list를 signature body parsing 전에 fail closed 한다.
- REST/gRPC `commit` 오류 응답은 malformed updated bucket ciphertext/hash sentinel과 malformed `new_root_hash` sentinel을 반사하지 않으며, updated bucket `ciphertext_sha256` shape는 commit signature message construction 전에 검증한다.
- REST/gRPC `commit` missing Merkle metadata 오류 응답은 collection-local `private_hnsw_oram` filesystem path를 반사하지 않는다.
- REST/gRPC `read_paths` fixture는 path count, requested path count, dummy padding flag가 fixed path budget과 다르거나 exact duplicate/oversized/malformed path label을 포함하면 bucket read 전에 fail-closed로 거부하고 malformed label 본문을 반사하지 않는다. Common read budget helper unit test도 requested path 수, 실제 path 수, dummy padding flag mismatch가 session/detail 값을 반사하지 않는 고정 오류로 떨어지는지 고정한다.
- REST/gRPC `read_paths` 성공 경로는 collection/vector, key lineage, epoch/root, path labels, padding metadata에 대한 Ed25519 client signature를 검증한 뒤 encrypted buckets를 반환하고, invalid read signature는 fail-closed로 거부한다.
- REST/gRPC `read_paths`는 session lookup 전에 leaf label을 canonical fixed-length base64url form으로 제한하고 duplicate path label을 거부하며, fixed-budget/session epoch-root 검증 뒤 shape-valid 요청의 Ed25519 request signature를 ORAM bucket path 계산보다 먼저 검증한다.
- REST/gRPC `commit`은 bounded request-size/epoch checks 뒤 `old_root_hash`/`new_root_hash`를 canonical 32-byte base64url shape로 먼저 제한하고, Ed25519 request signature를 Merkle/writeback preparation보다 먼저 검증한다.
- OpenAPI `Beta` path surface도 private HNSW ORAM manifest/bucket/session/read/commit/close와 private result ORAM manifest/bucket/session/read/commit/close REST endpoints를 노출한다. 암호화 envelope DTO는 SDK-owned wire contract라 현재 OpenAPI에서는 opaque object request/response로 고정한다.
- REST/gRPC private HNSW `read_paths`/`commit`과 private result ORAM `read_buckets`/`commit` request signature key id는 session manifest의 `owner_signing_key_id`와 달라도 fail closed 한다.
- gRPC private HNSW/result ORAM proto conversion은 unspecified enum뿐 아니라 unknown nonzero enum 값도 fail closed 하고, unsupported enum 값을 status message에 반사하지 않는다.
- active session의 `read_paths`와 `commit`은 session open 이후 runtime instance policy가 바뀌어도 session manifest를 현재 runtime context와 다시 비교하고 drift를 fail closed 한다.
- REST와 gRPC route fixtures는 active session 이후 runtime `hnsw`, `fixed_budget`, `oram`, 또는 private-result `result_privacy` policy가 drift된 settings로 HNSW `read_paths`, result ORAM `read_buckets`, 또는 `commit`을 호출하면 fail closed 되는 경계를 모두 검증한다.
- private HNSW snapshot restore preflight는 `private_payload_oram_required` manifest를 collection에 `private-result-oram/v1` payload binding과 대응하는 result ORAM snapshot store가 있을 때만 허용하고, 없으면 fail closed 한다.
- CLI/startup snapshot mapping recovery도 crypto runtime validation 이후 private HNSW ORAM restore-layout preflight를 실행해 storage-level snapshot recovery와 같은 bucket/root consistency 검증을 적용하고, store-originated layout 오류는 collection-local `private_hnsw_oram` 경로나 bucket body를 반사하지 않도록 sanitize한다.
- CLI/startup private HNSW ORAM restore-layout 실패는 bucket id, bucket commitment mismatch detail, store file detail을 반사하지 않는 고정 메시지로 보고한다.
- private HNSW ORAM vector store 이름은 safe store path component가 아니거나 `client.state`, `position.map`, `stash`처럼 separator를 제거하면 client-owned state alias가 되는 값을 거부하고, snapshot source/archive/restore preflight도 같은 unsafe component와 확장자 없는 dotted alias/확장자 포함 alias를 fail closed 한다.
- CLI/REST snapshot recovery는 private HNSW ORAM restore-layout preflight 이후 runtime `signature_public_keys`로 stored manifest Ed25519 signature를 검증하고, tampered manifest signature를 bucket/root/path 반사 없이 fail closed 한다.
- storage-level `Collection::restore_snapshot` 자체도 shard restore 전에 private HNSW ORAM restore-layout preflight를 실행하고, layout 오류가 collection-local `private_hnsw_oram` 경로나 bucket body를 반사하지 않도록 sanitize한다.
- CLI/startup과 storage-level snapshot recovery도 private result ORAM restore-layout preflight를 실행하고, REST recovery validator는 result ORAM manifest Ed25519 signature를 runtime registry로 검증한다. orphan `private_result_oram/` store와 bucket/root layout mismatch 같은 오류는 collection-local path, reserved directory name, bucket ciphertext 반사 없이 fail closed 한다.
- collection-level private HNSW ORAM snapshot manifest/bucket-contract mismatch 오류도 manifest ids, vector name, dimension, bucket id, bucket ciphertext를 반사하지 않는다.
- REST/gRPC session open의 stale requested epoch 오류는 requested/current epoch 값을 반사하지 않고, private HNSW runtime `result_privacy` unsupported-value 오류도 submitted option value를 반사하지 않는다.
- collection/runtime vector dim/distance mismatch 오류는 실제 dim/distance 값을 반사하지 않는다.
- `qdrant-sec` private HNSW provider/client와 private result ORAM helper의 `Display` 오류 문자열은 structured enum fields를 보존하되 bucket id, epoch, version, ciphertext length, leaf, unsupported algorithm 같은 값은 반사하지 않도록 고정 메시지화한다.
- `qdrant-sec` private HNSW client와 private result ORAM error `Debug` 회귀도 Display와 같은 structured-value variant를 직접 렌더링해 bucket id, epoch, version, context sentinel, unsupported algorithm/detail이 반사되지 않는지 고정한다.
- Collection store initial upload의 unsupported/tampered manifest signature 오류도 submitted algorithm, signature key/body, manifest root, bucket ciphertext/hash/commitment를 반사하지 않고 layout 생성 전 fail closed 된다.
- Collection store writeback의 unsupported commit signature algorithm 오류도 submitted signature key/body, old/new root, updated bucket ciphertext, bucket commitment를 반사하지 않고 저장 epoch/bucket/Merkle 상태를 유지한다.
- `qdrant-sec` private result ORAM client helper의 encryption wrapper error는 inner AEAD algorithm/detail 문자열을 Display에 붙이지 않는다. Private HNSW helper는 resource-key validation 오류를 wrapper로 보존하지 않고 고정 `InvalidResourceKeyId`로 매핑해 submitted key detail을 반사하지 않는다.
- snapshot creation/restore preflight는 on-disk private HNSW ORAM vector store가 collection encryption rule에 매칭되지 않거나, configured vector store가 없거나, parent store가 symlink이거나, client-owned ORAM state 또는 non-empty temp write state가 섞여 있으면 fail-closed로 거부한다.
- manifest signature, manifest ORAM capacity, bucket hash, stale epoch, invalid commit signature, symlink/permission hardening, snapshot leakage, crash recovery는 현재 provider/store/API fixture에 추가되어 있다.

완료 조건:

- `vector/client-ckks@v1`는 server-blind opaque storage, `vector/openfhe-ckks@v1`는 trusted-bridge search, `vector/private-hnsw-oram@v1`는 client-led ORAM-HNSW search로 명확히 분리된다.
- Qdrant는 private provider에서 vector/query plaintext, distance/score, HNSW traversal decision, top-k result 결정을 수행하지 않는다.
- private provider의 snapshot/restore/shard transfer는 encrypted buckets, manifest, epoch/root metadata만 다루고 fail-closed 검증을 갖춘다.
