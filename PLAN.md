# qdrant-sec Large Work Plan

이 문서는 `RISK_REGISTER.md`의 대형 작업을 구현 순서대로 정리한다. 작은 방어 패치는 이미 별도 커밋으로 일부 처리됐고, 여기서는 설계, migration, 테스트 인프라, 구조 변경이 필요한 작업만 다룬다.

기준 브랜치: `sec`
최종 갱신: 2026-06-15

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
- OpenFHE bridge path/hash validation, parent-dir checks, env secret stripping, timeout/stdout/stderr malicious-behavior coverage, worker pool, batch protocol이 들어가 있다.
- Encrypted payload read policy는 raw/redacted/decrypted 모드로 연결되어 있다. `decrypted`는 server-side `$qdrant_sec` payload text와 metadata value AEAD markers에만 적용되고 runtime settings와 global manage 또는 collection-scoped `payload_decrypt` 권한이 필요하며, client-side `$qdrant_client_aead`는 계속 raw/redacted만 지원한다.
- Metadata value AEAD와 client-generated blind-index token field는 canonical provider로 들어갔다. Blind-index token은 exact-match 전용이고 range/geo/full-text searchable encryption은 계속 unsupported다.
- `vector/private-hnsw-oram@v1`와 `payload/private-result-oram@v1`는 Phase 11 provider/API/store/SDK helper surface까지 연결되어 있다. Qdrant는 private HNSW ORAM에서 encrypted bucket store, manifest/signature validation, session lease, fixed-budget read/commit, epoch/root CAS만 수행하고, client SDK가 HNSW traversal, distance 계산, top-k, result payload ORAM fetch planning을 수행한다.
- Private ORAM REST/gRPC surface, OpenAPI Beta paths, metrics endpoint labels, snapshot/restore preflight, active-session snapshot guard, ordinary search/upsert/payload read fail-closed guard, redaction/leakage tests가 들어가 있다.

남은 대형 작업:

- CKKS encrypted vector production-grade indexing: sidecar storage/search, segment-level ciphertext HNSW graph primitive, and client-supplied encrypted query ciphertext scoring are implemented, but plaintext-vector `HNSWIndex` file-format reuse, score decryption, and broader distributed rebuild/recovery coverage are still not implemented.
- Crypto migration workflow: admin plan/rewrite/decrypt endpoints, point scan, verified checkpoint, decrypt completion, and re-encrypt primitive are implemented. 남은 범위는 background orchestration, persisted resume scheduling, rollback automation, and old-key disable/destroy retirement gate다.
- Cluster-wide client nonce replay ledger: request/process/collection-local/reload cache는 있지만 consensus-backed global ledger는 없다.
- Metadata encryption: server-side metadata value AEAD와 client-generated exact-match blind-index token field provider/query integration은 들어갔다. Metadata value AEAD는 `encrypted_payload=decrypted` read mode와 `payload_decrypt` 권한을 공유한다. Server-computed tokens, range/geo/full-text searchable encryption, and dedicated metadata RBAC는 아직 없다.
- Encrypted payload read policy: raw envelope 반환은 기본값이고, REST/gRPC redacted/decrypted modes와 collection-scoped `payload_decrypt` capability는 연결되어 있다. 남은 범위는 export/read dump 정책과 SDK-side client envelope decrypt flow다.
- KMS/Vault key providers: local/env/file/fd/`unix_socket`/`vault_kv2`/wrapped material 기반은 있지만 external KMS lifecycle은 future work다.
- Broader distributed integration: current unit/integration coverage는 많지만 multi-node parity/restore/replay ledger e2e는 남아 있다.
- Private HNSW ORAM productionization: read-only bulk-built single-writer MVP와 result ORAM fetch path는 들어갔지만 dynamic online HNSW insertion, multi-writer/consensus-backed ORAM epoch ownership, private ORAM bucket shard transfer/resharding, and broader multi-node e2e benchmark coverage는 future work다.

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
  - 현재 Rust helper는 f32 reference neighbor graph build, explicit-level f32 layered graph build, deterministic node-id level assignment, HNSW-style redundant-neighbor pruning, prebuilt node-block ORAM packing, encrypted bucket sealing/Merkle root generation, signed upload bundle packaging/preflight, manifest-aware writeback commit planning, verified encrypted traversal wrapper, post-commit signed manifest refresh, client state snapshot export/import, RK-derived encrypted client-state backup을 제공한다. 서버 테스트는 SDK-packaged manifest/bucket bundle이 REST/gRPC bucket upload와 같은 manifest epoch/root, fixed ciphertext size, Merkle commitment 계약을 만족하는지도 검증하고, crypto crate와 collection store fixture는 context-bound client key derivation으로 SDK upload/read_paths/verified-search/writeback-commit round trip을 검증한다. REST JSON DTO와 gRPC protobuf DTO fixture도 context-bound SDK-built manifest/buckets/session/read_paths/commit wire package를 round trip하고, gRPC fixture는 Merkle proof가 포함된 read response를 SDK verifier에 통과시킨다. REST/gRPC live route fixtures는 Dispatcher-backed collection에서 manifest upload, bucket upload, session open, `read_paths`, SDK proof verification, commit, close, post-commit signed manifest refresh, refreshed-epoch session open을 통과한다. SDK distribution packaging은 serde-compatible `PrivateHnswOramUploadBundle` API와 `validate_private_hnsw_oram_upload_bundle` preflight로 완료했다.
- Phase E: `ids_visible` result privacy를 문서화하고, `private_payload_oram_required` payload/result fetch 설계를 별도 provider 또는 index-token 확장으로 구체화한다.
  - 현재 working MVP는 `ids_visible`과 `private_payload_oram_required` private HNSW result mode를 구분하고, manifest/session policy도 runtime result privacy와 불일치하는 manifest를 거부한다. Runtime schema와 server-side HNSW manifest upload, bucket upload, session open, snapshot restore preflight는 `private_payload_oram_required`를 collection의 `private-result-oram/v1` payload rule이 `payload/private-result-oram@v1` provider에 함께 묶인 경우에만 허용하고, binding이 없으면 fail closed 한다. HNSW snapshot restore preflight도 paired result ORAM snapshot manifest의 `oram.path_batch_size`가 private HNSW `fixed_budget.fixed_result_k`를 나누는지 확인해 restored index가 partial final `read_buckets` batch를 만들지 못하게 한다. 일반 Qdrant search/query API는 계속 client-led private session 요구 오류를 반환한다.
  - HNSW SDK search hit은 node block의 `payload_fetch_token`을 전달하기 시작했고, `validate_private_hnsw_search_result_privacy` helper는 `private_payload_oram_required`에서 token 없는 hit을 fail closed 한다. SDK fetch-plan helper는 hit token을 정확히 `fixed_result_k`개 payload/result ORAM fetch token batch로 패딩하되 distinct dummy-token pool을 요구해 중복 logical fetch token을 거부한다. Collection runtime은 `private_payload_oram_required`에서 result ORAM `oram.path_batch_size`가 private HNSW `fixed_budget.fixed_result_k`를 나누지 못하면 거부해 SDK가 partial final `read_buckets` batch를 만들 수 없게 한다. result ORAM client fetch planner와 verified fetch wrapper도 token batch 길이가 `oram.path_batch_size`의 정확한 배수가 아니면 fail closed 한다. private result ORAM fetch planner는 이 token batch와 client-held token-position map을 session `read_buckets` bucket-id sequence로 바꾸며, shared path bucket 중복을 제거하지 않고 보존해 fixed ORAM path volume이 overlap에 따라 줄어들지 않도록 한다. 서버 read validator도 duplicate bucket id를 허용하되 non-empty, whole-path-shaped, canonical Path ORAM heap path, 정확한 fixed-budget batch만 받는다. crypto crate는 collection/key lineage, index epoch, root hash, bucket count, exact padded bucket-id sequence를 묶는 canonical `read_buckets` message/sign/verify helper도 제공하고, REST/gRPC `read_buckets` API는 이 signed read request를 필수로 검증한 뒤 encrypted bucket read 또는 detailed path-shape error로 진행한다. planner는 missing position, duplicate token, duplicate position entry, out-of-range leaf를 fail closed 한다. private result ORAM client-only payload block/plaintext bucket codec도 추가되어 payload bytes, payload fetch token, point token, generation, deletion state를 fixed-size encrypted bucket body 안에 넣을 수 있다. bucket AEAD seal/open helper는 collection/key/epoch AAD, context-bound bucket commitment, ciphertext hash check, Merkle-proof-before-open read batch 검증까지 제공한다. SDK-side result ORAM state/access helper는 token position map/stash로 payload fetch token을 Path ORAM path에서 꺼내고 새 leaf로 remap한 뒤 commit용 plaintext writeback bucket을 만든다. Verified token-fetch helper는 client position map에서 expected bucket path sequence를 재구성해 read plan과 일치해야만 planned encrypted bucket batches를 열고, batched Path ORAM access 사이의 local writeback overlay를 적용하며, payload blocks와 result ORAM commit planner용 unique resealed writeback buckets를 반환한다. REST/gRPC result ORAM commit guard는 owner-signed `updated_buckets`를 `oram.path_batch_size * (oram.tree_height + 1)` fixed writeback budget으로 제한해 commit volume이 manifest `bucket_count`까지 확장되지 않게 하고, multi-batch result fetch는 반복 fixed-size read/commit window로 처리한다. empty/duplicate/stale/malformed/invalid-signature commit은 계속 fail closed 한다. HNSW SDK finalizer는 real HNSW hit만 fetched payload block에 매핑하고 fetch-token 순서, point-token binding, deleted payload rejection을 검증한다. result ORAM client-state plaintext snapshot shape도 추가해 token position map/stash backup shape를 검증하고, encrypted snapshot helper는 client-derived state key와 collection/key/epoch/root AAD로 backup ciphertext를 seal/open한다.
  - Result ORAM `read_buckets` crypto message builder/signer/validator는 signed `bucket_count`에서 canonical Path ORAM tree height를 역산하고, non-canonical tree size, partial path, invalid root-to-leaf bucket sequence를 signature acceptance 전에 거부한다.
  - REST/gRPC result ORAM `read_buckets` route fixtures now also assert that signed malformed path-shape errors and out-of-range bucket-id signature failures do not reflect submitted root hashes, session ids, read signatures, or bucket ciphertext bodies.
  - REST/gRPC result ORAM `read_buckets`와 `commit` request signature key id도 session manifest의 `owner_signing_key_id`와 달라도 fail closed 한다. Runtime `signature_public_keys`에 등록된 다른 key id만으로는 해당 private result index의 read/writeback request를 authorize하지 않는다.
  - `payload/private-result-oram@v1` runtime provider validation은 초기 E2에서 열렸고 현재 REST/gRPC session/read/commit 표면까지 연결됐다. runtime instance는 server materials/backend 없이 `key_id`, `expected_rk_id`, pinned RK epoch, Path ORAM shape, integrity booleans, signature public key registry만 허용한다. `private-result-oram/v1` collection binding validation은 provider `payload/private-result-oram@v1`만 허용하며 ordinary point upsert/sync/delete/delete-by-filter/payload write/delete/clear plan과 payload index/schema plan에는 들어가지 않는다. 그런 요청은 private result ORAM session API 안내와 함께 fail closed 한다. Ordinary point upsert/sync는 payload 내용이 public-looking이더라도 private result ORAM epoch contract 밖에서 point payload state를 만들거나 교체할 수 있으므로 binding이 있으면 닫고, key-less `overwrite_payload`는 full payload replacement로 취급한다. key-less `set_payload`도 protected path의 parent/child key overlap을 건드리면 fail closed 하며, exact child-only public payload merges만 일반 경로에서 허용한다. Ordinary retrieve/scroll/search/query raw payload reads도 `with_payload`가 private result ORAM payload path를 반환하려 하면 같은 session API 안내와 함께 fail closed 하고, payload 생략 또는 redacted encrypted payload output만 일반 read 경로에서 허용한다. Trusted-bridge CKKS sidecar fallback, point-id resolution, grouped sidecar search, CKKS search matrix는 이제 full raw payload 대신 reserved vector sidecar와 필요한 group key만 요청해 private result ORAM payload path를 실수로 건드리지 않는다. Filter/order-by/group-by/facet/formula selector가 private result ORAM payload path를 inspect하려는 경우도 blind-index 안내 대신 private result ORAM session API 안내로 fail closed 한다. REST/gRPC manifest/bucket upload API, session open/close, signed session-bound `read_buckets`, signed writeback `commit` API도 열었다.
  - `PrivateResultOramManifest`, `PrivateResultOramBucket`, `PrivateResultOramSignature`, canonical manifest/commit signature message, Ed25519 signature verification/signing helpers, collection/key/epoch/capacity context validation, Path ORAM tree_height/bucket_count validation, encrypted bucket shape/hash validation, context-bound bucket commitment validation, bucket commitment Merkle root/proof verifier, client writeback commit planning helper, manifest-aware writeback commit planning helper, signed upload bundle packaging/preflight, post-commit signed manifest refresh helper는 crypto crate에 contract surface로 들어갔다. collection-local `PrivateResultOramStore` 구현은 `private_result_oram/manifest.json`, `manifest.sig`, encrypted buckets, Merkle commitment metadata, epoch `current.json` CAS, canonical `merkle_path_batch/v1` read proof DTO, initial upload bundle ingest, signed initial upload bundle ingest, writeback commit helper를 private HNSW ORAM store와 같은 fail-closed hardening으로 다룬다. initial upload bundle ingest는 crypto crate의 같은 preflight helper를 사용한 뒤 store runtime ciphertext size cap을 추가로 적용하고, signed ingest entrypoint는 owner Ed25519 manifest signature를 검증한 뒤에만 layout/bucket/current epoch 파일을 쓴다. writeback commit helper는 stale current epoch과 manifest epoch/root context를 bucket/Merkle writeback 전에 preflight하고, updated bucket commitment가 ciphertext hash와 collection/key lineage/bucket epoch context에 묶여 있는지 Merkle prepare 전에 검증해 실패한 stale/tampered commit이 저장 파일을 먼저 바꾸지 않도록 한다. collection snapshot은 configured `private-result-oram/v1` binding이 있을 때만 `private_result_oram/`을 포함하고, collection restore와 CLI/REST/storage recovery preflight는 manifest/current epoch, buckets, Merkle metadata, runtime Ed25519 signature를 fail-closed로 검증한다. runtime session은 single-writer lock과 active snapshot/upload guard를 사용하며, read/commit은 active session epoch/root와 current store epoch/root가 맞을 때만 수행된다.
  - Phase E rollout은 네 단계로 나눈다. E1은 provider/binding/result privacy enum을 예약하고 store/crypto contract를 fail-closed contract로 고정했다. E2는 runtime provider validation만 열되 collection binding과 API는 계속 닫아 provider options, signature registry, RK pinning, ORAM capacity, ciphertext cap 정책을 먼저 고정했다. E3는 collection binding, snapshot/restore preflight, manifest/bucket upload/read API를 열되 private HNSW `private_payload_oram_required`와 연결하지 않았다. E4는 private result ORAM session/read/commit API와 HNSW result fetch-token SDK linkage를 열었고, HNSW manifest/session/snapshot policy는 collection에 result ORAM binding이 있을 때만 `private_payload_oram_required`를 허용한다.
  - OpenAPI Beta surface는 private HNSW ORAM과 private result ORAM manifest upload/read, bucket upload, session open/close, read, commit REST paths를 노출하고 `docs/redoc/master/openapi.json` 생성물과 consistency endpoint count를 갱신했다. Consistency check는 14개 private ORAM REST method/path/operationId와 14개 generated gRPC method path도 직접 고정한다. REST/gRPC request metrics whitelist도 같은 private ORAM fixed endpoint labels를 포함하되 path labels, bucket ids, session ids, ciphertext, client-state fields는 metric labels에 넣지 않는다. gRPC metrics canonicalization fixture는 HNSW/result manifest get/upload, HNSW bucket upload, read, commit, close-session의 동적 suffix도 fixed method label로만 축약되는지 검증한다.
- Phase F: upper-layer client cache, speculative neighbor prefetch, neighbor clustering, graph-tailored ORAM 실험을 benchmark와 함께 추가한다.
  - upper-layer client cache는 `PrivateHnswClientNodeCache`와 `*_with_cache` search helper로 시작했다. 캐시 hit는 local node copy로 traversal/distance를 수행하되 `padding_node_id` ORAM access를 소비해 fixed-step request volume을 유지한다.
  - search access metrics는 `PrivateHnswSearchResult::access_metrics`와 `PrivateHnswSearchAccessMetrics`로 시작했다. SDK benchmark가 fixed-budget ORAM search의 path access 수, unique leaf 수, budget exhaustion 여부를 plaintext 노출 없이 기록할 수 있다. zero-step params는 빈 결과라도 exhausted로 보고하지 않는다. Strict SDK caller용 `validate_private_hnsw_strict_search_result` helper도 추가해 result privacy와 fixed-step budget exhaustion을 함께 fail-closed로 검증한다.
  - layered f32 builder는 u64 `level_mask` 경계를 fail-closed로 다룬다. level 63은 `u64::MAX` mask로 표현하고, level 64 이상은 panic/overflow 없이 invalid `levels` config로 거부한다.
  - benchmark harness는 `cargo bench -p qdrant-sec --bench private_hnsw_oram_bench`로 시작했다. 현재는 64x32 f32 fixture의 plaintext index build, fixed-budget plaintext ORAM-HNSW traversal, upper-layer client-cache traversal, client-AEAD encrypted bucket traversal, speculative prefetch planning, neighbor-clustered leaf planning, directional neighbor filtering, graph-traversal path batch planning with retained/path stats를 잰다. Benchmark fixture도 collection/vector/RK epoch context-bound client key derivation을 사용한다.
  - speculative neighbor prefetch는 `plan_private_hnsw_oram_speculative_prefetch` helper로 시작했다. SDK가 client position map에서 후보 node leaf를 deduplicate하고 고정 path 수까지 server `read_paths` duplicate-label guard와 호환되는 unique dummy leaf로 padding한 label 묶음을 만들 수 있다. Leaf-label bucket-path helper도 duplicate label을 bucket sequence 생성 전에 거부한다.
  - neighbor clustering은 `plan_private_hnsw_oram_neighbor_clustered_leaves` helper로 시작했다. bulk build 전에 entry에서 graph-order BFS를 수행해 관련 node chain을 인접 leaf에 배정하는 실험용 leaf planner이며, entry node id가 build block set에 없으면 fallback하지 않고 fail closed 한다.
  - directional neighbor filtering은 `plan_private_hnsw_oram_directional_neighbor_filter` helper로 시작했다. client가 현재 노드/neighbor block/query vector를 로컬에서 해독한 뒤 query 방향으로 진행하는 neighbor만 거리순으로 고르는 실험용 planner다.
  - graph-traversal tailored ORAM은 `plan_private_hnsw_oram_graph_traversal_path_batch` helper로 시작했다. directional neighbor filter 결과를 client position map과 speculative prefetch padding에 연결해 fixed-size `read_paths` batch를 만든다. `*_with_stats` variant는 directional filter retained count와 실제 position-map-backed path count를 분리해 benchmark가 graph-filter selectivity와 ORAM path volume을 따로 기록할 수 있게 한다.
  - graph traversal/prefetch planner는 real candidate가 0개이거나 directional filter가 모든 neighbor를 버리는 경우에도 dummy leaf로 정확한 fixed-size path batch를 만들고, padding leaf도 중복 없이 순환하는지 회귀 테스트로 고정한다.
- Phase G: cluster parity fingerprint, private-ORAM transfer fail-closed, shard-local epoch ownership, consensus-backed epoch/root CAS를 설계하고 e2e 테스트한다.
  - cluster parity fingerprint는 기존 crypto runtime capability fingerprint에 private HNSW ORAM과 private result ORAM options/signing verifier policy가 포함되는 테스트로 고정했다. ORAM tree shape, private HNSW signing verifier drift, private result ORAM signing verifier drift는 peer parity mismatch로 실패한다. mismatch 오류, `/readyz` readiness mismatch 출력, distributed telemetry mismatch summary는 peer id만 남기고 local/peer fingerprint 문자열이나 private ORAM verifier key sentinel을 반사하지 않는다.
  - App telemetry는 private HNSW ORAM과 private result ORAM `signature_public_keys` registry 원문을 직렬화하지 않고 non-secret runtime capability fingerprint만 내보내며, private ORAM verifier public key sentinel fixture로 회귀를 고정한다.
  - private-ORAM transfer/resharding/shard-key layout change/replica removal fail-closed는 private HNSW ORAM과 private result ORAM bucket store를 쓰는 collection의 cluster update 진입점에서 시작형 shard transfer(`move_shard`, `replicate_shard`, `replicate_points`, `restart_transfer`), resharding progress(`start_resharding`, `finish_migrating_points`, `commit_read_hash_ring`, `commit_write_hash_ring`, `finish_resharding`), shard-key layout 변경(`create_sharding_key`, `drop_sharding_key`), replica removal(`drop_replica`)을 consensus submit 전에 막도록 연결했다. 자동 dead-replica shard transfer recovery도 private ORAM bucket store collection에서는 transfer 제안을 스킵한다. 이미 consensus에 들어온 transfer라도 `Start`, `Restart`, `Finish`, `RecoveryToPartial`, `SnapshotRecovered` 진행 operation은 local transfer task start 또는 replica state progression 전에 다시 fail closed 하고, cleanup용 `Abort`만 허용한다. 이미 consensus에 들어온 resharding `Start`, `CommitRead`, `CommitWrite`, `Finish`와 resharding replica-state progress도 local resharding/hash-ring/replica-state 진행 전에 fail closed 하고 cleanup용 `Abort`만 허용한다. `create_shard_key`/`drop_shard_key` meta-op, direct replica-set `Remove` update, direct `create_replica_set`도 local layout 변경 전에 fail closed 한다. private ORAM bucket file migration과 consensus-backed epoch/root ownership이 구현될 때까지 shard transfer, resharding, shard-key layout 변경, replica removal을 허용하지 않는다.
  - replica-state update guard는 private ORAM collection에서 `Resharding`/`ReshardingScaleDown`이 관련된 전이만 fail closed 하고, non-resharding state-only transition은 열어 둔다. `Active`/`Dead`/`Partial`/`Initializing`/`Listener`/`PartialSnapshot`/`Recovery`/`ActiveRead`/`ManualRecovery` 전이가 guard에 막히지 않는지 테스트로 고정했다.
  - consensus snapshot apply도 private ORAM bucket store collection에서는 transfer state 주입, non-empty resharding state 주입, shard layout config 변경, shard id set/shard-key mapping/replica membership 변경, resharding replica-state 주입을 fail closed 한다. Empty transfer/resharding cleanup state와 non-resharding replica state-only sync만 허용해 bucket movement 없이 local shard 파일을 만들거나 제거하지 못하게 한다. non-resharding replica state-only sync는 `Dead`/`Partial`/`Initializing`/`Listener`/`PartialSnapshot`/`Recovery`/`ActiveRead`/`ManualRecovery` 상태 적용이 guard에 막히지 않는지 테스트로 고정했다.
  - Storage consensus apply guard 오류도 private HNSW/result ORAM collection id/name, runtime key id, rule id, instance id, binding id, collection-local store directory name 같은 config sentinel을 반사하지 않는지 transfer/resharding/shard-key/replica-remove fixture로 고정한다. Cluster submit guard 오류도 같은 store directory sentinel을 반사하지 않는지 검증한다.
  - Private ORAM resharding/shard-key guards는 consensus submit과 collection-local layout 변경 경계 모두에서 호출자가 넘긴 operation label을 오류에 반사하지 않고 고정 resharding/shard-key layout 메시지만 반환한다.
  - 수동 shard snapshot 생성/stream/download/recovery와 partial snapshot manifest 조회도 private ORAM bucket store collection에서는 fail closed 한다. partial snapshot recovery는 recovery lock 상태를 관찰하기 전에 같은 guard로 먼저 닫는다. guard 오류는 호출자가 넘긴 operation label, private ORAM key id, rule id, instance id, binding id, collection-local store directory name을 반사하지 않는다. 현재 private index는 collection-local `private_hnsw_oram/` 또는 `private_result_oram/` bucket store이므로 shard snapshot만으로는 epoch/root parity를 보존할 수 없다.
  - distributed private ORAM epoch operations는 consensus-backed epoch/root CAS가 구현될 때까지 fail closed 한다. 현재 MVP의 ORAM commit CAS는 node-local 파일 상태만 원자화하므로 manifest upload, bucket upload, session open, session-bound read, commit은 cluster mode에서 진행하지 않는다. REST/gRPC route fixtures도 manifest upload, bucket upload, session open, session-bound read, commit이 모두 같은 consensus-backed CAS guard에서 거부되는지 검증한다.
  - Private HNSW/result ORAM active-session epoch/root mismatch guard는 `read_paths`/`read_buckets`/`commit` 같은 operation label을 오류에 반사하지 않고 고정 active-session mismatch 메시지만 반환한다.
  - Private HNSW/result ORAM initial upload epoch mismatch guard는 store helper에 전달되는 `upload bundle` operation label을 오류에 반사하지 않고 고정 initial-epoch mismatch 메시지만 반환한다.

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
- collection snapshot guard는 private HNSW manifest/bucket upload write window가 열린 collection에서도 fail closed 한다.
- REST/gRPC ORAM session fixture는 active private HNSW ORAM session이 있는 collection의 collection/full snapshot 생성도 거부하고, collection/full snapshot guard가 잡힌 동안 새 session open과 manifest/bucket upload도 거부한다. 오류는 session id, root hash, bucket ciphertext sentinel, collection-local `private_hnsw_oram` path를 반사하지 않는지 검증한다. Registry-level active-session/upload/snapshot guards는 collection id suffix/prefix 또는 다른 vector upload와 충돌 없이 exact collection/vector index marker만 막는지도 회귀 테스트로 고정한다.
- REST/gRPC private result ORAM live fixture도 collection/full snapshot guard가 잡힌 동안 session open, manifest upload, bucket upload를 거부하고, active result ORAM session이 있는 collection의 collection/full snapshot 생성도 거부한다. 오류는 session id, result root hash, bucket ciphertext, collection-local `private_result_oram` path를 반사하지 않는지 검증한다. Registry-level upload/snapshot guards는 collection id suffix/prefix 충돌 없이 exact collection marker만 막는지도 회귀 테스트로 고정한다.
- SDK/client state, REST/common wire DTO, canonical signature input/context, AEAD/commitment context, verifier public key, collection-local private ORAM store의 Rust `Debug` surface도 session id, root hash, decoded epoch root hash, path label, bucket id, ORAM epoch, ciphertext length/body, signature key id/body, RK id, client position/stash, payload bytes, collection-local filesystem path를 반사하지 않도록 수동 redaction으로 바꿨고, qdrant-sec/qdrant/collection unit tests가 sentinel leak absence를 검증한다.
- collection snapshot 생성은 archive 작성 전에 private HNSW ORAM manifest/current epoch/bucket/Merkle restore-layout parity를 preflight하고, 누락 bucket 같은 layout 오류를 collection-local path나 root hash 반사 없이 fail closed 한다.
- collection snapshot 생성은 private result ORAM store도 archive 작성 전에 manifest/current epoch/bucket/Merkle restore-layout parity를 preflight하고, configured binding 없는 orphan store나 누락 bucket 같은 layout 오류를 collection-local path나 root hash 반사 없이 fail closed 한다.
- private HNSW ORAM과 private result ORAM restore preflight는 manifest bucket range 전체를 검사하며 first/middle/last bucket 누락과 storage-level restore 경로를 bucket filename, collection-local path, root hash, signature/ciphertext-like base64url token 반사 없이 fail closed 한다.
- private ORAM snapshot source preflight와 archive append도 canonical store layout 외 파일을 거부한다. restore preflight는 추가 bucket/layout 파일, malformed current/epoch commit file, missing temp directory archive 형태를 회귀 테스트로 고정했고, current/epoch commit file은 bounded JSON epoch/root shape와 canonical root hash를 요구하며 commit file은 filename epoch 일치도 요구한다.
- REST/gRPC ORAM session fixture는 writeback commit 이후 stale signed manifest로는 새 epoch session을 열 수 없고, closed session id는 `read_paths`와 `commit`에 재사용할 수 없으며, refreshed signed manifest upload 뒤에는 같은 epoch session을 열 수 있음을 검증한다.
- REST/gRPC `read_paths`와 `commit` 오류 응답은 unknown session id sentinel을 반사하지 않는다.
- REST/gRPC session close 오류 응답은 unknown session id sentinel을 반사하지 않는다.
- REST/gRPC `read_paths`, `commit`, `close`는 oversized/malformed session id를 registry lookup 전에 거부하고 submitted session id를 반사하지 않는다. well-shaped unknown session id는 기존 missing/expired-session 오류로 fail closed 된다.
- REST access log와 JSON validation boundary도 private ORAM 경로를 별도 sanitize한다. Access log는 session id, read path label, bucket/manifest/read/commit tail, private ORAM query string을 redaction하고 exact marker lookalike는 일반 경로로 유지한다. Private ORAM JSON body validation/deserialization 오류는 unknown field와 malformed body sentinel을 반사하지 않으며, gRPC route parameter validation도 oversized collection/vector 값과 malformed private ORAM collection-name sentinel을 오류 메시지에 넣지 않는다.
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
- SDK manifest/read_paths/read_buckets/commit signing helpers와 read_paths/read_buckets/commit message builders는 malformed manifest, path-count mismatch, malformed 또는 duplicate read path label/root/hash, partial result ORAM bucket path, unsupported request signature algorithm, malformed signature key id, non-advancing commit epoch, empty commit을 canonical message construction 전에 거부한다.
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
- SDK helper는 commit plan의 old epoch/root가 현재 manifest와 맞을 때만 refreshed manifest/signature를 만들고, stale old root는 client-side에서 거부한다.
- SDK upload bundle preflight는 manifest shape, manifest signature shape/owner key id, bucket ciphertext hash, bucket commitment, manifest root hash를 먼저 검증하고, bucket ciphertext hash와 context-bound commitment가 self-consistent하더라도 decoded ciphertext 길이가 manifest-derived fixed bucket ciphertext size와 다르면 client-side에서 거부한다. `validate_private_hnsw_oram_upload_bundle_with_signature`와 bundle method `validate_initial_upload_contract_with_signature`는 같은 preflight에 runtime manifest validation context와 Ed25519 verification을 묶어 호출할 수 있게 한다. `PrivateHnswOramStore::write_initial_upload_bundle_with_signature`도 이 helper를 호출한 뒤에만 layout/bucket/current epoch 파일을 쓰므로 owner signature 실패는 저장 상태를 만들지 않는다.
- manifest-aware `sign_private_hnsw_oram_read_paths_for_manifest` helper는 manifest epoch/root/key lineage/owner signing key, `oram.path_batch_size`, tree-bounded unique leaf label을 읽기 서명 context로 사용해 fixed read batch 수, leaf range, duplicate path label이 맞지 않으면 SDK에서 서명 전에 fail closed 한다.
- SDK/reference commit planning helper는 manifest epoch/root/bucket_count를 old commit context로 사용하고, updated bucket commitment가 ciphertext hash와 collection/vector/key lineage/bucket epoch context에 묶여 있지 않으면 commit 서명 전에 fail closed 한다. manifest-aware HNSW commit planner는 서버 commit guard와 같은 `oram.path_batch_size * (oram.tree_height + 1)` fixed writeback budget도 강제한다.
- SDK verified encrypted search/fetch helper도 writeback epoch가 read/session epoch보다 전진하지 않으면 첫 ORAM read 또는 local access remap 전에 fail closed 한다. HNSW verified search와 cached verified search는 `InvalidCommitEpoch`로 닫고, private result ORAM verified token fetch는 `new_epoch` manifest-field 오류로 닫아 서버 commit CAS와 같은 non-advancing epoch 불변식을 client boundary에서도 유지한다. Public HNSW plaintext/encrypted/verified search와 private result ORAM multi-batch verified fetch는 작업용 client state에만 remap/writeback을 누적하고 모든 proof/open/reseal 또는 plaintext validation이 성공한 뒤 원본 state를 갱신한다. HNSW search wrapper는 pending writeback overlay를 subsequent reads에 적용하되 caller writeback callback은 full search success 후 한 번만 호출하므로, 뒤 batch proof 실패나 post-access decode 실패가 앞 remap/writeback을 남기지 않는다.
- `PrivateHnswOramStore::commit_writeback_with_signature`는 runtime REST/gRPC commit 경로에 연결되어 canonical Ed25519 commit signature를 저장 manifest lineage로 검증한 뒤에만 fixed ciphertext size, context-bound bucket commitment, Merkle update, bucket writes, epoch/root CAS를 적용한다. stored manifest epoch/root 또는 bucket_count가 commit old context와 맞지 않는 경우도 bucket/Merkle/epoch 상태를 바꾸기 전에 fail closed 한다. invalid signature, malformed ciphertext, stale root, commitment-context mismatch, bucket ciphertext hash mismatch, short/oversized fixed ciphertext, wrong new Merkle root는 bucket/Merkle/epoch 상태를 바꾸기 전에 fail closed 하며, runtime 오류 응답은 ciphertext 범주 같은 안전한 힌트만 보존하고 ciphertext body, bucket id, root hash는 반사하지 않는다.
- SDK encrypted client-state backup helper는 ORAM position map/stash snapshot shape를 seal 전에 검증하고, open 전에 ciphertext hash shape와 encoded ciphertext 길이를 제한해 malformed/oversized backup ciphertext를 거부하며, duplicate position/stash, malformed node/token id, malformed leaf label을 snapshot import 경계에서 fail closed 한다. encrypted backup DTO가 position entries, leaf labels, stash blocks, node ids, point/payload fetch tokens, vector bytes, neighbor ids를 plaintext로 직렬화하지 않는지도 검증한다.
- private result ORAM encrypted client-state backup open도 HNSW client-state backup과 같은 epoch/root context binding, malformed ciphertext, short ciphertext, malformed hash, tampered ciphertext fail-closed 회귀를 갖고, encrypted backup DTO가 position tokens, leaf labels, stash payload fetch tokens, point tokens, payload bytes를 plaintext로 직렬화하지 않는지 검증한다.
- manifest-aware `sign_private_result_oram_read_buckets_for_manifest` helper는 manifest epoch/root/key lineage/owner signing key와 `oram.path_batch_size * (oram.tree_height + 1)` fixed bucket-id volume 및 canonical Path ORAM heap path shape를 읽기 서명 context로 사용해 fixed read batch 수나 path shape가 맞지 않으면 SDK에서 서명 전에 fail closed 한다.
- private result ORAM도 동일하게 commit plan의 old epoch/root와 현재 manifest를 묶어 refreshed manifest/signature를 만들고 stale old root를 거부한다. manifest-aware SDK commit planner는 서버 commit guard와 같은 `oram.path_batch_size * (oram.tree_height + 1)` fixed writeback budget을 강제해 oversized aggregate writeback plan을 로컬에서 fail closed 한다.
- private result ORAM upload bundle preflight도 manifest signature shape와 owner key id를 먼저 검증한다. `validate_private_result_oram_upload_bundle_with_signature`와 bundle method `validate_initial_upload_contract_with_signature`는 upload API가 shape/bucket/root preflight와 owner Ed25519 verification을 하나의 helper로 호출할 수 있게 한다. `PrivateResultOramStore::write_initial_upload_bundle_with_signature`도 이 helper를 호출한 뒤에만 layout/bucket/current epoch 파일을 쓰므로 owner signature 실패는 저장 상태를 만들지 않는다. `PrivateResultOramStore::commit_writeback_with_signature`는 canonical Ed25519 commit signature를 store manifest lineage로 검증한 뒤에만 기존 bucket/Merkle/epoch writeback 경로로 들어가므로 invalid signature는 저장 상태를 바꾸지 않는다. REST/gRPC commit handler도 canonical commit signature validator가 duplicate bucket refs 같은 malformed writeback shape를 generic signature-failure path에서 먼저 닫은 뒤에만 Merkle/writeback 검증으로 진행한다. manifest-aware commit planning/signature helper도 empty commit, malformed updated bucket ciphertext hash, updated bucket commitment가 ciphertext hash와 collection/key lineage/bucket epoch context에 묶여 있지 않은 commit을 서명/검증 전에 fail closed 한다.
- private result ORAM store의 upload bundle, commit, stored Merkle tree root mismatch 오류는 computed Merkle root를 반사하지 않는다. Bucket read/proof/commit 오류도 bucket id나 bucket epoch 값을 반사하지 않도록 일반화한다.
- private result ORAM store의 current epoch와 Merkle tree context 오류도 stored/requested epoch, bucket_count, unsupported version 값을 반사하지 않도록 일반화한다.
- private result ORAM store의 file/directory hardening 오류도 collection-local path, temp filename, symlink target, OS error 문자열을 반사하지 않도록 고정 메시지화한다.
- private result ORAM manifest-only upload helper는 manifest/signature write가 성공한 뒤에만 initial current epoch를 publish하고, current manifest 재업로드는 저장 manifest/signature와 byte-identical일 때만 허용하며, writeback 이후 current epoch가 새 manifest epoch/root로 이미 전진한 post-commit refresh는 허용한다. Private HNSW/result ORAM current manifest reupload mismatch 오류도 제출/저장 signature와 root hash를 반사하지 않도록 테스트로 고정했다.
- private result ORAM store의 bucket shape 검증은 encoded ciphertext 길이를 decode 전에 제한한다. writeback commit도 empty update와 non-advancing epoch를 거부하고 current epoch/root와 manifest epoch/root/bucket_count를 먼저 확인하며, updated bucket commitment가 ciphertext hash와 collection/key lineage/bucket epoch context에 묶여 있지 않으면 bucket/Merkle write 전에 fail closed 한다.
- private HNSW와 private result ORAM store의 bucket JSON read cap은 decoded ciphertext cap에 고정 여유분만 더하지 않고 base64url encoded 길이와 bounded JSON metadata overhead를 합산한다. 따라서 allowlist의 큰 bucket/block 조합도 정상 read되면서 oversized file은 계속 fail closed 된다.
- private HNSW와 private result ORAM의 client/server boundary arithmetic은 bucket plaintext codec length, canonical signature field length, Path ORAM path batch capacity, session lease expiry, registry refcount, Merkle bucket count, Merkle proof sibling count/level, request length, bucket id conversion을 checked conversion으로 처리해 overflow나 platform-width mismatch가 silent wrap 대신 fail closed 되도록 고정했다.
- private result ORAM initial epoch helper도 같은 epoch/root 재업로드만 idempotent하게 허용하고 mismatched manifest epoch/root 재업로드는 기존 `current.json`을 덮지 않는다. 같은 epoch/root의 initial upload bundle 재업로드도 저장된 manifest/signature, Merkle tree, bucket set과 byte-identical일 때만 no-op으로 허용하며, 각각의 mismatch를 별도 fail-closed 테스트로 고정했다.
- private HNSW ORAM initial upload bundle도 private result ORAM과 같은 parity를 갖는다. manifest Merkle root mismatch는 layout을 만들기 전에 거부하고, existing current epoch/root mismatch는 manifest/bucket/Merkle write 전에 fail closed 하며, 같은 epoch/root 재업로드는 저장된 manifest/signature, Merkle tree, bucket set이 byte-identical일 때만 no-op으로 허용한다. 두 store의 existing manifest/Merkle/bucket-set mismatch 오류도 제출되거나 저장된 root hash, signature, bucket commitment, ciphertext body를 반사하지 않도록 테스트로 고정했다.
- private result ORAM read-batch helper는 encrypted bucket read 전에 current epoch/root를 preflight하고, 반환 bucket과 Merkle proof leaf commitment가 서로 맞지 않으면 ciphertext, bucket id, root 값을 반사하지 않고 fail closed 한다.
- private ORAM bucket의 `index_epoch`는 해당 bucket이 마지막으로 쓰인 epoch를 뜻한다. writeback commit 후 변경되지 않은 bucket은 current index epoch보다 낮은 bucket epoch를 유지할 수 있으며, current Merkle root가 그 기존 bucket commitment를 포함할 때만 read proof로 반환된다. requested session epoch보다 미래인 bucket은 read/proof verifier에서 fail closed 한다.
- private result ORAM store는 directory chmod 전에 symlink/type을 검사하고, bucket symlink와 group/world-accessible bucket directory/file을 fail-closed로 거부한다. Snapshot source/restore preflight도 private HNSW/result ORAM root/nested symlink, unsupported file type, restore inspection error, client-state/position-map/stash alias를 fail closed로 거부하면서 symlink target path, bucket filename, collection-local path, OS error 문자열을 오류에 반사하지 않는다.
- collection-facing private HNSW ORAM runtime validation 오류는 내부 setup error detail을 붙이지 않고 고정 메시지로 반환해 unsupported option 이름, option 값, reason 문자열이 collection runtime BadInput에 반사되지 않는다.
- private HNSW와 private result ORAM Merkle proof store generator는 empty bucket batch를 거부하고, store-level Merkle commit prepare도 empty updated bucket set을 거부한다. SDK JSON verifier도 proof body를 파싱 전에 크기 제한하고, empty proof/bucket set을 거부하며, fixed-size path batch를 위해 반복 bucket/proof entry가 byte-identical인 경우만 허용하고 conflicting duplicate는 fail-closed로 거부한다.
- private HNSW ORAM Merkle proof serialization failure도 serde error detail 없이 고정 service error로 반환한다.
- SDK verified encrypted search는 upper-layer client cache hit 경로에서도 Merkle proof를 bucket decrypt, state remap, ORAM writeback보다 먼저 검증한다.
- REST access log와 denied-auth audit path는 private ORAM close-session URL의 session id를 템플릿으로 치환하고 private ORAM read/commit query string과 비정상 private ORAM endpoint tail segment를 redacted 처리한다. malformed private result ORAM close-session path도 session id를 반사하지 않는다. slow request log/request hash redaction은 private HNSW ORAM path/read/access/visited-node traversal aliases, query vector/embedding/plaintext aliases, score/distance aliases, candidate heap/score/distance aliases, node score/distance aliases, request/commit/read/manifest signature aliases, private result ORAM bucket ids, read bucket ids, bucket id sequences, bucket/leaf commitments, updated bucket writebacks, session ids, client-state aliases, point/payload fetch tokens를 숨기며 snake_case/camelCase 단수·복수 alias fixture로 회귀를 고정한다.
- denied-auth audit error redaction도 private ORAM path/root/bucket/node/vector/token aliases와 query vector/embedding/plaintext, score/distance, candidate/node score/distance aliases를 숨기며 sentinel fixture로 회귀를 고정한다.
- private result ORAM nested request 객체 안의 `session_id`/`sessionId`, `bucket_ids`/`bucketIds`, `bucket_commitments`/`bucketCommitments`, `updated_buckets`/`updatedBuckets`, client-state ciphertext/hash aliases도 slow-request log와 request hash에서 redacted projection으로 동일화한다.
- panic telemetry와 gRPC status logging redaction도 private ORAM session/path/raw read_paths/access path/read bucket id/bucket sequence/bucket or leaf commitment/entry node/level mask/visited node/neighbor/query vector/score/distance/candidate score/distance/node score/distance/result/token/client-state/client-state ciphertext/hash/position-map/stash/update bucket/signature, owner/signing key id, signature-public-key registry snake_case·camelCase alias sentinel을 반사하지 않는지 검증한다.
- private result ORAM ordinary payload write/read guards는 configured protected payload path 파싱 실패 시 parser debug detail이나 submitted path token을 반사하지 않고 고정 오류로 fail closed 한다.
- Common/REST/gRPC update fixtures도 private HNSW ORAM `Upsert`/`Delete`/legacy `DeleteDeprecated`/`DeleteVectors`/internal `SyncPoints`와 private result ORAM `Upsert`/`SetPayload`/`OverwritePayload`/`DeletePayload`/`ClearPayload`/legacy `ClearPayloadDeprecated`/`Delete`/legacy `DeleteDeprecated`가 direct ordinary update guard와 같은 session API 안내로 fail closed 되는지 고정한다.
- Common/internal/gRPC create/delete-field-index fixtures도 `private-result-oram/v1` payload path의 payload index/schema creation/deletion이 같은 private result ORAM session API 안내로 fail closed 되는지 고정한다.
- Public create/delete-field-index guard는 private result ORAM payload-path 검증 전에 `write().extras()` 권한을 먼저 확인해 unauthorized caller에게 provider/session/path detail을 드러내지 않는지도 고정한다.
- gRPC `GetPoints`/`ScrollPoints`/`SearchPoints`/batch search/`SearchPointGroups`/`RecommendPoints`/batch recommend/`RecommendPointGroups`/`DiscoverPoints`/batch discover/`QueryPoints`/batch query/`QueryPointGroups` ordinary payload read wrappers도 `private-result-oram/v1` payload path를 반환하려 하면 common read guard와 같은 private result ORAM session API 안내로 fail closed 되는지 고정한다.
- Common/gRPC `encrypted_payload=decrypted` read requests와 REST group lookup preflight도 `private-result-oram/v1` payload path에 대해 generic decrypt-runtime 오류로 빠지지 않고 같은 private result ORAM session API 안내로 fail closed 되는지 고정한다.
- Common/gRPC read fixtures는 private result ORAM collection에서도 payload를 요청하지 않는 허용 경로를 열어 두어, payload-omitted retrieve/scroll/search 요청이 private result ORAM session을 요구하지 않는지도 고정한다.
- gRPC grouped `with_lookup` payload requests도 lookup collection이 `private-result-oram/v1` payload path를 반환하려 하면 main hit payload가 꺼져 있어도 같은 private result ORAM session API 안내로 fail closed 되는지 고정한다.
- gRPC facet, count filter, scroll filter/order-by, formula query, grouped search, grouped query selector wrappers도 `private-result-oram/v1` payload path를 inspect하려 하면 common selector guard와 같은 private result ORAM session API 안내로 fail closed 되는지 고정한다.
- gRPC `PointsSelector` filter variant도 private HNSW ORAM `delete`/`delete_vectors`와 private result ORAM `set_payload`/`overwrite_payload`/`delete_payload`/`clear_payload`/`delete`에서 point-id selector와 같은 private session API 안내로 fail closed 되는지 고정한다.
- REST request metrics fixture도 private result ORAM `read_buckets`와 close-session endpoint에서 fixed endpoint label만 방출하고 dynamic bucket id/session id sentinel을 방출하지 않는지 검증한다. Metrics/OpenAPI surface checks use segment-aware private ORAM path matching and include malformed/lookalike path negatives so partial or similar path names do not become fixed labels.
- REST/gRPC private HNSW와 private result ORAM bucket upload/commit request-shape preflight는 collection, manifest, session lookup 전에 empty upload/writeback, duplicate upload bucket id, malformed `ciphertext_sha256`/`bucket_commitment`를 거부하며 submitted root hash, bucket ciphertext, commit signature body, collection-local store path를 반사하지 않는다.
- REST/gRPC private result ORAM bucket upload preflight도 mismatched 또는 malformed root hash를 submitted root hash와 bucket ciphertext 반사 없이 fail closed 한다.
- REST/gRPC private result ORAM bucket upload ciphertext/hash mismatch 오류도 submitted bucket ciphertext body를 반사하지 않고 generic ciphertext validation failure로 멈춘다.
- REST/gRPC private result ORAM `read_buckets`와 `commit`은 mismatched 또는 malformed root hash를 fail closed 하면서 submitted root hash, commit signature body, updated bucket ciphertext를 오류에 반사하지 않는다.
- REST/gRPC `read_paths` 오류 응답은 mismatched root hash sentinel, malformed path label sentinel, stored bucket ciphertext를 반사하지 않는다. path-to-bucket derivation helper도 하위 leaf-label decode 오류를 그대로 반사하지 않는다.
- REST/gRPC `read_paths` missing encrypted bucket/proof 오류 응답은 collection-local `private_hnsw_oram` filesystem path를 반사하지 않는다.
- REST/gRPC `read_paths`는 store current epoch/root가 active session과 맞지 않으면 bucket을 읽기 전에 fail closed 하고 stale root, stored bucket ciphertext, collection-local `private_hnsw_oram` path를 반사하지 않는다.
- REST/gRPC `read_paths`는 collection store의 batch+proof helper로 bucket을 읽어 current epoch/root를 store layer에서도 재확인하고, 응답 직전에 각 bucket commitment가 같은 순서의 Merkle proof leaf와 일치하는지 검증하며, mismatch가 있으면 ciphertext나 store path를 반사하지 않고 fail closed 한다.
- REST/gRPC `read_paths`와 `commit` malformed client signature shape 오류 응답은 submitted signature sentinel을 반사하지 않는다. Crypto signature message builders/validators도 collection/vector/key lineage, root hash, read path label, duplicate path label, `requested_paths`/path count 일치성, non-advancing commit epoch, updated bucket ciphertext hash shape를 signature body parsing/message construction 전에 검증한다.
- REST/gRPC `read_paths` 성공 응답은 bucket id를 unique set으로 축약하지 않고 요청된 ORAM path별 bucket sequence를 보존해 `requested_paths * (tree_height + 1)` 크기를 유지하며, SDK verifier는 반복 bucket/proof가 byte-identical일 때만 허용한다.
- REST/gRPC `commit` old epoch/root mismatch 오류 응답은 submitted old root hash sentinel을 반사하지 않는다.
- REST/gRPC `commit` fixture는 empty 또는 oversized `updated_buckets`를 fixed writeback request-size validation에서 거부하고, crypto commit signature validator도 empty bucket list를 signature body parsing 전에 fail closed 한다.
- REST/gRPC `commit` 오류 응답은 malformed updated bucket ciphertext/hash sentinel과 malformed `new_root_hash` sentinel을 반사하지 않으며, updated bucket `ciphertext_sha256` shape는 commit signature message construction 전에 검증한다.
- REST/gRPC `commit` missing Merkle metadata 오류 응답은 collection-local `private_hnsw_oram` filesystem path를 반사하지 않는다.
- REST/gRPC `read_paths` fixture는 path count, requested path count, dummy padding flag가 fixed path budget과 다르거나 exact duplicate/oversized/malformed path label을 포함하면 bucket read 전에 fail-closed로 거부하고 malformed label 본문을 반사하지 않는다.
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
- Collection store initial upload의 unsupported/tampered manifest signature 오류도 submitted algorithm, signature key/body, manifest root, bucket ciphertext/hash/commitment를 반사하지 않고 layout 생성 전 fail closed 된다.
- Collection store writeback의 unsupported commit signature algorithm 오류도 submitted signature key/body, old/new root, updated bucket ciphertext, bucket commitment를 반사하지 않고 저장 epoch/bucket/Merkle 상태를 유지한다.
- `qdrant-sec` private HNSW client와 private result ORAM client helper의 encryption wrapper error도 inner AEAD algorithm/detail 문자열을 Display에 붙이지 않는다.
- snapshot creation/restore preflight는 on-disk private HNSW ORAM vector store가 collection encryption rule에 매칭되지 않거나, configured vector store가 없거나, parent store가 symlink이거나, client-owned ORAM state 또는 non-empty temp write state가 섞여 있으면 fail-closed로 거부한다.
- manifest signature, manifest ORAM capacity, bucket hash, stale epoch, invalid commit signature, symlink/permission hardening, snapshot leakage, crash recovery는 현재 provider/store/API fixture에 추가되어 있다.

완료 조건:

- `vector/client-ckks@v1`는 server-blind opaque storage, `vector/openfhe-ckks@v1`는 trusted-bridge search, `vector/private-hnsw-oram@v1`는 client-led ORAM-HNSW search로 명확히 분리된다.
- Qdrant는 private provider에서 vector/query plaintext, distance/score, HNSW traversal decision, top-k result 결정을 수행하지 않는다.
- private provider의 snapshot/restore/shard transfer는 encrypted buckets, manifest, epoch/root metadata만 다루고 fail-closed 검증을 갖춘다.
