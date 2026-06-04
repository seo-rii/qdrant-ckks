# qdrant-sec Large Work Plan

이 문서는 `RISK_REGISTER.md`의 대형 작업을 구현 순서대로 정리한다. 작은 방어 패치는 이미 별도 커밋으로 일부 처리됐고, 여기서는 설계, migration, 테스트 인프라, 구조 변경이 필요한 작업만 다룬다.

기준 브랜치: `sec`
최종 갱신: 2026-05-14

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

남은 대형 작업:

- CKKS encrypted vector production-grade indexing: sidecar storage/search, segment-level ciphertext HNSW graph primitive, and client-supplied encrypted query ciphertext scoring are implemented, but plaintext-vector `HNSWIndex` file-format reuse, score decryption, and broader distributed rebuild/recovery coverage are still not implemented.
- Crypto migration workflow: admin plan/rewrite/decrypt endpoints, point scan, verified checkpoint, decrypt completion, and re-encrypt primitive are implemented. 남은 범위는 background orchestration, persisted resume scheduling, rollback automation, and old-key disable/destroy retirement gate다.
- Cluster-wide client nonce replay ledger: request/process/collection-local/reload cache는 있지만 consensus-backed global ledger는 없다.
- Metadata encryption: server-side metadata value AEAD와 client-generated exact-match blind-index token field provider/query integration은 들어갔다. Metadata value AEAD는 `encrypted_payload=decrypted` read mode와 `payload_decrypt` 권한을 공유한다. Server-computed tokens, range/geo/full-text searchable encryption, and dedicated metadata RBAC는 아직 없다.
- Encrypted payload read policy: raw envelope 반환은 기본값이고, REST/gRPC redacted/decrypted modes와 collection-scoped `payload_decrypt` capability는 연결되어 있다. 남은 범위는 export/read dump 정책과 SDK-side client envelope decrypt flow다.
- KMS/Vault key providers: local/env/file/fd/`unix_socket`/`vault_kv2`/wrapped material 기반은 있지만 external KMS lifecycle은 future work다.
- Broader distributed integration: current unit/integration coverage는 많지만 multi-node parity/restore/replay ledger e2e는 남아 있다.

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

목표: `lib/ckks`를 공통 crypto layer와 provider-specific layer로 나눈다.

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
- 새 provider 추가가 `lib/ckks`에 계속 결합되지 않는다.

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

- Phase A: control-plane provider/binding const, runtime allowlist, strict-profile validation, collection binding validation, normal vector write/search fail-closed skeleton을 추가한다.
- Phase B: `PrivateHnswOramManifest` 타입, manifest signature format, collection-local `private_hnsw_oram/{vector}` store, bucket read/write primitive, epoch `current.json` CAS primitive를 추가한다.
- Phase C: REST/gRPC manifest, session open/close, ORAM `read_paths`, `commit`, session lease, single-writer lock, fixed request-size validation을 추가한다.
- Phase D: Rust 또는 Python reference SDK로 read-only bulk build, Path ORAM client, client-led HNSW traversal, known-answer fixtures를 제공한다.
  - 현재 Rust helper는 f32 reference neighbor graph build, explicit-level f32 layered graph build, deterministic node-id level assignment, HNSW-style redundant-neighbor pruning, prebuilt node-block ORAM packing, encrypted bucket sealing/Merkle root generation, signed upload bundle packaging, verified encrypted traversal wrapper, post-commit signed manifest refresh, client state snapshot export/import, RK-derived encrypted client-state backup을 제공한다. 서버 테스트는 SDK-packaged manifest/bucket bundle이 REST/gRPC bucket upload와 같은 manifest epoch/root 및 Merkle commitment 계약을 만족하는지도 검증하고, collection store fixture는 SDK upload/read_paths/verified-search/writeback-commit round trip을 검증한다. REST JSON DTO와 gRPC protobuf DTO fixture도 SDK-built manifest/buckets/session/read_paths/commit wire package를 round trip하고, gRPC fixture는 Merkle proof가 포함된 read response를 SDK verifier에 통과시킨다. REST/gRPC live route fixtures는 Dispatcher-backed collection에서 manifest upload, bucket upload, session open, `read_paths`, SDK proof verification, commit, close, post-commit signed manifest refresh, refreshed-epoch session open을 통과한다. SDK distribution packaging은 serde-compatible `PrivateHnswOramUploadBundle` API로 완료했다.
- Phase E: `ids_visible` result privacy를 문서화하고, `private_payload_oram_required` payload/result fetch 설계를 별도 provider 또는 index-token 확장으로 구체화한다.
  - 현재 MVP는 `ids_visible`만 runtime에서 허용하고, manifest/session policy도 runtime result privacy와 불일치하는 manifest를 거부한다. `private_payload_oram_required`는 wire enum으로 예약하지만 payload ORAM provider가 구현될 때까지 runtime validation에서 fail closed 한다.
  - `payload/private-result-oram@v1` 및 `private-result-oram/v1` 식별자는 예약했지만 runtime provider로는 아직 허용하지 않는다. runtime instance나 collection encryption rule에 등장하면 reserved/not implemented 오류로 fail closed 한다.
  - `PrivateResultOramManifest`, `PrivateResultOramBucket`, `PrivateResultOramSignature`, canonical manifest/commit signature message, Ed25519 signature verification/signing helpers, collection/key/epoch/capacity context validation, Path ORAM tree_height/bucket_count validation, encrypted bucket shape/hash validation, bucket commitment Merkle root/proof verifier, client writeback commit planning helper, signed upload bundle packaging, post-commit signed manifest refresh helper는 crypto crate에 contract skeleton으로 추가했다. collection-local `PrivateResultOramStore` skeleton도 추가해 `private_result_oram/manifest.json`, `manifest.sig`, encrypted buckets, Merkle commitment metadata, epoch `current.json` CAS, canonical `merkle_path_batch/v1` read proof DTO, initial upload bundle ingest, writeback commit helper를 private HNSW ORAM store와 같은 fail-closed hardening으로 다룬다. writeback commit helper는 stale current epoch을 bucket/Merkle writeback 전에 preflight해 실패한 stale commit이 저장 파일을 먼저 바꾸지 않도록 한다. collection snapshot은 `private_result_oram/`이 있으면 포함하지만, 현재 restore는 `payload/private-result-oram@v1` runtime이 열릴 때까지 그 디렉터리나 symlink를 fail-closed로 거부한다. runtime upload/session API는 아직 열지 않는다.
- Phase F: upper-layer client cache, speculative neighbor prefetch, neighbor clustering, graph-tailored ORAM 실험을 benchmark와 함께 추가한다.
  - upper-layer client cache는 `PrivateHnswClientNodeCache`와 `*_with_cache` search helper로 시작했다. 캐시 hit는 local node copy로 traversal/distance를 수행하되 `padding_node_id` ORAM access를 소비해 fixed-step request volume을 유지한다.
  - search access metrics는 `PrivateHnswSearchResult::access_metrics`와 `PrivateHnswSearchAccessMetrics`로 시작했다. SDK benchmark가 fixed-budget ORAM search의 path access 수, unique leaf 수, budget exhaustion 여부를 plaintext 노출 없이 기록할 수 있다.
  - benchmark harness는 `cargo bench -p qdrant-sec --bench private_hnsw_oram_bench`로 시작했다. 현재는 64x32 f32 fixture의 plaintext index build, fixed-budget plaintext ORAM-HNSW traversal, upper-layer client-cache traversal, client-AEAD encrypted bucket traversal, speculative prefetch planning, neighbor-clustered leaf planning, directional neighbor filtering, graph-traversal path batch planning을 잰다.
  - speculative neighbor prefetch는 `plan_private_hnsw_oram_speculative_prefetch` helper로 시작했다. SDK가 client position map에서 후보 node leaf를 deduplicate하고 고정 path 수까지 dummy leaf로 padding한 `read_paths` label 묶음을 만들 수 있다.
  - neighbor clustering은 `plan_private_hnsw_oram_neighbor_clustered_leaves` helper로 시작했다. bulk build 전에 entry에서 graph-order BFS를 수행해 관련 node chain을 인접 leaf에 배정하는 실험용 leaf planner다.
  - directional neighbor filtering은 `plan_private_hnsw_oram_directional_neighbor_filter` helper로 시작했다. client가 현재 노드/neighbor block/query vector를 로컬에서 해독한 뒤 query 방향으로 진행하는 neighbor만 거리순으로 고르는 실험용 planner다.
  - graph-traversal tailored ORAM은 `plan_private_hnsw_oram_graph_traversal_path_batch` helper로 시작했다. directional neighbor filter 결과를 client position map과 speculative prefetch padding에 연결해 fixed-size `read_paths` batch를 만든다.
- Phase G: cluster parity fingerprint, private-HNSW transfer fail-closed, shard-local epoch ownership, consensus-backed epoch/root CAS를 설계하고 e2e 테스트한다.
  - cluster parity fingerprint는 기존 crypto runtime capability fingerprint에 private HNSW ORAM options/signing verifier policy가 포함되는 테스트로 고정했다. ORAM tree shape 또는 private HNSW signing verifier drift는 peer parity mismatch로 실패한다.
  - private-HNSW transfer fail-closed는 cluster update 진입점에서 시작형 shard transfer(`move_shard`, `replicate_shard`, `replicate_points`, `restart_transfer`)를 consensus submit 전에 막도록 연결했다. private ORAM bucket file transfer와 consensus-backed epoch/root ownership이 구현될 때까지 shard transfer를 허용하지 않는다.
  - distributed session open은 consensus-backed epoch/root CAS가 구현될 때까지 fail closed 한다. 현재 MVP의 ORAM commit CAS는 node-local 파일 상태만 원자화하므로 cluster session을 열지 않는다.

테스트:

- runtime strict mode에서 private provider는 허용되고 server materials/backend, unsupported options, non-client-led search, loose fixed budget, unpinned RK id/epoch은 거부된다.
- collection config는 `private-hnsw-oram/v1` binding과 rule당 단일 vector name만 허용하고, 같은 vector name에 대한 다른 vector binding overlap, vector dim/distance와 runtime options mismatch를 거부한다.
- normal `upsert`/`update_vectors` plaintext write와 server-side search/scoring은 private ORAM session API 안내 메시지로 fail closed 된다. 실제 `do_upsert_points`/`do_update_vectors`, root `do_query_points`, 그리고 universal query prefetch/fusion 경계도 같은 fail-closed 메시지로 고정했다.
- private ORAM bucket store는 missing canonical layout을 `NotFound`로 fail-closed 처리하고, directory chmod 전에 symlink/type을 검사하며, symlink bucket과 Unix group/world-accessible bucket directory/file을 fail-closed로 거부한다.
- crash window에서 bucket/Merkle writeback이 epoch CAS보다 먼저 보이더라도 old current epoch와 new bucket/root를 섞어 serving하지 않고 fail closed 한다.
- collection snapshot은 client-sealed private HNSW bucket ciphertext를 포함하되 private ORAM snapshot source symlink와 bucket plaintext sentinel bytes를 archive에 허용하지 않고, restore preflight는 result privacy, collection/vector context, vector dim/distance, manifest signature key id, Path ORAM tree_height/bucket_count mismatch, current epoch/root, bucket commitments로 재계산한 manifest root mismatch, manifest bucket range 전체의 bucket presence mismatch와 bucket symlink를 fail-closed로 거부한다.
- REST/gRPC ORAM commit fixture는 non-increasing new_epoch, invalid Ed25519 commit signature, successful commit 이후 stale old_epoch replay를 모두 fail-closed로 검증한다. Commit path는 bucket/Merkle writeback 전에 store current epoch/root도 active session의 old epoch/root와 일치하는지 preflight한다.
- REST/gRPC ORAM session fixture는 strict mode `fixed_budget=false`, non-current desired epoch, reserved `private_payload_oram_required` result privacy를 session open에서 거부한다.
- REST/gRPC ORAM session fixture는 active session이 있는 같은 private index에 대해 두 번째 session open을 `ConcurrentWriter`로 거부한다.
- REST/gRPC ORAM session fixture는 active session이 있는 같은 private index에 대해 signed manifest upload와 initial encrypted bucket upload도 거부한다.
- REST/gRPC ORAM session fixture는 writeback commit 이후 stale signed manifest로는 새 epoch session을 열 수 없고, closed session id는 `read_paths`와 `commit`에 재사용할 수 없으며, refreshed signed manifest upload 뒤에는 같은 epoch session을 열 수 있음을 검증한다.
- REST/gRPC `read_paths`와 `commit` 오류 응답은 unknown session id sentinel을 반사하지 않는다.
- REST/gRPC session close 오류 응답은 unknown session id sentinel을 반사하지 않는다.
- REST/gRPC manifest read fixture는 uploaded manifest/signature를 runtime policy와 Ed25519 검증을 거쳐 반환한다. Manifest upload 전 manifest read, bucket upload, session open은 sanitized `NotFound`로 fail closed 되고, manifest/bucket upload fixture는 signed manifest collection/vector/key lineage/vector metadata context mismatch, Path ORAM tree_height/bucket_count mismatch, invalid manifest Ed25519 signature, bucket `ciphertext_sha256` mismatch, incomplete bucket set, duplicated bucket id를 upload 경계에서 fail closed로 거부한다.
- REST/gRPC manifest upload, `read_paths`, `commit` signature key id lookup 오류 응답은 submitted key id sentinel을 반사하지 않는다.
- REST/gRPC manifest upload unsupported signature algorithm 오류 응답은 submitted algorithm sentinel을 반사하지 않는다.
- REST/gRPC manifest upload malformed signature 오류 응답은 submitted signature sentinel을 반사하지 않는다.
- REST/gRPC manifest upload store layout 오류 응답은 collection-local `private_hnsw_oram` filesystem path를 반사하지 않는다.
- REST/gRPC manifest read corrupt store 오류 응답은 collection-local `private_hnsw_oram` filesystem path를 반사하지 않는다.
- REST/gRPC bucket upload epoch/root 오류 응답은 submitted root hash sentinel을 반사하지 않는다.
- REST/gRPC bucket upload Merkle root mismatch 오류 응답은 computed Merkle root를 반사하지 않는다.
- REST/gRPC bucket upload 오류 응답은 malformed bucket ciphertext sentinel을 반사하지 않는다.
- REST/gRPC bucket upload store layout 오류 응답은 collection-local `private_hnsw_oram` filesystem path를 반사하지 않는다.
- REST/gRPC bucket upload/session open current epoch store 오류 응답은 collection-local `private_hnsw_oram` filesystem path를 반사하지 않는다.
- REST/gRPC session open client_id shape 오류 응답은 submitted client id sentinel을 반사하지 않는다.
- SDK helper는 commit plan의 old epoch/root가 현재 manifest와 맞을 때만 refreshed manifest/signature를 만들고, stale old root는 client-side에서 거부한다.
- private result ORAM skeleton도 동일하게 commit plan의 old epoch/root와 현재 manifest를 묶어 refreshed manifest/signature를 만들고 stale old root를 거부한다.
- private result ORAM store skeleton의 upload bundle, commit, stored Merkle tree root mismatch 오류는 computed Merkle root를 반사하지 않는다.
- private result ORAM store skeleton은 directory chmod 전에 symlink/type을 검사하고, bucket symlink와 group/world-accessible bucket directory/file을 fail-closed로 거부한다.
- REST/gRPC `read_paths` 오류 응답은 mismatched root hash sentinel, malformed path label sentinel, stored bucket ciphertext를 반사하지 않는다.
- REST/gRPC `read_paths` missing encrypted bucket/proof 오류 응답은 collection-local `private_hnsw_oram` filesystem path를 반사하지 않는다.
- REST/gRPC `read_paths`와 `commit` malformed client signature shape 오류 응답은 submitted signature sentinel을 반사하지 않는다.
- REST/gRPC `commit` old epoch/root mismatch 오류 응답은 submitted old root hash sentinel을 반사하지 않는다.
- REST/gRPC `commit` fixture는 empty 또는 oversized `updated_buckets`를 fixed writeback request-size validation에서 거부한다.
- REST/gRPC `commit` 오류 응답은 malformed updated bucket ciphertext sentinel을 반사하지 않는다.
- REST/gRPC `commit` missing Merkle metadata 오류 응답은 collection-local `private_hnsw_oram` filesystem path를 반사하지 않는다.
- REST/gRPC `read_paths` fixture는 path count, requested path count, dummy padding flag가 fixed path budget과 다르거나 exact duplicate path label을 포함하면 bucket read 전에 fail-closed로 거부한다.
- REST/gRPC `read_paths` 성공 경로는 collection/vector, key lineage, epoch/root, path labels, padding metadata에 대한 Ed25519 client signature를 검증한 뒤 encrypted buckets를 반환하고, invalid read signature는 fail-closed로 거부한다.
- snapshot restore preflight는 `private_payload_oram_required` manifest를 payload ORAM provider 구현 전까지 거부하고 `ids_visible`만 허용한다.
- CLI/startup snapshot mapping recovery도 crypto runtime validation 이후 private HNSW ORAM restore-layout preflight를 실행해 storage-level snapshot recovery와 같은 bucket/root consistency 검증을 적용한다.
- manifest signature, manifest ORAM capacity, bucket hash, stale epoch, invalid commit signature, symlink/permission hardening, snapshot leakage, crash recovery는 현재 provider/store/API fixture에 추가되어 있다.

완료 조건:

- `vector/client-ckks@v1`는 server-blind opaque storage, `vector/openfhe-ckks@v1`는 trusted-bridge search, `vector/private-hnsw-oram@v1`는 client-led ORAM-HNSW search로 명확히 분리된다.
- Qdrant는 private provider에서 vector/query plaintext, distance/score, HNSW traversal decision, top-k result 결정을 수행하지 않는다.
- private provider의 snapshot/restore/shard transfer는 encrypted buckets, manifest, epoch/root metadata만 다루고 fail-closed 검증을 갖춘다.
