use std::cmp::Ordering;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fs, io};

use common::counter::hardware_counter::HardwareCounterCell;
use common::types::{PointOffsetType, ScoredPointOffset, TelemetryDetail};

use crate::common::operation_error::{OperationError, OperationResult};
use crate::data_types::query_context::VectorQueryContext;
use crate::data_types::vectors::{QueryVector, VectorRef};
use crate::id_tracker::IdTracker;
use crate::index::struct_payload_index::StructPayloadIndex;
use crate::index::{PayloadIndex, VectorIndex};
use crate::telemetry::VectorIndexSearchesTelemetry;
use crate::types::{Filter, Order, Payload, SearchParams};

const CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_VERSION: u8 = 1;
const CKKS_CIPHERTEXT_HNSW_GRAPH_FILE: &str = "ckks_ciphertext_hnsw_graph.json";
const CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_MAX_BYTES: u64 = 512 * 1024 * 1024;
pub const CKKS_VECTOR_SIDECAR_PAYLOAD_FIELD: &str = "$qdrant_sec_vectors";
pub const CKKS_VECTOR_SIDECAR_MARKER: &str = "$qdrant_sec_ckks_vector";

#[derive(Clone, Debug)]
pub struct CkksCiphertextHnswGraph {
    links: Arc<Vec<Vec<usize>>>,
}

#[derive(Clone, Debug)]
pub struct CkksCiphertextHnswIndex<C> {
    records: Arc<Vec<C>>,
    graph: CkksCiphertextHnswGraph,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CkksCiphertextHnswHit {
    pub point_index: usize,
    pub score: f32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CkksCiphertextHnswRecordHit<'a, C> {
    pub point_index: usize,
    pub record: &'a C,
    pub score: f32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CkksCiphertextIndexedRecord {
    pub point_offset: PointOffsetType,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct CkksCiphertextVectorIndex {
    index: CkksCiphertextHnswIndex<CkksCiphertextIndexedRecord>,
    graph_file: Option<PathBuf>,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct CkksCiphertextHnswGraphFile {
    version: u8,
    record_count: usize,
    links: Vec<Vec<usize>>,
}

impl CkksCiphertextHnswGraph {
    pub fn from_validated_links(links: Vec<Vec<usize>>) -> Option<Self> {
        if links_have_valid_neighbors(&links)
            && links_are_reciprocal(&links)
            && links_are_connected(&links)
        {
            Some(Self {
                links: Arc::new(links),
            })
        } else {
            None
        }
    }

    pub fn links(&self) -> &[Vec<usize>] {
        self.links.as_ref()
    }

    pub fn links_are_reciprocal(links: &[Vec<usize>]) -> bool {
        links_are_reciprocal(links)
    }

    pub fn links_are_connected(links: &[Vec<usize>]) -> bool {
        links_are_connected(links)
    }

    pub fn add_bounded_undirected_link(
        links: &mut [Vec<usize>],
        first: usize,
        second: usize,
        max_degree: usize,
    ) {
        add_bounded_undirected_link(links, first, second, max_degree);
    }

    pub fn add_connectivity_backbone(links: &mut [Vec<usize>]) {
        add_connectivity_backbone(links);
    }

    pub fn build<E>(
        points_len: usize,
        m: usize,
        score_order: Order,
        mut score_previous_points: impl FnMut(usize) -> Result<Vec<f32>, E>,
    ) -> Result<Self, E> {
        let mut links = vec![Vec::<usize>::new(); points_len];
        if points_len == 0 {
            return Ok(Self {
                links: Arc::new(links),
            });
        }

        let max_degree = m.saturating_mul(2).max(1);
        for idx in 1..points_len {
            let scores = score_previous_points(idx)?;
            debug_assert_eq!(scores.len(), idx);
            let mut neighbors = scores
                .into_iter()
                .enumerate()
                .map(|(point_index, score)| CkksCiphertextHnswHit { point_index, score })
                .collect::<Vec<_>>();
            sort_hits(score_order, &mut neighbors);
            for neighbor in neighbors.into_iter().take(m) {
                add_bounded_undirected_link(&mut links, idx, neighbor.point_index, max_degree);
            }
        }

        add_connectivity_backbone(&mut links);
        Ok(Self {
            links: Arc::new(links),
        })
    }

    pub fn build_optimizer_candidate_graph(points_len: usize, m: usize) -> Self {
        let mut links = vec![Vec::<usize>::new(); points_len];
        if points_len == 0 {
            return Self {
                links: Arc::new(links),
            };
        }

        // Segment optimization does not own an OpenFHE scoring runtime. Build a
        // deterministic connected candidate graph here; query-time CKKS search
        // still scores visited ciphertext candidates through the runtime bridge.
        let max_degree = m.saturating_mul(2).max(1);
        for idx in 1..points_len {
            let first_candidate = idx.saturating_sub(m.max(1));
            for candidate in first_candidate..idx {
                add_bounded_undirected_link(&mut links, idx, candidate, max_degree);
            }
        }

        add_connectivity_backbone(&mut links);
        Self {
            links: Arc::new(links),
        }
    }

    pub fn search<E>(
        &self,
        ef: usize,
        top: usize,
        score_order: Order,
        score_threshold: Option<f32>,
        mut score_candidates: impl FnMut(&[usize]) -> Result<Vec<f32>, E>,
    ) -> Result<Vec<CkksCiphertextHnswHit>, E> {
        let links = self.links();
        if links.is_empty() || top == 0 {
            return Ok(Vec::new());
        }

        let mut visited = vec![false; links.len()];
        let mut frontier = vec![0usize];
        let mut scored = Vec::<CkksCiphertextHnswHit>::new();

        while !frontier.is_empty() && scored.len() < ef {
            frontier.sort_unstable();
            frontier.dedup();
            frontier.retain(|candidate| {
                let fresh = !visited[*candidate];
                visited[*candidate] = true;
                fresh
            });
            if frontier.is_empty() {
                break;
            }

            let scores = score_candidates(&frontier)?;
            debug_assert_eq!(scores.len(), frontier.len());
            let mut batch = frontier
                .into_iter()
                .zip(scores)
                .map(|(point_index, score)| CkksCiphertextHnswHit { point_index, score })
                .collect::<Vec<_>>();
            sort_hits(score_order, &mut batch);

            frontier = Vec::new();
            for hit in batch {
                if score_passes_threshold(score_order, hit.score, score_threshold) {
                    scored.push(hit);
                }
                for neighbor in &links[hit.point_index] {
                    if !visited[*neighbor] {
                        frontier.push(*neighbor);
                    }
                }
                if scored.len() >= ef {
                    break;
                }
            }
        }

        sort_hits(score_order, &mut scored);
        scored.truncate(top);
        Ok(scored)
    }
}

impl CkksCiphertextIndexedRecord {
    pub fn new(point_offset: PointOffsetType, ciphertext: Vec<u8>) -> Self {
        Self {
            point_offset,
            ciphertext,
        }
    }
}

impl CkksCiphertextVectorIndex {
    pub fn graph_file_path(directory: impl AsRef<Path>) -> PathBuf {
        directory.as_ref().join(CKKS_CIPHERTEXT_HNSW_GRAPH_FILE)
    }

    pub fn from_graph(
        records: Vec<CkksCiphertextIndexedRecord>,
        graph: CkksCiphertextHnswGraph,
    ) -> Option<Self> {
        CkksCiphertextHnswIndex::from_graph(records, graph).map(|index| Self {
            index,
            graph_file: None,
        })
    }

    pub fn build<E>(
        records: Vec<CkksCiphertextIndexedRecord>,
        m: usize,
        score_order: Order,
        score_previous_records: impl FnMut(
            &CkksCiphertextIndexedRecord,
            &[&CkksCiphertextIndexedRecord],
        ) -> Result<Vec<f32>, E>,
    ) -> Result<Self, E> {
        Ok(Self {
            index: CkksCiphertextHnswIndex::build(records, m, score_order, score_previous_records)?,
            graph_file: None,
        })
    }

    pub fn build_optimizer_candidate_graph(
        records: Vec<CkksCiphertextIndexedRecord>,
        m: usize,
    ) -> Self {
        let graph = CkksCiphertextHnswGraph::build_optimizer_candidate_graph(records.len(), m);
        let index = CkksCiphertextHnswIndex::from_graph(records, graph)
            .expect("candidate graph node count is derived from records");
        Self {
            index,
            graph_file: None,
        }
    }

    pub fn open_graph_file(
        records: Vec<CkksCiphertextIndexedRecord>,
        path: impl AsRef<Path>,
    ) -> OperationResult<Option<Self>> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(None);
        }

        let bytes = read_graph_file(path).map_err(|err| {
            OperationError::service_error(format!(
                "failed to read CKKS ciphertext HNSW graph file {}: {err}",
                path.display(),
            ))
        })?;
        let graph_file: CkksCiphertextHnswGraphFile =
            serde_json::from_slice(&bytes).map_err(|err| {
                OperationError::service_error(format!(
                    "failed to parse CKKS ciphertext HNSW graph file {}: {err}",
                    path.display(),
                ))
            })?;

        if graph_file.version != CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_VERSION {
            return Err(OperationError::service_error(format!(
                "unsupported CKKS ciphertext HNSW graph file version {} in {}",
                graph_file.version,
                path.display(),
            )));
        }
        if graph_file.record_count != records.len() {
            return Err(OperationError::service_error(format!(
                "CKKS ciphertext HNSW graph file {} record count {} does not match {} indexed records",
                path.display(),
                graph_file.record_count,
                records.len(),
            )));
        }
        let Some(graph) = CkksCiphertextHnswGraph::from_validated_links(graph_file.links) else {
            return Err(OperationError::service_error(format!(
                "CKKS ciphertext HNSW graph file {} contains invalid links",
                path.display(),
            )));
        };
        let Some(mut index) = Self::from_graph(records, graph) else {
            return Err(OperationError::service_error(format!(
                "CKKS ciphertext HNSW graph file {} does not match indexed records",
                path.display(),
            )));
        };
        index.graph_file = Some(path.to_path_buf());
        Ok(Some(index))
    }

    pub fn persist_graph_file(&mut self, path: impl AsRef<Path>) -> OperationResult<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                OperationError::service_error(format!(
                    "failed to create CKKS ciphertext HNSW graph directory {}: {err}",
                    parent.display(),
                ))
            })?;
        }
        let graph_file = CkksCiphertextHnswGraphFile {
            version: CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_VERSION,
            record_count: self.index.records().len(),
            links: self.index.graph().links().to_vec(),
        };
        let bytes = serde_json::to_vec(&graph_file).map_err(|err| {
            OperationError::service_error(format!(
                "failed to serialize CKKS ciphertext HNSW graph file {}: {err}",
                path.display(),
            ))
        })?;
        write_graph_file(path, &bytes).map_err(|err| {
            OperationError::service_error(format!(
                "failed to write CKKS ciphertext HNSW graph file {}: {err}",
                path.display(),
            ))
        })?;
        self.graph_file = Some(path.to_path_buf());
        Ok(())
    }

    pub fn search_ciphertext<E>(
        &self,
        ef: usize,
        top: usize,
        score_order: Order,
        score_threshold: Option<f32>,
        score_records: impl FnMut(&[&CkksCiphertextIndexedRecord]) -> Result<Vec<f32>, E>,
    ) -> Result<Vec<ScoredPointOffset>, E> {
        let hits =
            self.search_ciphertext_records(ef, top, score_order, score_threshold, score_records)?;

        Ok(hits
            .into_iter()
            .map(|hit| ScoredPointOffset {
                idx: hit.record.point_offset,
                score: hit.score,
            })
            .collect())
    }

    pub fn search_ciphertext_records<E>(
        &self,
        ef: usize,
        top: usize,
        score_order: Order,
        score_threshold: Option<f32>,
        score_records: impl FnMut(&[&CkksCiphertextIndexedRecord]) -> Result<Vec<f32>, E>,
    ) -> Result<Vec<CkksCiphertextHnswRecordHit<'_, CkksCiphertextIndexedRecord>>, E> {
        self.index
            .search(ef, top, score_order, score_threshold, score_records)
    }

    pub fn graph(&self) -> &CkksCiphertextHnswGraph {
        self.index.graph()
    }

    pub fn records(&self) -> &[CkksCiphertextIndexedRecord] {
        self.index.records()
    }
}

pub fn ckks_ciphertext_records_from_payload_index(
    id_tracker: &dyn IdTracker,
    payload_index: &StructPayloadIndex,
    vector_name: &str,
    hw_counter: &HardwareCounterCell,
) -> OperationResult<Vec<CkksCiphertextIndexedRecord>> {
    let mut records = Vec::new();
    for point_offset in id_tracker.point_mappings().iter_internal() {
        let payload = payload_index.get_payload_sequential(point_offset, hw_counter)?;
        if let Some(ciphertext) = ckks_ciphertext_from_payload(&payload, vector_name)? {
            records.push(CkksCiphertextIndexedRecord::new(
                point_offset,
                ciphertext.as_bytes().to_vec(),
            ));
        }
    }
    Ok(records)
}

pub fn ckks_ciphertext_from_payload<'a>(
    payload: &'a Payload,
    vector_name: &str,
) -> OperationResult<Option<&'a str>> {
    let Some(sidecar) = payload
        .0
        .get(CKKS_VECTOR_SIDECAR_PAYLOAD_FIELD)
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(None);
    };
    let Some(value) = sidecar.get(vector_name) else {
        return Ok(None);
    };
    let Some(marker) = value
        .as_object()
        .and_then(|object| object.get(CKKS_VECTOR_SIDECAR_MARKER))
    else {
        return Err(OperationError::service_error(format!(
            "stored CKKS vector sidecar entry '{vector_name}' is malformed",
        )));
    };
    let Some(ciphertext) = marker
        .get("envelope")
        .and_then(|envelope| envelope.get("ciphertext"))
        .and_then(serde_json::Value::as_str)
    else {
        return Err(OperationError::service_error(format!(
            "stored CKKS vector sidecar entry '{vector_name}' is missing ciphertext",
        )));
    };
    Ok(Some(ciphertext))
}

impl<C> CkksCiphertextHnswIndex<C> {
    pub fn from_graph(records: Vec<C>, graph: CkksCiphertextHnswGraph) -> Option<Self> {
        (records.len() == graph.links().len()).then(|| Self {
            records: Arc::new(records),
            graph,
        })
    }

    pub fn build<E>(
        records: Vec<C>,
        m: usize,
        score_order: Order,
        mut score_previous_records: impl FnMut(&C, &[&C]) -> Result<Vec<f32>, E>,
    ) -> Result<Self, E> {
        let graph = CkksCiphertextHnswGraph::build(records.len(), m, score_order, |idx| {
            let candidates = records[..idx].iter().collect::<Vec<_>>();
            score_previous_records(&records[idx], &candidates)
        })?;

        Ok(Self {
            records: Arc::new(records),
            graph,
        })
    }

    pub fn records(&self) -> &[C] {
        self.records.as_ref()
    }

    pub fn graph(&self) -> &CkksCiphertextHnswGraph {
        &self.graph
    }

    pub fn search<E>(
        &self,
        ef: usize,
        top: usize,
        score_order: Order,
        score_threshold: Option<f32>,
        mut score_records: impl FnMut(&[&C]) -> Result<Vec<f32>, E>,
    ) -> Result<Vec<CkksCiphertextHnswRecordHit<'_, C>>, E> {
        let hits = self
            .graph
            .search(ef, top, score_order, score_threshold, |candidates| {
                let records = candidates
                    .iter()
                    .map(|candidate| &self.records[*candidate])
                    .collect::<Vec<_>>();
                score_records(&records)
            })?;

        Ok(hits
            .into_iter()
            .map(|hit| CkksCiphertextHnswRecordHit {
                point_index: hit.point_index,
                record: &self.records[hit.point_index],
                score: hit.score,
            })
            .collect())
    }
}

impl VectorIndex for CkksCiphertextVectorIndex {
    fn search(
        &self,
        vectors: &[&QueryVector],
        _filter: Option<&Filter>,
        _top: usize,
        _params: Option<&SearchParams>,
        _query_context: &VectorQueryContext,
    ) -> OperationResult<Vec<Vec<ScoredPointOffset>>> {
        Err(OperationError::validation_error(format!(
            "CKKS ciphertext HNSW index does not accept plaintext QueryVector search requests; received {} query vector(s)",
            vectors.len(),
        )))
    }

    fn get_telemetry_data(&self, _detail: TelemetryDetail) -> VectorIndexSearchesTelemetry {
        VectorIndexSearchesTelemetry::default()
    }

    fn files(&self) -> Vec<PathBuf> {
        self.graph_file.iter().cloned().collect()
    }

    fn immutable_files(&self) -> Vec<PathBuf> {
        self.files()
    }

    fn indexed_vector_count(&self) -> usize {
        self.index.records().len()
    }

    fn size_of_searchable_vectors_in_bytes(&self) -> usize {
        self.index
            .records()
            .iter()
            .map(|record| record.ciphertext.len())
            .sum()
    }

    fn update_vector(
        &mut self,
        _id: PointOffsetType,
        _vector: Option<VectorRef>,
        _hw_counter: &HardwareCounterCell,
    ) -> OperationResult<()> {
        Err(OperationError::validation_error(
            "CKKS ciphertext HNSW index cannot be updated with plaintext vectors",
        ))
    }
}

fn add_bounded_undirected_link(
    links: &mut [Vec<usize>],
    first: usize,
    second: usize,
    max_degree: usize,
) {
    if first == second {
        return;
    }
    add_bounded_directed_link(links, first, second, max_degree);
    add_bounded_directed_link(links, second, first, max_degree);
}

fn add_bounded_directed_link(links: &mut [Vec<usize>], from: usize, to: usize, max_degree: usize) {
    let removed = {
        let neighbors = &mut links[from];
        if neighbors.contains(&to) {
            return;
        }
        neighbors.push(to);
        if neighbors.len() <= max_degree {
            return;
        }
        neighbors.remove(0)
    };
    links[removed].retain(|neighbor| *neighbor != from);
}

fn add_unbounded_undirected_link(links: &mut [Vec<usize>], first: usize, second: usize) {
    if first == second {
        return;
    }
    if !links[first].contains(&second) {
        links[first].push(second);
    }
    if !links[second].contains(&first) {
        links[second].push(first);
    }
}

fn add_connectivity_backbone(links: &mut [Vec<usize>]) {
    for idx in 1..links.len() {
        add_unbounded_undirected_link(links, idx - 1, idx);
    }
}

fn write_graph_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temporary_path = path.with_extension("json.tmp");
    write_private_graph_file(&temporary_path, bytes)?;
    fs::rename(&temporary_path, path)?;
    #[cfg(unix)]
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    sync_graph_parent_directory(path)?;
    Ok(())
}

fn read_graph_file(path: &Path) -> io::Result<Vec<u8>> {
    validate_private_graph_parent(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "graph file must be a regular non-symlink file",
        ));
    }
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "graph file must be a regular non-symlink file",
        ));
    }
    if metadata.len() > CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "graph file is too large: {} bytes exceeds {} bytes",
                metadata.len(),
                CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_MAX_BYTES
            ),
        ));
    }
    validate_private_graph_file_metadata(path, &metadata)?;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "opened graph file must be a regular file",
        ));
    }
    if opened_metadata.len() > CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "graph file is too large: {} bytes exceeds {} bytes",
                opened_metadata.len(),
                CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_MAX_BYTES
            ),
        ));
    }
    validate_private_graph_file_metadata(path, &opened_metadata)?;

    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    let mut limited_file = file.take(CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_MAX_BYTES + 1);
    limited_file.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "graph file is too large: {} bytes exceeds {} bytes",
                bytes.len(),
                CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_MAX_BYTES
            ),
        ));
    }
    Ok(bytes)
}

fn write_private_graph_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    validate_private_graph_parent(path)?;
    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("graph file {path:?} must not be a symlink"),
        ));
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::set_permissions(path, PermissionsExt::from_mode(0o600))?;
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        fs::write(path, bytes)
    }
}

fn validate_private_graph_file_metadata(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("graph file {path:?} must not be group/world accessible"),
            ));
        }

        let owner = metadata.uid();
        let effective_uid = nix::unistd::Uid::effective().as_raw();
        if owner != 0 && owner != effective_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("graph file {path:?} must be owned by root or the Qdrant process user"),
            ));
        }
    }

    Ok(())
}

fn validate_private_graph_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let Some(parent) = path.parent() else {
            return Ok(());
        };
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("graph file parent {parent:?} must be a directory"),
            ));
        }
        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("graph file parent {parent:?} must not be group/world writable"),
            ));
        }

        let owner = metadata.uid();
        let effective_uid = nix::unistd::Uid::effective().as_raw();
        if owner != 0 && owner != effective_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "graph file parent {parent:?} must be owned by root or the Qdrant process user"
                ),
            ));
        }
    }

    Ok(())
}

fn sync_graph_parent_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let Some(parent) = path.parent() else {
            return Ok(());
        };
        let directory = fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(parent)?;
        directory.sync_all()?;
    }

    Ok(())
}

fn links_have_valid_neighbors(links: &[Vec<usize>]) -> bool {
    links.iter().enumerate().all(|(from, neighbors)| {
        let mut unique_neighbors = std::collections::HashSet::with_capacity(neighbors.len());
        neighbors.iter().all(|neighbor| {
            *neighbor < links.len() && *neighbor != from && unique_neighbors.insert(*neighbor)
        })
    })
}

fn links_are_reciprocal(links: &[Vec<usize>]) -> bool {
    links.iter().enumerate().all(|(from, neighbors)| {
        neighbors
            .iter()
            .all(|neighbor| links[*neighbor].iter().any(|candidate| *candidate == from))
    })
}

fn links_are_connected(links: &[Vec<usize>]) -> bool {
    if links.is_empty() {
        return true;
    }

    let mut visited = vec![false; links.len()];
    let mut stack = vec![0usize];
    while let Some(idx) = stack.pop() {
        if visited[idx] {
            continue;
        }
        visited[idx] = true;
        for neighbor in &links[idx] {
            if !visited[*neighbor] {
                stack.push(*neighbor);
            }
        }
    }

    visited.into_iter().all(|seen| seen)
}

fn score_passes_threshold(order: Order, score: f32, score_threshold: Option<f32>) -> bool {
    score_threshold.is_none_or(|threshold| match order {
        Order::LargeBetter => score > threshold,
        Order::SmallBetter => score < threshold,
    })
}

fn sort_hits(order: Order, hits: &mut [CkksCiphertextHnswHit]) {
    hits.sort_unstable_by(|first, second| compare_hits(order, first, second));
}

fn compare_hits(
    order: Order,
    first: &CkksCiphertextHnswHit,
    second: &CkksCiphertextHnswHit,
) -> Ordering {
    let score_order = first
        .score
        .total_cmp(&second.score)
        .then_with(|| first.point_index.cmp(&second.point_index));
    match order {
        Order::LargeBetter => score_order.reverse(),
        Order::SmallBetter => score_order,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::vector_index_base::VectorIndexEnum;

    #[test]
    fn bounded_links_remain_reciprocal_when_pruned() {
        let mut links = vec![Vec::<usize>::new(); 4];
        CkksCiphertextHnswGraph::add_bounded_undirected_link(&mut links, 1, 0, 2);
        CkksCiphertextHnswGraph::add_bounded_undirected_link(&mut links, 2, 0, 2);
        CkksCiphertextHnswGraph::add_bounded_undirected_link(&mut links, 3, 0, 2);

        assert_eq!(links[0], vec![2, 3]);
        assert!(!links[1].contains(&0));
        assert!(!links[0].contains(&1));
        assert!(links[2].contains(&0));
        assert!(links[3].contains(&0));
        assert!(CkksCiphertextHnswGraph::links_are_reciprocal(&links));
    }

    #[test]
    fn connectivity_backbone_restores_pruned_graph() {
        let mut links = vec![Vec::<usize>::new(); 4];
        CkksCiphertextHnswGraph::add_bounded_undirected_link(&mut links, 1, 0, 2);
        CkksCiphertextHnswGraph::add_bounded_undirected_link(&mut links, 2, 0, 2);
        CkksCiphertextHnswGraph::add_bounded_undirected_link(&mut links, 3, 0, 2);

        assert!(!CkksCiphertextHnswGraph::links_are_connected(&links));
        CkksCiphertextHnswGraph::add_connectivity_backbone(&mut links);

        assert!(CkksCiphertextHnswGraph::links_are_reciprocal(&links));
        assert!(CkksCiphertextHnswGraph::links_are_connected(&links));
    }

    #[test]
    fn rejects_invalid_cached_links() {
        assert!(CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], Vec::new()]).is_none());
        assert!(CkksCiphertextHnswGraph::from_validated_links(vec![vec![2], vec![0]]).is_none());
        assert!(CkksCiphertextHnswGraph::from_validated_links(vec![vec![0], Vec::new()]).is_none());
    }

    #[test]
    fn builds_graph_from_ciphertext_pairwise_scores() {
        let values = [0.0_f32, 0.2, 0.8, 1.0];
        let graph = CkksCiphertextHnswGraph::build(
            values.len(),
            1,
            Order::SmallBetter,
            |idx| -> Result<Vec<f32>, std::convert::Infallible> {
                Ok((0..idx)
                    .map(|candidate| (values[idx] - values[candidate]).abs())
                    .collect())
            },
        )
        .unwrap();

        assert!(CkksCiphertextHnswGraph::links_are_reciprocal(graph.links()));
        assert!(CkksCiphertextHnswGraph::links_are_connected(graph.links()));
        assert!(graph.links()[1].contains(&0));
        assert!(graph.links()[2].contains(&1));
        assert!(graph.links()[3].contains(&2));
    }

    #[test]
    fn builds_optimizer_candidate_graph_without_scoring_runtime() {
        let graph = CkksCiphertextHnswGraph::build_optimizer_candidate_graph(5, 2);

        assert!(CkksCiphertextHnswGraph::links_are_reciprocal(graph.links()));
        assert!(CkksCiphertextHnswGraph::links_are_connected(graph.links()));
        assert!(graph.links()[0].contains(&1));
        assert!(graph.links()[4].contains(&3));
    }

    #[test]
    fn searches_graph_with_query_scorer() {
        let graph = CkksCiphertextHnswGraph::from_validated_links(vec![
            vec![1],
            vec![0, 2],
            vec![1, 3],
            vec![2],
        ])
        .unwrap();
        let values = [0.0_f32, 0.2, 0.8, 1.0];
        let query = 0.9_f32;

        let results = graph
            .search(
                4,
                2,
                Order::SmallBetter,
                None,
                |candidates| -> Result<Vec<f32>, std::convert::Infallible> {
                    Ok(candidates
                        .iter()
                        .map(|candidate| (query - values[*candidate]).abs())
                        .collect())
                },
            )
            .unwrap();

        assert_eq!(
            results
                .iter()
                .map(|hit| hit.point_index)
                .collect::<Vec<_>>(),
            vec![2, 3],
        );
    }

    #[test]
    fn index_rejects_graph_record_count_mismatch() {
        let graph = CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0]]).unwrap();

        assert!(CkksCiphertextHnswIndex::from_graph(vec!["a"], graph).is_none());
    }

    #[test]
    fn index_builds_and_searches_ciphertext_records() {
        #[derive(Clone, Debug, PartialEq)]
        struct CiphertextRecord {
            ciphertext: &'static str,
            clear_fixture: f32,
        }

        let records = vec![
            CiphertextRecord {
                ciphertext: "ct-0",
                clear_fixture: 0.0,
            },
            CiphertextRecord {
                ciphertext: "ct-1",
                clear_fixture: 0.2,
            },
            CiphertextRecord {
                ciphertext: "ct-2",
                clear_fixture: 0.8,
            },
            CiphertextRecord {
                ciphertext: "ct-3",
                clear_fixture: 1.0,
            },
        ];
        let index = CkksCiphertextHnswIndex::build(
            records,
            1,
            Order::SmallBetter,
            |record, candidates| -> Result<Vec<f32>, std::convert::Infallible> {
                assert!(record.ciphertext.starts_with("ct-"));
                Ok(candidates
                    .iter()
                    .map(|candidate| (record.clear_fixture - candidate.clear_fixture).abs())
                    .collect())
            },
        )
        .unwrap();

        let query = 0.9_f32;
        let results = index
            .search(
                4,
                2,
                Order::SmallBetter,
                None,
                |candidates| -> Result<Vec<f32>, std::convert::Infallible> {
                    Ok(candidates
                        .iter()
                        .map(|candidate| {
                            assert!(candidate.ciphertext.starts_with("ct-"));
                            (query - candidate.clear_fixture).abs()
                        })
                        .collect())
                },
            )
            .unwrap();

        assert_eq!(
            results
                .iter()
                .map(|hit| (hit.point_index, hit.record.ciphertext))
                .collect::<Vec<_>>(),
            vec![(2, "ct-2"), (3, "ct-3")],
        );
        assert!(CkksCiphertextHnswGraph::links_are_connected(
            index.graph().links()
        ));
    }

    #[test]
    fn vector_index_enum_exposes_ciphertext_hnsw_stats() {
        let index = CkksCiphertextVectorIndex::build(
            vec![
                CkksCiphertextIndexedRecord::new(10, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(11, b"ciphertext-b".to_vec()),
            ],
            1,
            Order::LargeBetter,
            |record, candidates| -> Result<Vec<f32>, std::convert::Infallible> {
                Ok(candidates
                    .iter()
                    .map(|candidate| {
                        if record.ciphertext > candidate.ciphertext {
                            1.0
                        } else {
                            0.0
                        }
                    })
                    .collect())
            },
        )
        .unwrap();

        let results = index
            .search_ciphertext(
                2,
                1,
                Order::LargeBetter,
                None,
                |candidates| -> Result<Vec<f32>, std::convert::Infallible> {
                    Ok(candidates
                        .iter()
                        .map(|candidate| {
                            if candidate.ciphertext == b"ciphertext-b" {
                                10.0
                            } else {
                                1.0
                            }
                        })
                        .collect())
                },
            )
            .unwrap();
        assert_eq!(
            results,
            vec![ScoredPointOffset {
                idx: 11,
                score: 10.0
            }]
        );

        let enum_index = VectorIndexEnum::CkksCiphertextHnsw(index);
        assert!(enum_index.is_index());
        assert!(!enum_index.is_on_disk());
        assert_eq!(enum_index.indexed_vectors(), 2);
        assert_eq!(VectorIndex::indexed_vector_count(&enum_index), 2);
        assert_eq!(
            VectorIndex::size_of_searchable_vectors_in_bytes(&enum_index),
            b"ciphertext-a".len() + b"ciphertext-b".len(),
        );
        enum_index.populate().unwrap();
        enum_index.clear_cache().unwrap();
    }

    #[test]
    fn vector_index_builds_optimizer_candidate_graph() {
        let index = CkksCiphertextVectorIndex::build_optimizer_candidate_graph(
            vec![
                CkksCiphertextIndexedRecord::new(10, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(11, b"ciphertext-b".to_vec()),
                CkksCiphertextIndexedRecord::new(12, b"ciphertext-c".to_vec()),
            ],
            2,
        );

        assert_eq!(index.indexed_vector_count(), 3);
        assert_eq!(index.records()[1].point_offset, 11);
        assert_eq!(index.records()[1].ciphertext, b"ciphertext-b");
        assert!(CkksCiphertextHnswGraph::links_are_reciprocal(
            index.graph().links()
        ));
        assert!(CkksCiphertextHnswGraph::links_are_connected(
            index.graph().links()
        ));
    }

    #[test]
    fn ciphertext_vector_index_rejects_plaintext_vector_index_search_api() {
        let index = CkksCiphertextVectorIndex::build_optimizer_candidate_graph(
            vec![CkksCiphertextIndexedRecord::new(
                10,
                b"ciphertext-a".to_vec(),
            )],
            1,
        );
        let query = QueryVector::Nearest(crate::data_types::vectors::VectorInternal::Dense(vec![
            0.1, 0.2,
        ]));

        let err = VectorIndex::search(
            &index,
            &[&query],
            None,
            1,
            None,
            &VectorQueryContext::default(),
        )
        .expect_err("ciphertext index must reject plaintext VectorIndex search API");

        assert!(
            err.to_string()
                .contains("does not accept plaintext QueryVector search requests"),
            "unexpected error: {err:?}",
        );
    }

    #[test]
    fn ciphertext_vector_index_can_reopen_from_valid_graph() {
        let records = vec![
            CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
            CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
        ];
        let graph = CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0]])
            .expect("valid reciprocal graph");

        let index = CkksCiphertextVectorIndex::from_graph(records, graph)
            .expect("record count matches graph nodes");

        let results = index
            .search_ciphertext(
                2,
                1,
                Order::LargeBetter,
                None,
                |candidates| -> Result<Vec<f32>, std::convert::Infallible> {
                    Ok(candidates
                        .iter()
                        .map(|candidate| {
                            if candidate.point_offset == 1 {
                                3.0
                            } else {
                                1.0
                            }
                        })
                        .collect())
                },
            )
            .unwrap();

        assert_eq!(results[0].idx, 1);
        assert_eq!(results[0].score, 3.0);
    }

    #[test]
    fn ciphertext_vector_index_exposes_segment_record_hits() {
        let graph =
            CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0, 2], vec![1]])
                .expect("valid reciprocal graph");
        let index = CkksCiphertextVectorIndex::from_graph(
            vec![
                CkksCiphertextIndexedRecord::new(42, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(43, b"ciphertext-b".to_vec()),
                CkksCiphertextIndexedRecord::new(44, b"ciphertext-c".to_vec()),
            ],
            graph,
        )
        .expect("record count matches graph nodes");

        let hits = index
            .search_ciphertext_records(
                3,
                2,
                Order::LargeBetter,
                None,
                |candidates| -> Result<Vec<f32>, std::convert::Infallible> {
                    Ok(candidates
                        .iter()
                        .map(|candidate| match candidate.point_offset {
                            42 => 0.1,
                            43 => 0.9,
                            44 => 0.7,
                            other => panic!("unexpected candidate offset {other}"),
                        })
                        .collect())
                },
            )
            .unwrap();

        assert_eq!(
            hits.iter()
                .map(|hit| (hit.point_index, hit.record.point_offset, hit.score))
                .collect::<Vec<_>>(),
            vec![(1, 43, 0.9), (2, 44, 0.7)],
        );
        assert_eq!(hits[0].record.ciphertext, b"ciphertext-b");
    }

    #[test]
    fn ciphertext_vector_index_persists_graph_as_index_file() {
        let directory = tempfile::tempdir().unwrap();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(directory.path());
        let mut index = CkksCiphertextVectorIndex::build(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            1,
            Order::LargeBetter,
            |record, candidates| -> Result<Vec<f32>, std::convert::Infallible> {
                Ok(candidates
                    .iter()
                    .map(|candidate| {
                        if record.ciphertext > candidate.ciphertext {
                            1.0
                        } else {
                            0.0
                        }
                    })
                    .collect())
            },
        )
        .unwrap();

        index.persist_graph_file(&graph_file).unwrap();

        assert_eq!(index.files(), vec![graph_file.clone()]);
        assert_eq!(index.immutable_files(), vec![graph_file.clone()]);
        assert!(graph_file.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = std::fs::metadata(&graph_file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let reopened = CkksCiphertextVectorIndex::open_graph_file(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            &graph_file,
        )
        .unwrap()
        .expect("persisted graph should reopen");

        assert_eq!(reopened.files(), vec![graph_file]);
        assert_eq!(reopened.immutable_files(), reopened.files());
        assert_eq!(reopened.graph().links(), index.graph().links());
    }

    #[cfg(unix)]
    #[test]
    fn ciphertext_vector_index_rejects_group_accessible_graph_file() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(directory.path());
        let mut index = CkksCiphertextVectorIndex::from_graph(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0]]).unwrap(),
        )
        .unwrap();
        index.persist_graph_file(&graph_file).unwrap();
        std::fs::set_permissions(&graph_file, PermissionsExt::from_mode(0o640)).unwrap();

        let err = CkksCiphertextVectorIndex::open_graph_file(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            &graph_file,
        )
        .unwrap_err();

        assert!(err.to_string().contains("group/world accessible"));
    }

    #[cfg(unix)]
    #[test]
    fn ciphertext_vector_index_rejects_graph_symlink_on_open() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(directory.path());
        let target_file = directory.path().join("graph-target");
        let mut index = CkksCiphertextVectorIndex::from_graph(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0]]).unwrap(),
        )
        .unwrap();
        index.persist_graph_file(&target_file).unwrap();
        symlink(&target_file, &graph_file).unwrap();

        let err = CkksCiphertextVectorIndex::open_graph_file(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            &graph_file,
        )
        .unwrap_err();

        assert!(err.to_string().contains("regular non-symlink file"));
    }

    #[cfg(unix)]
    #[test]
    fn ciphertext_vector_index_rejects_temp_graph_symlink_on_persist() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(directory.path());
        let temp_graph_file = graph_file.with_extension("json.tmp");
        let external_file = directory.path().join("external-target");
        std::fs::write(&external_file, b"do-not-overwrite").unwrap();
        symlink(&external_file, &temp_graph_file).unwrap();

        let mut index = CkksCiphertextVectorIndex::from_graph(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0]]).unwrap(),
        )
        .unwrap();

        let err = index.persist_graph_file(&graph_file).unwrap_err();

        assert!(err.to_string().contains("must not be a symlink"));
        assert_eq!(std::fs::read(&external_file).unwrap(), b"do-not-overwrite");
    }

    #[cfg(unix)]
    #[test]
    fn ciphertext_vector_index_rejects_writable_graph_parent() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(directory.path());
        let mut index = CkksCiphertextVectorIndex::from_graph(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0]]).unwrap(),
        )
        .unwrap();

        std::fs::set_permissions(directory.path(), PermissionsExt::from_mode(0o777)).unwrap();
        let err = index.persist_graph_file(&graph_file).unwrap_err();
        assert!(err.to_string().contains("must not be group/world writable"));

        std::fs::set_permissions(directory.path(), PermissionsExt::from_mode(0o700)).unwrap();
        index.persist_graph_file(&graph_file).unwrap();

        std::fs::set_permissions(directory.path(), PermissionsExt::from_mode(0o777)).unwrap();
        let err = CkksCiphertextVectorIndex::open_graph_file(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            &graph_file,
        )
        .unwrap_err();

        assert!(err.to_string().contains("must not be group/world writable"));
        std::fs::set_permissions(directory.path(), PermissionsExt::from_mode(0o700)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn ciphertext_vector_index_rejects_symlink_graph_parent() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let real_parent = directory.path().join("real-parent");
        let symlink_parent = directory.path().join("symlink-parent");
        std::fs::create_dir(&real_parent).unwrap();
        symlink(&real_parent, &symlink_parent).unwrap();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(&symlink_parent);

        let mut index = CkksCiphertextVectorIndex::from_graph(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0]]).unwrap(),
        )
        .unwrap();

        let err = index.persist_graph_file(&graph_file).unwrap_err();
        assert!(err.to_string().contains("must be a directory"));

        let real_graph_file = CkksCiphertextVectorIndex::graph_file_path(&real_parent);
        index.persist_graph_file(&real_graph_file).unwrap();
        let err = CkksCiphertextVectorIndex::open_graph_file(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            &graph_file,
        )
        .unwrap_err();
        assert!(err.to_string().contains("must be a directory"));
    }

    #[test]
    fn ciphertext_vector_index_rejects_graph_record_count_mismatch_on_open() {
        let directory = tempfile::tempdir().unwrap();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(directory.path());
        let mut index = CkksCiphertextVectorIndex::from_graph(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
            ],
            CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0]]).unwrap(),
        )
        .unwrap();
        index.persist_graph_file(&graph_file).unwrap();

        let err = CkksCiphertextVectorIndex::open_graph_file(
            vec![CkksCiphertextIndexedRecord::new(
                0,
                b"ciphertext-a".to_vec(),
            )],
            &graph_file,
        )
        .unwrap_err();

        assert!(err.to_string().contains("record count"));
    }

    #[test]
    fn ciphertext_vector_index_rejects_invalid_graph_links_on_open() {
        let directory = tempfile::tempdir().unwrap();
        let graph_file = CkksCiphertextVectorIndex::graph_file_path(directory.path());
        let invalid_graph = CkksCiphertextHnswGraphFile {
            version: CKKS_CIPHERTEXT_HNSW_GRAPH_FILE_VERSION,
            record_count: 3,
            links: vec![vec![1], vec![], vec![]],
        };
        write_graph_file(&graph_file, &serde_json::to_vec(&invalid_graph).unwrap()).unwrap();

        let err = CkksCiphertextVectorIndex::open_graph_file(
            vec![
                CkksCiphertextIndexedRecord::new(0, b"ciphertext-a".to_vec()),
                CkksCiphertextIndexedRecord::new(1, b"ciphertext-b".to_vec()),
                CkksCiphertextIndexedRecord::new(2, b"ciphertext-c".to_vec()),
            ],
            &graph_file,
        )
        .unwrap_err();

        assert!(err.to_string().contains("invalid links"));
    }

    #[test]
    fn ciphertext_record_extractor_reads_sidecar_ciphertext() {
        let payload = Payload(
            serde_json::from_value(serde_json::json!({
                CKKS_VECTOR_SIDECAR_PAYLOAD_FIELD: {
                    "embedding": {
                        CKKS_VECTOR_SIDECAR_MARKER: {
                            "version": 1,
                            "scheme": "openfhe-ckks",
                            "envelope": {
                                "version": 1,
                                "algorithm": "AES-256-GCM",
                                "key_id": "tenant-a:vector",
                                "nonce": "AAAAAAAAAAAAAAAA",
                                "ciphertext": "stored-ciphertext"
                            }
                        }
                    }
                }
            }))
            .unwrap(),
        );

        assert_eq!(
            ckks_ciphertext_from_payload(&payload, "embedding").unwrap(),
            Some("stored-ciphertext"),
        );
        assert_eq!(
            ckks_ciphertext_from_payload(&payload, "other").unwrap(),
            None
        );
    }

    #[test]
    fn ciphertext_record_extractor_rejects_malformed_sidecar() {
        let payload = Payload(
            serde_json::from_value(serde_json::json!({
                CKKS_VECTOR_SIDECAR_PAYLOAD_FIELD: {
                    "embedding": { "not_the_marker": {} }
                }
            }))
            .unwrap(),
        );

        let err = ckks_ciphertext_from_payload(&payload, "embedding").unwrap_err();
        assert!(err.to_string().contains("malformed"));
    }
}
