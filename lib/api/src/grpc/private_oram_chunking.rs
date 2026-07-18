use prost::Message;
use sha2::{Digest, Sha256};

use super::qdrant::PrivateOramInstallChunk;

pub const PRIVATE_ORAM_INSTALL_CHUNK_VERSION: u32 = 1;
pub const PRIVATE_ORAM_INSTALL_MAX_ENCODED_BYTES: usize = 512 * 1024 * 1024;
pub const PRIVATE_ORAM_INSTALL_MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const PRIVATE_ORAM_INSTALL_CHUNK_DATA_BYTES: usize =
    PRIVATE_ORAM_INSTALL_MAX_FRAME_BYTES - 1024;
const PRIVATE_ORAM_INSTALL_MAX_CHUNKS: usize =
    PRIVATE_ORAM_INSTALL_MAX_ENCODED_BYTES.div_ceil(PRIVATE_ORAM_INSTALL_CHUNK_DATA_BYTES);

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PrivateOramInstallChunkError {
    #[error("private ORAM install request is empty")]
    Empty,
    #[error("private ORAM install request is oversized")]
    Oversized,
    #[error("private ORAM install chunk shape is invalid")]
    InvalidChunk,
    #[error("private ORAM install chunk integrity check failed")]
    IntegrityMismatch,
    #[error("private ORAM install request allocation failed")]
    AllocationFailed,
    #[error("private ORAM install request encoding is invalid")]
    InvalidRequest,
}

pub fn encode_private_oram_install_chunks<M: Message>(
    request: &M,
) -> Result<Vec<PrivateOramInstallChunk>, PrivateOramInstallChunkError> {
    let encoded_len = request.encoded_len();
    if encoded_len == 0 {
        return Err(PrivateOramInstallChunkError::Empty);
    }
    if encoded_len > PRIVATE_ORAM_INSTALL_MAX_ENCODED_BYTES {
        return Err(PrivateOramInstallChunkError::Oversized);
    }

    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(encoded_len)
        .map_err(|_| PrivateOramInstallChunkError::AllocationFailed)?;
    request
        .encode(&mut encoded)
        .map_err(|_| PrivateOramInstallChunkError::InvalidRequest)?;
    if encoded.len() != encoded_len {
        return Err(PrivateOramInstallChunkError::InvalidRequest);
    }

    let chunk_count = encoded_len.div_ceil(PRIVATE_ORAM_INSTALL_CHUNK_DATA_BYTES);
    if chunk_count == 0 || chunk_count > PRIVATE_ORAM_INSTALL_MAX_CHUNKS {
        return Err(PrivateOramInstallChunkError::Oversized);
    }
    let chunk_count =
        u64::try_from(chunk_count).map_err(|_| PrivateOramInstallChunkError::Oversized)?;
    let total_bytes =
        u64::try_from(encoded_len).map_err(|_| PrivateOramInstallChunkError::Oversized)?;
    let request_sha256 = Sha256::digest(&encoded).to_vec();

    let mut chunks = Vec::new();
    chunks
        .try_reserve_exact(
            usize::try_from(chunk_count).map_err(|_| PrivateOramInstallChunkError::Oversized)?,
        )
        .map_err(|_| PrivateOramInstallChunkError::AllocationFailed)?;
    for (chunk_index, data) in encoded
        .chunks(PRIVATE_ORAM_INSTALL_CHUNK_DATA_BYTES)
        .enumerate()
    {
        let chunk = PrivateOramInstallChunk {
            version: PRIVATE_ORAM_INSTALL_CHUNK_VERSION,
            chunk_index: u64::try_from(chunk_index)
                .map_err(|_| PrivateOramInstallChunkError::Oversized)?,
            chunk_count,
            total_bytes,
            request_sha256: request_sha256.clone(),
            data: data.to_vec(),
        };
        if chunk.encoded_len() > PRIVATE_ORAM_INSTALL_MAX_FRAME_BYTES {
            return Err(PrivateOramInstallChunkError::Oversized);
        }
        chunks.push(chunk);
    }
    Ok(chunks)
}

#[derive(Debug)]
struct PrivateOramInstallChunkMetadata {
    chunk_count: u64,
    total_bytes: usize,
    request_sha256: [u8; 32],
}

#[derive(Debug, Default)]
pub struct PrivateOramInstallChunkDecoder {
    metadata: Option<PrivateOramInstallChunkMetadata>,
    next_chunk_index: u64,
    encoded_request: Vec<u8>,
    hasher: Sha256,
}

impl PrivateOramInstallChunkDecoder {
    pub fn push(
        &mut self,
        chunk: PrivateOramInstallChunk,
    ) -> Result<(), PrivateOramInstallChunkError> {
        if chunk.version != PRIVATE_ORAM_INSTALL_CHUNK_VERSION
            || chunk.encoded_len() > PRIVATE_ORAM_INSTALL_MAX_FRAME_BYTES
            || chunk.request_sha256.len() != 32
        {
            return Err(PrivateOramInstallChunkError::InvalidChunk);
        }
        let total_bytes = usize::try_from(chunk.total_bytes)
            .map_err(|_| PrivateOramInstallChunkError::Oversized)?;
        if total_bytes == 0 || total_bytes > PRIVATE_ORAM_INSTALL_MAX_ENCODED_BYTES {
            return Err(PrivateOramInstallChunkError::Oversized);
        }
        let expected_chunk_count = total_bytes.div_ceil(PRIVATE_ORAM_INSTALL_CHUNK_DATA_BYTES);
        let chunk_count = usize::try_from(chunk.chunk_count)
            .map_err(|_| PrivateOramInstallChunkError::Oversized)?;
        if chunk_count == 0
            || chunk_count > PRIVATE_ORAM_INSTALL_MAX_CHUNKS
            || chunk_count != expected_chunk_count
            || chunk.chunk_index != self.next_chunk_index
            || chunk.chunk_index >= chunk.chunk_count
        {
            return Err(PrivateOramInstallChunkError::InvalidChunk);
        }

        let chunk_index = usize::try_from(chunk.chunk_index)
            .map_err(|_| PrivateOramInstallChunkError::InvalidChunk)?;
        let expected_data_len = if chunk_index + 1 == chunk_count {
            total_bytes
                .checked_sub(
                    PRIVATE_ORAM_INSTALL_CHUNK_DATA_BYTES
                        .checked_mul(chunk_count - 1)
                        .ok_or(PrivateOramInstallChunkError::Oversized)?,
                )
                .ok_or(PrivateOramInstallChunkError::InvalidChunk)?
        } else {
            PRIVATE_ORAM_INSTALL_CHUNK_DATA_BYTES
        };
        if chunk.data.len() != expected_data_len {
            return Err(PrivateOramInstallChunkError::InvalidChunk);
        }

        let request_sha256: [u8; 32] = chunk
            .request_sha256
            .as_slice()
            .try_into()
            .map_err(|_| PrivateOramInstallChunkError::InvalidChunk)?;
        if let Some(metadata) = &self.metadata {
            if metadata.chunk_count != chunk.chunk_count
                || metadata.total_bytes != total_bytes
                || metadata.request_sha256 != request_sha256
            {
                return Err(PrivateOramInstallChunkError::InvalidChunk);
            }
        } else {
            self.metadata = Some(PrivateOramInstallChunkMetadata {
                chunk_count: chunk.chunk_count,
                total_bytes,
                request_sha256,
            });
        }

        let new_len = self
            .encoded_request
            .len()
            .checked_add(chunk.data.len())
            .ok_or(PrivateOramInstallChunkError::Oversized)?;
        if new_len > total_bytes {
            return Err(PrivateOramInstallChunkError::InvalidChunk);
        }
        self.encoded_request
            .try_reserve(chunk.data.len())
            .map_err(|_| PrivateOramInstallChunkError::AllocationFailed)?;
        self.hasher.update(&chunk.data);
        self.encoded_request.extend_from_slice(&chunk.data);
        self.next_chunk_index = self
            .next_chunk_index
            .checked_add(1)
            .ok_or(PrivateOramInstallChunkError::Oversized)?;
        Ok(())
    }

    pub fn finish<M: Message + Default>(self) -> Result<M, PrivateOramInstallChunkError> {
        let metadata = self.metadata.ok_or(PrivateOramInstallChunkError::Empty)?;
        if self.next_chunk_index != metadata.chunk_count
            || self.encoded_request.len() != metadata.total_bytes
        {
            return Err(PrivateOramInstallChunkError::InvalidChunk);
        }
        let digest = self.hasher.finalize();
        if &digest[..] != metadata.request_sha256.as_slice() {
            return Err(PrivateOramInstallChunkError::IntegrityMismatch);
        }
        M::decode(self.encoded_request.as_slice())
            .map_err(|_| PrivateOramInstallChunkError::InvalidRequest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::qdrant::InstallPrivateOramIndexRequest;

    fn multi_chunk_request() -> InstallPrivateOramIndexRequest {
        InstallPrivateOramIndexRequest {
            collection_name: "d".repeat(PRIVATE_ORAM_INSTALL_CHUNK_DATA_BYTES * 2),
            collection_id: "collection-id".to_string(),
            index_kind: 1,
            vector_name: "text".to_string(),
            bundle: None,
        }
    }

    #[test]
    fn private_oram_install_chunks_round_trip_exact_protobuf_request() {
        let request = multi_chunk_request();
        let chunks = encode_private_oram_install_chunks(&request).unwrap();
        assert!(chunks.len() >= 3);
        assert!(
            chunks
                .iter()
                .all(|chunk| chunk.encoded_len() <= PRIVATE_ORAM_INSTALL_MAX_FRAME_BYTES)
        );

        let mut decoder = PrivateOramInstallChunkDecoder::default();
        for chunk in chunks {
            decoder.push(chunk).unwrap();
        }
        let decoded: InstallPrivateOramIndexRequest = decoder.finish().unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn private_oram_install_chunks_reject_partial_reordered_and_corrupt_streams() {
        let request = multi_chunk_request();
        let chunks = encode_private_oram_install_chunks(&request).unwrap();

        let mut partial = PrivateOramInstallChunkDecoder::default();
        for chunk in chunks.iter().take(chunks.len() - 1).cloned() {
            partial.push(chunk).unwrap();
        }
        assert_eq!(
            partial
                .finish::<InstallPrivateOramIndexRequest>()
                .unwrap_err(),
            PrivateOramInstallChunkError::InvalidChunk,
        );

        let mut reordered = PrivateOramInstallChunkDecoder::default();
        assert_eq!(
            reordered.push(chunks[1].clone()).unwrap_err(),
            PrivateOramInstallChunkError::InvalidChunk,
        );

        let mut corrupt_chunks = chunks;
        corrupt_chunks.last_mut().unwrap().data[0] ^= 1;
        let mut corrupt = PrivateOramInstallChunkDecoder::default();
        for chunk in corrupt_chunks {
            corrupt.push(chunk).unwrap();
        }
        assert_eq!(
            corrupt
                .finish::<InstallPrivateOramIndexRequest>()
                .unwrap_err(),
            PrivateOramInstallChunkError::IntegrityMismatch,
        );
    }

    #[test]
    fn private_oram_install_chunks_reject_metadata_and_size_drift() {
        let request = multi_chunk_request();
        let mut chunks = encode_private_oram_install_chunks(&request).unwrap();
        chunks[1].request_sha256[0] ^= 1;
        let mut decoder = PrivateOramInstallChunkDecoder::default();
        decoder.push(chunks[0].clone()).unwrap();
        assert_eq!(
            decoder.push(chunks[1].clone()).unwrap_err(),
            PrivateOramInstallChunkError::InvalidChunk,
        );

        let oversized = PrivateOramInstallChunk {
            version: PRIVATE_ORAM_INSTALL_CHUNK_VERSION,
            chunk_index: 0,
            chunk_count: 1,
            total_bytes: u64::try_from(PRIVATE_ORAM_INSTALL_MAX_ENCODED_BYTES).unwrap() + 1,
            request_sha256: vec![0; 32],
            data: vec![0],
        };
        assert_eq!(
            PrivateOramInstallChunkDecoder::default()
                .push(oversized)
                .unwrap_err(),
            PrivateOramInstallChunkError::Oversized,
        );

        assert_eq!(
            encode_private_oram_install_chunks(&InstallPrivateOramIndexRequest::default())
                .unwrap_err(),
            PrivateOramInstallChunkError::Empty,
        );
    }
}
