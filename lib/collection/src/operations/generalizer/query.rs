use segment::data_types::vectors::{MultiDenseVectorInternal, NamedQuery, VectorInternal};
use segment::vector_storage::query::{
    ContextPair, ContextQuery, DiscoverQuery, FeedbackItem, NaiveFeedbackCoefficients,
    NaiveFeedbackQuery, RecoQuery,
};
use shard::query::query_enum::QueryEnum;
use sparse::common::sparse_vector::SparseVector;
use sparse::common::types::DimId;

use crate::operations::generalizer::Generalizer;
use crate::operations::universal_query::collection_query::VectorInputInternal;
use crate::operations::universal_query::shard_query::{
    MmrInternal, ScoringQuery, ShardPrefetch, ShardQueryRequest,
};

impl Generalizer for Vec<ShardQueryRequest> {
    fn remove_details(&self) -> Self {
        self.iter().map(|req| req.remove_details()).collect()
    }
}

impl Generalizer for ShardQueryRequest {
    fn remove_details(&self) -> Self {
        let ShardQueryRequest {
            prefetches,
            query,
            filter,
            score_threshold,
            limit,
            offset,
            params,
            with_vector,
            with_payload,
        } = self;

        ShardQueryRequest {
            prefetches: prefetches.iter().map(|p| p.remove_details()).collect(),
            query: query.as_ref().map(|q| q.remove_details()),
            filter: filter.as_ref().map(|filter| filter.remove_details()),
            score_threshold: *score_threshold,
            limit: *limit,
            offset: *offset,
            params: *params,
            with_vector: with_vector.clone(),
            with_payload: with_payload.clone(),
        }
    }
}

impl Generalizer for ShardPrefetch {
    fn remove_details(&self) -> Self {
        let ShardPrefetch {
            prefetches,
            query,
            limit,
            params,
            filter,
            score_threshold,
        } = self;

        Self {
            prefetches: prefetches.iter().map(|p| p.remove_details()).collect(),
            query: query.as_ref().map(|q| q.remove_details()),
            filter: filter.as_ref().map(|filter| filter.remove_details()),
            score_threshold: *score_threshold,
            limit: *limit,
            params: *params,
        }
    }
}

impl Generalizer for ScoringQuery {
    fn remove_details(&self) -> Self {
        match self {
            ScoringQuery::Vector(vector) => ScoringQuery::Vector(vector.remove_details()),
            ScoringQuery::Fusion(_) => self.clone(),
            ScoringQuery::OrderBy(_) => self.clone(),
            ScoringQuery::Formula(_) => self.clone(),
            ScoringQuery::Sample(_) => self.clone(),
            ScoringQuery::Mmr(mmr) => ScoringQuery::Mmr(mmr.remove_details()),
        }
    }
}

impl Generalizer for MmrInternal {
    fn remove_details(&self) -> Self {
        let Self {
            vector,
            using,
            lambda,
            candidates_limit,
        } = self;

        Self {
            vector: vector.remove_details(),
            using: using.clone(),
            lambda: *lambda,
            candidates_limit: *candidates_limit,
        }
    }
}

impl Generalizer for QueryEnum {
    fn remove_details(&self) -> Self {
        match self {
            QueryEnum::Nearest(nearest) => QueryEnum::Nearest(nearest.remove_details()),
            QueryEnum::RecommendBestScore(recommend) => {
                QueryEnum::RecommendBestScore(recommend.remove_details())
            }
            QueryEnum::RecommendSumScores(recommend) => {
                QueryEnum::RecommendSumScores(recommend.remove_details())
            }
            QueryEnum::Discover(disocover) => QueryEnum::Discover(disocover.remove_details()),
            QueryEnum::Context(context) => QueryEnum::Context(context.remove_details()),
            QueryEnum::FeedbackNaive(feedback) => {
                QueryEnum::FeedbackNaive(feedback.remove_details())
            }
        }
    }
}

impl<T: Generalizer> Generalizer for NamedQuery<T> {
    fn remove_details(&self) -> Self {
        let NamedQuery { query, using } = self;
        Self {
            using: using.clone(),
            query: query.remove_details(),
        }
    }
}

impl Generalizer for VectorInputInternal {
    fn remove_details(&self) -> Self {
        match self {
            VectorInputInternal::Vector(vector) => {
                VectorInputInternal::Vector(vector.remove_details())
            }
            VectorInputInternal::InferredVector(vector) => {
                VectorInputInternal::InferredVector(vector.remove_details())
            }
            VectorInputInternal::Id(id) => VectorInputInternal::Id(*id),
            VectorInputInternal::CkksEncryptedQuery(query) => {
                VectorInputInternal::CkksEncryptedQuery(query.remove_details())
            }
        }
    }
}

impl Generalizer for crate::operations::universal_query::collection_query::CkksEncryptedQueryInput {
    fn remove_details(&self) -> Self {
        Self {
            version: self.version,
            scheme: self.scheme.clone(),
            security_profile: self.security_profile.clone(),
            collection_id: self.collection_id.clone(),
            vector_name: self.vector_name.clone(),
            key_id: self.key_id.clone(),
            rk_id: self.rk_id.clone(),
            rk_epoch: self.rk_epoch,
            query_nonce: "[redacted]".to_string(),
            context_digest: self.context_digest.clone(),
            slots: self.slots,
            ciphertext_sha256: "[redacted]".to_string(),
            ciphertext: "[redacted]".to_string(),
            signature_alg: self.signature_alg.clone(),
            signature_key_id: self.signature_key_id.clone(),
            signature_b64: "[redacted]".to_string(),
        }
    }
}

impl Generalizer for VectorInternal {
    fn remove_details(&self) -> Self {
        match self {
            VectorInternal::Dense(dense) => VectorInternal::Dense(vec![dense.len() as f32]),
            VectorInternal::Sparse(sparse) => {
                VectorInternal::Sparse(generalized_sparse_vector(sparse.len()))
            }
            VectorInternal::MultiDense(multi) => {
                VectorInternal::MultiDense(MultiDenseVectorInternal::new(
                    vec![multi.num_vectors() as f32, multi.dim as f32],
                    2,
                ))
            }
        }
    }
}

fn generalized_sparse_vector(len: usize) -> SparseVector {
    SparseVector {
        indices: vec![len.min(DimId::MAX as usize) as DimId],
        values: vec![0.0],
    }
}

impl<T: Generalizer> Generalizer for DiscoverQuery<T> {
    fn remove_details(&self) -> Self {
        let DiscoverQuery { target, pairs } = self;
        Self {
            target: target.remove_details(),
            pairs: pairs.iter().map(|p| p.remove_details()).collect(),
        }
    }
}

impl<T: Generalizer> Generalizer for ContextQuery<T> {
    fn remove_details(&self) -> Self {
        let ContextQuery { pairs } = self;
        Self {
            pairs: pairs.iter().map(|p| p.remove_details()).collect(),
        }
    }
}

impl<T: Generalizer> Generalizer for ContextPair<T> {
    fn remove_details(&self) -> Self {
        let ContextPair { positive, negative } = self;
        Self {
            positive: positive.remove_details(),
            negative: negative.remove_details(),
        }
    }
}

impl<T: Generalizer> Generalizer for RecoQuery<T> {
    fn remove_details(&self) -> Self {
        let RecoQuery {
            positives,
            negatives,
        } = self;
        Self {
            positives: positives.iter().map(|p| p.remove_details()).collect(),
            negatives: negatives.iter().map(|p| p.remove_details()).collect(),
        }
    }
}

impl<T: Generalizer> Generalizer for NaiveFeedbackQuery<T> {
    fn remove_details(&self) -> Self {
        let Self {
            target,
            feedback,
            coefficients,
        } = self;
        Self {
            target: target.remove_details(),
            feedback: feedback.iter().map(|p| p.remove_details()).collect(),
            coefficients: coefficients.remove_details(),
        }
    }
}

impl<T: Generalizer> Generalizer for FeedbackItem<T> {
    fn remove_details(&self) -> Self {
        let FeedbackItem { vector, score: _ } = self;
        Self {
            vector: vector.remove_details(),
            score: 0.0.into(),
        }
    }
}

impl Generalizer for NaiveFeedbackCoefficients {
    fn remove_details(&self) -> Self {
        let NaiveFeedbackCoefficients { a: _, b: _, c: _ } = self;
        Self {
            a: 0.0.into(),
            b: 0.0.into(),
            c: 0.0.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::universal_query::collection_query::CkksEncryptedQueryInput;

    #[test]
    fn ckks_encrypted_query_generalizer_redacts_ciphertext_and_hash() {
        let query = CkksEncryptedQueryInput {
            version: 1,
            scheme: "openfhe-ckks".to_string(),
            security_profile: "ckks-128-n16384-d4-scale50".to_string(),
            collection_id: "docs-crypto-id".to_string(),
            vector_name: "embedding".to_string(),
            key_id: "tenant-a:vector".to_string(),
            rk_id: "tenant-a/vector-v1".to_string(),
            rk_epoch: 1,
            query_nonce: "qdrant-sec-query-nonce-sentinel".to_string(),
            context_digest: "context-digest".to_string(),
            slots: 4,
            ciphertext_sha256: "qdrant-sec-query-ciphertext-sha256-sentinel".to_string(),
            ciphertext: "qdrant-sec-query-ciphertext-sentinel".to_string(),
            signature_alg: "ed25519".to_string(),
            signature_key_id: "tenant-a:query-signing-v1".to_string(),
            signature_b64: "qdrant-sec-query-signature-sentinel".to_string(),
        };

        let generalized = query.remove_details();

        assert_eq!(generalized.ciphertext, "[redacted]");
        assert_eq!(generalized.ciphertext_sha256, "[redacted]");
        assert_eq!(generalized.query_nonce, "[redacted]");
        assert_eq!(generalized.signature_b64, "[redacted]");
        assert_ne!(
            generalized.ciphertext,
            "qdrant-sec-query-ciphertext-sentinel"
        );
        assert_ne!(
            generalized.ciphertext_sha256,
            "qdrant-sec-query-ciphertext-sha256-sentinel"
        );
        assert_ne!(
            generalized.signature_b64,
            "qdrant-sec-query-signature-sentinel"
        );
        assert_ne!(generalized.query_nonce, "qdrant-sec-query-nonce-sentinel");
    }
}
