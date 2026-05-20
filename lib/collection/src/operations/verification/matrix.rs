use api::rest::SearchMatrixRequestInternal;

use super::StrictModeVerification;
use crate::collection::distance_matrix::CollectionSearchMatrixRequest;

impl StrictModeVerification for SearchMatrixRequestInternal {
    fn query_limit(&self) -> Option<usize> {
        match (self.limit, self.sample) {
            (Some(limit), Some(sample)) => Some(limit.saturating_mul(sample)),
            (Some(limit), None) => Some(limit),
            (None, Some(sample)) => Some(sample),
            (None, None) => None,
        }
    }

    fn indexed_filter_read(&self) -> Option<&segment::types::Filter> {
        self.filter.as_ref()
    }

    fn indexed_filter_write(&self) -> Option<&segment::types::Filter> {
        None
    }

    fn request_exact(&self) -> Option<bool> {
        None
    }

    fn request_search_params(&self) -> Option<&segment::types::SearchParams> {
        None
    }
}

impl StrictModeVerification for CollectionSearchMatrixRequest {
    fn query_limit(&self) -> Option<usize> {
        Some(self.limit_per_sample.saturating_mul(self.sample_size))
    }

    fn indexed_filter_read(&self) -> Option<&segment::types::Filter> {
        self.filter.as_ref()
    }

    fn indexed_filter_write(&self) -> Option<&segment::types::Filter> {
        None
    }

    fn request_exact(&self) -> Option<bool> {
        None
    }

    fn request_search_params(&self) -> Option<&segment::types::SearchParams> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_matrix_query_limit_saturates_on_overflow() {
        let request = SearchMatrixRequestInternal {
            filter: None,
            sample: Some(usize::MAX),
            limit: Some(2),
            using: None,
        };
        assert_eq!(request.query_limit(), Some(usize::MAX));

        let request = CollectionSearchMatrixRequest {
            sample_size: usize::MAX,
            limit_per_sample: 2,
            filter: None,
            using: segment::data_types::vectors::DEFAULT_VECTOR_NAME.to_owned(),
        };
        assert_eq!(request.query_limit(), Some(usize::MAX));
    }
}
