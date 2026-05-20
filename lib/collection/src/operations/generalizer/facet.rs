use api::rest::FacetRequestInternal;
use segment::data_types::facets::FacetParams;

use crate::operations::generalizer::Generalizer;

impl Generalizer for FacetRequestInternal {
    fn remove_details(&self) -> Self {
        let FacetRequestInternal {
            key,
            limit,
            filter,
            exact,
        } = self;

        Self {
            key: key.clone(),
            limit: *limit,
            filter: filter.as_ref().map(|filter| filter.remove_details()),
            exact: *exact,
        }
    }
}

impl Generalizer for FacetParams {
    fn remove_details(&self) -> Self {
        let FacetParams {
            key,
            limit,
            filter,
            exact,
        } = self;

        Self {
            key: key.clone(),
            limit: *limit,
            filter: filter.as_ref().map(|filter| filter.remove_details()),
            exact: *exact,
        }
    }
}
