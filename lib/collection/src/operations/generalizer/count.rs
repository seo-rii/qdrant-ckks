use shard::count::CountRequestInternal;

use crate::operations::generalizer::Generalizer;

impl Generalizer for CountRequestInternal {
    fn remove_details(&self) -> Self {
        let CountRequestInternal { filter, exact } = self;
        Self {
            filter: filter.as_ref().map(|filter| filter.remove_details()),
            exact: *exact,
        }
    }
}
