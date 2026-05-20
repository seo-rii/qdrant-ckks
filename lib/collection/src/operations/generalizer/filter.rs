use segment::types::{
    Condition, FieldCondition, Filter, Match, MinShould, Nested, NestedCondition,
};

use crate::operations::generalizer::Generalizer;

impl Generalizer for Filter {
    fn remove_details(&self) -> Self {
        let Filter {
            should,
            min_should,
            must,
            must_not,
        } = self;

        Self {
            should: should.as_ref().map(|conditions| {
                conditions
                    .iter()
                    .map(|condition| condition.remove_details())
                    .collect()
            }),
            min_should: min_should
                .as_ref()
                .map(|min_should| min_should.remove_details()),
            must: must.as_ref().map(|conditions| {
                conditions
                    .iter()
                    .map(|condition| condition.remove_details())
                    .collect()
            }),
            must_not: must_not.as_ref().map(|conditions| {
                conditions
                    .iter()
                    .map(|condition| condition.remove_details())
                    .collect()
            }),
        }
    }
}

impl Generalizer for MinShould {
    fn remove_details(&self) -> Self {
        let MinShould {
            conditions,
            min_count,
        } = self;

        Self {
            conditions: conditions
                .iter()
                .map(|condition| condition.remove_details())
                .collect(),
            min_count: *min_count,
        }
    }
}

impl Generalizer for Condition {
    fn remove_details(&self) -> Self {
        match self {
            Condition::Field(field) => Condition::Field(field.remove_details()),
            Condition::IsEmpty(condition) => Condition::IsEmpty(condition.clone()),
            Condition::IsNull(condition) => Condition::IsNull(condition.clone()),
            Condition::HasId(condition) => Condition::HasId(condition.clone()),
            Condition::HasVector(condition) => Condition::HasVector(condition.clone()),
            Condition::Nested(condition) => Condition::Nested(condition.remove_details()),
            Condition::Filter(filter) => Condition::Filter(filter.remove_details()),
            Condition::CustomIdChecker(checker) => Condition::CustomIdChecker(checker.clone()),
        }
    }
}

impl Generalizer for NestedCondition {
    fn remove_details(&self) -> Self {
        Self {
            nested: Nested {
                key: self.nested.key.clone(),
                filter: self.nested.filter.remove_details(),
            },
        }
    }
}

impl Generalizer for FieldCondition {
    fn remove_details(&self) -> Self {
        let redacted_sensitive_condition = if self.r#match.is_some() {
            Some(Match::new_text("[redacted-match]"))
        } else if self.range.is_some() {
            Some(Match::new_text("[redacted-range]"))
        } else if self.geo_bounding_box.is_some() {
            Some(Match::new_text("[redacted-geo-bounding-box]"))
        } else if self.geo_radius.is_some() {
            Some(Match::new_text("[redacted-geo-radius]"))
        } else if self.geo_polygon.is_some() {
            Some(Match::new_text("[redacted-geo-polygon]"))
        } else {
            None
        };

        Self {
            key: self.key.clone(),
            r#match: redacted_sensitive_condition,
            range: None,
            geo_bounding_box: None,
            geo_radius: None,
            geo_polygon: None,
            values_count: self.values_count.clone(),
            is_empty: self.is_empty,
            is_null: self.is_null,
        }
    }
}
