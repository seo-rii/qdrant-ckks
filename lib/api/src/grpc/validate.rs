use std::borrow::Cow;
use std::collections::HashMap;

use common::validation::{validate_range_generic, validate_shard_different_peers};
use data_encoding::BASE64URL_NOPAD;
use segment::data_types::index::validate_integer_index_params;
use validator::{Validate, ValidationError, ValidationErrors};

use super::qdrant as grpc;

const TIMESTAMP_MIN_SECONDS: i64 = -62_135_596_800; // 0001-01-01T00:00:00Z
const TIMESTAMP_MAX_SECONDS: i64 = 253_402_300_799; // 9999-12-31T23:59:59Z
const CKKS_ENCRYPTED_QUERY_SCHEME: &str = "openfhe-ckks";
const CKKS_ENCRYPTED_QUERY_SECURITY_PROFILE: &str = "ckks-128-n16384-d4-scale50";
const CKKS_ENCRYPTED_QUERY_CONTEXT_DIGEST_B64_LEN: usize = 43;
const CKKS_ENCRYPTED_QUERY_SHA256_B64_LEN: usize = 43;
const CKKS_ENCRYPTED_QUERY_CIPHERTEXT_MAX_BYTES: usize = 16 * 1024 * 1024;
const CKKS_ENCRYPTED_QUERY_CIPHERTEXT_MAX_ENCODED_BYTES: usize =
    (CKKS_ENCRYPTED_QUERY_CIPHERTEXT_MAX_BYTES + 2) / 3 * 4;

pub trait ValidateExt {
    fn validate(&self) -> Result<(), ValidationErrors>;
}

impl Validate for dyn ValidateExt {
    #[inline]
    fn validate(&self) -> Result<(), ValidationErrors> {
        ValidateExt::validate(self)
    }
}

impl<V> ValidateExt for ::core::option::Option<V>
where
    V: Validate,
{
    #[inline]
    fn validate(&self) -> Result<(), ValidationErrors> {
        (&self).validate()
    }
}

impl<V> ValidateExt for &::core::option::Option<V>
where
    V: Validate,
{
    #[inline]
    fn validate(&self) -> Result<(), ValidationErrors> {
        self.as_ref().map(Validate::validate).unwrap_or(Ok(()))
    }
}

impl<K, V> ValidateExt for HashMap<K, V>
where
    V: Validate,
{
    #[inline]
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self.values().find_map(|v| v.validate().err()) {
            Some(err) => ValidationErrors::merge(Err(Default::default()), "[]", Err(err)),
            None => Ok(()),
        }
    }
}

impl Validate for grpc::vectors_config::Config {
    fn validate(&self) -> Result<(), ValidationErrors> {
        use grpc::vectors_config::Config;
        match self {
            Config::Params(params) => params.validate(),
            Config::ParamsMap(params_map) => params_map.validate(),
        }
    }
}

impl Validate for grpc::vectors_config_diff::Config {
    fn validate(&self) -> Result<(), ValidationErrors> {
        use grpc::vectors_config_diff::Config;
        match self {
            Config::Params(params) => params.validate(),
            Config::ParamsMap(params_map) => params_map.validate(),
        }
    }
}

impl Validate for grpc::quantization_config::Quantization {
    fn validate(&self) -> Result<(), ValidationErrors> {
        use grpc::quantization_config::Quantization;
        match self {
            Quantization::Scalar(scalar) => scalar.validate(),
            Quantization::Product(product) => product.validate(),
            Quantization::Binary(binary) => binary.validate(),
        }
    }
}

impl Validate for grpc::quantization_config_diff::Quantization {
    fn validate(&self) -> Result<(), ValidationErrors> {
        use grpc::quantization_config_diff::Quantization;
        match self {
            Quantization::Scalar(scalar) => scalar.validate(),
            Quantization::Product(product) => product.validate(),
            Quantization::Binary(binary) => binary.validate(),
            Quantization::Disabled(_) => Ok(()),
        }
    }
}

impl Validate for grpc::update_collection_cluster_setup_request::Operation {
    fn validate(&self) -> Result<(), ValidationErrors> {
        use grpc::update_collection_cluster_setup_request::Operation;
        match self {
            Operation::MoveShard(op) => op.validate(),
            Operation::ReplicateShard(op) => op.validate(),
            Operation::AbortTransfer(op) => op.validate(),
            Operation::DropReplica(op) => op.validate(),
            Operation::CreateShardKey(op) => op.validate(),
            Operation::DeleteShardKey(op) => op.validate(),
            Operation::RestartTransfer(op) => op.validate(),
            Operation::ReplicatePoints(op) => op.validate(),
        }
    }
}

impl Validate for grpc::MoveShard {
    fn validate(&self) -> Result<(), ValidationErrors> {
        validate_shard_different_peers(
            self.from_peer_id,
            self.to_peer_id,
            self.shard_id,
            self.to_shard_id,
        )
    }
}

impl Validate for grpc::ReplicateShard {
    fn validate(&self) -> Result<(), ValidationErrors> {
        validate_shard_different_peers(
            self.from_peer_id,
            self.to_peer_id,
            self.shard_id,
            self.to_shard_id,
        )
    }
}

impl Validate for crate::grpc::qdrant::AbortShardTransfer {
    fn validate(&self) -> Result<(), ValidationErrors> {
        validate_shard_different_peers(
            self.from_peer_id,
            self.to_peer_id,
            self.shard_id,
            self.to_shard_id,
        )
    }
}

impl Validate for grpc::CreateShardKey {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if self.replication_factor == Some(0) {
            let mut errors = ValidationErrors::new();
            errors.add(
                "replication_factor",
                ValidationError::new("Replication factor must be greater than 0"),
            );
            return Err(errors);
        }

        if self.shards_number == Some(0) {
            let mut errors = ValidationErrors::new();
            errors.add(
                "shards_number",
                ValidationError::new("Shards number must be greater than 0"),
            );
            return Err(errors);
        }

        Ok(())
    }
}

impl Validate for grpc::DeleteShardKey {
    fn validate(&self) -> Result<(), ValidationErrors> {
        Ok(())
    }
}

impl Validate for grpc::RestartTransfer {
    fn validate(&self) -> Result<(), ValidationErrors> {
        validate_shard_different_peers(
            self.from_peer_id,
            self.to_peer_id,
            self.shard_id,
            self.to_shard_id,
        )
    }
}

impl Validate for grpc::ReplicatePoints {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if self.from_shard_key != self.to_shard_key {
            return Ok(());
        }

        let mut errors = ValidationErrors::new();
        errors.add(
            "to_shard_key",
            validator::ValidationError::new("must be different from from_shard_key"),
        );
        Err(errors)
    }
}

impl Validate for grpc::condition::ConditionOneOf {
    fn validate(&self) -> Result<(), ValidationErrors> {
        use grpc::condition::ConditionOneOf;
        match self {
            ConditionOneOf::Field(field_condition) => field_condition.validate(),
            ConditionOneOf::Nested(nested) => nested.validate(),
            ConditionOneOf::Filter(filter) => filter.validate(),
            ConditionOneOf::IsEmpty(_) => Ok(()),
            ConditionOneOf::HasId(_) => Ok(()),
            ConditionOneOf::IsNull(_) => Ok(()),
            ConditionOneOf::HasVector(_) => Ok(()),
        }
    }
}

impl Validate for grpc::update_operation::Update {
    fn validate(&self) -> Result<(), ValidationErrors> {
        use grpc::update_operation::Update;
        match self {
            Update::Sync(op) => op.validate(),
            Update::Upsert(op) => op.validate(),
            Update::Delete(op) => op.validate(),
            Update::UpdateVectors(op) => op.validate(),
            Update::DeleteVectors(op) => op.validate(),
            Update::SetPayload(op) => op.validate(),
            Update::OverwritePayload(op) => op.validate(),
            Update::DeletePayload(op) => op.validate(),
            Update::ClearPayload(op) => op.validate(),
            Update::CreateFieldIndex(op) => op.validate(),
            Update::DeleteFieldIndex(op) => op.validate(),
        }
    }
}

impl Validate for grpc::FieldCondition {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let grpc::FieldCondition {
            key: _,
            r#match,
            range,
            datetime_range,
            geo_bounding_box,
            geo_radius,
            geo_polygon,
            values_count,
            is_empty,
            is_null,
        } = self;

        let all_fields_none = r#match.is_none()
            && range.is_none()
            && datetime_range.is_none()
            && geo_bounding_box.is_none()
            && geo_radius.is_none()
            && geo_polygon.is_none()
            && values_count.is_none()
            && is_empty.is_none()
            && is_null.is_none();

        if all_fields_none {
            let mut errors = ValidationErrors::new();
            errors.add(
                "match",
                ValidationError::new("At least one field condition must be specified"),
            );
            Err(errors)
        } else {
            Ok(())
        }
    }
}

impl Validate for grpc::Vector {
    fn validate(&self) -> Result<(), ValidationErrors> {
        #[expect(deprecated)]
        let grpc::Vector {
            data,
            indices,
            vectors_count,
            vector,
        } = self;

        if let Some(vector) = vector {
            vector.validate()?;
        }

        match (indices, vectors_count) {
            (Some(_), Some(_)) => {
                let mut errors = ValidationErrors::new();
                errors.add(
                    "indices",
                    ValidationError::new("`indices` and `vectors_count` cannot be both specified"),
                );
                Err(errors)
            }
            (Some(indices), None) => {
                sparse::common::sparse_vector::validate_sparse_vector_impl(&indices.data, data)
            }
            (None, Some(vectors_count)) => {
                common::validation::validate_multi_vector_len(*vectors_count, data)
            }
            (None, None) => Ok(()),
        }
    }
}

impl Validate for grpc::vector::Vector {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            grpc::vector::Vector::Dense(_dense) => Ok(()),
            grpc::vector::Vector::Sparse(sparse) => sparse.validate(),
            grpc::vector::Vector::MultiDense(multi) => multi.validate(),
            grpc::vector::Vector::Document(_document) => Ok(()),
            grpc::vector::Vector::Image(_image) => Ok(()),
            grpc::vector::Vector::Object(_obj) => Ok(()),
        }
    }
}

impl Validate for grpc::SparseVector {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let grpc::SparseVector { indices, values } = self;
        sparse::common::sparse_vector::validate_sparse_vector_impl(indices, values)
    }
}

impl Validate for grpc::MultiDenseVector {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let grpc::MultiDenseVector { vectors } = self;
        let multivec_length: Vec<_> = vectors.iter().map(|v| v.data.len()).collect();
        common::validation::validate_multi_vector_by_length(&multivec_length)
    }
}

impl Validate for super::qdrant::vectors::VectorsOptions {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            super::qdrant::vectors::VectorsOptions::Vector(v) => v.validate(),
            super::qdrant::vectors::VectorsOptions::Vectors(v) => v.validate(),
        }
    }
}

impl Validate for super::qdrant::query_enum::Query {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            super::qdrant::query_enum::Query::NearestNeighbors(q) => q.validate(),
            super::qdrant::query_enum::Query::RecommendBestScore(q) => q.validate(),
            super::qdrant::query_enum::Query::RecommendSumScores(q) => q.validate(),
            super::qdrant::query_enum::Query::Discover(q) => q.validate(),
            super::qdrant::query_enum::Query::Context(q) => q.validate(),
        }
    }
}

impl Validate for super::qdrant::query::Variant {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            grpc::query::Variant::Nearest(q) => q.validate(),
            grpc::query::Variant::NearestWithMmr(q) => q.validate(),
            grpc::query::Variant::Recommend(q) => q.validate(),
            grpc::query::Variant::Discover(q) => q.validate(),
            grpc::query::Variant::Context(q) => q.validate(),
            grpc::query::Variant::Formula(q) => q.validate(),
            grpc::query::Variant::Rrf(q) => q.validate(),
            grpc::query::Variant::RelevanceFeedback(q) => q.validate(),
            grpc::query::Variant::Sample(_)
            | grpc::query::Variant::Fusion(_)
            | grpc::query::Variant::OrderBy(_) => Ok(()),
        }
    }
}

impl Validate for super::qdrant::vector_input::Variant {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            grpc::vector_input::Variant::Id(_)
            | grpc::vector_input::Variant::Dense(_)
            | grpc::vector_input::Variant::Document(_)
            | grpc::vector_input::Variant::Image(_)
            | grpc::vector_input::Variant::Object(_) => Ok(()),
            grpc::vector_input::Variant::CkksEncryptedQuery(query) => query.validate(),
            grpc::vector_input::Variant::Sparse(sparse_vector) => sparse_vector.validate(),
            grpc::vector_input::Variant::MultiDense(multi_dense_vector) => {
                multi_dense_vector.validate()
            }
        }
    }
}

impl Validate for grpc::CkksEncryptedQueryVector {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();

        if self.version != 1 {
            errors.add(
                "version",
                ValidationError::new("unsupported_ckks_encrypted_query_version"),
            );
        }
        if self.scheme != CKKS_ENCRYPTED_QUERY_SCHEME {
            errors.add(
                "scheme",
                ValidationError::new("unsupported_ckks_encrypted_query_scheme"),
            );
        }
        if self.security_profile != CKKS_ENCRYPTED_QUERY_SECURITY_PROFILE {
            errors.add(
                "security_profile",
                ValidationError::new("unsupported_ckks_encrypted_query_security_profile"),
            );
        }
        if self.collection_id.is_empty() {
            errors.add(
                "collection_id",
                ValidationError::new("empty_ckks_encrypted_query_collection_id"),
            );
        }
        if self.vector_name.is_empty() {
            errors.add(
                "vector_name",
                ValidationError::new("empty_ckks_encrypted_query_vector_name"),
            );
        }
        if self.key_id.is_empty() {
            errors.add(
                "key_id",
                ValidationError::new("empty_ckks_encrypted_query_key_id"),
            );
        }
        if self.rk_id.is_empty() {
            errors.add(
                "rk_id",
                ValidationError::new("empty_ckks_encrypted_query_rk_id"),
            );
        }
        if self.rk_epoch == 0 {
            errors.add(
                "rk_epoch",
                ValidationError::new("empty_ckks_encrypted_query_rk_epoch"),
            );
        }
        if self.context_digest.is_empty() {
            errors.add(
                "context_digest",
                ValidationError::new("empty_ckks_encrypted_query_context_digest"),
            );
        } else if self.context_digest.len() != CKKS_ENCRYPTED_QUERY_CONTEXT_DIGEST_B64_LEN {
            errors.add(
                "context_digest",
                ValidationError::new("invalid_ckks_encrypted_query_context_digest_length"),
            );
        } else {
            match BASE64URL_NOPAD.decode(self.context_digest.as_bytes()) {
                Ok(decoded) if decoded.len() == 32 => {}
                Ok(_) => errors.add(
                    "context_digest",
                    ValidationError::new("invalid_ckks_encrypted_query_context_digest_length"),
                ),
                Err(_) => errors.add(
                    "context_digest",
                    ValidationError::new("invalid_ckks_encrypted_query_context_digest_base64url"),
                ),
            }
        }
        if self.slots == 0 {
            errors.add(
                "slots",
                ValidationError::new("empty_ckks_encrypted_query_slots"),
            );
        }
        if self.ciphertext_sha256.is_empty() {
            errors.add(
                "ciphertext_sha256",
                ValidationError::new("empty_ckks_encrypted_query_ciphertext_sha256"),
            );
        } else if self.ciphertext_sha256.len() != CKKS_ENCRYPTED_QUERY_SHA256_B64_LEN {
            errors.add(
                "ciphertext_sha256",
                ValidationError::new("invalid_ckks_encrypted_query_ciphertext_sha256_length"),
            );
        } else {
            match BASE64URL_NOPAD.decode(self.ciphertext_sha256.as_bytes()) {
                Ok(decoded) if decoded.len() == 32 => {}
                Ok(_) => errors.add(
                    "ciphertext_sha256",
                    ValidationError::new("invalid_ckks_encrypted_query_ciphertext_sha256_length"),
                ),
                Err(_) => errors.add(
                    "ciphertext_sha256",
                    ValidationError::new(
                        "invalid_ckks_encrypted_query_ciphertext_sha256_base64url",
                    ),
                ),
            }
        }
        if self.ciphertext.is_empty() {
            errors.add(
                "ciphertext",
                ValidationError::new("empty_ckks_encrypted_query_ciphertext"),
            );
        } else if self.ciphertext.len() > CKKS_ENCRYPTED_QUERY_CIPHERTEXT_MAX_ENCODED_BYTES {
            errors.add(
                "ciphertext",
                ValidationError::new("oversized_ckks_encrypted_query_ciphertext"),
            );
        } else {
            match BASE64URL_NOPAD.decode(self.ciphertext.as_bytes()) {
                Ok(decoded) if decoded.len() <= CKKS_ENCRYPTED_QUERY_CIPHERTEXT_MAX_BYTES => {}
                Ok(_) => errors.add(
                    "ciphertext",
                    ValidationError::new("oversized_ckks_encrypted_query_ciphertext"),
                ),
                Err(_) => errors.add(
                    "ciphertext",
                    ValidationError::new("invalid_ckks_encrypted_query_ciphertext_base64url"),
                ),
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl Validate for super::qdrant::expression::Variant {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            grpc::expression::Variant::Constant(_) => Ok(()),
            grpc::expression::Variant::Variable(_) => Ok(()),
            grpc::expression::Variant::Condition(condition) => condition.validate(),
            grpc::expression::Variant::GeoDistance(_) => Ok(()),
            grpc::expression::Variant::Datetime(_) => Ok(()),
            grpc::expression::Variant::DatetimeKey(_) => Ok(()),
            grpc::expression::Variant::Mult(mult_expression) => mult_expression.validate(),
            grpc::expression::Variant::Sum(sum_expression) => sum_expression.validate(),
            grpc::expression::Variant::Div(div_expression) => div_expression.validate(),
            grpc::expression::Variant::Neg(expression) => expression.validate(),
            grpc::expression::Variant::Abs(expression) => expression.validate(),
            grpc::expression::Variant::Sqrt(expression) => expression.validate(),
            grpc::expression::Variant::Pow(pow_expression) => pow_expression.validate(),
            grpc::expression::Variant::Exp(expression) => expression.validate(),
            grpc::expression::Variant::Log10(expression) => expression.validate(),
            grpc::expression::Variant::Ln(expression) => expression.validate(),
            grpc::expression::Variant::ExpDecay(decay_params_expression) => {
                decay_params_expression.validate()
            }
            grpc::expression::Variant::GaussDecay(decay_params_expression) => {
                decay_params_expression.validate()
            }
            grpc::expression::Variant::LinDecay(decay_params_expression) => {
                decay_params_expression.validate()
            }
        }
    }
}

impl Validate for grpc::feedback_strategy::Variant {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            grpc::feedback_strategy::Variant::Naive(naive_feedback_strategy) => {
                naive_feedback_strategy.validate()
            }
        }
    }
}

/// Validate that GeoLineString has at least 4 points and is closed.
pub fn validate_geo_polygon_line_helper(line: &grpc::GeoLineString) -> Result<(), ValidationError> {
    let points = &line.points;
    let min_length = 4;
    if points.len() < min_length {
        let mut err: ValidationError = ValidationError::new("min_line_length");
        err.add_param(Cow::from("length"), &points.len());
        err.add_param(Cow::from("min_length"), &min_length);
        return Err(err);
    }

    let first_point = &points[0];
    let last_point = &points[points.len() - 1];
    if first_point != last_point {
        return Err(ValidationError::new("closed_line"));
    }

    Ok(())
}

pub fn validate_geo_polygon_exterior(line: &grpc::GeoLineString) -> Result<(), ValidationError> {
    if line.points.is_empty() {
        return Err(ValidationError::new("not_empty"));
    }
    validate_geo_polygon_line_helper(line)?;
    Ok(())
}

pub fn validate_geo_polygon_interiors(
    lines: &Vec<grpc::GeoLineString>,
) -> Result<(), ValidationError> {
    for line in lines {
        validate_geo_polygon_line_helper(line)?;
    }
    Ok(())
}

/// Validate that the timestamp is within the range specified in the protobuf docs.
/// <https://protobuf.dev/reference/protobuf/google.protobuf/#timestamp>
pub fn validate_timestamp(ts: &prost_wkt_types::Timestamp) -> Result<(), ValidationError> {
    validate_range_generic(
        ts.seconds,
        Some(TIMESTAMP_MIN_SECONDS),
        Some(TIMESTAMP_MAX_SECONDS),
    )?;
    validate_range_generic(ts.nanos, Some(0), Some(999_999_999))?;
    Ok(())
}

impl Validate for super::qdrant::payload_index_params::IndexParams {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            grpc::payload_index_params::IndexParams::KeywordIndexParams(_) => Ok(()),
            grpc::payload_index_params::IndexParams::IntegerIndexParams(integer_index_params) => {
                integer_index_params.validate()
            }
            grpc::payload_index_params::IndexParams::FloatIndexParams(_) => Ok(()),
            grpc::payload_index_params::IndexParams::GeoIndexParams(_) => Ok(()),
            grpc::payload_index_params::IndexParams::TextIndexParams(_) => Ok(()),
            grpc::payload_index_params::IndexParams::BoolIndexParams(_) => Ok(()),
            grpc::payload_index_params::IndexParams::DatetimeIndexParams(_) => Ok(()),
            grpc::payload_index_params::IndexParams::UuidIndexParams(_) => Ok(()),
        }
    }
}

impl Validate for super::qdrant::IntegerIndexParams {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let super::qdrant::IntegerIndexParams {
            lookup,
            range,
            is_principal: _,
            on_disk: _,
            enable_hnsw: _,
        } = &self;
        validate_integer_index_params(lookup, range)
    }
}

impl Validate for super::qdrant::points_selector::PointsSelectorOneOf {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            grpc::points_selector::PointsSelectorOneOf::Points(_) => Ok(()),
            grpc::points_selector::PointsSelectorOneOf::Filter(filter) => filter.validate(),
        }
    }
}

#[cfg(test)]
mod tests {
    use data_encoding::BASE64URL_NOPAD;
    use validator::Validate;

    use super::{
        CKKS_ENCRYPTED_QUERY_CIPHERTEXT_MAX_ENCODED_BYTES,
        CKKS_ENCRYPTED_QUERY_CONTEXT_DIGEST_B64_LEN,
    };
    use crate::grpc::qdrant::{
        CkksEncryptedQueryVector, CreateCollection, CreateFieldIndexCollection, GeoLineString,
        GeoPoint, GeoPolygon, PrefetchQuery, Query, QueryBatchPoints, QueryPointGroups,
        QueryPoints, SearchBatchPoints, SearchPointGroups, SearchPoints, UpdateCollection,
        VectorInput, query, vector_input,
    };

    #[test]
    fn test_good_request() {
        let bad_request = CreateCollection {
            collection_name: "test_collection".into(),
            timeout: Some(10),
            ..Default::default()
        };
        assert!(
            bad_request.validate().is_ok(),
            "good collection request should not error on validation"
        );

        // Collection name validation must not be strict on non-creation
        let bad_request = UpdateCollection {
            collection_name: "no\\path".into(),
            ..Default::default()
        };
        assert!(
            bad_request.validate().is_ok(),
            "good collection request should not error on validation"
        );

        // Collection name validation must not be strict on non-creation
        let bad_request = UpdateCollection {
            collection_name: "no*path".into(),
            ..Default::default()
        };
        assert!(
            bad_request.validate().is_ok(),
            "good collection request should not error on validation"
        );
    }

    #[test]
    fn test_bad_collection_request() {
        let bad_request = CreateCollection {
            collection_name: "".into(),
            timeout: Some(0),
            ..Default::default()
        };
        assert!(
            bad_request.validate().is_err(),
            "bad collection request should error on validation"
        );

        // Collection name validation must be strict on creation
        let bad_request = CreateCollection {
            collection_name: "no/path".into(),
            ..Default::default()
        };
        assert!(
            bad_request.validate().is_err(),
            "bad collection request should error on validation"
        );

        // Collection name validation must be strict on creation
        let bad_request = CreateCollection {
            collection_name: "no*path".into(),
            ..Default::default()
        };
        assert!(
            bad_request.validate().is_err(),
            "bad collection request should error on validation"
        );

        // Collection name validation must still disallow some characters on update
        let bad_request = UpdateCollection {
            collection_name: "no/path".into(),
            ..Default::default()
        };
        assert!(
            bad_request.validate().is_err(),
            "bad collection request should error on validation"
        );

        let bad_request = CreateCollection {
            collection_name: "test_collection".into(),
            encryption_json: Some("x".repeat(1024 * 1024 + 1)),
            ..Default::default()
        };
        assert!(
            bad_request.validate().is_err(),
            "oversized create collection encryption_json should error on validation"
        );
    }

    #[test]
    fn test_bad_index_request() {
        let bad_request = CreateFieldIndexCollection {
            collection_name: "".into(),
            field_name: "".into(),
            ..Default::default()
        };
        assert!(
            bad_request.validate().is_err(),
            "bad index request should error on validation"
        );
    }

    #[test]
    fn test_bad_search_request() {
        let bad_request = SearchPoints {
            collection_name: "".into(),
            limit: 0,
            vector_name: Some("".into()),
            ..Default::default()
        };
        assert!(
            bad_request.validate().is_err(),
            "bad search request should error on validation"
        );

        let bad_request = SearchPoints {
            limit: 0,
            ..Default::default()
        };
        assert!(
            bad_request.validate().is_err(),
            "bad search request should error on validation"
        );

        let bad_request = SearchPoints {
            vector_name: Some("".into()),
            ..Default::default()
        };
        assert!(
            bad_request.validate().is_err(),
            "bad search request should error on validation"
        );
    }

    fn valid_ckks_encrypted_query() -> CkksEncryptedQueryVector {
        CkksEncryptedQueryVector {
            version: 1,
            scheme: "openfhe-ckks".to_string(),
            security_profile: "ckks-128-n16384-d4-scale50".to_string(),
            collection_id: "docs-crypto-id".to_string(),
            vector_name: "embedding".to_string(),
            key_id: "tenant-a:vector".to_string(),
            rk_id: "tenant-a/vector-v1".to_string(),
            rk_epoch: 1,
            context_digest: BASE64URL_NOPAD.encode(&[3_u8; 32]),
            slots: 2,
            ciphertext_sha256: "MFUx3MUOvKMc8dWzHp_HbtUfZrO23VoDDGU5rmUy-Xk".to_string(),
            ciphertext: BASE64URL_NOPAD.encode(b"ciphertext"),
        }
    }

    #[test]
    fn test_ckks_encrypted_query_validation() {
        let good_request = SearchPoints {
            collection_name: "docs".to_string(),
            limit: 1,
            ckks_encrypted_query: Some(valid_ckks_encrypted_query()),
            ..Default::default()
        };
        assert!(
            good_request.validate().is_ok(),
            "valid CKKS encrypted query should pass validation"
        );

        let bad_request = SearchPoints {
            collection_name: "docs".to_string(),
            limit: 1,
            ckks_encrypted_query: Some(CkksEncryptedQueryVector {
                version: 2,
                ..valid_ckks_encrypted_query()
            }),
            ..Default::default()
        };
        assert!(
            bad_request.validate().is_err(),
            "bad CKKS encrypted query version should error on validation"
        );

        let bad_request = SearchPoints {
            collection_name: "docs".to_string(),
            limit: 1,
            ckks_encrypted_query: Some(CkksEncryptedQueryVector {
                collection_id: String::new(),
                vector_name: String::new(),
                key_id: String::new(),
                rk_id: String::new(),
                rk_epoch: 0,
                context_digest: String::new(),
                slots: 0,
                ciphertext_sha256: String::new(),
                ciphertext: String::new(),
                ..valid_ckks_encrypted_query()
            }),
            ..Default::default()
        };
        assert!(
            bad_request.validate().is_err(),
            "empty CKKS encrypted query metadata should error on validation"
        );

        let bad_request = SearchPoints {
            collection_name: "docs".to_string(),
            limit: 1,
            ckks_encrypted_query: Some(CkksEncryptedQueryVector {
                context_digest: BASE64URL_NOPAD.encode(&[3_u8; 31]),
                ..valid_ckks_encrypted_query()
            }),
            ..Default::default()
        };
        assert!(
            bad_request.validate().is_err(),
            "short CKKS encrypted query context digest should error on validation"
        );

        let bad_request = SearchPoints {
            collection_name: "docs".to_string(),
            limit: 1,
            ckks_encrypted_query: Some(CkksEncryptedQueryVector {
                context_digest: "A".repeat(CKKS_ENCRYPTED_QUERY_CONTEXT_DIGEST_B64_LEN + 1),
                ..valid_ckks_encrypted_query()
            }),
            ..Default::default()
        };
        assert!(
            bad_request.validate().is_err(),
            "oversized CKKS encrypted query context digest should error before decode"
        );

        let bad_request = SearchPoints {
            collection_name: "docs".to_string(),
            limit: 1,
            ckks_encrypted_query: Some(CkksEncryptedQueryVector {
                ciphertext: "A".repeat(CKKS_ENCRYPTED_QUERY_CIPHERTEXT_MAX_ENCODED_BYTES + 1),
                ..valid_ckks_encrypted_query()
            }),
            ..Default::default()
        };
        assert!(
            bad_request.validate().is_err(),
            "oversized CKKS encrypted query ciphertext should error before decode"
        );

        let bad_request = SearchPoints {
            collection_name: "docs".to_string(),
            limit: 1,
            ckks_encrypted_query: Some(CkksEncryptedQueryVector {
                ciphertext_sha256: "not base64url!".to_string(),
                ..valid_ckks_encrypted_query()
            }),
            ..Default::default()
        };
        assert!(
            bad_request.validate().is_err(),
            "malformed CKKS encrypted query ciphertext hash should error on validation"
        );

        let bad_request = SearchPoints {
            collection_name: "docs".to_string(),
            limit: 1,
            ckks_encrypted_query: Some(CkksEncryptedQueryVector {
                context_digest: "not base64url!".to_string(),
                ciphertext: "also not base64url!".to_string(),
                ..valid_ckks_encrypted_query()
            }),
            ..Default::default()
        };
        assert!(
            bad_request.validate().is_err(),
            "malformed CKKS encrypted query base64url fields should error on validation"
        );
    }

    #[test]
    fn test_ckks_encrypted_query_vector_input_validation() {
        let good_input = VectorInput {
            variant: Some(vector_input::Variant::CkksEncryptedQuery(
                valid_ckks_encrypted_query(),
            )),
        };
        assert!(
            good_input.validate().is_ok(),
            "valid universal CKKS encrypted query should pass validation"
        );

        let bad_input = VectorInput {
            variant: Some(vector_input::Variant::CkksEncryptedQuery(
                CkksEncryptedQueryVector {
                    scheme: "other".to_string(),
                    ..valid_ckks_encrypted_query()
                },
            )),
        };
        assert!(
            bad_input.validate().is_err(),
            "bad universal CKKS encrypted query scheme should error on validation"
        );
    }

    #[test]
    fn test_ckks_encrypted_query_batch_validation() {
        let good_batch = SearchBatchPoints {
            collection_name: "docs".to_string(),
            search_points: vec![SearchPoints {
                collection_name: "docs".to_string(),
                limit: 1,
                ckks_encrypted_query: Some(valid_ckks_encrypted_query()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(
            good_batch.validate().is_ok(),
            "valid batched CKKS encrypted query should pass validation"
        );

        let bad_batch = SearchBatchPoints {
            collection_name: "docs".to_string(),
            search_points: vec![SearchPoints {
                collection_name: "docs".to_string(),
                limit: 1,
                ckks_encrypted_query: Some(CkksEncryptedQueryVector {
                    ciphertext: "not base64url!".to_string(),
                    ..valid_ckks_encrypted_query()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(
            bad_batch.validate().is_err(),
            "batched CKKS encrypted query should validate nested envelopes"
        );
    }

    #[test]
    fn test_ckks_encrypted_query_groups_validation() {
        let good_request = SearchPointGroups {
            collection_name: "docs".to_string(),
            limit: 1,
            group_by: "tenant".to_string(),
            group_size: 1,
            ckks_encrypted_query: Some(valid_ckks_encrypted_query()),
            ..Default::default()
        };
        assert!(
            good_request.validate().is_ok(),
            "valid grouped CKKS encrypted query should pass validation"
        );

        let bad_request = SearchPointGroups {
            collection_name: "docs".to_string(),
            limit: 1,
            group_by: "tenant".to_string(),
            group_size: 1,
            ckks_encrypted_query: Some(CkksEncryptedQueryVector {
                context_digest: "not base64url!".to_string(),
                ..valid_ckks_encrypted_query()
            }),
            ..Default::default()
        };
        assert!(
            bad_request.validate().is_err(),
            "grouped CKKS encrypted query should validate nested envelopes"
        );
    }

    #[test]
    fn test_ckks_encrypted_query_universal_query_validation() {
        let good_request = QueryPoints {
            collection_name: "docs".to_string(),
            limit: Some(1),
            query: Some(Query {
                variant: Some(query::Variant::Nearest(VectorInput {
                    variant: Some(vector_input::Variant::CkksEncryptedQuery(
                        valid_ckks_encrypted_query(),
                    )),
                })),
            }),
            ..Default::default()
        };
        assert!(
            good_request.validate().is_ok(),
            "valid gRPC universal CKKS encrypted query should pass validation"
        );

        let bad_batch = QueryBatchPoints {
            collection_name: "docs".to_string(),
            query_points: vec![QueryPoints {
                collection_name: "docs".to_string(),
                limit: Some(1),
                query: Some(Query {
                    variant: Some(query::Variant::Nearest(VectorInput {
                        variant: Some(vector_input::Variant::CkksEncryptedQuery(
                            CkksEncryptedQueryVector {
                                ciphertext: "not base64url!".to_string(),
                                ..valid_ckks_encrypted_query()
                            },
                        )),
                    })),
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(
            bad_batch.validate().is_err(),
            "gRPC universal query batch should validate nested CKKS encrypted query envelopes"
        );

        let bad_group_request = QueryPointGroups {
            collection_name: "docs".to_string(),
            limit: Some(1),
            group_by: "tenant".to_string(),
            group_size: Some(1),
            query: Some(Query {
                variant: Some(query::Variant::Nearest(VectorInput {
                    variant: Some(vector_input::Variant::CkksEncryptedQuery(
                        CkksEncryptedQueryVector {
                            context_digest: "not base64url!".to_string(),
                            ..valid_ckks_encrypted_query()
                        },
                    )),
                })),
            }),
            ..Default::default()
        };
        assert!(
            bad_group_request.validate().is_err(),
            "gRPC universal query groups should validate nested CKKS encrypted query envelopes"
        );

        let bad_prefetch_request = QueryPoints {
            collection_name: "docs".to_string(),
            limit: Some(1),
            prefetch: vec![PrefetchQuery {
                query: Some(Query {
                    variant: Some(query::Variant::Nearest(VectorInput {
                        variant: Some(vector_input::Variant::CkksEncryptedQuery(
                            CkksEncryptedQueryVector {
                                ciphertext: "not base64url!".to_string(),
                                ..valid_ckks_encrypted_query()
                            },
                        )),
                    })),
                }),
                limit: Some(1),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(
            bad_prefetch_request.validate().is_err(),
            "gRPC prefetch should validate nested CKKS encrypted query envelopes"
        );
    }

    #[test]
    fn test_geo_polygon() {
        let bad_polygon = GeoPolygon {
            exterior: Some(GeoLineString { points: vec![] }),
            interiors: vec![],
        };
        assert!(
            bad_polygon.validate().is_err(),
            "bad polygon should error on validation"
        );

        let bad_polygon = GeoPolygon {
            exterior: Some(GeoLineString {
                points: vec![
                    GeoPoint { lat: 1., lon: 1. },
                    GeoPoint { lat: 2., lon: 2. },
                    GeoPoint { lat: 3., lon: 3. },
                ],
            }),
            interiors: vec![],
        };
        assert!(
            bad_polygon.validate().is_err(),
            "bad polygon should error on validation"
        );

        let bad_polygon = GeoPolygon {
            exterior: Some(GeoLineString {
                points: vec![
                    GeoPoint { lat: 1., lon: 1. },
                    GeoPoint { lat: 2., lon: 2. },
                    GeoPoint { lat: 3., lon: 3. },
                    GeoPoint { lat: 4., lon: 4. },
                ],
            }),
            interiors: vec![],
        };

        assert!(
            bad_polygon.validate().is_err(),
            "bad polygon should error on validation"
        );

        let bad_polygon = GeoPolygon {
            exterior: Some(GeoLineString {
                points: vec![
                    GeoPoint { lat: 1., lon: 1. },
                    GeoPoint { lat: 2., lon: 2. },
                    GeoPoint { lat: 3., lon: 3. },
                    GeoPoint { lat: 1., lon: 1. },
                ],
            }),
            interiors: vec![GeoLineString {
                points: vec![
                    GeoPoint { lat: 1., lon: 1. },
                    GeoPoint { lat: 2., lon: 2. },
                    GeoPoint { lat: 3., lon: 3. },
                    GeoPoint { lat: 2., lon: 2. },
                ],
            }],
        };

        assert!(
            bad_polygon.validate().is_err(),
            "bad polygon should error on validation"
        );

        let good_polygon = GeoPolygon {
            exterior: Some(GeoLineString {
                points: vec![
                    GeoPoint { lat: 1., lon: 1. },
                    GeoPoint { lat: 2., lon: 2. },
                    GeoPoint { lat: 3., lon: 3. },
                    GeoPoint { lat: 1., lon: 1. },
                ],
            }),
            interiors: vec![],
        };
        assert!(
            good_polygon.validate().is_ok(),
            "good polygon should not error on validation"
        );
    }
}
