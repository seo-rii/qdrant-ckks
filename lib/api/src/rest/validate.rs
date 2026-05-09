use std::borrow::Cow;

use common::validation::validate_multi_vector;
use data_encoding::BASE64URL_NOPAD;
use segment::index::query_optimization::rescore_formula::parsed_formula::VariableId;
use validator::{Validate, ValidationError, ValidationErrors};

use super::{
    Batch, BatchVectorStruct, CkksEncryptedQueryVector, ContextInput, Expression, FormulaQuery,
    Fusion, NamedCkksEncryptedQueryVector, NamedVectorStruct, PointVectors, Query, QueryInterface,
    RecommendInput, RelevanceFeedbackInput, Sample, VectorInput,
};
use crate::rest::FeedbackStrategy;

const CKKS_ENCRYPTED_QUERY_SCHEME: &str = "openfhe-ckks";
const CKKS_ENCRYPTED_QUERY_SECURITY_PROFILE: &str = "ckks-128-n16384-d4-scale50";

impl Validate for NamedVectorStruct {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        match self {
            NamedVectorStruct::Default(_) => Ok(()),
            NamedVectorStruct::Dense(_) => Ok(()),
            NamedVectorStruct::Sparse(v) => v.validate(),
            NamedVectorStruct::CkksEncryptedQuery(query) => query.validate(),
        }
    }
}

impl Validate for NamedCkksEncryptedQueryVector {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        CkksEncryptedQueryVector {
            envelope: self.envelope.clone(),
        }
        .validate()
    }
}

impl Validate for QueryInterface {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        match self {
            QueryInterface::Nearest(vector) => vector.validate(),
            QueryInterface::Query(query) => query.validate(),
        }
    }
}

impl Validate for Query {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        match self {
            Query::Nearest(vector) => vector.validate(),
            Query::Recommend(recommend) => recommend.validate(),
            Query::Discover(discover) => discover.validate(),
            Query::Context(context) => context.validate(),
            Query::Fusion(fusion) => fusion.validate(),
            Query::Rrf(rrf) => rrf.validate(),
            Query::Formula(formula) => formula.validate(),
            Query::OrderBy(order_by) => order_by.validate(),
            Query::Sample(sample) => sample.validate(),
            Query::RelevanceFeedback(feedback) => feedback.validate(),
        }
    }
}

impl Validate for VectorInput {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        match self {
            VectorInput::Id(_id) => Ok(()),
            VectorInput::DenseVector(_dense) => Ok(()),
            VectorInput::SparseVector(sparse) => sparse.validate(),
            VectorInput::MultiDenseVector(multi) => validate_multi_vector(multi),
            VectorInput::Document(doc) => doc.validate(),
            VectorInput::Image(image) => image.validate(),
            VectorInput::CkksEncryptedQuery(query) => query.validate(),
            VectorInput::Object(obj) => obj.validate(),
        }
    }
}

impl Validate for CkksEncryptedQueryVector {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        let mut errors = ValidationErrors::new();
        if self.envelope.version != 1 {
            errors.add(
                "version",
                ValidationError::new("unsupported_ckks_encrypted_query_version"),
            );
        }
        if self.envelope.scheme != CKKS_ENCRYPTED_QUERY_SCHEME {
            errors.add(
                "scheme",
                ValidationError::new("unsupported_ckks_encrypted_query_scheme"),
            );
        }
        if self.envelope.security_profile != CKKS_ENCRYPTED_QUERY_SECURITY_PROFILE {
            errors.add(
                "security_profile",
                ValidationError::new("unsupported_ckks_encrypted_query_security_profile"),
            );
        }
        if self.envelope.context_digest.is_empty() {
            errors.add(
                "context_digest",
                ValidationError::new("empty_ckks_encrypted_query_context_digest"),
            );
        } else {
            match BASE64URL_NOPAD.decode(self.envelope.context_digest.as_bytes()) {
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
        if self.envelope.slots == 0 {
            errors.add(
                "slots",
                ValidationError::new("empty_ckks_encrypted_query_slots"),
            );
        }
        if self.envelope.ciphertext.is_empty() {
            errors.add(
                "ciphertext",
                ValidationError::new("empty_ckks_encrypted_query_ciphertext"),
            );
        } else if BASE64URL_NOPAD
            .decode(self.envelope.ciphertext.as_bytes())
            .is_err()
        {
            errors.add(
                "ciphertext",
                ValidationError::new("invalid_ckks_encrypted_query_ciphertext_base64url"),
            );
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl Validate for RecommendInput {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        let no_positives = self.positive.as_ref().map(|p| p.is_empty()).unwrap_or(true);
        let no_negatives = self.negative.as_ref().map(|n| n.is_empty()).unwrap_or(true);

        if no_positives && no_negatives {
            let mut errors = validator::ValidationErrors::new();
            errors.add(
                "positives, negatives",
                ValidationError::new(
                    "At least one positive or negative vector/id must be provided",
                ),
            );
            return Err(errors);
        }

        for item in self.iter() {
            item.validate()?;
        }

        Ok(())
    }
}

impl Validate for ContextInput {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        for item in self.0.iter().flatten().flat_map(|item| item.iter()) {
            item.validate()?;
        }

        Ok(())
    }
}

impl Validate for FeedbackStrategy {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            FeedbackStrategy::Naive(simple_feedback_strategy) => {
                simple_feedback_strategy.validate()
            }
        }
    }
}
impl Validate for Fusion {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        match self {
            Fusion::Rrf | Fusion::Dbsf => Ok(()),
        }
    }
}

impl Validate for FormulaQuery {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        let Self { formula, defaults } = self;

        // validate formula Expression
        formula.validate()?;
        let mut errors = validator::ValidationErrors::new();

        for (key, value) in defaults.iter() {
            let var_id = match key.parse() {
                Ok(var_id) => var_id,
                Err(err) => {
                    let validation =
                        ValidationError::new("Invalid variable name").with_message(Cow::Owned(err));
                    errors.add("defaults", validation);
                    continue;
                }
            };

            match var_id {
                VariableId::Score(_) if value.as_number().is_none() => {
                    let validation = ValidationError::new("Score default must be a number");
                    errors.add("defaults", validation);
                }
                _ => (),
            }
        }

        Ok(())
    }
}

impl Validate for Sample {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            Sample::Random => Ok(()),
        }
    }
}

impl Validate for BatchVectorStruct {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            BatchVectorStruct::Single(_) => Ok(()),
            BatchVectorStruct::MultiDense(vectors) => {
                for vector in vectors {
                    validate_multi_vector(vector)?;
                }
                Ok(())
            }
            BatchVectorStruct::Named(v) => {
                common::validation::validate_iter(v.values().flat_map(|batch| batch.iter()))
            }
            BatchVectorStruct::Document(_) => Ok(()),
            BatchVectorStruct::Image(_) => Ok(()),
            BatchVectorStruct::Object(_) => Ok(()),
        }
    }
}

impl Validate for Batch {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let batch = self;

        let bad_input_description = |ids: usize, vecs: usize| -> String {
            format!("number of ids and vectors must be equal ({ids} != {vecs})")
        };
        let create_error = |message: String| -> ValidationErrors {
            let mut errors = ValidationErrors::new();
            errors.add("batch", {
                let mut error = ValidationError::new("point_insert_operation");
                error.message.replace(Cow::from(message));
                error
            });
            errors
        };

        self.vectors.validate()?;
        match &batch.vectors {
            BatchVectorStruct::Single(vectors) => {
                if batch.ids.len() != vectors.len() {
                    return Err(create_error(bad_input_description(
                        batch.ids.len(),
                        vectors.len(),
                    )));
                }
            }
            BatchVectorStruct::MultiDense(vectors) => {
                if batch.ids.len() != vectors.len() {
                    return Err(create_error(bad_input_description(
                        batch.ids.len(),
                        vectors.len(),
                    )));
                }
            }
            BatchVectorStruct::Named(named_vectors) => {
                for vectors in named_vectors.values() {
                    if batch.ids.len() != vectors.len() {
                        return Err(create_error(bad_input_description(
                            batch.ids.len(),
                            vectors.len(),
                        )));
                    }
                }
            }
            BatchVectorStruct::Document(_) => {}
            BatchVectorStruct::Image(_) => {}
            BatchVectorStruct::Object(_) => {}
        }
        if let Some(payload_vector) = &batch.payloads
            && payload_vector.len() != batch.ids.len()
        {
            return Err(create_error(format!(
                "number of ids and payloads must be equal ({} != {})",
                batch.ids.len(),
                payload_vector.len(),
            )));
        }
        Ok(())
    }
}

impl Validate for PointVectors {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if self.vector.is_empty() {
            let mut err = ValidationError::new("length");
            err.message = Some(Cow::from("must specify vectors to update for point"));
            err.add_param(Cow::from("min"), &1);
            let mut errors = ValidationErrors::new();
            errors.add("vector", err);
            Err(errors)
        } else {
            self.vector.validate()
        }
    }
}

impl Validate for Expression {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            Expression::Constant(_) => Ok(()),
            Expression::Variable(_) => Ok(()),
            Expression::Condition(condition) => condition.validate(),
            Expression::GeoDistance(_) => Ok(()),
            Expression::Datetime(_) => Ok(()),
            Expression::DatetimeKey(_) => Ok(()),
            Expression::Mult(mult_expression) => mult_expression.validate(),
            Expression::Sum(sum_expression) => sum_expression.validate(),
            Expression::Neg(neg_expression) => neg_expression.validate(),
            Expression::Abs(abs_expression) => abs_expression.validate(),
            Expression::Div(div_expression) => div_expression.validate(),
            Expression::Sqrt(sqrt_expression) => sqrt_expression.validate(),
            Expression::Pow(pow_expression) => pow_expression.validate(),
            Expression::Exp(exp_expression) => exp_expression.validate(),
            Expression::Log10(log10_expression) => log10_expression.validate(),
            Expression::Ln(ln_expression) => ln_expression.validate(),
            Expression::LinDecay(lin_decay_expression) => lin_decay_expression.validate(),
            Expression::ExpDecay(exp_decay_expression) => exp_decay_expression.validate(),
            Expression::GaussDecay(gauss_decay_expression) => gauss_decay_expression.validate(),
        }
    }
}

/// Struct level validation for `FeedbackInput`
pub fn validate_relevance_feedback_input(
    relevance_feedback_input: &RelevanceFeedbackInput,
) -> Result<(), ValidationError> {
    if relevance_feedback_input.feedback.is_empty() {
        let mut err = ValidationError::new("feedback");
        err.message = Some(Cow::from("feedback elements must be non-empty"));
        return Err(err);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use data_encoding::BASE64URL_NOPAD;
    use validator::Validate;

    use super::*;
    use crate::rest::{
        CkksEncryptedQueryVectorEnvelope, Prefetch, QueryBaseGroupRequest, QueryGroupsRequest,
        QueryGroupsRequestInternal, QueryRequest, QueryRequestBatch, QueryRequestInternal,
    };

    fn valid_ckks_encrypted_query() -> CkksEncryptedQueryVector {
        CkksEncryptedQueryVector {
            envelope: CkksEncryptedQueryVectorEnvelope {
                version: 1,
                scheme: "openfhe-ckks".to_string(),
                security_profile: "ckks-128-n16384-d4-scale50".to_string(),
                context_digest: BASE64URL_NOPAD.encode(&[3_u8; 32]),
                slots: 2,
                ciphertext: BASE64URL_NOPAD.encode(b"ciphertext"),
            },
        }
    }

    #[test]
    fn test_ckks_encrypted_query_validation() {
        assert!(
            valid_ckks_encrypted_query().validate().is_ok(),
            "valid REST CKKS encrypted query should pass validation"
        );

        let bad_query = CkksEncryptedQueryVector {
            envelope: CkksEncryptedQueryVectorEnvelope {
                version: 2,
                ..valid_ckks_encrypted_query().envelope
            },
        };
        assert!(
            bad_query.validate().is_err(),
            "bad REST CKKS encrypted query version should error on validation"
        );

        let bad_query = CkksEncryptedQueryVector {
            envelope: CkksEncryptedQueryVectorEnvelope {
                scheme: "other".to_string(),
                security_profile: "other".to_string(),
                ..valid_ckks_encrypted_query().envelope
            },
        };
        assert!(
            bad_query.validate().is_err(),
            "bad REST CKKS encrypted query scheme/profile should error on validation"
        );

        let bad_query = CkksEncryptedQueryVector {
            envelope: CkksEncryptedQueryVectorEnvelope {
                context_digest: String::new(),
                slots: 0,
                ciphertext: String::new(),
                ..valid_ckks_encrypted_query().envelope
            },
        };
        assert!(
            bad_query.validate().is_err(),
            "empty REST CKKS encrypted query metadata should error on validation"
        );

        let bad_query = CkksEncryptedQueryVector {
            envelope: CkksEncryptedQueryVectorEnvelope {
                context_digest: BASE64URL_NOPAD.encode(&[3_u8; 31]),
                ..valid_ckks_encrypted_query().envelope
            },
        };
        assert!(
            bad_query.validate().is_err(),
            "short REST CKKS encrypted query context digest should error on validation"
        );

        let bad_query = CkksEncryptedQueryVector {
            envelope: CkksEncryptedQueryVectorEnvelope {
                context_digest: "not base64url!".to_string(),
                ciphertext: "also not base64url!".to_string(),
                ..valid_ckks_encrypted_query().envelope
            },
        };
        assert!(
            bad_query.validate().is_err(),
            "malformed REST CKKS encrypted query base64url fields should error on validation"
        );
    }

    #[test]
    fn test_ckks_encrypted_query_wrappers_validate_nested_envelope() {
        let named_query = NamedCkksEncryptedQueryVector {
            name: None,
            envelope: valid_ckks_encrypted_query().envelope,
        };
        assert!(
            named_query.validate().is_ok(),
            "valid named REST CKKS encrypted query should pass validation"
        );

        let bad_named_query = NamedCkksEncryptedQueryVector {
            name: None,
            envelope: CkksEncryptedQueryVectorEnvelope {
                ciphertext: "not base64url!".to_string(),
                ..valid_ckks_encrypted_query().envelope
            },
        };
        assert!(
            bad_named_query.validate().is_err(),
            "named REST CKKS encrypted query should validate the nested envelope"
        );

        let bad_vector_input = VectorInput::CkksEncryptedQuery(CkksEncryptedQueryVector {
            envelope: CkksEncryptedQueryVectorEnvelope {
                context_digest: BASE64URL_NOPAD.encode(&[3_u8; 31]),
                ..valid_ckks_encrypted_query().envelope
            },
        });
        assert!(
            bad_vector_input.validate().is_err(),
            "universal REST CKKS encrypted query should validate the nested envelope"
        );
    }

    #[test]
    fn test_ckks_encrypted_query_batch_validation() {
        let good_batch = QueryRequestBatch {
            searches: vec![QueryRequest {
                internal: QueryRequestInternal {
                    prefetch: None,
                    query: Some(QueryInterface::Nearest(VectorInput::CkksEncryptedQuery(
                        valid_ckks_encrypted_query(),
                    ))),
                    using: None,
                    filter: None,
                    params: None,
                    score_threshold: None,
                    limit: Some(1),
                    offset: None,
                    with_vector: None,
                    with_payload: None,
                    lookup_from: None,
                },
                shard_key: None,
            }],
        };
        assert!(
            good_batch.validate().is_ok(),
            "valid REST batched CKKS encrypted query should pass validation"
        );

        let bad_batch = QueryRequestBatch {
            searches: vec![QueryRequest {
                internal: QueryRequestInternal {
                    prefetch: None,
                    query: Some(QueryInterface::Nearest(VectorInput::CkksEncryptedQuery(
                        CkksEncryptedQueryVector {
                            envelope: CkksEncryptedQueryVectorEnvelope {
                                ciphertext: "not base64url!".to_string(),
                                ..valid_ckks_encrypted_query().envelope
                            },
                        },
                    ))),
                    using: None,
                    filter: None,
                    params: None,
                    score_threshold: None,
                    limit: Some(1),
                    offset: None,
                    with_vector: None,
                    with_payload: None,
                    lookup_from: None,
                },
                shard_key: None,
            }],
        };
        assert!(
            bad_batch.validate().is_err(),
            "REST query batch should validate nested CKKS encrypted query envelopes"
        );
    }

    #[test]
    fn test_ckks_encrypted_query_groups_validation() {
        let good_request = QueryGroupsRequest {
            search_group_request: QueryGroupsRequestInternal {
                prefetch: None,
                query: Some(QueryInterface::Nearest(VectorInput::CkksEncryptedQuery(
                    valid_ckks_encrypted_query(),
                ))),
                using: None,
                filter: None,
                params: None,
                score_threshold: None,
                with_vector: None,
                with_payload: None,
                lookup_from: None,
                group_request: QueryBaseGroupRequest {
                    group_by: "tenant".parse().unwrap(),
                    group_size: Some(1),
                    limit: Some(1),
                    with_lookup: None,
                },
            },
            shard_key: None,
        };
        assert!(
            good_request.validate().is_ok(),
            "valid REST grouped CKKS encrypted query should pass validation"
        );

        let bad_request = QueryGroupsRequest {
            search_group_request: QueryGroupsRequestInternal {
                prefetch: None,
                query: Some(QueryInterface::Nearest(VectorInput::CkksEncryptedQuery(
                    CkksEncryptedQueryVector {
                        envelope: CkksEncryptedQueryVectorEnvelope {
                            context_digest: "not base64url!".to_string(),
                            ..valid_ckks_encrypted_query().envelope
                        },
                    },
                ))),
                using: None,
                filter: None,
                params: None,
                score_threshold: None,
                with_vector: None,
                with_payload: None,
                lookup_from: None,
                group_request: QueryBaseGroupRequest {
                    group_by: "tenant".parse().unwrap(),
                    group_size: Some(1),
                    limit: Some(1),
                    with_lookup: None,
                },
            },
            shard_key: None,
        };
        assert!(
            bad_request.validate().is_err(),
            "REST query groups should validate nested CKKS encrypted query envelopes"
        );
    }

    #[test]
    fn test_ckks_encrypted_query_prefetch_validation() {
        let bad_request = QueryRequest {
            internal: QueryRequestInternal {
                prefetch: Some(vec![Prefetch {
                    prefetch: None,
                    query: Some(QueryInterface::Nearest(VectorInput::CkksEncryptedQuery(
                        CkksEncryptedQueryVector {
                            envelope: CkksEncryptedQueryVectorEnvelope {
                                ciphertext: "not base64url!".to_string(),
                                ..valid_ckks_encrypted_query().envelope
                            },
                        },
                    ))),
                    using: None,
                    filter: None,
                    params: None,
                    score_threshold: None,
                    limit: Some(1),
                    lookup_from: None,
                }]),
                query: None,
                using: None,
                filter: None,
                params: None,
                score_threshold: None,
                limit: Some(1),
                offset: None,
                with_vector: None,
                with_payload: None,
                lookup_from: None,
            },
            shard_key: None,
        };
        assert!(
            bad_request.validate().is_err(),
            "REST prefetch should validate nested CKKS encrypted query envelopes"
        );
    }
}
