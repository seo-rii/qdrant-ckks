use std::collections::HashSet;

use api::grpc::RelevanceFeedbackInput;
use api::grpc::qdrant::vector_input::Variant;
use api::grpc::qdrant::{
    ContextInput, ContextInputPair, DiscoverInput, PrefetchQuery, Query, QueryPointGroups,
    QueryPoints, RecommendInput, VectorInput, query,
};
use api::rest::schema as rest;
use segment::data_types::vectors::DEFAULT_VECTOR_NAME;
use tonic::Status;

use super::service::{InferenceData, InferenceInput, InferenceRequest};

pub struct BatchAccumGrpc {
    pub(crate) objects: HashSet<InferenceData>,
}

impl BatchAccumGrpc {
    pub fn new() -> Self {
        Self {
            objects: HashSet::new(),
        }
    }

    pub fn add(&mut self, data: InferenceData) {
        self.objects.insert(data);
    }

    pub fn extend(&mut self, other: BatchAccumGrpc) {
        self.objects.extend(other.objects);
    }

    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}

impl From<&BatchAccumGrpc> for InferenceRequest {
    fn from(batch: &BatchAccumGrpc) -> Self {
        Self {
            inputs: batch
                .objects
                .iter()
                .cloned()
                .map(InferenceInput::from)
                .collect(),
            inference: None,
            token: None,
        }
    }
}

fn collect_vector_input(vector: &VectorInput, batch: &mut BatchAccumGrpc) -> Result<(), Status> {
    let Some(variant) = &vector.variant else {
        return Ok(());
    };

    match variant {
        Variant::Id(_) => {}
        Variant::Dense(_) => {}
        Variant::Sparse(_) => {}
        Variant::MultiDense(_) => {}
        Variant::CkksEncryptedQuery(_) => {}
        Variant::Document(document) => {
            let doc = rest::Document::try_from(document.clone())
                .map_err(|_| Status::invalid_argument("Invalid document inference input"))?;
            batch.add(InferenceData::Document(doc));
        }
        Variant::Image(image) => {
            let img = rest::Image::try_from(image.clone())
                .map_err(|_| Status::invalid_argument("Invalid image inference input"))?;
            batch.add(InferenceData::Image(img));
        }
        Variant::Object(object) => {
            let obj = rest::InferenceObject::try_from(object.clone())
                .map_err(|_| Status::invalid_argument("Invalid object inference input"))?;
            batch.add(InferenceData::Object(obj));
        }
    }
    Ok(())
}

pub(crate) fn collect_context_input(
    context: &ContextInput,
    batch: &mut BatchAccumGrpc,
) -> Result<(), Status> {
    let ContextInput { pairs } = context;

    for pair in pairs {
        collect_context_input_pair(pair, batch)?;
    }

    Ok(())
}

fn collect_feedback_input(
    feedback: &RelevanceFeedbackInput,
    batch: &mut BatchAccumGrpc,
) -> Result<(), Status> {
    let RelevanceFeedbackInput {
        target,
        feedback,
        strategy: _,
    } = feedback;

    if let Some(target) = target {
        collect_vector_input(target, batch)?;
    }

    for item in feedback {
        if let Some(vector) = &item.example {
            collect_vector_input(vector, batch)?;
        }
    }

    Ok(())
}

fn collect_context_input_pair(
    pair: &ContextInputPair,
    batch: &mut BatchAccumGrpc,
) -> Result<(), Status> {
    let ContextInputPair { positive, negative } = pair;

    if let Some(positive) = positive {
        collect_vector_input(positive, batch)?;
    }

    if let Some(negative) = negative {
        collect_vector_input(negative, batch)?;
    }

    Ok(())
}

pub(crate) fn collect_discover_input(
    discover: &DiscoverInput,
    batch: &mut BatchAccumGrpc,
) -> Result<(), Status> {
    let DiscoverInput { target, context } = discover;

    if let Some(vector) = target {
        collect_vector_input(vector, batch)?;
    }

    if let Some(context) = context {
        for pair in &context.pairs {
            collect_context_input_pair(pair, batch)?;
        }
    }

    Ok(())
}

pub(crate) fn collect_recommend_input(
    recommend: &RecommendInput,
    batch: &mut BatchAccumGrpc,
) -> Result<(), Status> {
    let RecommendInput {
        positive,
        negative,
        strategy: _,
    } = recommend;

    for vector in positive {
        collect_vector_input(vector, batch)?;
    }

    for vector in negative {
        collect_vector_input(vector, batch)?;
    }

    Ok(())
}

pub(crate) fn collect_query(query: &Query, batch: &mut BatchAccumGrpc) -> Result<(), Status> {
    let Some(variant) = &query.variant else {
        return Ok(());
    };

    match variant {
        query::Variant::Nearest(nearest) => collect_vector_input(nearest, batch)?,
        query::Variant::Recommend(recommend) => collect_recommend_input(recommend, batch)?,
        query::Variant::Discover(discover) => collect_discover_input(discover, batch)?,
        query::Variant::Context(context) => collect_context_input(context, batch)?,
        query::Variant::OrderBy(_) => {}
        query::Variant::Fusion(_) => {}
        query::Variant::Rrf(_) => {}
        query::Variant::Sample(_) => {}
        query::Variant::Formula(_) => {}
        query::Variant::NearestWithMmr(nearest_with_mmr) => {
            nearest_with_mmr
                .nearest
                .as_ref()
                .map(|vector| collect_vector_input(vector, batch))
                .transpose()?;
        }
        query::Variant::RelevanceFeedback(feedback) => collect_feedback_input(feedback, batch)?,
    }

    Ok(())
}

pub(crate) fn collect_prefetch(
    prefetch: &PrefetchQuery,
    batch: &mut BatchAccumGrpc,
) -> Result<(), Status> {
    let PrefetchQuery {
        prefetch,
        query,
        using: _,
        filter: _,
        params: _,
        score_threshold: _,
        limit: _,
        lookup_from: _,
    } = prefetch;

    if let Some(query) = query {
        collect_query(query, batch)?;
    }

    for p in prefetch {
        collect_prefetch(p, batch)?;
    }

    Ok(())
}

pub(crate) fn reject_query_points_inference_for_encrypted_vectors(
    query_points: &QueryPoints,
    encrypted_vector_names: &HashSet<String>,
) -> Result<(), Status> {
    if encrypted_vector_names.is_empty() {
        return Ok(());
    }

    let using = query_points.using.as_deref().unwrap_or(DEFAULT_VECTOR_NAME);
    reject_query_inference_for_encrypted_vector(
        query_points.query.as_ref(),
        using,
        encrypted_vector_names,
    )?;
    reject_prefetches_inference_for_encrypted_vectors(
        &query_points.prefetch,
        encrypted_vector_names,
    )
}

pub(crate) fn reject_query_point_groups_inference_for_encrypted_vectors(
    query_points: &QueryPointGroups,
    encrypted_vector_names: &HashSet<String>,
) -> Result<(), Status> {
    if encrypted_vector_names.is_empty() {
        return Ok(());
    }

    let using = query_points.using.as_deref().unwrap_or(DEFAULT_VECTOR_NAME);
    reject_query_inference_for_encrypted_vector(
        query_points.query.as_ref(),
        using,
        encrypted_vector_names,
    )?;
    reject_prefetches_inference_for_encrypted_vectors(
        &query_points.prefetch,
        encrypted_vector_names,
    )
}

fn reject_prefetches_inference_for_encrypted_vectors(
    prefetches: &[PrefetchQuery],
    encrypted_vector_names: &HashSet<String>,
) -> Result<(), Status> {
    for prefetch in prefetches {
        let using = prefetch.using.as_deref().unwrap_or(DEFAULT_VECTOR_NAME);
        reject_query_inference_for_encrypted_vector(
            prefetch.query.as_ref(),
            using,
            encrypted_vector_names,
        )?;
        reject_prefetches_inference_for_encrypted_vectors(
            &prefetch.prefetch,
            encrypted_vector_names,
        )?;
    }
    Ok(())
}

fn reject_query_inference_for_encrypted_vector(
    query: Option<&Query>,
    using: &str,
    encrypted_vector_names: &HashSet<String>,
) -> Result<(), Status> {
    let Some(query) = query else {
        return Ok(());
    };
    if !encrypted_vector_names.contains(using) {
        return Ok(());
    }
    let Some(variant) = &query.variant else {
        return Ok(());
    };

    match variant {
        query::Variant::Nearest(vector) => reject_vector_input_inference(using, vector),
        query::Variant::Recommend(recommend) => {
            for vector in &recommend.positive {
                reject_vector_input_inference(using, vector)?;
            }
            for vector in &recommend.negative {
                reject_vector_input_inference(using, vector)?;
            }
            Ok(())
        }
        query::Variant::Discover(discover) => {
            if let Some(target) = &discover.target {
                reject_vector_input_inference(using, target)?;
            }
            if let Some(context) = &discover.context {
                for pair in &context.pairs {
                    reject_context_pair_inference(using, pair)?;
                }
            }
            Ok(())
        }
        query::Variant::Context(context) => {
            for pair in &context.pairs {
                reject_context_pair_inference(using, pair)?;
            }
            Ok(())
        }
        query::Variant::NearestWithMmr(nearest_with_mmr) => {
            if let Some(nearest) = &nearest_with_mmr.nearest {
                reject_vector_input_inference(using, nearest)?;
            }
            Ok(())
        }
        query::Variant::RelevanceFeedback(feedback) => {
            if let Some(target) = &feedback.target {
                reject_vector_input_inference(using, target)?;
            }
            for item in &feedback.feedback {
                if let Some(example) = &item.example {
                    reject_vector_input_inference(using, example)?;
                }
            }
            Ok(())
        }
        query::Variant::OrderBy(_)
        | query::Variant::Fusion(_)
        | query::Variant::Rrf(_)
        | query::Variant::Sample(_)
        | query::Variant::Formula(_) => Ok(()),
    }
}

fn reject_context_pair_inference(using: &str, pair: &ContextInputPair) -> Result<(), Status> {
    if let Some(positive) = &pair.positive {
        reject_vector_input_inference(using, positive)?;
    }
    if let Some(negative) = &pair.negative {
        reject_vector_input_inference(using, negative)?;
    }
    Ok(())
}

fn reject_vector_input_inference(_using: &str, vector: &VectorInput) -> Result<(), Status> {
    let kind = match vector.variant.as_ref() {
        Some(Variant::Document(_)) => "document",
        Some(Variant::Image(_)) => "image",
        Some(Variant::Object(_)) => "object",
        Some(
            Variant::Id(_)
            | Variant::Dense(_)
            | Variant::Sparse(_)
            | Variant::MultiDense(_)
            | Variant::CkksEncryptedQuery(_),
        )
        | None => return Ok(()),
    };

    Err(Status::invalid_argument(format!(
        "encrypted vector search does not allow {kind} inference query inputs; use a client-encrypted CKKS query envelope, a stored point-id query, or an explicit raw dense vector only when plaintext query opt-in is enabled",
    )))
}

#[cfg(test)]
mod tests {
    use api::rest::schema::{Document, Image, InferenceObject};
    use serde_json::json;

    use super::*;

    fn create_test_document(text: &str) -> Document {
        Document {
            text: text.to_string(),
            model: "test-model".to_string(),
            options: Default::default(),
        }
    }

    fn create_test_image(url: &str) -> Image {
        Image {
            image: json!({"data": url.to_string()}),
            model: "test-model".to_string(),
            options: Default::default(),
        }
    }

    fn create_test_object(data: &str) -> InferenceObject {
        InferenceObject {
            object: json!({"data": data}),
            model: "test-model".to_string(),
            options: Default::default(),
        }
    }

    #[test]
    fn test_batch_accum_basic() {
        let mut batch = BatchAccumGrpc::new();
        assert!(batch.objects.is_empty());

        let doc = InferenceData::Document(create_test_document("test"));
        batch.add(doc.clone());
        assert_eq!(batch.objects.len(), 1);

        batch.add(doc);
        assert_eq!(batch.objects.len(), 1);
    }

    #[test]
    fn test_batch_accum_extend() {
        let mut batch1 = BatchAccumGrpc::new();
        let mut batch2 = BatchAccumGrpc::new();

        let doc1 = InferenceData::Document(create_test_document("test1"));
        let doc2 = InferenceData::Document(create_test_document("test2"));

        batch1.add(doc1);
        batch2.add(doc2);

        batch1.extend(batch2);
        assert_eq!(batch1.objects.len(), 2);
    }

    #[test]
    fn test_deduplication() {
        let mut batch = BatchAccumGrpc::new();

        let doc1 = InferenceData::Document(create_test_document("same"));
        let doc2 = InferenceData::Document(create_test_document("same"));

        batch.add(doc1);
        batch.add(doc2);

        assert_eq!(batch.objects.len(), 1);
    }

    #[test]
    fn test_different_model_same_content() {
        let mut batch = BatchAccumGrpc::new();

        let mut doc1 = create_test_document("same");
        let mut doc2 = create_test_document("same");
        doc1.model = "model1".to_string();
        doc2.model = "model2".to_string();

        batch.add(InferenceData::Document(doc1));
        batch.add(InferenceData::Document(doc2));

        assert_eq!(batch.objects.len(), 2);
    }

    #[test]
    fn test_reject_query_points_inference_for_encrypted_vectors() {
        let mut encrypted = HashSet::new();
        encrypted.insert("embedding".to_string());
        let request = QueryPoints {
            using: Some("embedding".to_string()),
            query: Some(Query {
                variant: Some(query::Variant::Nearest(VectorInput {
                    variant: Some(Variant::Document(create_test_document("secret").into())),
                })),
            }),
            ..Default::default()
        };

        let err = reject_query_points_inference_for_encrypted_vectors(&request, &encrypted)
            .expect_err("encrypted vector query must reject inference before execution");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(
            err.message()
                .contains("does not allow document inference query inputs")
        );
        assert!(!err.message().contains("embedding"));
    }

    #[test]
    fn test_reject_nested_prefetch_inference_for_encrypted_vectors() {
        let mut encrypted = HashSet::new();
        encrypted.insert("embedding".to_string());
        let request = QueryPoints {
            using: Some("other".to_string()),
            prefetch: vec![PrefetchQuery {
                using: Some("embedding".to_string()),
                query: Some(Query {
                    variant: Some(query::Variant::Nearest(VectorInput {
                        variant: Some(Variant::Image(create_test_image("secret.jpg").into())),
                    })),
                }),
                ..Default::default()
            }],
            ..Default::default()
        };

        let err = reject_query_points_inference_for_encrypted_vectors(&request, &encrypted)
            .expect_err("encrypted vector prefetch must reject inference before execution");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(
            err.message()
                .contains("does not allow image inference query inputs")
        );
        assert!(!err.message().contains("embedding"));
    }

    #[test]
    fn grpc_batch_conversion_errors_do_not_echo_inference_inputs() {
        let sentinel = "do-not-echo-grpc-batch-secret";
        let bad_value = api::grpc::qdrant::Value {
            kind: Some(api::grpc::qdrant::value::Kind::DoubleValue(f64::NAN)),
        };

        let mut batch = BatchAccumGrpc::new();
        let doc = VectorInput {
            variant: Some(Variant::Document(api::grpc::qdrant::Document {
                text: sentinel.to_string(),
                model: "test-model".to_string(),
                options: std::collections::HashMap::from([("bad".to_string(), bad_value)]),
            })),
        };
        let err = collect_vector_input(&doc, &mut batch).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "Invalid document inference input");
        assert!(!err.message().contains(sentinel), "{err:?}");

        let mut batch = BatchAccumGrpc::new();
        let image = VectorInput {
            variant: Some(Variant::Image(api::grpc::qdrant::Image {
                image: Some(api::grpc::qdrant::Value {
                    kind: Some(api::grpc::qdrant::value::Kind::DoubleValue(f64::NAN)),
                }),
                model: sentinel.to_string(),
                options: std::collections::HashMap::new(),
            })),
        };
        let err = collect_vector_input(&image, &mut batch).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "Invalid image inference input");
        assert!(!err.message().contains(sentinel), "{err:?}");

        let mut batch = BatchAccumGrpc::new();
        let object = VectorInput {
            variant: Some(Variant::Object(api::grpc::qdrant::InferenceObject {
                object: Some(api::grpc::qdrant::Value {
                    kind: Some(api::grpc::qdrant::value::Kind::DoubleValue(f64::NAN)),
                }),
                model: sentinel.to_string(),
                options: std::collections::HashMap::new(),
            })),
        };
        let err = collect_vector_input(&object, &mut batch).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "Invalid object inference input");
        assert!(!err.message().contains(sentinel), "{err:?}");
    }
}
