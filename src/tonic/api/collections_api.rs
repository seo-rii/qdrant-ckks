use std::sync::Arc;
use std::time::{Duration, Instant};

use api::grpc::qdrant::collections_server::Collections;
use api::grpc::qdrant::{
    ChangeAliases, CollectionClusterInfoRequest, CollectionClusterInfoResponse,
    CollectionExistsRequest, CollectionExistsResponse, CollectionOperationResponse,
    CreateCollection, CreateShardKeyRequest, CreateShardKeyResponse, DeleteCollection,
    DeleteShardKeyRequest, DeleteShardKeyResponse, GetCollectionInfoRequest,
    GetCollectionInfoResponse, ListAliasesRequest, ListAliasesResponse,
    ListCollectionAliasesRequest, ListCollectionsRequest, ListCollectionsResponse,
    ListShardKeysRequest, ListShardKeysResponse, UpdateCollection,
    UpdateCollectionClusterSetupRequest, UpdateCollectionClusterSetupResponse,
};
use collection::operations::cluster_ops::{
    ClusterOperations, CreateShardingKeyOperation, DropShardingKeyOperation,
};
use collection::operations::types::CollectionsAliasesResponse;
use collection::operations::verification::new_unchecked_verification_pass;
use storage::dispatcher::Dispatcher;
use tonic::{Request, Response, Status};

use super::validate;
use crate::common::collections::*;
use crate::common::crypto::validate_create_collection_crypto_runtime;
use crate::common::snapshots::begin_private_oram_collection_lifecycle_guard;
use crate::settings::Settings;
use crate::tonic::api::collections_common::get;
use crate::tonic::auth::extract_auth;

pub struct CollectionsService {
    dispatcher: Arc<Dispatcher>,
    settings: Settings,
}

impl CollectionsService {
    pub fn new(dispatcher: Arc<Dispatcher>, settings: Settings) -> Self {
        Self {
            dispatcher,
            settings,
        }
    }

    async fn perform_operation<O>(
        &self,
        mut request: Request<O>,
    ) -> Result<Response<CollectionOperationResponse>, Status>
    where
        O: WithTimeout
            + TryInto<
                storage::content_manager::collection_meta_ops::CollectionMetaOperations,
                Error = Status,
            >,
    {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let operation = request.into_inner();
        let wait_timeout = operation.wait_timeout();
        let result = self
            .dispatcher
            .submit_collection_meta_op(operation.try_into()?, auth, wait_timeout)
            .await?;

        let response = CollectionOperationResponse::from((timing, result));
        Ok(Response::new(response))
    }
}

#[tonic::async_trait]
impl Collections for CollectionsService {
    async fn get(
        &self,
        mut request: Request<GetCollectionInfoRequest>,
    ) -> Result<Response<GetCollectionInfoResponse>, Status> {
        validate(request.get_ref())?;
        let auth = extract_auth(&mut request);

        // Nothing to verify here.
        let pass = new_unchecked_verification_pass();

        get(
            self.dispatcher.toc(&auth, &pass),
            request.into_inner(),
            &auth,
            None,
        )
        .await
    }

    async fn list(
        &self,
        mut request: Request<ListCollectionsRequest>,
    ) -> Result<Response<ListCollectionsResponse>, Status> {
        validate(request.get_ref())?;
        let timing = Instant::now();
        let auth = extract_auth(&mut request);

        // Nothing to verify here.
        let pass = new_unchecked_verification_pass();

        let result = do_list_collections(self.dispatcher.toc(&auth, &pass), &auth).await?;

        let response = ListCollectionsResponse::from((timing, result));
        Ok(Response::new(response))
    }

    async fn create(
        &self,
        mut request: Request<CreateCollection>,
    ) -> Result<Response<CollectionOperationResponse>, Status> {
        validate(request.get_ref())?;
        let auth = extract_auth(&mut request);
        let operation = request.into_inner();
        let wait_timeout = operation.timeout.map(Duration::from_secs);
        let meta_operation: storage::content_manager::collection_meta_ops::CollectionMetaOperations =
            operation.try_into()?;
        let storage::content_manager::collection_meta_ops::CollectionMetaOperations::CreateCollection(
            create_operation,
        ) = meta_operation
        else {
            return Err(Status::internal(
                "grpc create collection converted to unexpected collection meta operation",
            ));
        };
        validate_create_collection_crypto_runtime(
            &self.settings,
            &create_operation.collection_name,
            &create_operation.create_collection,
        )?;

        let timing = Instant::now();
        let result = self
            .dispatcher
            .submit_collection_meta_op(
                storage::content_manager::collection_meta_ops::CollectionMetaOperations::CreateCollection(create_operation),
                auth,
                wait_timeout,
            )
            .await?;

        Ok(Response::new(CollectionOperationResponse::from((
            timing, result,
        ))))
    }

    async fn update(
        &self,
        mut request: Request<UpdateCollection>,
    ) -> Result<Response<CollectionOperationResponse>, Status> {
        validate(request.get_ref())?;
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let operation = request.into_inner();
        let wait_timeout = operation.wait_timeout();
        let collection_name = operation.collection_name.clone();
        let _private_oram_lifecycle_guard = begin_private_oram_collection_lifecycle_guard(
            &self.dispatcher,
            &auth,
            &collection_name,
        )
        .await?;
        let result = self
            .dispatcher
            .submit_collection_meta_op(operation.try_into()?, auth, wait_timeout)
            .await?;

        Ok(Response::new(CollectionOperationResponse::from((
            timing, result,
        ))))
    }

    async fn delete(
        &self,
        mut request: Request<DeleteCollection>,
    ) -> Result<Response<CollectionOperationResponse>, Status> {
        validate(request.get_ref())?;
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let operation = request.into_inner();
        let wait_timeout = operation.wait_timeout();
        let collection_name = operation.collection_name.clone();
        let _private_oram_lifecycle_guard = begin_private_oram_collection_lifecycle_guard(
            &self.dispatcher,
            &auth,
            &collection_name,
        )
        .await?;
        let result = self
            .dispatcher
            .submit_collection_meta_op(operation.try_into()?, auth, wait_timeout)
            .await?;

        Ok(Response::new(CollectionOperationResponse::from((
            timing, result,
        ))))
    }

    async fn update_aliases(
        &self,
        request: Request<ChangeAliases>,
    ) -> Result<Response<CollectionOperationResponse>, Status> {
        validate(request.get_ref())?;
        self.perform_operation(request).await
    }

    async fn list_collection_aliases(
        &self,
        mut request: Request<ListCollectionAliasesRequest>,
    ) -> Result<Response<ListAliasesResponse>, Status> {
        validate(request.get_ref())?;
        let timing = Instant::now();
        let auth = extract_auth(&mut request);

        // Nothing to verify here.
        let pass = new_unchecked_verification_pass();

        let ListCollectionAliasesRequest { collection_name } = request.into_inner();
        let CollectionsAliasesResponse { aliases } =
            do_list_collection_aliases(self.dispatcher.toc(&auth, &pass), &auth, &collection_name)
                .await?;
        let response = ListAliasesResponse {
            aliases: aliases.into_iter().map(|alias| alias.into()).collect(),
            time: timing.elapsed().as_secs_f64(),
        };
        Ok(Response::new(response))
    }

    async fn list_aliases(
        &self,
        mut request: Request<ListAliasesRequest>,
    ) -> Result<Response<ListAliasesResponse>, Status> {
        validate(request.get_ref())?;
        let timing = Instant::now();
        let auth = extract_auth(&mut request);

        // Nothing to verify here.
        let pass = new_unchecked_verification_pass();

        let CollectionsAliasesResponse { aliases } =
            do_list_aliases(self.dispatcher.toc(&auth, &pass), &auth).await?;
        let response = ListAliasesResponse {
            aliases: aliases.into_iter().map(|alias| alias.into()).collect(),
            time: timing.elapsed().as_secs_f64(),
        };
        Ok(Response::new(response))
    }

    async fn collection_exists(
        &self,
        mut request: Request<CollectionExistsRequest>,
    ) -> Result<Response<CollectionExistsResponse>, Status> {
        let timing = Instant::now();
        validate(request.get_ref())?;
        let auth = extract_auth(&mut request);

        // Nothing to verify here.
        let pass = new_unchecked_verification_pass();

        let CollectionExistsRequest { collection_name } = request.into_inner();
        let result =
            do_collection_exists(self.dispatcher.toc(&auth, &pass), &auth, &collection_name)
                .await?;
        let response = CollectionExistsResponse {
            result: Some(result),
            time: timing.elapsed().as_secs_f64(),
        };

        Ok(Response::new(response))
    }

    async fn collection_cluster_info(
        &self,
        mut request: Request<CollectionClusterInfoRequest>,
    ) -> Result<Response<CollectionClusterInfoResponse>, Status> {
        validate(request.get_ref())?;
        let auth = extract_auth(&mut request);

        // Nothing to verify here.
        let pass = new_unchecked_verification_pass();

        let response = do_get_collection_cluster(
            self.dispatcher.toc(&auth, &pass),
            &auth,
            request.into_inner().collection_name.as_str(),
        )
        .await?
        .into();

        Ok(Response::new(response))
    }

    async fn update_collection_cluster_setup(
        &self,
        mut request: Request<UpdateCollectionClusterSetupRequest>,
    ) -> Result<Response<UpdateCollectionClusterSetupResponse>, Status> {
        validate(request.get_ref())?;
        let auth = extract_auth(&mut request);
        let UpdateCollectionClusterSetupRequest {
            collection_name,
            operation,
            timeout,
            ..
        } = request.into_inner();
        let result = do_update_collection_cluster(
            self.dispatcher.as_ref(),
            collection_name,
            operation
                .ok_or_else(|| Status::new(tonic::Code::InvalidArgument, "empty operation"))?
                .try_into()?,
            auth,
            timeout.map(std::time::Duration::from_secs),
        )
        .await?;
        Ok(Response::new(UpdateCollectionClusterSetupResponse {
            result,
        }))
    }

    async fn list_shard_keys(
        &self,
        mut request: Request<ListShardKeysRequest>,
    ) -> Result<Response<ListShardKeysResponse>, Status> {
        validate(request.get_ref())?;
        let timing = Instant::now();
        let auth = extract_auth(&mut request);

        // Nothing to verify here.
        let pass = new_unchecked_verification_pass();

        let result = do_get_collection_shard_keys(
            self.dispatcher.toc(&auth, &pass),
            &auth,
            request.into_inner().collection_name.as_str(),
        )
        .await?;

        let response = ListShardKeysResponse::from((timing, result));
        Ok(Response::new(response))
    }

    async fn create_shard_key(
        &self,
        mut request: Request<CreateShardKeyRequest>,
    ) -> Result<Response<CreateShardKeyResponse>, Status> {
        let auth = extract_auth(&mut request);

        let CreateShardKeyRequest {
            collection_name,
            request,
            timeout,
        } = request.into_inner();

        let Some(request) = request else {
            return Err(Status::new(tonic::Code::InvalidArgument, "empty request"));
        };

        let timeout = timeout.map(std::time::Duration::from_secs);

        let operation = ClusterOperations::CreateShardingKey(CreateShardingKeyOperation {
            create_sharding_key: request.try_into()?,
        });

        let result = do_update_collection_cluster(
            self.dispatcher.as_ref(),
            collection_name,
            operation,
            auth,
            timeout,
        )
        .await?;

        Ok(Response::new(CreateShardKeyResponse { result }))
    }

    async fn delete_shard_key(
        &self,
        mut request: Request<DeleteShardKeyRequest>,
    ) -> Result<Response<DeleteShardKeyResponse>, Status> {
        let auth = extract_auth(&mut request);

        let DeleteShardKeyRequest {
            collection_name,
            request,
            timeout,
        } = request.into_inner();

        let Some(request) = request else {
            return Err(Status::new(tonic::Code::InvalidArgument, "empty request"));
        };

        let timeout = timeout.map(std::time::Duration::from_secs);

        let operation = ClusterOperations::DropShardingKey(DropShardingKeyOperation {
            drop_sharding_key: request.try_into()?,
        });

        let result = do_update_collection_cluster(
            self.dispatcher.as_ref(),
            collection_name,
            operation,
            auth,
            timeout,
        )
        .await?;

        Ok(Response::new(DeleteShardKeyResponse { result }))
    }
}

trait WithTimeout {
    fn wait_timeout(&self) -> Option<Duration>;
}

macro_rules! impl_with_timeout {
    ($operation:ty) => {
        impl WithTimeout for $operation {
            fn wait_timeout(&self) -> Option<Duration> {
                self.timeout.map(Duration::from_secs)
            }
        }
    };
}

impl_with_timeout!(CreateCollection);
impl_with_timeout!(UpdateCollection);
impl_with_timeout!(DeleteCollection);
impl_with_timeout!(ChangeAliases);
impl_with_timeout!(UpdateCollectionClusterSetupRequest);

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use api::grpc::qdrant::collections_server::Collections;
    use storage::rbac::{Access, Auth};

    use super::*;
    use crate::common::private_hnsw::begin_private_hnsw_collection_snapshot;
    use crate::common::private_hnsw_wire_fixture::{
        COLLECTION_NAME, create_private_hnsw_collection, route_e2e_guard, test_dispatcher,
    };

    #[test]
    fn update_and_delete_collection_reject_private_oram_snapshot_window() {
        let _guard = route_e2e_guard();
        let (_temp, dispatcher) = test_dispatcher();
        let dispatcher = Arc::new(dispatcher);
        let service = CollectionsService::new(dispatcher.clone(), Settings::new(None).unwrap());

        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(dispatcher.as_ref()).await;

            let auth = Auth::new_internal(Access::full("private ORAM collection tonic route test"));
            let pass = new_unchecked_verification_pass();
            let collection_pass = auth
                .check_collection_access(
                    COLLECTION_NAME,
                    storage::rbac::AccessRequirements::new().manage(),
                    "private_oram_tonic_collection_route_test",
                )
                .unwrap();
            let collection = dispatcher
                .toc(&auth, &pass)
                .get_collection(&collection_pass)
                .await
                .unwrap();
            let config = collection.config_snapshot().await;
            let _snapshot_guard =
                begin_private_hnsw_collection_snapshot(collection.name(), &config)
                    .expect("private HNSW snapshot guard should open");

            let update_err = Collections::update(
                &service,
                Request::new(UpdateCollection {
                    collection_name: COLLECTION_NAME.to_string(),
                    optimizers_config: None,
                    timeout: None,
                    params: None,
                    hnsw_config: None,
                    vectors_config: None,
                    quantization_config: None,
                    sparse_vectors_config: None,
                    strict_mode_config: None,
                    metadata: Default::default(),
                }),
            )
            .await
            .expect_err("private ORAM collection update must reject active snapshot");
            assert_eq!(update_err.code(), tonic::Code::InvalidArgument);
            assert!(
                update_err
                    .message()
                    .contains("lifecycle operation requires no active collection snapshot"),
                "{update_err}",
            );
            assert!(
                !update_err.message().contains(COLLECTION_NAME),
                "{update_err}"
            );

            let delete_err = Collections::delete(
                &service,
                Request::new(DeleteCollection {
                    collection_name: COLLECTION_NAME.to_string(),
                    timeout: None,
                }),
            )
            .await
            .expect_err("private ORAM collection delete must reject active snapshot");
            assert_eq!(delete_err.code(), tonic::Code::InvalidArgument);
            assert!(
                delete_err
                    .message()
                    .contains("lifecycle operation requires no active collection snapshot"),
                "{delete_err}",
            );
            assert!(
                !delete_err.message().contains(COLLECTION_NAME),
                "{delete_err}"
            );
        });
    }
}
