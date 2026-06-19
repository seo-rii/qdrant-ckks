use std::ops::Deref;
use std::sync::Arc;

use atomic_refcell::AtomicRefCell;
use common::counter::hardware_counter::HardwareCounterCell;
use common::types::PointOffsetType;

use crate::common::operation_error::OperationResult;
use crate::payload_storage::PayloadStorage;
use crate::payload_storage::payload_storage_enum::PayloadStorageEnum;
use crate::types::{OwnedPayloadRef, Payload};

#[derive(Clone)]
pub struct PayloadProvider {
    payload_storage: Arc<AtomicRefCell<PayloadStorageEnum>>,
    empty_payload: Payload,
}

impl PayloadProvider {
    pub fn new(payload_storage: Arc<AtomicRefCell<PayloadStorageEnum>>) -> Self {
        Self {
            payload_storage,
            empty_payload: Default::default(),
        }
    }

    pub fn try_with_payload<F, G>(
        &self,
        point_id: PointOffsetType,
        callback: F,
        hw_counter: &HardwareCounterCell,
    ) -> OperationResult<G>
    where
        F: FnOnce(OwnedPayloadRef) -> G,
    {
        let payload_storage_guard = self.payload_storage.borrow();
        let payload_ptr_opt = match payload_storage_guard.deref() {
            #[cfg(feature = "testing")]
            PayloadStorageEnum::InMemoryPayloadStorage(s) => {
                s.payload_ptr(point_id).map(OwnedPayloadRef::from)
            }
            #[cfg(feature = "rocksdb")]
            PayloadStorageEnum::SimplePayloadStorage(s) => {
                s.payload_ptr(point_id).map(OwnedPayloadRef::from)
            }
            #[cfg(feature = "rocksdb")]
            PayloadStorageEnum::OnDiskPayloadStorage(s) => s
                .read_payload(point_id, hw_counter)?
                .map(OwnedPayloadRef::from),
            PayloadStorageEnum::MmapPayloadStorage(s) => {
                let payload = s.get(point_id, hw_counter)?;
                Some(OwnedPayloadRef::from(payload))
            }
        };

        let payload = if let Some(payload_ptr) = payload_ptr_opt {
            payload_ptr
        } else {
            OwnedPayloadRef::from(&self.empty_payload)
        };

        Ok(callback(payload))
    }
}
