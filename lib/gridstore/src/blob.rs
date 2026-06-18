use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::error::GridstoreError;

pub trait Blob {
    fn try_to_bytes(&self) -> std::result::Result<Vec<u8>, GridstoreError>;

    fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("Failed to serialize gridstore blob")
    }

    fn try_from_bytes(bytes: &[u8]) -> std::result::Result<Self, GridstoreError>
    where
        Self: Sized;

    fn from_bytes(bytes: &[u8]) -> Self
    where
        Self: Sized,
    {
        Self::try_from_bytes(bytes).expect("Failed to deserialize gridstore blob")
    }
}

impl Blob for Vec<u8> {
    fn try_to_bytes(&self) -> std::result::Result<Vec<u8>, GridstoreError> {
        Ok(self.clone())
    }

    fn try_from_bytes(bytes: &[u8]) -> std::result::Result<Self, GridstoreError> {
        Ok(bytes.to_vec())
    }
}

impl Blob for Vec<ecow::EcoString> {
    fn try_to_bytes(&self) -> std::result::Result<Vec<u8>, GridstoreError> {
        serde_cbor::to_vec(self).map_err(|err| {
            GridstoreError::service_error(format!(
                "Failed to serialize Vec<ecow::EcoString>: {err}"
            ))
        })
    }

    fn try_from_bytes(bytes: &[u8]) -> std::result::Result<Self, GridstoreError> {
        serde_cbor::from_slice(bytes).map_err(|err| {
            GridstoreError::validation_error(format!(
                "Failed to deserialize Vec<ecow::EcoString>: {err}"
            ))
        })
    }
}

impl Blob for Vec<(f64, f64)> {
    fn try_to_bytes(&self) -> std::result::Result<Vec<u8>, GridstoreError> {
        Ok(self
            .iter()
            .flat_map(|(a, b)| a.to_le_bytes().into_iter().chain(b.to_le_bytes()))
            .collect())
    }

    fn try_from_bytes(bytes: &[u8]) -> std::result::Result<Self, GridstoreError> {
        let chunk_size = size_of::<f64>() * 2;
        if !bytes.len().is_multiple_of(chunk_size) {
            return Err(GridstoreError::validation_error(format!(
                "Unexpected number of bytes for Vec<(f64, f64)>: {}",
                bytes.len()
            )));
        }

        let mut values = Vec::with_capacity(bytes.len() / chunk_size);
        for chunk in bytes.chunks_exact(chunk_size) {
            let mut a = [0; size_of::<f64>()];
            let mut b = [0; size_of::<f64>()];
            a.copy_from_slice(&chunk[..size_of::<f64>()]);
            b.copy_from_slice(&chunk[size_of::<f64>()..]);
            values.push((f64::from_le_bytes(a), f64::from_le_bytes(b)));
        }

        Ok(values)
    }
}

macro_rules! impl_blob_vec_zerocopy {
    ($type:ty) => {
        impl Blob for Vec<$type>
        where
            $type: FromBytes + IntoBytes + Immutable,
        {
            fn try_to_bytes(&self) -> std::result::Result<Vec<u8>, GridstoreError> {
                Ok(self
                    .iter()
                    .flat_map(|item| item.as_bytes())
                    .copied()
                    .collect())
            }

            fn try_from_bytes(bytes: &[u8]) -> std::result::Result<Self, GridstoreError> {
                let chunk_size = size_of::<$type>();
                if !bytes.len().is_multiple_of(chunk_size) {
                    return Err(GridstoreError::validation_error(format!(
                        "Unexpected number of bytes for Vec<{}>: {}",
                        stringify!($type),
                        bytes.len()
                    )));
                }

                bytes
                    .chunks_exact(chunk_size)
                    .map(|v| {
                        <$type>::read_from_bytes(v).map_err(|err| {
                            GridstoreError::validation_error(format!(
                                "Invalid chunk for Vec<{}>: {err}",
                                stringify!($type)
                            ))
                        })
                    })
                    .collect()
            }
        }
    };
}

impl_blob_vec_zerocopy!(i64);
impl_blob_vec_zerocopy!(u128);
impl_blob_vec_zerocopy!(f64);
