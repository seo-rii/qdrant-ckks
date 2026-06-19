use crate::common::operation_error::{OperationError, OperationResult};

const FLOAT_NAN: u8 = 0x00;
const FLOAT_NEG: u8 = 0x01;
const FLOAT_ZERO: u8 = 0x02;
const FLOAT_POS: u8 = 0x03;

const F64_KEY_LEN: usize = 13;
const I64_KEY_LEN: usize = 12;
const U128_KEY_LEN: usize = 20;

/// Encode a f64 into `buf`
///
/// The encoded format for a f64 is :
///
/// **for positives:** the f64 bits ( in IEEE 754 format ) are re-interpreted as an int64 and
/// encoded using big-endian order.
///
/// **for negative** f64 : invert all the bits and encode it using bit-endian order.
///
/// A single-byte prefix tag is appended to the front of the encoding slice to ensures that
/// NaNs are always sorted first.
///
/// This approach was inspired by <https://github.com/cockroachdb/cockroach/blob/master/pkg/util/encoding/float.go>
///
///
/// #f64 encoding format
///
///```text
/// 0                    1                9
/// ┌───────────────────┬─────────────────┐
/// │     Float Type    │  NEG:  !key_val │
/// │  NAN/NEG/ZERO/POS |  POS:   key_val │
/// │    (big-endian)   │   (big-endian)  │
/// └───────────────────┴─────────────────┘
/// ```
///
pub fn encode_f64_ascending(val: f64, buf: &mut Vec<u8>) {
    if val.is_nan() {
        buf.push(FLOAT_NAN);
        buf.extend([0_u8; std::mem::size_of::<f64>()]);
        return;
    }

    if val == 0f64 {
        buf.push(FLOAT_ZERO);
        buf.extend([0_u8; std::mem::size_of::<f64>()]);
        return;
    }

    let f_as_u64 = val.to_bits();

    if f_as_u64 & (1 << 63) != 0 {
        let f = !f_as_u64;
        buf.push(FLOAT_NEG);
        buf.extend(f.to_be_bytes());
    } else {
        buf.push(FLOAT_POS);
        buf.extend(f_as_u64.to_be_bytes());
    }
}

/// Decode a f64 from a slice.
pub fn decode_f64_ascending(buf: &[u8]) -> OperationResult<f64> {
    let Some((&prefix, rest)) = buf.split_first() else {
        return Err(OperationError::service_error(
            "cannot decode f64 from an empty key",
        ));
    };
    if rest.len() < std::mem::size_of::<f64>() {
        return Err(OperationError::service_error(
            "cannot decode f64 from a truncated key",
        ));
    }
    let bytes = rest[..std::mem::size_of::<f64>()]
        .try_into()
        .map_err(|_| OperationError::service_error("cannot decode f64 key bytes"))?;

    match prefix {
        FLOAT_NAN => Ok(f64::NAN),
        FLOAT_NEG => {
            let u = u64::from_be_bytes(bytes);
            let f = !u;
            Ok(f64::from_bits(f))
        }
        FLOAT_ZERO => Ok(0f64),
        FLOAT_POS => {
            let u = u64::from_be_bytes(bytes);
            Ok(f64::from_bits(u))
        }
        _ => Err(OperationError::service_error(format!(
            "invalid f64 key prefix {prefix}"
        ))),
    }
}

/// Encode a i64 into `buf` so that is sorts ascending.
pub fn encode_i64_ascending(val: i64, buf: &mut Vec<u8>) {
    let i = val ^ i64::MIN;
    buf.extend(i.to_be_bytes());
}

/// Decode a i64 from a slice
pub fn decode_i64_ascending(buf: &[u8]) -> OperationResult<i64> {
    let bytes: [u8; std::mem::size_of::<i64>()] = buf
        .get(..std::mem::size_of::<i64>())
        .ok_or_else(|| OperationError::service_error("cannot decode i64 from a truncated key"))?
        .try_into()
        .map_err(|_| OperationError::service_error("cannot decode i64 key bytes"))?;
    let i = i64::from_be_bytes(bytes);
    Ok(i ^ i64::MIN)
}

/// Encodes a f64 key so that it sort in ascending order.
///
/// The key is compound by the numeric value of the key plus a u32 representing
/// the payload offset within the payload store.
///
/// # float key encoding format
///
///```text
///
/// 0                    1                9             13
/// ┌───────────────────┬─────────────────┬──────────────┐
/// │     Float Type    │  NEG:  !key_val │              │
/// │  NAN/NEG/ZERO/POS |  POS:   key_val │ point_offset │
/// │    (big-endian)   │   (big-endian)  │              │
/// └───────────────────┴─────────────────┴──────────────┘
/// ```
///
pub fn encode_f64_key_ascending(key_val: f64, point_offset: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(F64_KEY_LEN);
    encode_f64_ascending(key_val, &mut buf);
    buf.extend(point_offset.to_be_bytes());
    buf
}

pub fn decode_f64_key_ascending(buf: &[u8]) -> OperationResult<(u32, f64)> {
    if buf.len() != F64_KEY_LEN {
        return Err(OperationError::service_error(format!(
            "incorrect f64 key length {}, expected {F64_KEY_LEN}",
            buf.len()
        )));
    }
    let point_offset = u32::from_be_bytes(
        buf[F64_KEY_LEN - std::mem::size_of::<u32>()..]
            .try_into()
            .map_err(|_| OperationError::service_error("cannot decode f64 point offset"))?,
    );
    Ok((point_offset, decode_f64_ascending(buf)?))
}

/// Encodes a i64 key so that it sort in ascending order.
///
/// The key is compound by the numeric value of the key plus a u32 representing
/// the payload offset within the payload store.
///
/// # int key encoding format
///
///```text
///
/// 0                    8             12
/// ┌────────────────────┬──────────────┐
/// │ key_val ^ i64::MIN │ point_offset │
/// │    (big-endian)    │ (big-endian) │
/// └────────────────────┴──────────────┘
///```
pub fn encode_i64_key_ascending(key_val: i64, point_offset: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(I64_KEY_LEN);
    encode_i64_ascending(key_val, &mut buf);
    buf.extend(point_offset.to_be_bytes());
    buf
}

pub fn decode_i64_key_ascending(buf: &[u8]) -> OperationResult<(u32, i64)> {
    if buf.len() != I64_KEY_LEN {
        return Err(OperationError::service_error(format!(
            "incorrect i64 key length {}, expected {I64_KEY_LEN}",
            buf.len()
        )));
    }
    let point_offset = u32::from_be_bytes(
        buf[I64_KEY_LEN - std::mem::size_of::<u32>()..]
            .try_into()
            .map_err(|_| OperationError::service_error("cannot decode i64 point offset"))?,
    );
    Ok((point_offset, decode_i64_ascending(buf)?))
}

/// Encodes a u128 key so that it sort in ascending order.
///
/// The key is compound by the numeric value of the key plus a u32 representing
/// the payload offset within the payload store.
///
/// # int key encoding format
///
///```text
///
/// 0                     16            20
/// ┌─────────────────────┬──────────────┐
/// │       key_val       │ point_offset │
/// │    (big-endian)     │ (big-endian) │
/// └─────────────────────┴──────────────┘
///```
pub fn encode_u128_key_ascending(key_val: u128, point_offset: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(U128_KEY_LEN);
    buf.extend(key_val.to_be_bytes());
    buf.extend(point_offset.to_be_bytes());
    buf
}

pub fn decode_u128_key_ascending(buf: &[u8]) -> OperationResult<(u32, u128)> {
    if buf.len() != U128_KEY_LEN {
        return Err(OperationError::service_error(format!(
            "incorrect u128 key length {}, expected {U128_KEY_LEN}",
            buf.len()
        )));
    }
    let point_offset = u32::from_be_bytes(
        buf[U128_KEY_LEN - std::mem::size_of::<u32>()..]
            .try_into()
            .map_err(|_| OperationError::service_error("cannot decode u128 point offset"))?,
    );
    let value = u128::from_be_bytes(
        buf[..std::mem::size_of::<u128>()]
            .try_into()
            .map_err(|_| OperationError::service_error("cannot decode u128 key bytes"))?,
    );
    Ok((point_offset, value))
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use crate::index::key_encoding::{
        decode_f64_ascending, decode_f64_key_ascending, decode_i64_ascending,
        decode_i64_key_ascending, decode_u128_key_ascending, encode_f64_ascending,
        encode_i64_ascending,
    };

    #[test]
    fn test_encode_f64() {
        test_f64_encoding_roundtrip(0.42342);
        test_f64_encoding_roundtrip(0f64);
        test_f64_encoding_roundtrip(f64::NAN);
        test_f64_encoding_roundtrip(-0.423423983);
    }

    #[test]
    fn test_encode_i64() {
        test_i64_encoding_roundtrip(i64::MIN);
        test_i64_encoding_roundtrip(i64::MAX);
        test_i64_encoding_roundtrip(0);
        test_i64_encoding_roundtrip(41262);
        test_i64_encoding_roundtrip(-98793);
    }

    #[test]
    fn test_f64_lex_order() {
        let mut nan_buf = Vec::new();
        let mut zero_buf = Vec::new();
        let mut pos_buf = Vec::new();
        let mut neg_buf = Vec::new();

        encode_f64_ascending(f64::NAN, &mut nan_buf);
        encode_f64_ascending(0f64, &mut zero_buf);
        encode_f64_ascending(0.2435224412, &mut pos_buf);
        encode_f64_ascending(-0.82976347, &mut neg_buf);

        assert_eq!(nan_buf.cmp(&neg_buf), Ordering::Less);
        assert_eq!(neg_buf.cmp(&zero_buf), Ordering::Less);
        assert_eq!(zero_buf.cmp(&pos_buf), Ordering::Less);
    }

    #[test]
    fn test_i64_lex_order() {
        let mut zero_buf = Vec::new();
        let mut pos_buf = Vec::new();
        let mut neg_buf = Vec::new();

        encode_i64_ascending(0, &mut zero_buf);
        encode_i64_ascending(123, &mut pos_buf);
        encode_i64_ascending(-4324, &mut neg_buf);

        assert_eq!(neg_buf.cmp(&zero_buf), Ordering::Less);
        assert_eq!(zero_buf.cmp(&pos_buf), Ordering::Less);
    }

    #[test]
    fn test_decode_rejects_malformed_keys() {
        assert!(decode_f64_ascending(&[]).is_err());
        assert!(decode_f64_ascending(&[0x7f, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(decode_i64_ascending(&[0; 7]).is_err());
        assert!(decode_f64_key_ascending(&[0; 12]).is_err());
        assert!(decode_i64_key_ascending(&[0; 11]).is_err());
        assert!(decode_u128_key_ascending(&[0; 19]).is_err());
    }

    fn test_f64_encoding_roundtrip(val: f64) {
        let mut buf = Vec::new();
        encode_f64_ascending(val, &mut buf);
        let dec_val = decode_f64_ascending(buf.as_slice()).unwrap();
        if val.is_nan() {
            assert!(dec_val.is_nan());
            return;
        }
        assert_eq!(val, dec_val);
    }

    fn test_i64_encoding_roundtrip(val: i64) {
        let mut buf = Vec::new();
        encode_i64_ascending(val, &mut buf);
        let res = decode_i64_ascending(buf.as_slice()).unwrap();
        assert_eq!(val, res);
    }
}
