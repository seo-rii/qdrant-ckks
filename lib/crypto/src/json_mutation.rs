//! Test-only JSON leaf mutation shared by the signature-coverage fuzzers.
//!
//! A signed protocol message is serialized to JSON, one scalar leaf is replaced by a different
//! value and the result is handed back to the message's validator. A validator that still accepts
//! the message shows that the field is covered neither by the signature nor by a derived digest,
//! so whoever relays the message could swap it.

use serde_json::Value;

/// Number of scalar leaves (strings, numbers, booleans) in `value`, in document order.
pub fn json_leaf_count(value: &Value) -> usize {
    match value {
        Value::Null => 0,
        Value::Bool(_) | Value::Number(_) | Value::String(_) => 1,
        Value::Array(items) => items.iter().map(json_leaf_count).sum(),
        Value::Object(fields) => fields.values().map(json_leaf_count).sum(),
    }
}

/// Replaces one scalar leaf of `value` (the `index`-th in document order, taken modulo the leaf
/// count) with a different value and returns the JSON pointer of that leaf. `salt` selects the
/// corruption so repeated cases hit several corruptions per field. Panics when `value` has no
/// scalar leaf.
pub fn mutate_json_leaf(value: &mut Value, index: usize, salt: u8) -> String {
    let leaves = json_leaf_count(value);
    assert!(leaves > 0, "document has no scalar leaf");
    let mut remaining = index % leaves;
    let mut path = String::new();
    assert!(
        mutate_leaf(value, &mut remaining, salt, &mut path),
        "leaf index {index} is out of range"
    );
    path
}

fn mutate_leaf(value: &mut Value, remaining: &mut usize, salt: u8, path: &mut String) -> bool {
    match value {
        Value::Null => false,
        Value::Array(items) => {
            for (offset, item) in items.iter_mut().enumerate() {
                let len = path.len();
                path.push_str(&format!("/{offset}"));
                if mutate_leaf(item, remaining, salt, path) {
                    return true;
                }
                path.truncate(len);
            }
            false
        }
        Value::Object(fields) => {
            for (key, item) in fields.iter_mut() {
                let len = path.len();
                path.push('/');
                path.push_str(key);
                if mutate_leaf(item, remaining, salt, path) {
                    return true;
                }
                path.truncate(len);
            }
            false
        }
        scalar => {
            if *remaining > 0 {
                *remaining -= 1;
                return false;
            }
            *scalar = mutated_scalar(scalar, salt);
            true
        }
    }
}

fn mutated_scalar(value: &Value, salt: u8) -> Value {
    match value {
        Value::Bool(flag) => Value::Bool(!flag),
        Value::Number(number) => {
            if let Some(unsigned) = number.as_u64() {
                Value::from(unsigned ^ (1u64 << (salt % 64)))
            } else if let Some(signed) = number.as_i64() {
                Value::from(signed ^ 1)
            } else {
                Value::from(number.as_f64().unwrap_or_default() + 1.0)
            }
        }
        Value::String(text) => Value::String(mutated_string(text, salt)),
        Value::Null | Value::Array(_) | Value::Object(_) => unreachable!("scalar expected"),
    }
}

fn mutated_string(text: &str, salt: u8) -> String {
    // Decimal strings (`decimal_u64` fields) stay decimal, so the value changes rather than the
    // encoding and the message reaches the signature check.
    if !text.is_empty()
        && text.len() <= 20
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && let Ok(number) = text.parse::<u64>()
    {
        return (number ^ (1u64 << (salt % 64))).to_string();
    }
    let mut chars: Vec<char> = text.chars().collect();
    match salt % 4 {
        0 | 1 if !chars.is_empty() => {
            // Same length, one character changed: fixed-width digests stay well-formed.
            let position = usize::from(salt / 4) % chars.len();
            chars[position] = if chars[position] == 'A' { 'B' } else { 'A' };
        }
        2 => chars.push('A'),
        _ => {
            chars.pop();
        }
    }
    let mutated: String = chars.into_iter().collect();
    if mutated == text {
        format!("{text}A")
    } else {
        mutated
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn every_leaf_is_reachable_and_every_mutation_changes_the_document() {
        let document = json!({
            "version": 1,
            "ids": ["11", "12"],
            "nested": {"flag": true, "digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "empty": ""},
            "none": null
        });
        assert_eq!(json_leaf_count(&document), 6);
        for index in 0..6 {
            for salt in [0u8, 1, 2, 3, 7, 200, 255] {
                let mut mutated = document.clone();
                let path = mutate_json_leaf(&mut mutated, index, salt);
                assert_ne!(mutated, document, "{path} with salt {salt}");
                assert!(mutated.pointer(&path).is_some(), "{path}");
            }
        }
        let mut decimal = json!("11");
        mutate_json_leaf(&mut decimal, 0, 0);
        assert_eq!(decimal, json!("10"));
    }
}
