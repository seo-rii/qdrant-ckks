use std::path::Path;
use std::sync::atomic::AtomicBool;

use clap::Parser;
use common::counter::hardware_counter::HardwareCounterCell;
use qdrant_sec::{
    CLIENT_ENCRYPTED_PAYLOAD_MARKER, ENCRYPTED_CKKS_VECTOR_MARKER, ENCRYPTED_PAYLOAD_MARKER,
    ENCRYPTED_VECTOR_SIDECAR_FIELD, GENERIC_CIPHERTEXT_MARKER,
};
use segment::entry::ReadSegmentEntry;
use segment::segment_constructor::load_segment;
use segment::types::{Payload, PointIdType};
use serde_json::Value;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Path to the segment folder. May be a list
    #[clap(short, long, num_args=1..)]
    path: Vec<String>,

    /// Print segment info
    #[clap(long)]
    info: bool,

    /// Point ID to inspect
    #[clap(long)]
    point_id_int: Option<u64>,

    /// Point ID to inspect (UUID)
    #[clap(long)]
    point_id_uuid: Option<String>,

    /// Print encrypted payload/vector markers without redaction.
    #[clap(long)]
    raw_payload: bool,
}

fn main() {
    let args: Args = Args::parse();
    for segment_path in args.path {
        let path = Path::new(&segment_path);
        if !path.exists() {
            eprintln!("Path does not exist: {segment_path}");
            continue;
        }
        if !path.is_dir() {
            eprintln!("Path is not a directory: {segment_path}");
            continue;
        }

        // Open segment

        let segment_uuid = path
            .file_name()
            .and_then(|s| Uuid::try_parse(s.to_str()?).ok())
            .unwrap_or(Uuid::nil());

        let segment = match load_segment(path, segment_uuid, None, &AtomicBool::new(false)) {
            Ok(segment) => segment,
            Err(err) => {
                eprintln!("Failed to load segment {segment_path}: {err}");
                continue;
            }
        };

        eprintln!(
            "path = {:#?}, size-points = {}",
            path,
            segment.available_point_count()
        );

        if args.info {
            let info = segment.info();
            eprintln!("info = {info:#?}");
        }

        if let Some(point_id_int) = args.point_id_int {
            let point_id = PointIdType::NumId(point_id_int);

            let internal_id = segment.get_internal_id(point_id);
            if internal_id.is_some() {
                let version = segment.point_version(point_id);
                let payload = match segment.payload(point_id, &HardwareCounterCell::disposable()) {
                    Ok(payload) => payload,
                    Err(err) => {
                        eprintln!("Failed to read payload for point {point_id}: {err}");
                        continue;
                    }
                };
                // let vectors = segment.all_vectors(point_id).unwrap();

                println!("Internal ID: {internal_id:?}");
                println!("Version: {version:?}");
                if args.raw_payload {
                    println!("Payload: {payload:?}");
                } else {
                    println!("Payload: {:?}", payload_redacted_for_display(payload));
                }
                // println!("Vectors: {vectors:?}");
            }
        }
    }
}

fn payload_redacted_for_display(payload: Payload) -> Payload {
    let mut value = Value::Object(payload.0);
    redact_encrypted_payload_markers(&mut value);
    match value {
        Value::Object(map) => Payload(map),
        _ => Payload(Default::default()),
    }
}

fn redact_encrypted_payload_markers(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if map.contains_key(ENCRYPTED_PAYLOAD_MARKER)
                || map.contains_key(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
                || map.contains_key(ENCRYPTED_CKKS_VECTOR_MARKER)
                || map.contains_key(GENERIC_CIPHERTEXT_MARKER)
            {
                *value =
                    Value::String("[encrypted marker redacted; use --raw-payload]".to_string());
                return;
            }

            for (key, value) in map.iter_mut() {
                if key == ENCRYPTED_VECTOR_SIDECAR_FIELD {
                    *value = Value::String(
                        "[encrypted vector sidecar redacted; use --raw-payload]".to_string(),
                    );
                } else {
                    redact_encrypted_payload_markers(value);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                redact_encrypted_payload_markers(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn payload_redaction_hides_server_client_and_vector_markers() {
        let payload = Payload(
            json!({
                "server": {
                    "$qdrant_sec": {
                        "nonce": "server-nonce",
                        "ciphertext": "server-ciphertext"
                    }
                },
                "client": {
                    "$qdrant_client_aead": {
                        "nonce": "client-nonce",
                        "ciphertext": "client-ciphertext"
                    }
                },
                "metadata": {
                    "$qdrant_ciphertext": {
                        "nonce": "metadata-nonce",
                        "ciphertext": "metadata-ciphertext"
                    }
                },
                "$qdrant_sec_vectors": {
                    "embedding": {
                        "$qdrant_sec_ckks_vector": {
                            "nonce": "vector-nonce",
                            "ciphertext": "vector-ciphertext"
                        }
                    }
                },
                "public": "visible"
            })
            .as_object()
            .unwrap()
            .clone(),
        );

        let redacted = format!("{:?}", payload_redacted_for_display(payload));

        assert!(redacted.contains("visible"));
        assert!(redacted.contains("encrypted marker redacted"));
        assert!(redacted.contains("encrypted vector sidecar redacted"));
        assert!(!redacted.contains("server-nonce"));
        assert!(!redacted.contains("server-ciphertext"));
        assert!(!redacted.contains("client-nonce"));
        assert!(!redacted.contains("client-ciphertext"));
        assert!(!redacted.contains("metadata-nonce"));
        assert!(!redacted.contains("metadata-ciphertext"));
        assert!(!redacted.contains("vector-nonce"));
        assert!(!redacted.contains("vector-ciphertext"));
    }
}
