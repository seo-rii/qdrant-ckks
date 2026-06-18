use std::env;
use std::path::Path;

use collection::operations::OperationWithClockTag;
use collection::operations::loggable::Loggable;
use shard::operations::CollectionUpdateOperations;
use shard::wal::SerdeWal;
use storage::content_manager::consensus::consensus_wal::ConsensusOpWal;
use storage::content_manager::consensus_ops::ConsensusOperations;
use wal::WalOptions;

/// Executable to inspect the content of a write ahead log folder (collection OR consensus WAL).
/// e.g:
/// `cargo run --bin wal_inspector storage/collections/test-collection/0/wal/ collection`
/// `cargo run --bin wal_inspector -- storage/node4/wal/ consensus` (expects `collections_meta_wal` folder as first child)
fn main() {
    let args: Vec<String> = env::args().collect();
    let raw = args.iter().any(|arg| arg == "--raw");
    let positional = args
        .iter()
        .skip(1)
        .filter(|arg| arg.as_str() != "--raw")
        .collect::<Vec<_>>();
    if positional.len() != 2 {
        eprintln!("Usage: wal_inspector [--raw] <wal_path> <collection|consensus>");
        return;
    }
    let wal_path = Path::new(positional[0]);
    let wal_type = positional[1].as_str();
    match wal_type {
        "collection" => print_collection_wal(wal_path, raw),
        "consensus" => print_consensus_wal(wal_path, raw),
        _ => eprintln!("Unknown wal type: {wal_type}"),
    }
}

fn print_consensus_wal(wal_path: &Path, raw: bool) {
    // must live within a folder named `collections_meta_wal`
    let wal = match ConsensusOpWal::new(wal_path) {
        Ok(wal) => wal,
        Err(err) => {
            eprintln!("Unable to open consensus WAL in directory {wal_path:?}: {err}.");
            return;
        }
    };
    println!("==========================");
    let first_index = match wal.first_entry() {
        Ok(first_index) => first_index,
        Err(err) => {
            eprintln!("Unable to read first consensus WAL entry: {err}");
            return;
        }
    };
    println!("First entry: {first_index:?}");
    let last_index = match wal.last_entry() {
        Ok(last_index) => last_index,
        Err(err) => {
            eprintln!("Unable to read last consensus WAL entry: {err}");
            return;
        }
    };
    println!("Last entry: {last_index:?}");
    let index_offset = match wal.index_offset() {
        Ok(index_offset) => index_offset,
        Err(err) => {
            eprintln!("Unable to read consensus WAL index offset: {err:?}");
            return;
        }
    };
    println!(
        "Offset of first entry: {:?}",
        index_offset.wal_to_raft_offset
    );
    let entries = match wal.entries(
        first_index.map(|f| f.index).unwrap_or(1),
        last_index.map(|f| f.index).unwrap_or(0) + 1,
        None,
    ) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!("Unable to read consensus WAL entries: {err:?}");
            return;
        }
    };
    for entry in entries {
        println!("==========================");
        let data = consensus_entry_data_for_display(&entry, raw);
        println!(
            "Entry ID:{}\nterm:{}\nentry_type:{}\ndata:{:?}",
            entry.index, entry.term, entry.entry_type, data
        )
    }
}

fn print_collection_wal(wal_path: &Path, raw: bool) {
    let wal: Result<SerdeWal<OperationWithClockTag>, _> =
        SerdeWal::new(wal_path, WalOptions::default());

    match wal {
        Err(error) => {
            eprintln!("Unable to open write ahead log in directory {wal_path:?}: {error}.");
        }
        Ok(wal) => {
            // print all entries
            let mut count = 0;
            for entry in wal.read_all(true) {
                match entry {
                    Ok((idx, op)) => {
                        println!("==========================");
                        println!(
                            "Entry: {idx} Operation: {} Clock: {:?}",
                            collection_operation_for_display(&op.operation, raw),
                            op.clock_tag
                        );
                        count += 1;
                    }
                    Err(e) => {
                        eprintln!("Failed to read WAL entry: {e}");
                    }
                }
            }
            println!("==========================");
            println!("End of WAL.");
            println!("Found {count} entries.");
        }
    }
}

fn consensus_entry_data_for_display(entry: &raft::eraftpb::Entry, raw: bool) -> String {
    match ConsensusOperations::try_from(entry) {
        Ok(command) if raw => format!("{command:?}"),
        Ok(command) => format!("{:?}", command.redacted_log()),
        Err(_) if raw => format!("{:?}", entry.data),
        Err(_) => format!(
            "UnparsedRaftEntry {{ data_bytes: {}, context_bytes: {} }}",
            entry.data.len(),
            entry.context.len(),
        ),
    }
}

fn collection_operation_for_display(operation: &CollectionUpdateOperations, raw: bool) -> String {
    if raw {
        format!("{operation:?}")
    } else {
        operation.to_log_value().to_string()
    }
}

#[cfg(test)]
mod tests {
    use qdrant_sec::{
        CLIENT_ENCRYPTED_PAYLOAD_MARKER, ENCRYPTED_CKKS_VECTOR_MARKER, ENCRYPTED_PAYLOAD_MARKER,
        ENCRYPTED_VECTOR_SIDECAR_FIELD,
    };
    use raft::eraftpb::Entry;
    use segment::types::{Payload, PointIdType};
    use serde_json::json;
    use shard::operations::payload_ops::{PayloadOps, SetPayloadOp};

    use super::*;

    #[test]
    fn consensus_entry_display_redacts_unparsed_data_by_default() {
        let entry = Entry {
            term: 11,
            index: 13,
            data: b"qdrant-sec-unparsed-consensus-data-sentinel".to_vec(),
            context: b"qdrant-sec-unparsed-consensus-context-sentinel".to_vec(),
            ..Default::default()
        };

        let default_display = consensus_entry_data_for_display(&entry, false);
        assert!(!default_display.contains("qdrant-sec-unparsed-consensus-data-sentinel"));
        assert!(!default_display.contains("qdrant-sec-unparsed-consensus-context-sentinel"));
        assert!(default_display.contains("data_bytes"));
        assert!(default_display.contains("context_bytes"));

        let raw_display = consensus_entry_data_for_display(&entry, true);
        assert_eq!(raw_display, format!("{:?}", entry.data));
        assert!(!raw_display.contains("data_bytes"));
    }

    #[test]
    fn collection_wal_display_redacts_payloads_by_default() {
        let operation =
            CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
                payload: Payload(
                    json!({
                        "body": {
                            CLIENT_ENCRYPTED_PAYLOAD_MARKER: {
                                "nonce": "client-nonce",
                                "ciphertext": "client-ciphertext"
                            }
                        }
                    })
                    .as_object()
                    .unwrap()
                    .clone(),
                ),
                points: Some(vec![PointIdType::NumId(1)]),
                filter: None,
                key: None,
            }));

        let redacted = collection_operation_for_display(&operation, false);
        let raw = collection_operation_for_display(&operation, true);

        assert!(redacted.contains("[redacted]"));
        assert!(!redacted.contains("client-nonce"));
        assert!(!redacted.contains("client-ciphertext"));
        assert!(raw.contains("client-nonce"));
        assert!(raw.contains("client-ciphertext"));
    }

    #[test]
    fn collection_wal_display_redacts_server_and_vector_envelopes_by_default() {
        let operation =
            CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
                payload: Payload(
                    json!({
                        "body": {
                            ENCRYPTED_PAYLOAD_MARKER: {
                                "envelope": {
                                    "nonce": "server-nonce-sentinel",
                                    "ciphertext": "server-ciphertext-sentinel"
                                }
                            }
                        },
                        ENCRYPTED_VECTOR_SIDECAR_FIELD: {
                            "embedding": {
                                ENCRYPTED_CKKS_VECTOR_MARKER: {
                                    "metadata": {
                                        "envelope": {
                                            "nonce": "vector-metadata-nonce-sentinel",
                                            "ciphertext": "vector-metadata-ciphertext-sentinel"
                                        }
                                    },
                                    "ciphertext": "ckks-vector-ciphertext-sentinel"
                                }
                            }
                        }
                    })
                    .as_object()
                    .unwrap()
                    .clone(),
                ),
                points: Some(vec![PointIdType::NumId(7)]),
                filter: None,
                key: None,
            }));

        let redacted = collection_operation_for_display(&operation, false);
        let raw = collection_operation_for_display(&operation, true);

        for sentinel in [
            "server-nonce-sentinel",
            "server-ciphertext-sentinel",
            "vector-metadata-nonce-sentinel",
            "vector-metadata-ciphertext-sentinel",
            "ckks-vector-ciphertext-sentinel",
        ] {
            assert!(
                !redacted.contains(sentinel),
                "default WAL display leaked {sentinel}",
            );
            assert!(raw.contains(sentinel), "raw WAL display lost {sentinel}");
        }
        assert!(redacted.contains("[redacted]"));
    }
}
