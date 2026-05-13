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
        "consensus" => print_consensus_wal(wal_path),
        _ => eprintln!("Unknown wal type: {wal_type}"),
    }
}

fn print_consensus_wal(wal_path: &Path) {
    // must live within a folder named `collections_meta_wal`
    let wal = ConsensusOpWal::new(wal_path);
    println!("==========================");
    let first_index = wal.first_entry().unwrap();
    println!("First entry: {first_index:?}");
    let last_index = wal.last_entry().unwrap();
    println!("Last entry: {last_index:?}");
    println!(
        "Offset of first entry: {:?}",
        wal.index_offset().unwrap().wal_to_raft_offset
    );
    let entries = wal
        .entries(
            first_index.map(|f| f.index).unwrap_or(1),
            last_index.map(|f| f.index).unwrap_or(0) + 1,
            None,
        )
        .unwrap();
    for entry in entries {
        println!("==========================");
        let command = ConsensusOperations::try_from(&entry);
        let data = match command {
            Ok(command) => format!("{command:?}"),
            Err(_) => format!("{:?}", entry.data),
        };
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

fn collection_operation_for_display(operation: &CollectionUpdateOperations, raw: bool) -> String {
    if raw {
        format!("{operation:?}")
    } else {
        operation.to_log_value().to_string()
    }
}

#[cfg(test)]
mod tests {
    use segment::types::{Payload, PointIdType};
    use serde_json::json;
    use shard::operations::payload_ops::{PayloadOps, SetPayloadOp};

    use super::*;

    #[test]
    fn collection_wal_display_redacts_payloads_by_default() {
        let operation =
            CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
                payload: Payload(
                    json!({
                        "body": {
                            "$qdrant_client_aead": {
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
}
