use std::env;
use std::path::Path;

use wal::Wal;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: wal_pop <wal_path>");
        return;
    }
    let wal_path = Path::new(&args[1]);

    let mut wal = match Wal::open(wal_path) {
        Ok(wal) => wal,
        Err(err) => {
            eprintln!("Can't open consensus WAL: {err}");
            return;
        }
    };

    let last_index = wal.last_index();

    eprintln!("last_index = {last_index}");

    if let Err(err) = wal.truncate(last_index) {
        eprintln!("Failed to truncate WAL: {err}");
        return;
    }
    if let Err(err) = wal.flush_open_segment() {
        eprintln!("Failed to flush WAL: {err}");
    }
}
