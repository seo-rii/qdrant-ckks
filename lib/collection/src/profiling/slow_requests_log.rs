use std::hash::{Hash, Hasher};
use std::time::Duration;

use ahash::AHashMap;
use chrono::{DateTime, Utc};
use common::fixed_length_priority_queue::FixedLengthPriorityQueue;
use count_min_sketch::CountMinSketch64;
use itertools::Itertools;
use schemars::JsonSchema;
use serde::Serialize;

use crate::operations::loggable::Loggable;

const MAX_SLOW_REQUEST_LOG_BODY_BYTES: usize = 64 * 1024;

#[derive(Serialize, Clone, JsonSchema)]
pub struct LogEntry {
    collection_name: String,
    #[serde(serialize_with = "duration_as_seconds")]
    duration: Duration,
    datetime: DateTime<Utc>,
    request_name: &'static str,
    approx_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_usage_ratio: Option<f32>,
    request_body: serde_json::Value,

    /// Used for fast comparison and lookup
    #[serde(skip)]
    content_hash: u64,
}

impl LogEntry {
    pub fn new(
        collection_name: String,
        duration: Duration,
        datetime: DateTime<Utc>,
        request_name: &'static str,
        request_body: serde_json::Value,
        content_hash: u64, // Pre-computed content hash
        cpu_usage_ratio: Option<f32>,
    ) -> Self {
        LogEntry {
            collection_name,
            duration,
            datetime,
            request_name,
            approx_count: 1,
            cpu_usage_ratio,
            request_body,
            content_hash,
        }
    }

    pub fn upd_counter(&mut self, count: usize) {
        self.approx_count = count;
    }
}

impl PartialEq for LogEntry {
    fn eq(&self, other: &Self) -> bool {
        self.content_hash == other.content_hash
            && self.duration == other.duration
            && self.collection_name == other.collection_name
    }
}

impl Eq for LogEntry {}

fn duration_as_seconds<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_f64(duration.as_millis() as f64 / 1000.0)
}

impl PartialOrd for LogEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LogEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.duration.cmp(&other.duration)
    }
}

pub struct SlowRequestsLog {
    log_priority_queue: AHashMap<&'static str, FixedLengthPriorityQueue<LogEntry>>,
    counters: Option<CountMinSketch64<u64>>,
    max_entries: usize,
}

impl SlowRequestsLog {
    pub fn new(max_entries: usize) -> Self {
        SlowRequestsLog {
            log_priority_queue: Default::default(),
            // 95% probability, 10% tolerance.
            counters: CountMinSketch64::new(1024, 0.95, 0.1).ok(),
            max_entries,
        }
    }

    /// Try insert an entry into the log in the way, that it is not duplicated by content.
    fn try_insert_dedup(&mut self, entry: LogEntry) -> Option<LogEntry> {
        let queue = self
            .log_priority_queue
            .entry(entry.request_name)
            .or_insert_with(|| FixedLengthPriorityQueue::new(self.max_entries));

        let duplicate = queue.iter_unsorted().find(|e| {
            e.content_hash == entry.content_hash // Fast check
        });

        if let Some(duplicate) = duplicate {
            if duplicate.duration >= entry.duration {
                // Existing record took longer, keep it
                None
            } else {
                // New record took longer, replace existing record
                queue.retain(|e| e.content_hash != entry.content_hash);
                queue.push(entry)
            }
        } else {
            // just insert
            queue.push(entry)
        }
    }

    fn inc_counter(&mut self, content_hash: u64) {
        if let Some(counters) = &mut self.counters {
            counters.increment(&content_hash);
        }
    }

    fn content_hash(request_hash: u64, collection_name: &str) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        request_hash.hash(&mut hasher);
        collection_name.hash(&mut hasher);
        hasher.finish()
    }

    /// Try to log a request if the log.
    /// If proposed log is slower than the fastest logged request, it will be kept in the log.
    /// Otherwise, it will be ignored.
    ///
    /// Returns the log entry that was removed from the log, if any.
    pub fn log_request(
        &mut self,
        collection_name: &str,
        duration: Duration,
        datetime: DateTime<Utc>,
        request: &dyn Loggable,
        cpu_usage_ratio: Option<f32>,
    ) -> Option<LogEntry> {
        if self.max_entries == 0 {
            return None;
        }

        let queue = self
            .log_priority_queue
            .entry(request.request_name())
            .or_insert_with(|| FixedLengthPriorityQueue::new(self.max_entries));

        if queue.is_full() {
            // Check if we can insert into the queue before hashing or serializing the request.
            let Some(fastest_logged) = queue.top() else {
                return None;
            };

            if duration <= fastest_logged.duration {
                // Our queue is already slower than this request.
                return None;
            }
        }

        let (mut request_body, request_hash) = request.to_log_value_and_hash();
        match serde_json::to_vec(&request_body) {
            Ok(serialized) if serialized.len() > MAX_SLOW_REQUEST_LOG_BODY_BYTES => {
                let original_type = match &request_body {
                    serde_json::Value::Null => "null",
                    serde_json::Value::Bool(_) => "bool",
                    serde_json::Value::Number(_) => "number",
                    serde_json::Value::String(_) => "string",
                    serde_json::Value::Array(_) => "array",
                    serde_json::Value::Object(_) => "object",
                };
                request_body = serde_json::json!({
                    "truncated": true,
                    "reason": "slow_request_log_body_budget_exceeded",
                    "original_type": original_type,
                    "redacted_projection_bytes": serialized.len(),
                    "budget_bytes": MAX_SLOW_REQUEST_LOG_BODY_BYTES,
                });
            }
            Ok(_) => {}
            Err(err) => {
                request_body = serde_json::json!({
                    "truncated": true,
                    "reason": "slow_request_log_body_serialization_failed",
                    "error": err.to_string(),
                    "budget_bytes": MAX_SLOW_REQUEST_LOG_BODY_BYTES,
                });
            }
        }
        let content_hash = Self::content_hash(request_hash, collection_name);

        self.inc_counter(content_hash);

        let entry = LogEntry::new(
            collection_name.to_string(),
            duration,
            datetime,
            request.request_name(),
            request_body,
            content_hash,
            cpu_usage_ratio,
        );

        self.try_insert_dedup(entry)
    }

    pub fn get_log_entries(&self, limit: usize, method_name_substr: Option<&str>) -> Vec<LogEntry> {
        self.log_priority_queue
            .iter()
            .filter(|(key, _value)| {
                if let Some(substr) = &method_name_substr {
                    key.contains(substr)
                } else {
                    true
                }
            })
            .flat_map(|(_key, queue)| queue.iter_unsorted())
            .sorted_by(|a, b| b.cmp(a))
            .take(limit)
            .cloned()
            .map(|mut entry| {
                let approx_count = self
                    .counters
                    .as_ref()
                    .map(|counters| counters.estimate(&entry.content_hash))
                    .unwrap_or(entry.approx_count as u64);
                entry.upd_counter(approx_count as usize);
                entry
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::time::Duration;

    use serde_json::{Value, json};

    use super::*;

    struct DummyLoggable;
    impl Loggable for DummyLoggable {
        fn to_log_value(&self) -> Value {
            json!({"dummy": true})
        }

        fn request_name(&self) -> &'static str {
            "dummy"
        }

        fn request_hash(&self) -> u64 {
            42
        }
    }

    struct LargeLoggable;
    impl Loggable for LargeLoggable {
        fn to_log_value(&self) -> Value {
            json!({
                "shape": "x".repeat(MAX_SLOW_REQUEST_LOG_BODY_BYTES + 1),
            })
        }

        fn request_name(&self) -> &'static str {
            "large"
        }

        fn request_hash(&self) -> u64 {
            99
        }
    }

    struct CountingLoggable {
        log_value_calls: Cell<usize>,
        request_hash_calls: Cell<usize>,
    }

    impl CountingLoggable {
        fn new() -> Self {
            Self {
                log_value_calls: Cell::new(0),
                request_hash_calls: Cell::new(0),
            }
        }
    }

    impl Loggable for CountingLoggable {
        fn to_log_value(&self) -> Value {
            self.log_value_calls.set(self.log_value_calls.get() + 1);
            json!({"secret": "must-not-be-materialized-for-fast-skip"})
        }

        fn request_name(&self) -> &'static str {
            "counting"
        }

        fn request_hash(&self) -> u64 {
            self.request_hash_calls
                .set(self.request_hash_calls.get() + 1);
            7
        }
    }

    #[test]
    fn test_get_slow_requests_returns_all_logged() {
        let mut log = SlowRequestsLog::new(3);
        let request = DummyLoggable;
        log.log_request("col1", Duration::from_secs(1), Utc::now(), &request, None);
        log.log_request("col2", Duration::from_secs(2), Utc::now(), &request, None);
        log.log_request("col3", Duration::from_secs(3), Utc::now(), &request, None);
        let entries = log.get_log_entries(10, None);
        assert_eq!(entries.len(), 3);

        let evicted = log.log_request("col4", Duration::from_secs(4), Utc::now(), &request, None);
        assert!(evicted.is_some());
        let evicted = evicted.unwrap();
        assert_eq!(evicted.collection_name, "col1");

        let entries = log.get_log_entries(10, None);
        assert_eq!(entries.len(), 3);

        let evicted = log.log_request("col5", Duration::from_secs(1), Utc::now(), &request, None);
        assert!(evicted.is_none());
        let entries = log.get_log_entries(10, None);
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn zero_capacity_slow_request_log_is_noop() {
        let mut log = SlowRequestsLog::new(0);
        let request = DummyLoggable;

        let evicted = log.log_request("col", Duration::from_secs(1), Utc::now(), &request, None);

        assert!(evicted.is_none());
        assert!(log.get_log_entries(10, None).is_empty());
    }

    #[test]
    fn full_queue_fast_request_skips_hash_and_log_projection() {
        let mut log = SlowRequestsLog::new(1);
        let slow = CountingLoggable::new();
        let fast = CountingLoggable::new();

        log.log_request("col", Duration::from_secs(10), Utc::now(), &slow, None);
        assert_eq!(slow.request_hash_calls.get(), 0);
        assert_eq!(slow.log_value_calls.get(), 1);

        let evicted = log.log_request("col", Duration::from_secs(1), Utc::now(), &fast, None);

        assert!(evicted.is_none());
        assert_eq!(
            fast.request_hash_calls.get(),
            0,
            "skipped fast requests must not hash secret-bearing request bodies",
        );
        assert_eq!(
            fast.log_value_calls.get(),
            0,
            "skipped fast requests must not build redacted JSON projections",
        );
    }

    #[test]
    fn oversized_redacted_request_body_is_truncated_before_storage() {
        let mut log = SlowRequestsLog::new(1);
        let request = LargeLoggable;

        log.log_request("col", Duration::from_secs(1), Utc::now(), &request, None);

        let entries = log.get_log_entries(1, None);
        assert_eq!(entries.len(), 1);
        let request_body = &entries[0].request_body;
        assert_eq!(request_body["truncated"], true);
        assert_eq!(
            request_body["reason"],
            "slow_request_log_body_budget_exceeded"
        );
        assert_eq!(request_body["original_type"], "object");
        assert!(
            request_body["redacted_projection_bytes"].as_u64().unwrap()
                > MAX_SLOW_REQUEST_LOG_BODY_BYTES as u64
        );
        assert!(
            serde_json::to_vec(request_body).unwrap().len() < MAX_SLOW_REQUEST_LOG_BODY_BYTES,
            "stored log body should stay below the configured byte budget",
        );
    }
}
