// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! JWKS key cache with TTL-based refresh, miss-eviction, and optional file persistence.
//!
//! When verification options include a [`JwksCache`], online JWKS responses are
//! cached in-memory (and optionally on disk) so subsequent verifications are fast.
//!
//! ## Refresh strategy
//!
//! - **TTL-based**: Entries older than `refresh_interval` are refreshed on next access.
//! - **Miss-eviction**: If `miss_threshold` consecutive key lookups miss against a
//!   cached entry, the entry is evicted and re-fetched. This handles service key
//!   rotations where the old cache is 100% stale.
//! - **Manual clear**: [`JwksCache::clear`] drops all entries and the backing file.
//!
//! ## File persistence
//!
//! When `cache_file_path` is set, the cache is loaded from disk on construction
//! and flushed after each update. This makes the cache durable across process
//! restarts.

use code_transparency_client::JwksDocument;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Default TTL for cached JWKS entries (1 hour).
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(3600);

/// Default number of consecutive misses before evicting a cache entry.
pub const DEFAULT_MISS_THRESHOLD: u32 = 5;

/// Default sliding window size for the global verification tracker.
pub const DEFAULT_VERIFICATION_WINDOW: usize = 20;

/// Maximum number of entries allowed in the cache.
///
/// When inserting a new entry would exceed this limit, the oldest entry
/// (by `fetched_at`) is evicted first. This prevents unbounded memory
/// growth from an attacker registering many distinct issuer URLs.
pub const MAX_CACHE_ENTRIES: usize = 1000;

/// A cached JWKS entry with metadata.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The cached JWKS document, wrapped in Arc for zero-copy sharing.
    jwks: Arc<JwksDocument>,
    /// When this entry was last fetched/refreshed.
    fetched_at: Instant,
    /// Count of consecutive key-lookup misses against this entry.
    consecutive_misses: u32,
}

/// Thread-safe JWKS cache with TTL refresh, miss-eviction, and
/// global cache-poisoning detection.
///
/// ## Cache-poisoning protection
///
/// The cache tracks a sliding window of recent verification outcomes
/// (hit = verification succeeded using cached keys, miss = failed).
/// If the window is full and **every** entry is a miss (`100% failure rate`),
/// [`check_poisoned`](Self::check_poisoned) returns `true` and
/// [`force_refresh`](Self::force_refresh) should be called to evict all
/// entries, forcing fresh fetches from the service.
///
/// Pass an `Arc<JwksCache>` on [`CodeTransparencyVerificationOptions`] to
/// enable transparent caching of online JWKS responses during verification.
#[derive(Debug)]
pub struct JwksCache {
    inner: RwLock<CacheInner>,
    /// How long before a cached entry is considered stale and re-fetched.
    pub refresh_interval: Duration,
    /// How many consecutive key misses trigger eviction of an entry.
    pub miss_threshold: u32,
    /// Optional file path for durable persistence.
    cache_file_path: Option<PathBuf>,
    /// Sliding window of global verification outcomes (true=hit, false=miss).
    verification_window: RwLock<VerificationWindow>,
}

/// Tracks a sliding window of verification outcomes for poisoning detection.
#[derive(Debug)]
struct VerificationWindow {
    outcomes: Vec<bool>,
    capacity: usize,
    pos: usize,
    count: usize,
}

impl VerificationWindow {
    fn new(capacity: usize) -> Self {
        Self {
            outcomes: vec![false; capacity],
            capacity,
            pos: 0,
            count: 0,
        }
    }

    fn record(&mut self, hit: bool) {
        self.outcomes[self.pos] = hit;
        self.pos = (self.pos + 1) % self.capacity;
        if self.count < self.capacity {
            self.count += 1;
        }
    }

    /// Returns `true` if the window is full and every outcome is a miss.
    fn is_all_miss(&self) -> bool {
        self.count >= self.capacity && self.outcomes.iter().all(|&v| !v)
    }

    fn reset(&mut self) {
        self.pos = 0;
        self.count = 0;
        self.outcomes.fill(false);
    }
}

#[derive(Debug)]
struct CacheInner {
    entries: HashMap<String, CacheEntry>,
}

impl JwksCache {
    /// Creates a new in-memory cache with default settings.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(CacheInner {
                entries: HashMap::new(),
            }),
            refresh_interval: DEFAULT_REFRESH_INTERVAL,
            miss_threshold: DEFAULT_MISS_THRESHOLD,
            cache_file_path: None,
            verification_window: RwLock::new(VerificationWindow::new(DEFAULT_VERIFICATION_WINDOW)),
        }
    }

    /// Creates a cache with custom TTL and miss threshold.
    pub fn with_settings(refresh_interval: Duration, miss_threshold: u32) -> Self {
        Self {
            inner: RwLock::new(CacheInner {
                entries: HashMap::new(),
            }),
            refresh_interval,
            miss_threshold,
            cache_file_path: None,
            verification_window: RwLock::new(VerificationWindow::new(DEFAULT_VERIFICATION_WINDOW)),
        }
    }

    /// Creates a file-backed cache that persists across process restarts.
    ///
    /// If the file exists, entries are loaded from it on construction.
    pub fn with_file(
        path: impl Into<PathBuf>,
        refresh_interval: Duration,
        miss_threshold: u32,
    ) -> Self {
        let path = path.into();
        let entries = Self::load_from_file(&path).unwrap_or_default();

        // Loaded entries get `fetched_at = now` since we don't persist timestamps
        let now = Instant::now();
        let cache_entries: HashMap<String, CacheEntry> = entries
            .into_iter()
            .map(|(issuer, jwks)| {
                (
                    issuer,
                    CacheEntry {
                        jwks: Arc::new(jwks),
                        fetched_at: now,
                        consecutive_misses: 0,
                    },
                )
            })
            .collect();

        Self {
            inner: RwLock::new(CacheInner {
                entries: cache_entries,
            }),
            refresh_interval,
            miss_threshold,
            cache_file_path: Some(path),
            verification_window: RwLock::new(VerificationWindow::new(DEFAULT_VERIFICATION_WINDOW)),
        }
    }

    /// Look up a cached JWKS for an issuer. Returns `None` if not cached or stale.
    ///
    /// Returns an `Arc<JwksDocument>` — callers get a refcount bump instead of
    /// a deep clone (5-50 KB saved per lookup).
    ///
    /// A stale entry (older than `refresh_interval`) returns `None` so the
    /// caller fetches fresh data and calls [`insert`](Self::insert).
    pub fn get(&self, issuer: &str) -> Option<Arc<JwksDocument>> {
        let inner = self.inner.read().ok()?;
        let entry = inner.entries.get(issuer)?;

        if entry.fetched_at.elapsed() > self.refresh_interval {
            return None; // stale — caller should refresh
        }

        Some(entry.jwks.clone())
    }

    /// Record a key-lookup miss against a cached entry.
    ///
    /// If the miss count reaches `miss_threshold`, the entry is evicted
    /// and the method returns `true` (signaling the caller to re-fetch).
    pub fn record_miss(&self, issuer: &str) -> bool {
        let mut inner = match self.inner.write() {
            Ok(w) => w,
            Err(_) => return false,
        };

        if let Some(entry) = inner.entries.get_mut(issuer) {
            entry.consecutive_misses += 1;
            if entry.consecutive_misses >= self.miss_threshold {
                inner.entries.remove(issuer);
                self.flush_inner(&inner);
                return true; // evicted — caller should re-fetch
            }
        }
        false
    }

    /// Insert or update a cached JWKS for an issuer.
    ///
    /// Resets the miss counter and refreshes the timestamp.
    /// Evicts expired entries first, then enforces [`MAX_CACHE_ENTRIES`].
    /// If still at capacity after evicting expired entries, the oldest
    /// entry (by `fetched_at`) is removed.
    pub fn insert(&self, issuer: &str, jwks: JwksDocument) {
        let mut inner = match self.inner.write() {
            Ok(w) => w,
            Err(_) => return,
        };

        // Evict expired entries
        let ttl = self.refresh_interval;
        inner
            .entries
            .retain(|_, v| v.fetched_at.elapsed() <= ttl);

        // Enforce size limit (skip if updating an existing key)
        if !inner.entries.contains_key(issuer)
            && inner.entries.len() >= MAX_CACHE_ENTRIES
        {
            if let Some(oldest_key) = inner
                .entries
                .iter()
                .min_by_key(|(_, v)| v.fetched_at)
                .map(|(k, _)| k.clone())
            {
                inner.entries.remove(&oldest_key);
            }
        }

        inner.entries.insert(
            issuer.to_string(),
            CacheEntry {
                jwks: Arc::new(jwks),
                fetched_at: Instant::now(),
                consecutive_misses: 0,
            },
        );

        self.flush_inner(&inner);
    }

    /// Clear all cached entries and delete the backing file.
    pub fn clear(&self) {
        if let Ok(mut inner) = self.inner.write() {
            inner.entries.clear();
        }
        if let Some(ref path) = self.cache_file_path {
            let _ = std::fs::remove_file(path);
        }
        if let Ok(mut w) = self.verification_window.write() {
            w.reset();
        }
    }

    // ========================================================================
    // Global verification outcome tracking (cache-poisoning detection)
    // ========================================================================

    /// Record that a verification using cached keys succeeded.
    pub fn record_verification_hit(&self) {
        if let Ok(mut w) = self.verification_window.write() {
            w.record(true);
        }
    }

    /// Record that a verification using cached keys failed.
    pub fn record_verification_miss(&self) {
        if let Ok(mut w) = self.verification_window.write() {
            w.record(false);
        }
    }

    /// Returns `true` if the last N verifications all failed, indicating
    /// the cache may be poisoned and should be force-refreshed.
    ///
    /// The window size is `DEFAULT_VERIFICATION_WINDOW` (20). All 20 slots
    /// must be filled with misses before this returns `true`.
    pub fn check_poisoned(&self) -> bool {
        self.verification_window
            .read()
            .map(|w| w.is_all_miss())
            .unwrap_or(false)
    }

    /// Evict all cached entries (force re-fetch) and reset the verification
    /// window. Call this when [`check_poisoned`](Self::check_poisoned) returns
    /// `true`.
    ///
    /// Unlike [`clear`](Self::clear), this does NOT delete the backing file —
    /// it only invalidates the in-memory state so the next access triggers
    /// a network fetch.
    pub fn force_refresh(&self) {
        if let Ok(mut inner) = self.inner.write() {
            inner.entries.clear();
        }
        if let Ok(mut w) = self.verification_window.write() {
            w.reset();
        }
    }

    /// Returns the number of cached issuers.
    pub fn len(&self) -> usize {
        self.inner.read().map(|i| i.entries.len()).unwrap_or(0)
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns all cached issuer hosts.
    pub fn issuers(&self) -> Vec<String> {
        self.inner
            .read()
            .map(|i| i.entries.keys().cloned().collect())
            .unwrap_or_default()
    }

    // ========================================================================
    // File persistence
    // ========================================================================

    fn flush_inner(&self, inner: &CacheInner) {
        if let Some(ref path) = self.cache_file_path {
            let serializable: HashMap<&str, &JwksDocument> = inner
                .entries
                .iter()
                .map(|(k, v)| (k.as_str(), v.jwks.as_ref()))
                .collect();
            if let Ok(json) = serde_json::to_string_pretty(&serializable) {
                let _ = std::fs::write(path, json);
            }
        }
    }

    fn load_from_file(path: &std::path::Path) -> Option<HashMap<String, JwksDocument>> {
        let data = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&data).ok()
    }
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new()
    }
}
