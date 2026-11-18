//! Diagnostic-only instrumentation. Never linked into a shipped service.
//! Spans are inclusive; thread CPU/allocations exclude the separate S3 I/O thread.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Instant;

pub const STAGES: [&str; 15] = [
    "engine",
    "s3_get",
    "s3_put",
    "native_sql",
    "result_encode",
    "native_commit",
    "checkpoint",
    "result_decode",
    "head_fingerprint",
    "head_decode",
    "head_encode",
    "object_encode",
    "object_validate",
    "queue_wait",
    "native_publish",
];
static VALUES: [[AtomicU64; 6]; 15] = [const { [const { AtomicU64::new(0) }; 6] }; 15];
static HTTP: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
thread_local! { static LOCAL: Cell<(u64,u64)> = const { Cell::new((0,0)) }; }

fn allocation(bytes: usize) {
    ALLOCS.fetch_add(1, Relaxed);
    BYTES.fetch_add(bytes as u64, Relaxed);
    let _ = LOCAL.try_with(|v| {
        let (a, b) = v.get();
        v.set((a + 1, b + bytes as u64));
    });
}

struct Counting;
#[global_allocator]
static ALLOCATOR: Counting = Counting;
// Only the diagnostic crate supplies an allocator. All allocation behavior is
// delegated unchanged to System, including errors and alignment contracts.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        allocation(l.size());
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        allocation(l.size());
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        allocation(n);
        unsafe { System.realloc(p, l, n) }
    }
}

fn cpu(clock: libc::clockid_t) -> u64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // Linux diagnostic only. No product FFI or native publication behavior changes.
    let result = unsafe { libc::clock_gettime(clock, &mut value) };
    assert_eq!(result, 0, "diagnostic clock_gettime");
    value.tv_sec as u64 * 1_000_000_000 + value.tv_nsec as u64
}

pub struct Span {
    stage: usize,
    begin: Instant,
    cpu: u64,
    alloc: (u64, u64),
}
impl Span {
    pub fn new(stage: usize) -> Self {
        Self {
            stage,
            begin: Instant::now(),
            cpu: cpu(libc::CLOCK_THREAD_CPUTIME_ID),
            alloc: LOCAL.with(Cell::get),
        }
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        let elapsed = self.begin.elapsed().as_nanos() as u64;
        let cpu = cpu(libc::CLOCK_THREAD_CPUTIME_ID) - self.cpu;
        let (a, b) = LOCAL.with(Cell::get);
        for (cell, value) in
            VALUES[self.stage]
                .iter()
                .zip([1, elapsed, cpu, a - self.alloc.0, b - self.alloc.1, 0])
        {
            cell.fetch_add(value, Relaxed);
        }
    }
}
pub fn bytes(stage: usize, count: usize) {
    VALUES[stage][5].fetch_add(count as u64, Relaxed);
}
pub fn queue_wait(ns: u64) {
    VALUES[13][0].fetch_add(1, Relaxed);
    VALUES[13][1].fetch_add(ns, Relaxed);
}
pub fn snapshot() -> (u64, u64, u64, Vec<[u64; 6]>) {
    (
        cpu(libc::CLOCK_PROCESS_CPUTIME_ID),
        ALLOCS.load(Relaxed),
        BYTES.load(Relaxed),
        VALUES
            .iter()
            .map(|r| std::array::from_fn(|i| r[i].load(Relaxed)))
            .collect(),
    )
}

/// Counter-only subscriber. These event locations are explicitly pinned to
/// hyper-util 0.1.21. No request data, headers or credentials are formatted.
pub fn connections() -> [u64; 3] {
    std::array::from_fn(|i| HTTP[i].load(Relaxed))
}
pub fn install_connections() {
    struct Counter;
    impl tracing::Subscriber for Counter {
        fn enabled(&self, m: &tracing::Metadata<'_>) -> bool {
            matches!(
                (m.target(), m.line()),
                ("hyper_util::client::legacy::connect::http", Some(786 | 789))
                    | ("hyper_util::client::legacy::pool", Some(267))
            )
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, e: &tracing::Event<'_>) {
            let m = e.metadata();
            let index = match (m.target(), m.line()) {
                ("hyper_util::client::legacy::connect::http", Some(786)) => 0,
                ("hyper_util::client::legacy::connect::http", Some(789)) => 1,
                ("hyper_util::client::legacy::pool", Some(267)) => 2,
                _ => return,
            };
            HTTP[index].fetch_add(1, Relaxed);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }
    tracing::subscriber::set_global_default(Counter).expect("diagnostic subscriber");
}
