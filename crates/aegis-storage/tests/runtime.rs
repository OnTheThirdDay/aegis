//! Database work never holds up the async runtime: the gateway relays
//! device traffic on the same runtime that serves the console.

use aegis_storage::Store;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_slow_database_call_does_not_stall_other_tasks() {
    let store = Arc::new(Store::open_in_memory().expect("store"));
    // Stands in for tunnel traffic: a task that needs the (only) worker
    // regularly.
    let ticks = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&ticks);
    let ticker = tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_millis(10));
        loop {
            every.tick().await;
            counter.fetch_add(1, Ordering::Relaxed);
        }
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    // A slow write (or a wait for a busy database) on the worker thread.
    let before = ticks.load(Ordering::Relaxed);
    let slow = tokio::spawn({
        let store = Arc::clone(&store);
        async move {
            store
                .tx(|_| {
                    std::thread::sleep(Duration::from_millis(400));
                    Ok(())
                })
                .expect("tx");
        }
    });
    slow.await.expect("slow task");
    let during = ticks.load(Ordering::Relaxed) - before;
    ticker.abort();
    assert!(
        during >= 20,
        "the other task kept running during the database call ({during} ticks in 400 ms)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn works_on_blocking_threads_too() {
    // The management API already runs some calls through spawn_blocking.
    let store = Arc::new(Store::open_in_memory().expect("store"));
    let s = Arc::clone(&store);
    tokio::task::spawn_blocking(move || s.tx(|_| Ok(())).expect("tx"))
        .await
        .expect("blocking task");
    store.read(|_| Ok(())).expect("read on a worker");
}

#[test]
fn works_without_a_runtime() {
    // aegisctl and other synchronous callers.
    let store = Store::open_in_memory().expect("store");
    store.tx(|_| Ok(())).expect("tx");
    store.integrity_check().expect("integrity");
}

#[tokio::test]
async fn works_on_a_single_threaded_runtime() {
    let store = Store::open_in_memory().expect("store");
    store.read(|_| Ok(())).expect("read");
}
