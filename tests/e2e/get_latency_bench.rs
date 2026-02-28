//! Benchmark: measure per-GET latency on a 25-node testnet.
//!
//! Stores one chunk via `QuantumClient`, then retrieves it many times,
//! printing timing for each GET to identify outliers.
//!
//! Run with:
//! ```sh
//! cargo test --test e2e get_latency_bench -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use bytes::Bytes;
use saorsa_core::P2PNode;
use saorsa_node::client::{QuantumClient, QuantumConfig};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::{TestHarness, TestNetworkConfig};

/// Number of sequential GETs to run after PUT.
const GET_ITERATIONS: usize = 50;

/// Client timeout (seconds).
const CLIENT_TIMEOUT_SECS: u64 = 30;

/// Number of closest peers to query (matches QuantumClient::CLOSE_GROUP_SIZE).
const CLOSE_GROUP_SIZE: usize = 8;

/// Benchmark chunk GET latency on a 25-node testnet.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Benchmark - run with --ignored --nocapture"]
async fn get_latency_bench() {
    let harness = TestHarness::setup_with_config(TestNetworkConfig::default())
        .await
        .expect("Failed to setup 25-node testnet");

    let node = harness.node(5).expect("Node 5 should exist");
    let config = QuantumConfig {
        timeout_secs: CLIENT_TIMEOUT_SECS,
        replica_count: 1,
        encrypt_data: false,
    };
    let client = QuantumClient::new(config).with_node(Arc::clone(&node));

    // --- PUT ---
    let content = Bytes::from(vec![0xABu8; 1024]);
    let put_start = Instant::now();
    let address = client
        .put_chunk(content.clone())
        .await
        .expect("put_chunk failed");
    let put_elapsed = put_start.elapsed();

    println!("\n===== GET LATENCY BENCHMARK (25 nodes, 1 KB chunk) =====");
    println!("PUT took {put_elapsed:?}");
    println!("Chunk address: {}", hex::encode(address));
    println!("Running {GET_ITERATIONS} sequential GETs…\n");
    println!("{:>4}  {:>12}", "#", "latency");
    println!("{}", "-".repeat(20));

    let mut latencies = Vec::with_capacity(GET_ITERATIONS);

    for i in 0..GET_ITERATIONS {
        let start = Instant::now();
        let result = client.get_chunk(&address).await.expect("get_chunk failed");
        let elapsed = start.elapsed();

        assert!(result.is_some(), "Chunk should be found (iteration {i})");
        let chunk = result.unwrap();
        assert_eq!(chunk.content.as_ref(), &[0xABu8; 1024]);

        println!("{:>4}  {:>12?}", i, elapsed);
        latencies.push(elapsed);
    }

    print_stats(&latencies);

    drop(client);
    drop(node);
    harness
        .teardown()
        .await
        .expect("Failed to teardown harness");
}

/// Breakdown: compare local DHT lookup (no network) vs full network lookup
/// vs full GET to identify where the linear growth comes from.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Benchmark - run with --ignored --nocapture"]
async fn get_latency_breakdown() {
    let harness = TestHarness::setup_with_config(TestNetworkConfig::default())
        .await
        .expect("Failed to setup 25-node testnet");

    let node = harness.node(5).expect("Node 5 should exist");
    let config = QuantumConfig {
        timeout_secs: CLIENT_TIMEOUT_SECS,
        replica_count: 1,
        encrypt_data: false,
    };
    let client = QuantumClient::new(config).with_node(Arc::clone(&node));

    // --- PUT ---
    let content = Bytes::from(vec![0xABu8; 1024]);
    let address = client
        .put_chunk(content.clone())
        .await
        .expect("put_chunk failed");

    println!("\n===== GET LATENCY BREAKDOWN (25 nodes, 1 KB chunk) =====");
    println!("Chunk address: {}", hex::encode(address));
    println!("Running {GET_ITERATIONS} sequential GETs with breakdown…\n");
    println!(
        "{:>4}  {:>12}  {:>12}  {:>12}  {:>10}",
        "#", "dht_local", "dht_network", "get_chunk", "bg_events"
    );
    println!("{}", "-".repeat(60));

    let mut totals = Vec::with_capacity(GET_ITERATIONS);

    for i in 0..GET_ITERATIONS {
        let bg_events = drain_pending_events(&node);

        // Phase 1: Local-only DHT lookup (no network RPCs)
        let local_start = Instant::now();
        let _local_closest = node
            .dht()
            .find_closest_nodes_local(&address, CLOSE_GROUP_SIZE)
            .await;
        let local_dur = local_start.elapsed();

        // Phase 2: Full network DHT lookup (iterative Kademlia)
        let net_start = Instant::now();
        let _net_closest = node
            .dht()
            .find_closest_nodes(&address, CLOSE_GROUP_SIZE)
            .await
            .expect("DHT network lookup failed");
        let net_dur = net_start.elapsed();

        // Phase 3: Full client GET (includes its own DHT lookup + send + wait)
        let get_start = Instant::now();
        let result = client.get_chunk(&address).await.expect("get_chunk failed");
        let get_dur = get_start.elapsed();

        assert!(result.is_some(), "Chunk should be found (iteration {i})");

        println!(
            "{:>4}  {:>12?}  {:>12?}  {:>12?}  {:>10}",
            i, local_dur, net_dur, get_dur, bg_events
        );
        totals.push(get_dur);
    }

    print_stats(&totals);

    drop(client);
    drop(node);
    harness
        .teardown()
        .await
        .expect("Failed to teardown harness");
}

/// Drain all pending events from the broadcast channel without blocking.
fn drain_pending_events(node: &P2PNode) -> usize {
    let mut rx = node.subscribe_events();
    let mut count = 0;
    loop {
        match rx.try_recv() {
            Ok(_) => count += 1,
            Err(_) => break,
        }
    }
    count
}

fn print_stats(latencies: &[Duration]) {
    let mut sorted = latencies.to_vec();
    sorted.sort();
    let total: Duration = sorted.iter().sum();
    let min = sorted[0];
    let max = sorted[sorted.len() - 1];
    let mean = total / sorted.len() as u32;
    let median = sorted[sorted.len() / 2];
    let p90 = sorted[(sorted.len() as f64 * 0.9) as usize];
    let p99 = sorted[(sorted.len() as f64 * 0.99) as usize];

    let outlier_threshold = median * 3;
    let outlier_count = sorted.iter().filter(|d| **d > outlier_threshold).count();

    println!("\n===== STATS (get_chunk) =====");
    println!("  min:      {min:?}");
    println!("  max:      {max:?}");
    println!("  mean:     {mean:?}");
    println!("  median:   {median:?}");
    println!("  p90:      {p90:?}");
    println!("  p99:      {p99:?}");
    println!("  outliers: {outlier_count} (> 3x median = {outlier_threshold:?})");
    println!("  total:    {total:?}");
}
