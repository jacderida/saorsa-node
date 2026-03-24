//! E2E tests for merkle batch payment verification across live nodes.
//!
//! These tests validate merkle payment security and correctness by sending
//! crafted merkle proofs to live testnet nodes with `payment_enforcement: true`.
//!
//! **Test Coverage**:
//! - Merkle-tagged garbage rejected
//! - Valid merkle proof with wrong xorname rejected
//! - Merkle proof with tampered candidate signatures rejected
//! - Merkle proof construction, serialization, and size validation
//! - Concurrent merkle proof verification across multiple nodes

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::harness::TestHarness;
use super::testnet::TestNetworkConfig;
use ant_evm::merkle_payments::{
    MerklePaymentCandidateNode, MerklePaymentCandidatePool, MerklePaymentProof, MerkleTree,
    CANDIDATES_PER_POOL,
};
use ant_evm::RewardsAddress;
use ant_node::ant_protocol::{
    ChunkMessage, ChunkMessageBody, ChunkPutRequest, ChunkPutResponse, ProtocolError,
    PROOF_TAG_MERKLE,
};
use ant_node::compute_address;
use ant_node::payment::serialize_merkle_proof;
use evmlib::quoting_metrics::QuotingMetrics;
use evmlib::testnet::Testnet;
use rand::Rng;
use saorsa_core::MlDsa65;
use saorsa_pqc::pqc::types::MlDsaSecretKey;
use saorsa_pqc::pqc::MlDsaOperations;
use serial_test::serial;
use std::time::Duration;
use tokio::time::sleep;
use tracing::info;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check if a `ChunkMessageBody` indicates payment rejection.
fn is_payment_rejection(body: &ChunkMessageBody) -> bool {
    matches!(
        body,
        ChunkMessageBody::PutResponse(
            ChunkPutResponse::PaymentRequired { .. }
                | ChunkPutResponse::Error(ProtocolError::PaymentFailed(_))
        )
    )
}

/// Send a PUT request directly to a node's `AntProtocol` handler.
async fn send_put_to_node(
    harness: &TestHarness,
    node_index: usize,
    request: ChunkPutRequest,
) -> Result<ChunkMessage, String> {
    let node = harness
        .test_node(node_index)
        .ok_or_else(|| format!("Node {node_index} not found"))?;
    let protocol = node
        .ant_protocol
        .as_ref()
        .ok_or("No ant_protocol on node")?;

    let request_id: u64 = rand::thread_rng().gen();
    let message = ChunkMessage {
        request_id,
        body: ChunkMessageBody::PutRequest(request),
    };
    let message_bytes = message
        .encode()
        .map_err(|e| format!("Encode failed: {e}"))?;
    let response_bytes = protocol
        .handle_message(&message_bytes)
        .await
        .map_err(|e| format!("Handle failed: {e}"))?;
    ChunkMessage::decode(&response_bytes).map_err(|e| format!("Decode failed: {e}"))
}

/// Create a lightweight test harness with payment enforcement and Anvil wiring.
async fn setup_enforcement_env() -> Result<(TestHarness, Testnet), Box<dyn std::error::Error>> {
    let testnet = Testnet::new().await;
    let network = testnet.to_network();
    let config = TestNetworkConfig::minimal()
        .with_payment_enforcement()
        .with_evm_network(network);
    let harness = TestHarness::setup_with_config(config).await?;
    sleep(Duration::from_secs(5)).await;
    Ok((harness, testnet))
}

/// Build a valid `MerklePaymentProof` with real ML-DSA-65 signatures.
///
/// Returns `(target_xorname, tagged_proof_bytes, addresses_in_tree)`.
fn build_valid_merkle_proof() -> (xor_name::XorName, Vec<u8>, Vec<xor_name::XorName>) {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_secs();

    let addresses: Vec<xor_name::XorName> = (0..4u8)
        .map(|i| xor_name::XorName::from_content(&[i]))
        .collect();
    let tree = MerkleTree::from_xornames(addresses.clone()).expect("tree");

    let candidate_nodes: [MerklePaymentCandidateNode; CANDIDATES_PER_POOL] =
        std::array::from_fn(|i| {
            let ml_dsa = MlDsa65::new();
            let (pub_key, secret_key) = ml_dsa.generate_keypair().expect("keygen");
            let metrics = QuotingMetrics {
                data_size: 1024,
                data_type: 0,
                close_records_stored: i * 10,
                records_per_type: vec![],
                max_records: 500,
                received_payment_count: 0,
                live_time: 100,
                network_density: None,
                network_size: None,
            };
            #[allow(clippy::cast_possible_truncation)]
            let reward_address = RewardsAddress::new([i as u8; 20]);
            let msg =
                MerklePaymentCandidateNode::bytes_to_sign(&metrics, &reward_address, timestamp);
            let sk = MlDsaSecretKey::from_bytes(secret_key.as_bytes()).expect("sk");
            let signature = ml_dsa.sign(&sk, &msg).expect("sign").as_bytes().to_vec();

            MerklePaymentCandidateNode {
                pub_key: pub_key.as_bytes().to_vec(),
                quoting_metrics: metrics,
                reward_address,
                merkle_payment_timestamp: timestamp,
                signature,
            }
        });

    let reward_candidates = tree
        .reward_candidates(timestamp)
        .expect("reward candidates");
    let midpoint_proof = reward_candidates
        .first()
        .expect("at least one candidate")
        .clone();

    let pool = MerklePaymentCandidatePool {
        midpoint_proof,
        candidate_nodes,
    };

    let first_address = *addresses.first().expect("first address");
    let address_proof = tree
        .generate_address_proof(0, first_address)
        .expect("proof");

    let merkle_proof = MerklePaymentProof::new(first_address, address_proof, pool);
    let tagged = serialize_merkle_proof(&merkle_proof).expect("serialize merkle proof");

    (first_address, tagged, addresses)
}

/// Build a merkle proof with one tampered candidate signature.
fn build_tampered_signature_merkle_proof() -> (xor_name::XorName, Vec<u8>) {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_secs();

    let addresses: Vec<xor_name::XorName> = (0..4u8)
        .map(|i| xor_name::XorName::from_content(&[i]))
        .collect();
    let tree = MerkleTree::from_xornames(addresses.clone()).expect("tree");

    let mut candidate_nodes: [MerklePaymentCandidateNode; CANDIDATES_PER_POOL] =
        std::array::from_fn(|i| {
            let ml_dsa = MlDsa65::new();
            let (pub_key, secret_key) = ml_dsa.generate_keypair().expect("keygen");
            let metrics = QuotingMetrics {
                data_size: 1024,
                data_type: 0,
                close_records_stored: i * 10,
                records_per_type: vec![],
                max_records: 500,
                received_payment_count: 0,
                live_time: 100,
                network_density: None,
                network_size: None,
            };
            #[allow(clippy::cast_possible_truncation)]
            let reward_address = RewardsAddress::new([i as u8; 20]);
            let msg =
                MerklePaymentCandidateNode::bytes_to_sign(&metrics, &reward_address, timestamp);
            let sk = MlDsaSecretKey::from_bytes(secret_key.as_bytes()).expect("sk");
            let signature = ml_dsa.sign(&sk, &msg).expect("sign").as_bytes().to_vec();

            MerklePaymentCandidateNode {
                pub_key: pub_key.as_bytes().to_vec(),
                quoting_metrics: metrics,
                reward_address,
                merkle_payment_timestamp: timestamp,
                signature,
            }
        });

    // Tamper the first candidate's signature
    if let Some(byte) = candidate_nodes
        .first_mut()
        .and_then(|c| c.signature.first_mut())
    {
        *byte ^= 0xFF;
    }

    let reward_candidates = tree
        .reward_candidates(timestamp)
        .expect("reward candidates");
    let midpoint_proof = reward_candidates
        .first()
        .expect("at least one candidate")
        .clone();

    let pool = MerklePaymentCandidatePool {
        midpoint_proof,
        candidate_nodes,
    };

    let first_address = *addresses.first().expect("first address");
    let address_proof = tree
        .generate_address_proof(0, first_address)
        .expect("proof");

    let merkle_proof = MerklePaymentProof::new(first_address, address_proof, pool);
    let tagged = serialize_merkle_proof(&merkle_proof).expect("serialize merkle proof");

    (first_address, tagged)
}

// ===========================================================================
// Category 1: Merkle-tagged garbage (Direct Protocol Handler)
// ===========================================================================

/// Attack: Send merkle-tagged garbage to a live node.
/// Node MUST reject with a deserialization/payment error.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_attack_merkle_tagged_garbage() -> Result<(), Box<dyn std::error::Error>> {
    info!("MERKLE ATTACK TEST: merkle-tagged garbage bytes");

    let (harness, _testnet) = setup_enforcement_env().await?;

    let test_data = b"Attack: merkle-tagged garbage";
    let address = compute_address(test_data);

    // Build garbage with correct merkle tag but invalid body
    let mut garbage = vec![PROOF_TAG_MERKLE];
    garbage.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    // Pad to minimum proof size (32 bytes)
    while garbage.len() < 32 {
        garbage.push(0x00);
    }

    let request = ChunkPutRequest::with_payment(address, test_data.to_vec(), garbage);

    let response = send_put_to_node(&harness, 0, request)
        .await
        .map_err(|e| format!("Send failed: {e}"))?;

    assert!(
        is_payment_rejection(&response.body),
        "Merkle-tagged garbage MUST be rejected, got: {response:?}"
    );
    info!("Correctly rejected: merkle-tagged garbage");

    harness.teardown().await?;
    Ok(())
}

// ===========================================================================
// Category 2: Valid merkle proof, wrong xorname
// ===========================================================================

/// Attack: Send a structurally valid merkle proof but for the wrong chunk.
/// Node MUST reject with address mismatch.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_attack_merkle_proof_wrong_xorname() -> Result<(), Box<dyn std::error::Error>> {
    info!("MERKLE ATTACK TEST: valid merkle proof, wrong xorname");

    let (harness, _testnet) = setup_enforcement_env().await?;

    // Build a valid merkle proof for one xorname
    let (_proof_xorname, tagged_proof, _addrs) = build_valid_merkle_proof();

    // Try to use it for a completely different chunk
    let wrong_data = b"This chunk was never paid for via this merkle proof";
    let wrong_address = compute_address(wrong_data);

    let request = ChunkPutRequest::with_payment(wrong_address, wrong_data.to_vec(), tagged_proof);

    let response = send_put_to_node(&harness, 0, request)
        .await
        .map_err(|e| format!("Send failed: {e}"))?;

    assert!(
        is_payment_rejection(&response.body),
        "Merkle proof for wrong xorname MUST be rejected, got: {response:?}"
    );
    info!("Correctly rejected: merkle proof for wrong xorname");

    harness.teardown().await?;
    Ok(())
}

// ===========================================================================
// Category 3: Tampered candidate signatures
// ===========================================================================

/// Attack: Send a merkle proof where one candidate's ML-DSA-65 signature is tampered.
/// Node MUST reject — the tampered signature prevents pool verification.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_attack_merkle_tampered_candidate_signature() -> Result<(), Box<dyn std::error::Error>>
{
    info!("MERKLE ATTACK TEST: tampered candidate signature");

    let (harness, _testnet) = setup_enforcement_env().await?;

    let (proof_xorname, tagged_proof) = build_tampered_signature_merkle_proof();

    // Use the correct xorname but the proof has a tampered signature
    let test_data = proof_xorname.0.to_vec();
    let request = ChunkPutRequest::with_payment(proof_xorname.0, test_data, tagged_proof);

    let response = send_put_to_node(&harness, 0, request)
        .await
        .map_err(|e| format!("Send failed: {e}"))?;

    assert!(
        is_payment_rejection(&response.body),
        "Merkle proof with tampered signature MUST be rejected, got: {response:?}"
    );
    info!("Correctly rejected: tampered candidate signature");

    harness.teardown().await?;
    Ok(())
}

// ===========================================================================
// Category 4: Merkle proof construction and serialization validation
// ===========================================================================

/// Verify that a full merkle proof with 16 ML-DSA-65 candidates
/// serializes within the allowed size limits.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_merkle_proof_serialized_size_e2e() -> Result<(), Box<dyn std::error::Error>> {
    info!("MERKLE TEST: proof serialization size validation");

    let (_xorname, tagged_proof, _addrs) = build_valid_merkle_proof();

    // 16 candidates with ~1952-byte pub keys and ~3309-byte signatures ≈ ~130 KB
    // Must be within [32, 262144] bytes
    assert!(
        tagged_proof.len() >= 32,
        "Merkle proof ({} bytes) must be >= 32 bytes",
        tagged_proof.len()
    );
    assert!(
        tagged_proof.len() <= 262_144,
        "Merkle proof ({} bytes) must be <= 256 KB",
        tagged_proof.len()
    );

    let size_kb = tagged_proof.len() / 1024;
    info!(
        "Merkle proof size: {} bytes (~{size_kb} KB) — within limits",
        tagged_proof.len(),
    );

    Ok(())
}

/// Verify merkle proof tag detection works correctly end-to-end.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_merkle_proof_tag_detection_e2e() -> Result<(), Box<dyn std::error::Error>> {
    info!("MERKLE TEST: proof tag detection");

    let (_xorname, tagged_proof, _addrs) = build_valid_merkle_proof();

    assert_eq!(
        tagged_proof.first().copied(),
        Some(PROOF_TAG_MERKLE),
        "First byte must be PROOF_TAG_MERKLE (0x02)"
    );

    let detected = ant_node::payment::detect_proof_type(&tagged_proof);
    assert_eq!(
        detected,
        Some(ant_node::payment::ProofType::Merkle),
        "detect_proof_type must identify as Merkle"
    );

    info!("Merkle proof tag detection confirmed");
    Ok(())
}

// ===========================================================================
// Category 5: Concurrent merkle attacks across multiple nodes
// ===========================================================================

/// Attack: Send merkle-tagged garbage to ALL nodes concurrently.
/// Every node MUST reject independently.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_attack_merkle_garbage_all_nodes_concurrent() -> Result<(), Box<dyn std::error::Error>>
{
    info!("MERKLE ATTACK TEST: garbage to all nodes concurrently");

    let (harness, _testnet) = setup_enforcement_env().await?;

    let test_data = b"Attack: concurrent merkle garbage";
    let address = compute_address(test_data);

    let mut garbage = vec![PROOF_TAG_MERKLE];
    garbage.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
    while garbage.len() < 32 {
        garbage.push(0x00);
    }

    // Send to all available nodes concurrently
    let node_count = harness.node_count();
    let mut handles = Vec::new();

    for i in 0..node_count {
        if harness.test_node(i).is_some() {
            let request =
                ChunkPutRequest::with_payment(address, test_data.to_vec(), garbage.clone());
            let msg = ChunkMessage {
                request_id: rand::thread_rng().gen(),
                body: ChunkMessageBody::PutRequest(request),
            };
            let msg_bytes = msg.encode().expect("encode");

            if let Some(protocol) = harness.test_node(i).and_then(|n| n.ant_protocol.as_ref()) {
                let proto = protocol.clone();
                handles.push(tokio::spawn(async move {
                    let resp_bytes = proto
                        .handle_message(&msg_bytes)
                        .await
                        .map_err(|e| format!("Node {i}: {e}"))?;
                    let resp = ChunkMessage::decode(&resp_bytes)
                        .map_err(|e| format!("Node {i} decode: {e}"))?;
                    Ok::<(usize, ChunkMessage), String>((i, resp))
                }));
            }
        }
    }

    let mut rejection_count = 0;
    for handle in handles {
        let (node_idx, response) = handle.await.expect("task panicked")?;
        assert!(
            is_payment_rejection(&response.body),
            "Node {node_idx} MUST reject merkle garbage, got: {response:?}"
        );
        rejection_count += 1;
    }

    assert!(
        rejection_count > 0,
        "At least one node should have been tested"
    );
    info!("All {rejection_count} nodes correctly rejected merkle garbage");

    harness.teardown().await?;
    Ok(())
}

// ===========================================================================
// Category 6: Replay / cross-chunk proof reuse
// ===========================================================================

/// Attack: Build a valid merkle proof for address[0] in the tree, then try
/// to use it to store a chunk whose address matches address[1] in the same
/// tree. The proof's `address` field is bound to address[0], so the node
/// must reject the mismatch.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_attack_merkle_proof_cross_address_replay() -> Result<(), Box<dyn std::error::Error>> {
    info!("MERKLE ATTACK TEST: cross-address replay within same tree");

    let (harness, _testnet) = setup_enforcement_env().await?;

    // Build proof bound to addresses[0]
    let (_first_address, tagged_proof, addresses) = build_valid_merkle_proof();

    // Try to use it for addresses[1] (different address in the same tree)
    let second_address = addresses.get(1).expect("should have 4 addresses");

    let request =
        ChunkPutRequest::with_payment(second_address.0, second_address.0.to_vec(), tagged_proof);

    let response = send_put_to_node(&harness, 0, request)
        .await
        .map_err(|e| format!("Send failed: {e}"))?;

    assert!(
        is_payment_rejection(&response.body),
        "Cross-address replay MUST be rejected, got: {response:?}"
    );
    info!("Correctly rejected: cross-address replay within same tree");

    harness.teardown().await?;
    Ok(())
}
