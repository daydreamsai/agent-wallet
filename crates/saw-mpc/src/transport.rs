//! Transport layer: adapts WebSocket connections to the Stream/Sink
//! interface that cggmp21's round-based protocols expect.
//!
//! Each MPC session gets a pair of (incoming Stream, outgoing Sink)
//! that carries serialized protocol messages over an authenticated
//! WebSocket connection.

use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use serde::{de::DeserializeOwned, Serialize};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{debug, error};

use crate::types::{MpcMessage, PartyId};

/// Channel capacity for MPC message passing.
const CHANNEL_CAPACITY: usize = 64;

/// Creates an in-memory transport pair for testing.
/// Returns (party_a_tx, party_a_rx, party_b_tx, party_b_rx).
pub fn in_memory_pair() -> (
    mpsc::Sender<MpcMessage>,
    mpsc::Receiver<MpcMessage>,
    mpsc::Sender<MpcMessage>,
    mpsc::Receiver<MpcMessage>,
) {
    let (a_tx, b_rx) = mpsc::channel(CHANNEL_CAPACITY);
    let (b_tx, a_rx) = mpsc::channel(CHANNEL_CAPACITY);
    (a_tx, a_rx, b_tx, b_rx)
}

/// Creates an in-memory transport hub for N parties (for testing/keygen).
/// Returns a Vec of (sender, receiver) pairs, one per party.
/// Messages sent by party i are delivered to the appropriate recipient(s).
pub fn in_memory_hub(n: usize) -> Vec<(mpsc::Sender<MpcMessage>, mpsc::Receiver<MpcMessage>)> {
    // Each party gets a sender (to hub) and receiver (from hub)
    let mut to_hub: Vec<mpsc::Sender<MpcMessage>> = Vec::with_capacity(n);
    let mut from_parties: Vec<mpsc::Receiver<MpcMessage>> = Vec::with_capacity(n);
    let mut to_parties: Vec<mpsc::Sender<MpcMessage>> = Vec::with_capacity(n);
    let mut from_hub: Vec<mpsc::Receiver<MpcMessage>> = Vec::with_capacity(n);

    for _ in 0..n {
        let (tx_to_hub, rx_from_party) = mpsc::channel(CHANNEL_CAPACITY);
        let (tx_to_party, rx_from_hub) = mpsc::channel(CHANNEL_CAPACITY);
        to_hub.push(tx_to_hub);
        from_parties.push(rx_from_party);
        to_parties.push(tx_to_party);
        from_hub.push(rx_from_hub);
    }

    // Spawn a hub task that routes messages
    let n_parties = n;
    tokio::spawn(async move {
        // Merge all incoming streams
        let mut combined = futures::stream::select_all(
            from_parties
                .into_iter()
                .map(|rx| rx.boxed()),
        );

        while let Some(msg) = combined.next().await {
            match msg.to {
                Some(recipient) => {
                    // P2P: send to specific party
                    if (recipient as usize) < n_parties {
                        let _ = to_parties[recipient as usize].send(msg).await;
                    }
                }
                None => {
                    // Broadcast: send to all except sender
                    for (i, tx) in to_parties.iter_mut().enumerate() {
                        if i != msg.from as usize {
                            let _ = tx.send(msg.clone()).await;
                        }
                    }
                }
            }
        }
    });

    to_hub
        .into_iter()
        .zip(from_hub.into_iter())
        .collect()
}
