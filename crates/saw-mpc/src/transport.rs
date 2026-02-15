//! Transport layer: provides `Delivery` implementations for cggmp21.
//!
//! - `in_memory_delivery`: for testing with multiple parties in one process
//! - WebSocket delivery: TODO for production use

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use cggmp21::round_based::{
    Incoming, MessageDestination, MessageType, MsgId, Outgoing, PartyIndex,
};
use tokio::sync::Mutex;

/// Error type for delivery.
#[derive(Debug)]
pub struct DeliveryError(pub String);

impl fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "delivery error: {}", self.0)
    }
}

impl std::error::Error for DeliveryError {}

/// In-memory delivery for N parties in one process (testing).
///
/// Returns a Vec of (Receiver, Sender) pairs — one per party — that
/// implement the `Delivery` trait expected by cggmp21.
pub fn in_memory_delivery<M>(
    n: u16,
) -> Vec<(
    mpsc::UnboundedReceiver<Result<Incoming<M>, DeliveryError>>,
    mpsc::UnboundedSender<Outgoing<M>>,
)>
where
    M: Clone + Send + 'static,
{
    let msg_counter = Arc::new(AtomicU64::new(0));

    let mut party_out_txs = Vec::with_capacity(n as usize);
    let mut party_in_txs: Vec<mpsc::UnboundedSender<Result<Incoming<M>, DeliveryError>>> =
        Vec::with_capacity(n as usize);
    let mut party_in_rxs = Vec::with_capacity(n as usize);

    let mut out_rxs = Vec::with_capacity(n as usize);

    for _ in 0..n {
        let (out_tx, out_rx) = mpsc::unbounded::<Outgoing<M>>();
        let (in_tx, in_rx) = mpsc::unbounded::<Result<Incoming<M>, DeliveryError>>();
        party_out_txs.push(out_tx);
        out_rxs.push(out_rx);
        party_in_txs.push(in_tx);
        party_in_rxs.push(in_rx);
    }

    let shared_in_txs = Arc::new(party_in_txs);

    // Spawn a router per sender party
    for sender_idx in 0..n {
        let mut rx = out_rxs.remove(0);
        let txs = shared_in_txs.clone();
        let counter = msg_counter.clone();
        let n_parties = n;

        tokio::spawn(async move {
            while let Some(outgoing) = rx.next().await {
                let msg_id = counter.fetch_add(1, Ordering::Relaxed);

                match outgoing.recipient {
                    MessageDestination::AllParties => {
                        for r in 0..n_parties {
                            if r != sender_idx {
                                let incoming = Incoming {
                                    id: msg_id,
                                    sender: sender_idx,
                                    msg_type: MessageType::Broadcast,
                                    msg: outgoing.msg.clone(),
                                };
                                let _ = txs[r as usize].unbounded_send(Ok(incoming));
                            }
                        }
                    }
                    MessageDestination::OneParty(recipient) => {
                        if recipient < n_parties {
                            let incoming = Incoming {
                                id: msg_id,
                                sender: sender_idx,
                                msg_type: MessageType::P2P,
                                msg: outgoing.msg.clone(),
                            };
                            let _ = txs[recipient as usize].unbounded_send(Ok(incoming));
                        }
                    }
                }
            }
        });
    }

    // Return (incoming_rx, outgoing_tx) pairs — this tuple implements Delivery
    party_in_rxs
        .into_iter()
        .zip(party_out_txs)
        .map(|(rx, tx)| (rx, tx))
        .collect()
}
