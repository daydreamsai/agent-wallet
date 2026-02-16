//! Transport layer: provides `Delivery` implementations for cggmp21.
//!
//! - `in_memory_delivery`: for testing with multiple parties in one process
//! - `WsDelivery`: WebSocket-based delivery for production use
//!
//! The WebSocket transport works in two modes:
//! - **Client** (saw-daemon): connects to saw-policy's WS server
//! - **Server** (saw-policy): listens for incoming connections from saw-daemon

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use futures::channel::mpsc;
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use cggmp21::round_based::{
    Incoming, MessageDestination, MessageType, Outgoing,
};

use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::Mutex;

use crate::error::MpcError;
use crate::protocol::{MpcWireMessage, SessionId, WireMessage};
use crate::types::PartyId;

/// Error type for delivery.
#[derive(Debug)]
pub struct DeliveryError(pub String);

impl fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "delivery error: {}", self.0)
    }
}

impl std::error::Error for DeliveryError {}

// ---------------------------------------------------------------------------
// WebSocket transport
// ---------------------------------------------------------------------------

use tokio_tungstenite::tungstenite::Message as WsMessage;

/// A WebSocket connection that can send/receive `WireMessage`s and be
/// converted into a cggmp21-compatible `Delivery` for MPC protocol messages.
///
/// Generic over the underlying stream type so it works with both:
/// - Client connections (`MaybeTlsStream<TcpStream>`)  
/// - Server-accepted connections (`TcpStream`)
pub struct WsConnection<S> {
    ws_tx: Arc<Mutex<SplitSink<tokio_tungstenite::WebSocketStream<S>, WsMessage>>>,
    ws_rx: Arc<Mutex<SplitStream<tokio_tungstenite::WebSocketStream<S>>>>,
    /// This party's index
    pub party_id: PartyId,
    /// Remote party's index
    pub remote_party_id: PartyId,
    /// Total number of parties in the protocol
    pub num_parties: u16,
}

impl<S> WsConnection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    /// Wrap an already-established WebSocket stream.
    pub fn new(
        ws_stream: tokio_tungstenite::WebSocketStream<S>,
        party_id: PartyId,
        remote_party_id: PartyId,
        num_parties: u16,
    ) -> Self {
        let (ws_tx, ws_rx) = ws_stream.split();
        Self {
            ws_tx: Arc::new(Mutex::new(ws_tx)),
            ws_rx: Arc::new(Mutex::new(ws_rx)),
            party_id,
            remote_party_id,
            num_parties,
        }
    }

    /// Send a `WireMessage` over the WebSocket.
    pub async fn send(&self, msg: &WireMessage) -> Result<(), MpcError> {
        let data = serde_json::to_vec(msg).map_err(MpcError::Serde)?;
        let mut tx = self.ws_tx.lock().await;
        tx.send(WsMessage::Binary(data.into()))
            .await
            .map_err(|e| MpcError::Transport(format!("ws send: {e}")))?;
        Ok(())
    }

    /// Receive the next `WireMessage` from the WebSocket.
    /// Blocks until a message arrives or the connection closes.
    pub async fn recv(&self) -> Result<WireMessage, MpcError> {
        let mut rx = self.ws_rx.lock().await;
        loop {
            match rx.next().await {
                Some(Ok(WsMessage::Binary(data))) => {
                    return serde_json::from_slice(&data).map_err(MpcError::Serde);
                }
                Some(Ok(WsMessage::Text(text))) => {
                    return serde_json::from_str(&text).map_err(MpcError::Serde);
                }
                Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_))) => continue,
                Some(Ok(WsMessage::Close(_))) => {
                    return Err(MpcError::Transport("ws closed by remote".into()));
                }
                Some(Err(e)) => {
                    return Err(MpcError::Transport(format!("ws recv: {e}")));
                }
                None => {
                    return Err(MpcError::Transport("ws stream ended".into()));
                }
                _ => continue,
            }
        }
    }

    /// Convert this connection into a cggmp21-compatible `Delivery` for one MPC session.
    ///
    /// Returns `(incoming_rx, outgoing_tx)` — pass to `MpcParty::connected()`.
    ///
    /// **Consumes** the connection: the spawned tasks take ownership of the WS halves.
    /// Non-MPC `WireMessage`s (Ping, Pong, SignRequest, PolicyDecision) are dropped
    /// in this layer — handle those *before* calling `into_delivery`.
    pub fn into_delivery<M>(
        self,
        session_id: SessionId,
    ) -> (
        mpsc::UnboundedReceiver<Result<Incoming<M>, DeliveryError>>,
        mpsc::UnboundedSender<Outgoing<M>>,
    )
    where
        M: Serialize + DeserializeOwned + Clone + Send + 'static,
    {
        let (incoming_tx, incoming_rx) = mpsc::unbounded();
        let (outgoing_tx, outgoing_rx) = mpsc::unbounded::<Outgoing<M>>();

        let party_id = self.party_id;
        let ws_tx = self.ws_tx;
        let ws_rx = self.ws_rx;
        let msg_counter = Arc::new(AtomicU64::new(0));

        let sid_send = session_id.clone();
        let sid_recv = session_id;

        // Outgoing: MPC Outgoing<M> → serialize → WireMessage::Mpc → WebSocket
        tokio::spawn(async move {
            let mut rx = outgoing_rx;
            while let Some(outgoing) = rx.next().await {
                let to = match outgoing.recipient {
                    MessageDestination::AllParties => None,
                    MessageDestination::OneParty(p) => Some(p),
                };

                let data = match serde_json::to_vec(&outgoing.msg) {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::error!("serialize MPC msg: {e}");
                        continue;
                    }
                };

                let wire = WireMessage::Mpc(MpcWireMessage {
                    session_id: sid_send.clone(),
                    from: party_id,
                    to,
                    data,
                });

                let json = match serde_json::to_vec(&wire) {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::error!("serialize wire msg: {e}");
                        continue;
                    }
                };

                let mut tx = ws_tx.lock().await;
                if let Err(e) = tx.send(WsMessage::Binary(json.into())).await {
                    tracing::error!("ws send failed: {e}");
                    break;
                }
            }
        });

        // Incoming: WebSocket → WireMessage::Mpc → deserialize → Incoming<M>
        let counter = msg_counter;
        tokio::spawn(async move {
            let mut rx = ws_rx.lock().await;
            while let Some(item) = rx.next().await {
                let raw = match item {
                    Ok(WsMessage::Binary(data)) => data.to_vec(),
                    Ok(WsMessage::Text(text)) => text.into_bytes(),
                    Ok(WsMessage::Ping(_) | WsMessage::Pong(_)) => continue,
                    Ok(WsMessage::Close(_)) => {
                        let _ = incoming_tx.unbounded_send(Err(DeliveryError(
                            "ws closed".into(),
                        )));
                        break;
                    }
                    Err(e) => {
                        let _ = incoming_tx.unbounded_send(Err(DeliveryError(
                            format!("ws error: {e}"),
                        )));
                        break;
                    }
                    _ => continue,
                };

                let wire: WireMessage = match serde_json::from_slice(&raw) {
                    Ok(w) => w,
                    Err(e) => {
                        tracing::warn!("malformed wire msg: {e}");
                        continue;
                    }
                };

                if let WireMessage::Mpc(mpc_msg) = wire {
                    if mpc_msg.session_id != sid_recv {
                        continue;
                    }

                    let msg: M = match serde_json::from_slice(&mpc_msg.data) {
                        Ok(m) => m,
                        Err(e) => {
                            tracing::warn!("deserialize MPC payload: {e}");
                            continue;
                        }
                    };

                    let msg_type = if mpc_msg.to.is_some() {
                        MessageType::P2P
                    } else {
                        MessageType::Broadcast
                    };

                    let incoming = Incoming {
                        id: counter.fetch_add(1, Ordering::Relaxed),
                        sender: mpc_msg.from,
                        msg_type,
                        msg,
                    };

                    if incoming_tx.unbounded_send(Ok(incoming)).is_err() {
                        break;
                    }
                }
                // Non-MPC messages silently ignored in delivery layer
            }
        });

        (incoming_rx, outgoing_tx)
    }
}

// ---------------------------------------------------------------------------
// Convenience constructors
// ---------------------------------------------------------------------------

/// Client-side: connect to a WebSocket server.
pub async fn ws_connect(
    url: &str,
    party_id: PartyId,
    remote_party_id: PartyId,
    num_parties: u16,
) -> Result<
    WsConnection<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    MpcError,
> {
    tracing::info!(url, party_id, remote_party_id, "ws connecting");
    let (ws_stream, _) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(|e| MpcError::Transport(format!("ws connect: {e}")))?;
    Ok(WsConnection::new(ws_stream, party_id, remote_party_id, num_parties))
}

/// Server-side: accept a single WebSocket connection on a TCP listener.
pub async fn ws_accept(
    listener: &tokio::net::TcpListener,
    party_id: PartyId,
    remote_party_id: PartyId,
    num_parties: u16,
) -> Result<WsConnection<tokio::net::TcpStream>, MpcError> {
    tracing::info!(party_id, "waiting for incoming ws connection");
    let (tcp_stream, addr) = listener
        .accept()
        .await
        .map_err(|e| MpcError::Transport(format!("tcp accept: {e}")))?;
    tracing::info!(%addr, "accepted tcp connection, upgrading to ws");

    let ws_stream = tokio_tungstenite::accept_async(tcp_stream)
        .await
        .map_err(|e| MpcError::Transport(format!("ws handshake: {e}")))?;

    Ok(WsConnection::new(ws_stream, party_id, remote_party_id, num_parties))
}

// ---------------------------------------------------------------------------
// In-memory delivery (testing)
// ---------------------------------------------------------------------------

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

    party_in_rxs
        .into_iter()
        .zip(party_out_txs)
        .map(|(rx, tx)| (rx, tx))
        .collect()
}
