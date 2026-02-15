//! WebSocket relay server for multi-party MPC ceremonies.
//!
//! All parties connect to the relay. The relay routes MPC messages:
//! - Broadcast → forward to all other parties
//! - P2P → forward to the specific target party
//!
//! Used for keygen ceremonies where all 3 parties must participate.
//! For 2-party signing, use the direct WsConnection instead.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use serde::{Deserialize, Serialize};

use crate::transport::DeliveryError;
use crate::types::PartyId;

/// Message format for the relay protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayMessage {
    /// Protocol phase (e.g., "aux", "keygen", "sign")
    pub phase: String,
    /// Sender party ID
    pub from: PartyId,
    /// Target: None = broadcast, Some(id) = P2P
    pub to: Option<PartyId>,
    /// Serialized protocol message
    pub data: Vec<u8>,
}

/// Control messages between parties and the relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RelayEnvelope {
    /// Party announces itself on connect
    Join { party_id: PartyId },
    /// Relay confirms party joined
    Joined { party_id: PartyId, total: usize },
    /// Relay announces all parties are present
    AllJoined { parties: Vec<PartyId> },
    /// Signal to start a phase
    StartPhase { phase: String },
    /// Party signals phase complete
    PhaseComplete { phase: String, party_id: PartyId },
    /// MPC protocol message
    Mpc(RelayMessage),
    /// Error
    Error { message: String },
}

/// Run a relay server that routes MPC messages between N parties.
pub async fn run_relay(
    listen_addr: &str,
    expected_parties: u16,
) -> Result<(), crate::error::MpcError> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| crate::error::MpcError::Transport(format!("bind: {e}")))?;

    tracing::info!(listen = %listen_addr, expected = expected_parties, "relay server started");

    // Party senders: party_id → channel to send messages to that party
    let senders: Arc<Mutex<HashMap<PartyId, mpsc::UnboundedSender<RelayEnvelope>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let mut join_handles = Vec::new();
    let mut connected = 0u16;

    while connected < expected_parties {
        let (tcp, addr) = listener
            .accept()
            .await
            .map_err(|e| crate::error::MpcError::Transport(format!("accept: {e}")))?;

        tracing::info!(%addr, "new connection");

        let ws = tokio_tungstenite::accept_async(tcp)
            .await
            .map_err(|e| crate::error::MpcError::Transport(format!("handshake: {e}")))?;

        let (mut ws_tx, mut ws_rx) = ws.split();

        // Read Join message
        let join_msg = loop {
            match ws_rx.next().await {
                Some(Ok(WsMessage::Text(t))) => {
                    break serde_json::from_str::<RelayEnvelope>(&t)
                        .map_err(|e| crate::error::MpcError::Transport(format!("bad join: {e}")))?;
                }
                Some(Ok(WsMessage::Binary(d))) => {
                    break serde_json::from_slice::<RelayEnvelope>(&d)
                        .map_err(|e| crate::error::MpcError::Transport(format!("bad join: {e}")))?;
                }
                Some(Ok(_)) => continue,
                _ => return Err(crate::error::MpcError::Transport("connection lost before join".into())),
            }
        };

        let party_id = match join_msg {
            RelayEnvelope::Join { party_id } => party_id,
            _ => return Err(crate::error::MpcError::Transport("expected Join message".into())),
        };

        if party_id >= expected_parties {
            let err = RelayEnvelope::Error {
                message: format!("party_id {party_id} >= {expected_parties}"),
            };
            let _ = ws_tx
                .send(WsMessage::Text(serde_json::to_string(&err).unwrap().into()))
                .await;
            continue;
        }

        // Create channel for sending messages to this party
        let (party_tx, mut party_rx) = mpsc::unbounded_channel::<RelayEnvelope>();

        {
            let mut map = senders.lock().await;
            if map.contains_key(&party_id) {
                let err = RelayEnvelope::Error {
                    message: format!("party {party_id} already connected"),
                };
                let _ = ws_tx
                    .send(WsMessage::Text(serde_json::to_string(&err).unwrap().into()))
                    .await;
                continue;
            }
            map.insert(party_id, party_tx);
            connected = map.len() as u16;
        }

        // Send Joined confirmation
        let joined = RelayEnvelope::Joined {
            party_id,
            total: connected as usize,
        };
        let _ = ws_tx
            .send(WsMessage::Text(serde_json::to_string(&joined).unwrap().into()))
            .await;

        tracing::info!(party_id, connected, "party joined");

        // Spawn writer task: channel → WebSocket
        let write_handle = tokio::spawn(async move {
            while let Some(msg) = party_rx.recv().await {
                let json = serde_json::to_string(&msg).unwrap();
                if ws_tx.send(WsMessage::Text(json.into())).await.is_err() {
                    break;
                }
            }
        });

        // Spawn reader task: WebSocket → route to other parties
        let senders_clone = senders.clone();
        let _n = expected_parties;
        let read_handle = tokio::spawn(async move {
            while let Some(item) = ws_rx.next().await {
                let raw = match item {
                    Ok(WsMessage::Text(t)) => t.into_bytes(),
                    Ok(WsMessage::Binary(d)) => d.to_vec(),
                    Ok(WsMessage::Ping(_) | WsMessage::Pong(_)) => continue,
                    Ok(WsMessage::Close(_)) | Err(_) => break,
                    _ => continue,
                };

                let envelope: RelayEnvelope = match serde_json::from_slice(&raw) {
                    Ok(e) => e,
                    Err(_) => continue,
                };

                match &envelope {
                    RelayEnvelope::Mpc(relay_msg) => {
                        let map = senders_clone.lock().await;
                        match relay_msg.to {
                            Some(target) => {
                                // P2P: send to specific party
                                if let Some(tx) = map.get(&target) {
                                    let _ = tx.send(envelope.clone());
                                }
                            }
                            None => {
                                // Broadcast: send to all except sender
                                for (&pid, tx) in map.iter() {
                                    if pid != party_id {
                                        let _ = tx.send(envelope.clone());
                                    }
                                }
                            }
                        }
                    }
                    RelayEnvelope::PhaseComplete { .. } => {
                        // Forward to all other parties
                        let map = senders_clone.lock().await;
                        for (&pid, tx) in map.iter() {
                            if pid != party_id {
                                let _ = tx.send(envelope.clone());
                            }
                        }
                    }
                    _ => {}
                }
            }
        });

        join_handles.push((party_id, write_handle, read_handle));
    }

    // All parties connected — send AllJoined to everyone
    {
        let map = senders.lock().await;
        let parties: Vec<PartyId> = map.keys().copied().collect();
        let msg = RelayEnvelope::AllJoined {
            parties: parties.clone(),
        };
        for tx in map.values() {
            let _ = tx.send(msg.clone());
        }
        tracing::info!(?parties, "all parties joined, ceremony can begin");
    }

    // Keep relay alive until all read tasks finish (parties disconnect)
    for (pid, wh, rh) in join_handles {
        let _ = rh.await;
        wh.abort();
        tracing::info!(party_id = pid, "party disconnected");
    }

    Ok(())
}

/// Connect to a relay as a party and get a channel-based delivery for MPC.
///
/// Returns a delivery pair `(incoming_rx, outgoing_tx)` compatible with
/// cggmp21's `MpcParty::connected()`, plus a control channel for
/// phase coordination.
pub async fn connect_to_relay<M>(
    url: &str,
    party_id: PartyId,
    phase: &str,
) -> Result<
    (
        futures::channel::mpsc::UnboundedReceiver<Result<cggmp21::round_based::Incoming<M>, DeliveryError>>,
        futures::channel::mpsc::UnboundedSender<cggmp21::round_based::Outgoing<M>>,
    ),
    crate::error::MpcError,
>
where
    M: serde::Serialize + serde::de::DeserializeOwned + Clone + Send + 'static,
{
    let (ws, _) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(|e| crate::error::MpcError::Transport(format!("connect: {e}")))?;

    let (mut ws_tx, mut ws_rx) = ws.split();

    // Send Join
    let join = RelayEnvelope::Join { party_id };
    ws_tx
        .send(WsMessage::Text(serde_json::to_string(&join).unwrap().into()))
        .await
        .map_err(|e| crate::error::MpcError::Transport(format!("send join: {e}")))?;

    // Wait for Joined + AllJoined
    loop {
        let raw = match ws_rx.next().await {
            Some(Ok(WsMessage::Text(t))) => t.into_bytes(),
            Some(Ok(WsMessage::Binary(d))) => d.to_vec(),
            Some(Ok(_)) => continue,
            _ => return Err(crate::error::MpcError::Transport("connection lost".into())),
        };
        let env: RelayEnvelope = serde_json::from_slice(&raw)
            .map_err(|e| crate::error::MpcError::Transport(format!("bad msg: {e}")))?;
        match env {
            RelayEnvelope::Joined { .. } => continue,
            RelayEnvelope::AllJoined { .. } => break,
            RelayEnvelope::Error { message } => {
                return Err(crate::error::MpcError::Transport(format!("relay error: {message}")));
            }
            _ => continue,
        }
    }

    // Build channel-based delivery
    let (incoming_tx, incoming_rx) = futures::channel::mpsc::unbounded();
    let (outgoing_tx, mut outgoing_rx) =
        futures::channel::mpsc::unbounded::<cggmp21::round_based::Outgoing<M>>();

    let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let phase_str = phase.to_string();

    // Outgoing: MPC Outgoing<M> → RelayEnvelope::Mpc → WebSocket
    let phase_out = phase_str.clone();
    let ws_tx = Arc::new(Mutex::new(ws_tx));
    let ws_tx_out = ws_tx.clone();
    tokio::spawn(async move {
        use cggmp21::round_based::MessageDestination;

        while let Some(outgoing) = outgoing_rx.next().await {
            let to = match outgoing.recipient {
                MessageDestination::AllParties => None,
                MessageDestination::OneParty(p) => Some(p),
            };
            let data = match serde_json::to_vec(&outgoing.msg) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let env = RelayEnvelope::Mpc(RelayMessage {
                phase: phase_out.clone(),
                from: party_id,
                to,
                data,
            });
            let json = serde_json::to_string(&env).unwrap();
            let mut tx = ws_tx_out.lock().await;
            if tx.send(WsMessage::Text(json.into())).await.is_err() {
                break;
            }
        }
    });

    // Incoming: WebSocket → RelayEnvelope::Mpc → Incoming<M>
    let phase_in = phase_str;
    let ws_rx = Arc::new(Mutex::new(ws_rx));
    let ws_rx_in = ws_rx.clone();
    let cnt = counter;
    tokio::spawn(async move {
        use cggmp21::round_based::{Incoming, MessageType};

        let mut rx = ws_rx_in.lock().await;
        while let Some(item) = rx.next().await {
            let raw = match item {
                Ok(WsMessage::Text(t)) => t.into_bytes(),
                Ok(WsMessage::Binary(d)) => d.to_vec(),
                Ok(WsMessage::Close(_)) => {
                    let _ = incoming_tx.unbounded_send(Err(DeliveryError("closed".into())));
                    break;
                }
                Err(e) => {
                    let _ = incoming_tx.unbounded_send(Err(DeliveryError(format!("{e}"))));
                    break;
                }
                _ => continue,
            };

            let env: RelayEnvelope = match serde_json::from_slice(&raw) {
                Ok(e) => e,
                Err(_) => continue,
            };

            if let RelayEnvelope::Mpc(relay_msg) = env {
                if relay_msg.phase != phase_in {
                    continue;
                }
                if let Ok(msg) = serde_json::from_slice::<M>(&relay_msg.data) {
                    let msg_type = if relay_msg.to.is_some() {
                        MessageType::P2P
                    } else {
                        MessageType::Broadcast
                    };
                    let incoming = Incoming {
                        id: cnt.fetch_add(1, Ordering::Relaxed),
                        sender: relay_msg.from,
                        msg_type,
                        msg,
                    };
                    if incoming_tx.unbounded_send(Ok(incoming)).is_err() {
                        break;
                    }
                }
            }
        }
    });

    Ok((incoming_rx, outgoing_tx))
}
