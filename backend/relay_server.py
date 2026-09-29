"""
Privacy Messenger — Real Signal-Style Sealed Sender Relay Server
=================================================================
True Zero-Knowledge & Metadata Privacy:
1. Clients connect anonymously to `/relay/stream` (NO user_id in WebSocket URL).
2. Clients register short-lived, rotating Anonymous Delivery Tokens (`delivery_token`).
3. Outbound packets are addressed exclusively to `delivery_token`.
4. The Relay Server NEVER knows who the sender is (anonymous socket) AND NEVER knows who the recipient is (rotating delivery token).

Also doubles as:
- A signaling passthrough for NAT-traversal handshakes ("p2p_signal" messages):
  the relay just forwards an opaque payload by delivery_token, same as sealed
  packets, so peers can exchange STUN-discovered endpoints before switching to
  direct UDP. The relay never inspects P2P signal contents beyond routing.
- A short-lived store-and-forward queue: if a delivery_token is briefly
  offline, packets are held (bounded, TTL-limited) instead of being dropped,
  and flushed to that socket the moment it re-registers.
"""

import asyncio
import json
import logging
import secrets
import time
from typing import Dict, List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
import uvicorn

logging.basicConfig(level=logging.INFO, format="%(asctime)s [RELAY-SEALED] %(message)s")
logger = logging.getLogger("SealedRelayServer")

app = FastAPI(title="Privacy Messenger True Sealed-Sender Relay Server")

# Mapping: delivery_token -> WebSocket
token_sockets: Dict[str, WebSocket] = {}

# ─── Store-and-forward queue for briefly-offline recipients ──────────────────
QUEUE_TTL_SECONDS = 15 * 60   # drop anything older than 15 minutes
QUEUE_MAX_PER_TOKEN = 50      # cap per-token backlog (defends against abuse)
pending_queue: Dict[str, List[dict]] = {}


def _queue_packet(delivery_token: str, envelope: dict):
    bucket = pending_queue.setdefault(delivery_token, [])
    bucket.append({"ts": time.time(), "envelope": envelope})
    if len(bucket) > QUEUE_MAX_PER_TOKEN:
        del bucket[: len(bucket) - QUEUE_MAX_PER_TOKEN]


async def _flush_queue(delivery_token: str, ws: WebSocket):
    bucket = pending_queue.pop(delivery_token, None)
    if not bucket:
        return
    now = time.time()
    delivered = 0
    for item in bucket:
        if now - item["ts"] > QUEUE_TTL_SECONDS:
            continue
        await ws.send_json(item["envelope"])
        delivered += 1
    if delivered:
        logger.info(f"[Queue] Flushed {delivered} queued packet(s) to {delivery_token[:8]}...")


class RegisterTokenReq(BaseModel):
    delivery_token: str

@app.websocket("/relay/stream")
async def anonymous_relay_endpoint(ws: WebSocket):
    """
    Anonymous WebSocket Endpoint.
    Does NOT accept user_id in URL or headers.
    """
    await ws.accept()
    registered_tokens = set()
    logger.info("Anonymous client connected to relay stream")
    
    try:
        while True:
            raw_text = await ws.receive_text()
            data = json.loads(raw_text)
            msg_type = data.get("type")
            
            if msg_type == "register_token":
                token = data.get("delivery_token")
                if token:
                    token_sockets[token] = ws
                    registered_tokens.add(token)
                    logger.info(f"Registered anonymous delivery token: {token[:8]}...")
                    await ws.send_json({"type": "token_registered", "delivery_token": token})
                    await _flush_queue(token, ws)

            elif msg_type == "sealed_packet":
                delivery_token = data.get("delivery_token")
                packet = data.get("packet")

                if delivery_token and packet:
                    envelope = {
                        "type": "incoming_sealed_packet",
                        "delivery_token": delivery_token,
                        "packet": packet
                    }
                    target_ws = token_sockets.get(delivery_token)
                    if target_ws:
                        # Forward packet over anonymous stream to recipient token
                        await target_ws.send_json(envelope)
                        logger.info(f"Forwarded Sealed E2EE packet to delivery token: {delivery_token[:8]}...")
                    else:
                        _queue_packet(delivery_token, envelope)
                        logger.info(f"Delivery token {delivery_token[:8]}... offline. Queued packet ({QUEUE_TTL_SECONDS//60}min TTL).")
                        await ws.send_json({"type": "delivery_status", "delivery_token": delivery_token, "status": "queued"})

            elif msg_type == "p2p_signal":
                # Opaque NAT-traversal handshake passthrough (STUN endpoints etc.)
                # Same addressing/queueing as sealed_packet, but never treated as a message.
                delivery_token = data.get("delivery_token")
                signal = data.get("signal")
                if delivery_token and signal:
                    envelope = {
                        "type": "incoming_p2p_signal",
                        "delivery_token": delivery_token,
                        "signal": signal
                    }
                    target_ws = token_sockets.get(delivery_token)
                    if target_ws:
                        await target_ws.send_json(envelope)
                        logger.info(f"Forwarded P2P signal to delivery token: {delivery_token[:8]}...")
                    else:
                        _queue_packet(delivery_token, envelope)
                        logger.info(f"Delivery token {delivery_token[:8]}... offline. Queued P2P signal.")

    except WebSocketDisconnect:
        for t in registered_tokens:
            token_sockets.pop(t, None)
        logger.info(f"Anonymous client disconnected (Cleaned up {len(registered_tokens)} tokens)")


async def _queue_janitor():
    """Prunes expired queue entries for tokens that never reconnect, so memory can't grow unbounded."""
    while True:
        await asyncio.sleep(60)
        now = time.time()
        for token in list(pending_queue.keys()):
            bucket = [item for item in pending_queue[token] if now - item["ts"] <= QUEUE_TTL_SECONDS]
            if bucket:
                pending_queue[token] = bucket
            else:
                pending_queue.pop(token, None)


@app.on_event("startup")
async def on_startup():
    asyncio.create_task(_queue_janitor())


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=49156, log_level="info")
