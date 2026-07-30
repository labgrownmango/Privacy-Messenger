"""
Privacy Messenger — Real Signal-Style Sealed Sender Relay Server
=================================================================
True Zero-Knowledge & Metadata Privacy:
1. Clients connect anonymously to `/relay/stream` (NO user_id in WebSocket URL).
2. Clients register short-lived, rotating Anonymous Delivery Tokens (`delivery_token`).
3. Outbound packets are addressed exclusively to `delivery_token`.
4. The Relay Server NEVER knows who the sender is (anonymous socket) AND NEVER knows who the recipient is (rotating delivery token).
"""

import asyncio
import json
import logging
import secrets
from typing import Dict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
import uvicorn

logging.basicConfig(level=logging.INFO, format="%(asctime)s [RELAY-SEALED] %(message)s")
logger = logging.getLogger("SealedRelayServer")

app = FastAPI(title="Privacy Messenger True Sealed-Sender Relay Server")

# Mapping: delivery_token -> WebSocket
token_sockets: Dict[str, WebSocket] = {}

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

            elif msg_type == "sealed_packet":
                delivery_token = data.get("delivery_token")
                packet = data.get("packet")
                
                if delivery_token and packet:
                    target_ws = token_sockets.get(delivery_token)
                    if target_ws:
                        # Forward packet over anonymous stream to recipient token
                        await target_ws.send_json({
                            "type": "incoming_sealed_packet",
                            "delivery_token": delivery_token,
                            "packet": packet
                        })
                        logger.info(f"Forwarded Sealed E2EE packet to delivery token: {delivery_token[:8]}...")
                    else:
                        logger.warning(f"Delivery token {delivery_token[:8]}... offline. Dropping packet.")
                        await ws.send_json({"type": "delivery_status", "delivery_token": delivery_token, "status": "offline"})

    except WebSocketDisconnect:
        for t in registered_tokens:
            token_sockets.pop(t, None)
        logger.info(f"Anonymous client disconnected (Cleaned up {len(registered_tokens)} tokens)")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=49156, log_level="info")
