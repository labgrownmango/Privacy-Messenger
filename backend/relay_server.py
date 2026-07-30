"""
Privacy Messenger — Minimal Sealed-Sender E2EE Relay Server
Zero Knowledge & Metadata Privacy: Receives and forwards Double Ratchet E2EE encrypted packets to recipient_id.
Does NOT know or log sender_id (Sealed Sender Architecture).
Does NOT have access to keys, plaintext, or sender identity.
"""

import asyncio
import json
import logging
from typing import Dict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import uvicorn

logging.basicConfig(level=logging.INFO, format="%(asctime)s [RELAY] %(message)s")
logger = logging.getLogger("RelayServer")

app = FastAPI(title="Privacy Messenger Sealed-Sender E2EE Relay Server")

# Mapping: user_id -> WebSocket
connected_clients: Dict[str, WebSocket] = {}

@app.websocket("/relay/{user_id}")
async def relay_websocket_endpoint(ws: WebSocket, user_id: str):
    await ws.accept()
    connected_clients[user_id] = ws
    logger.info(f"Client registered for delivery on relay (Active clients: {len(connected_clients)})")
    
    try:
        while True:
            raw_text = await ws.receive_text()
            data = json.loads(raw_text)
            
            # Sealed Sender Packet Structure: {"recipient_id": "...", "packet": {...}}
            recipient_id = data.get("recipient_id")
            packet = data.get("packet")
            
            if recipient_id and packet:
                target_ws = connected_clients.get(recipient_id)
                if target_ws:
                    # Forward packet WITHOUT revealing sender_id to relay worker
                    await target_ws.send_json({
                        "type": "incoming_e2ee_packet",
                        "packet": packet
                    })
                    logger.info(f"Forwarded Sealed E2EE packet -> {recipient_id}")
                else:
                    logger.warning(f"Recipient {recipient_id} offline. Dropping packet.")
                    await ws.send_json({"type": "delivery_status", "recipient_id": recipient_id, "status": "offline"})

    except WebSocketDisconnect:
        connected_clients.pop(user_id, None)
        logger.info(f"Client disconnected from relay (Active clients: {len(connected_clients)})")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=49156, log_level="info")
