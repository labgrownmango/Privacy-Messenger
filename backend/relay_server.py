"""
Privacy Messenger — Minimal E2EE Relay Server
Zero Knowledge: Receives and forwards Double Ratchet E2EE encrypted packets between user_ids.
Does NOT have access to keys or plaintext.
"""

import asyncio
import json
import logging
from typing import Dict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import uvicorn

logging.basicConfig(level=logging.INFO, format="%(asctime)s [RELAY] %(message)s")
logger = logging.getLogger("RelayServer")

app = FastAPI(title="Privacy Messenger E2EE Relay Server")

# Mapping: user_id -> WebSocket
connected_clients: Dict[str, WebSocket] = {}

@app.websocket("/relay/{user_id}")
async def relay_websocket_endpoint(ws: WebSocket, user_id: str):
    await ws.accept()
    connected_clients[user_id] = ws
    logger.info(f"User connected to relay: {user_id} (Total active: {len(connected_clients)})")
    
    try:
        while True:
            raw_text = await ws.receive_text()
            data = json.loads(raw_text)
            
            # Packet structure: {"recipient_id": "...", "packet": {...}}
            recipient_id = data.get("recipient_id")
            packet = data.get("packet")
            
            if recipient_id and packet:
                target_ws = connected_clients.get(recipient_id)
                if target_ws:
                    await target_ws.send_json({
                        "type": "incoming_e2ee_packet",
                        "sender_id": user_id,
                        "packet": packet
                    })
                    logger.info(f"Forwarded E2EE packet from {user_id} -> {recipient_id}")
                else:
                    logger.warning(f"Recipient {recipient_id} not connected to relay. Dropping/queuing packet.")
                    await ws.send_json({"type": "delivery_status", "recipient_id": recipient_id, "status": "offline"})

    except WebSocketDisconnect:
        connected_clients.pop(user_id, None)
        logger.info(f"User disconnected from relay: {user_id} (Total active: {len(connected_clients)})")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=49156, log_level="info")
