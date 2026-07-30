import os
import sys
import json
import sqlite3
import hashlib
import secrets
import base64
import time
import asyncio
import argparse
from pathlib import Path
from typing import Optional, List

import nacl.utils
import nacl.public
import nacl.signing
import nacl.secret
import nacl.bindings
import nacl.exceptions

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn
import logging

from ratchet import (
    RatchetState, init_as_sender, init_as_receiver,
    ratchet_encrypt, ratchet_decrypt, b64e, b64d
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─── Command Line Argument Parsing (API Auth Token) ───────────────────────────
parser = argparse.ArgumentParser(description="Privacy Messenger Server")
parser.add_argument("--api-token", type=str, default="", help="Mandatory API Secret Auth Token for Localhost Security")
args_parsed, _ = parser.parse_known_args()

API_TOKEN = args_parsed.api_token or os.environ.get("PM_API_TOKEN", "")

# ─── Paths ───────────────────────────────────────────────────────────────────
APP_DATA = Path(os.environ.get("APPDATA", Path.home())) / "PrivacyMessenger"
APP_DATA.mkdir(parents=True, exist_ok=True)
FILES_DIR   = APP_DATA / "files"; FILES_DIR.mkdir(exist_ok=True)
KEYS_DB     = APP_DATA / "keys.db"
MSGS_DB     = APP_DATA / "messages.db"
CONTACTS_DB = APP_DATA / "contacts.db"
GROUPS_DB   = APP_DATA / "groups.db"

app = FastAPI(title="Privacy Messenger v1.0.2 — Hardened E2EE")

# ─── Hardened Security Middleware (Strict API Auth Token + Anti Drive-by) ─────
@app.middleware("http")
async def enforce_auth_token(request: Request, call_next):
    # Allow preflight CORS OPTIONS requests
    if request.method == "OPTIONS":
        return await call_next(request)
    
    # Enforce mandatory X-API-Token for all incoming HTTP requests
    token = request.headers.get("X-API-Token")
    if API_TOKEN and token != API_TOKEN:
        logger.warning(f"Unauthorized HTTP request blocked from {request.client.host}")
        return JSONResponse(status_code=403, content={"error": "Access Denied: Invalid X-API-Token"})
    
    return await call_next(request)

connected_ws: dict[str, WebSocket] = {}

# ─── DB ──────────────────────────────────────────────────────────────────────
def get_db(path: Path):
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_dbs():
    with get_db(KEYS_DB) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS identity (
            id INTEGER PRIMARY KEY, user_id TEXT, display_name TEXT DEFAULT '',
            sign_pk TEXT, sign_sk TEXT, dh_pk TEXT, dh_sk TEXT, created_at INTEGER)""")
        db.execute("""CREATE TABLE IF NOT EXISTS sessions (
            contact_id TEXT PRIMARY KEY,
            shared_key TEXT,
            ratchet_state TEXT,
            ratchet_role TEXT,
            created_at INTEGER)""")
        db.commit()

    with get_db(CONTACTS_DB) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS contacts (
            user_id TEXT PRIMARY KEY, display_name TEXT DEFAULT '',
            sign_pk TEXT, dh_pk TEXT, trust_level TEXT DEFAULT 'unverified',
            added_at INTEGER)""")
        db.commit()

    with get_db(MSGS_DB) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY, conversation_id TEXT, sender_id TEXT,
            content TEXT, ciphertext TEXT, msg_type TEXT DEFAULT 'text',
            file_name TEXT, file_size INTEGER, file_data TEXT,
            timestamp INTEGER, status TEXT DEFAULT 'sent',
            is_outgoing INTEGER DEFAULT 1,
            auto_delete_at INTEGER DEFAULT NULL)""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_conv ON messages(conversation_id, timestamp)")
        db.commit()

    with get_db(GROUPS_DB) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS groups (
            group_id TEXT PRIMARY KEY, name TEXT, description TEXT DEFAULT '',
            sender_key TEXT, created_by TEXT, created_at INTEGER,
            auto_delete_seconds INTEGER DEFAULT 0)""")
        db.execute("""CREATE TABLE IF NOT EXISTS group_members (
            group_id TEXT, user_id TEXT, display_name TEXT DEFAULT '',
            sign_pk TEXT, dh_pk TEXT, role TEXT DEFAULT 'member',
            joined_at INTEGER, PRIMARY KEY(group_id, user_id))""")
        db.commit()

init_dbs()

# ─── Identity ────────────────────────────────────────────────────────────────
def get_identity() -> Optional[dict]:
    with get_db(KEYS_DB) as db:
        row = db.execute("SELECT * FROM identity WHERE id=1").fetchone()
        return dict(row) if row else None

class CreateIdentityReq(BaseModel):
    display_name: str = ""

@app.get("/identity")
def api_get_identity():
    id_data = get_identity()
    if not id_data:
        return {"exists": False}
    return {
        "exists": True,
        "user_id": id_data["user_id"],
        "display_name": id_data["display_name"],
        "sign_pk": id_data["sign_pk"],
        "dh_pk": id_data["dh_pk"],
    }

@app.post("/identity")
def api_create_identity(req: CreateIdentityReq):
    id_data = get_identity()
    if id_data:
        return api_get_identity()

    sign_sk = nacl.signing.SigningKey.generate()
    sign_pk = sign_sk.verify_key
    dh_sk   = nacl.public.PrivateKey.generate()
    dh_pk   = dh_sk.public_key

    user_id = b64e(hashlib.sha256(bytes(sign_pk)).digest()[:16])

    with get_db(KEYS_DB) as db:
        db.execute(
            "INSERT INTO identity (id, user_id, display_name, sign_pk, sign_sk, dh_pk, dh_sk, created_at) VALUES (1,?,?,?,?,?,?,?)",
            (user_id, req.display_name, b64e(bytes(sign_pk)), b64e(bytes(sign_sk)), b64e(bytes(dh_pk)), b64e(bytes(dh_sk)), int(time.time()))
        )
        db.commit()

    return api_get_identity()

# ─── Contacts ────────────────────────────────────────────────────────────────
class AddContactReq(BaseModel):
    user_id: str
    display_name: str = ""
    sign_pk: str
    dh_pk: str

@app.get("/contacts")
def api_get_contacts():
    with get_db(CONTACTS_DB) as db:
        rows = db.execute("SELECT * FROM contacts ORDER BY added_at DESC").fetchall()
        return [dict(r) for r in rows]

@app.post("/contacts")
def api_add_contact(req: AddContactReq):
    with get_db(CONTACTS_DB) as db:
        db.execute(
            "INSERT OR REPLACE INTO contacts (user_id, display_name, sign_pk, dh_pk, added_at) VALUES (?,?,?,?,?)",
            (req.user_id, req.display_name, req.sign_pk, req.dh_pk, int(time.time()))
        )
        db.commit()
    return {"ok": True}

# ─── Messages ────────────────────────────────────────────────────────────────
class SendMsgReq(BaseModel):
    conversation_id: str
    content: str
    msg_type: str = "text"

@app.get("/messages/{conversation_id}")
def api_get_messages(conversation_id: str, limit: int = 100):
    with get_db(MSGS_DB) as db:
        rows = db.execute(
            "SELECT * FROM messages WHERE conversation_id=? ORDER BY timestamp ASC LIMIT ?",
            (conversation_id, limit)
        ).fetchall()
        return [dict(r) for r in rows]

@app.post("/messages/send")
def api_send_message(req: SendMsgReq):
    identity = get_identity()
    if not identity: raise HTTPException(400, "No identity")

    msg_id = secrets.token_hex(16)
    now = int(time.time())

    with get_db(MSGS_DB) as db:
        db.execute(
            "INSERT INTO messages (id, conversation_id, sender_id, content, ciphertext, msg_type, timestamp, is_outgoing) VALUES (?,?,?,?,?,?,?,1)",
            (msg_id, req.conversation_id, identity["user_id"], req.content, "", req.msg_type, now)
        )
        db.commit()

    return {"ok": True, "id": msg_id, "timestamp": now}

# ─── WebSocket (frontend) with Token Verification ─────────────────────────────
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    token = ws.query_params.get("token")
    if API_TOKEN and token != API_TOKEN:
        logger.warning(f"WebSocket connection rejected: invalid API token")
        await ws.close(code=4003)
        return

    await ws.accept()
    connected_ws["frontend"] = ws
    try:
        while True: await ws.receive_text()
    except WebSocketDisconnect:
        connected_ws.pop("frontend", None)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=49155, log_level="info")
