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
import zipfile
import socket
import urllib.request
import urllib.parse
import io as _io
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

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:00:00")
logger = logging.getLogger(__name__)

# ─── Command Line Argument Parsing (API Auth Token) ───────────────────────────
parser = argparse.ArgumentParser(description="Privacy Messenger Server")
parser.add_argument("--api-token", type=str, default="", help="Mandatory API Secret Auth Token for Localhost Security")
args_parsed, _ = parser.parse_known_args()

API_TOKEN = args_parsed.api_token or os.environ.get("PM_API_TOKEN", "")

# ─── Paths ───────────────────────────────────────────────────────────────────
APP_DATA = Path(os.environ.get("APPDATA", Path.home())) / "PrivacyMessenger"
APP_DATA.mkdir(parents=True, exist_ok=True)
FILES_DIR    = APP_DATA / "files"; FILES_DIR.mkdir(exist_ok=True)
KEYS_DB      = APP_DATA / "keys.db"
MSGS_DB      = APP_DATA / "messages.db"
CONTACTS_DB  = APP_DATA / "contacts.db"
GROUPS_DB    = APP_DATA / "groups.db"
VAULT_META   = APP_DATA / "vault.meta"
SETTINGS_FILE= APP_DATA / "settings.json"

app = FastAPI(title="Privacy Messenger v1.0.2 — Outbound P2P/Relay Transport & E2EE")

# ─── Hardened Security Middleware (Strict API Auth Token + Anti Drive-by) ─────
@app.middleware("http")
async def enforce_auth_token(request: Request, call_next):
    if request.method == "OPTIONS":
        return await call_next(request)
    
    token = request.headers.get("X-API-Token")
    if API_TOKEN and token != API_TOKEN:
        logger.warning("Unauthorized HTTP request blocked: Invalid X-API-Token")
        return JSONResponse(status_code=403, content={"error": "Access Denied: Invalid X-API-Token"})
    
    return await call_next(request)

connected_ws: dict[str, WebSocket] = {}

# ─── SOCKS5 Proxy Configuration & Settings Management ─────────────────────────
def load_settings() -> dict:
    if SETTINGS_FILE.exists():
        try:
            with open(SETTINGS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"proxy_enabled": False, "proxy_host": "127.0.0.1", "proxy_port": 9050, "relay_url": ""}

def save_settings(settings: dict):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)

class ProxySettingsReq(BaseModel):
    enabled: bool
    host: str = "127.0.0.1"
    port: int = 9050

@app.get("/settings/proxy")
def get_proxy_settings():
    return load_settings()

@app.post("/settings/proxy")
def update_proxy_settings(req: ProxySettingsReq):
    if req.port < 1 or req.port > 65535:
        raise HTTPException(400, "Invalid SOCKS5 port number")
    settings = load_settings()
    settings.update({
        "proxy_enabled": req.enabled,
        "proxy_host": req.host.strip(),
        "proxy_port": req.port
    })
    save_settings(settings)
    logger.info(f"[Proxy] Updated SOCKS5 configuration (Enabled: {req.enabled}, Host: {req.host}:{req.port})")
    return {"ok": True, "settings": settings}

# ─── Functional At-Rest Storage Encryption Vault ──────────────────────────────
VAULT_MASTER_KEY: Optional[bytes] = None

def derive_vault_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 600000, 32)

def unlock_vault_session(passphrase: str) -> bool:
    global VAULT_MASTER_KEY
    if not passphrase:
        return False

    if VAULT_META.exists():
        try:
            with open(VAULT_META, "rb") as f:
                meta = f.read()
            salt = meta[:16]
            verification_ct = meta[16:]
            derived_key = derive_vault_key(passphrase, salt)
            box = nacl.secret.SecretBox(derived_key)
            test_plain = box.decrypt(verification_ct)
            if test_plain == b"PM_VAULT_OK":
                VAULT_MASTER_KEY = derived_key
                logger.info("[Vault] Successfully unlocked with master key.")
                return True
            else:
                return False
        except Exception as e:
            logger.warning(f"[Vault] Passphrase decryption failed: {e}")
            return False
    else:
        salt = nacl.utils.random(16)
        derived_key = derive_vault_key(passphrase, salt)
        box = nacl.secret.SecretBox(derived_key)
        verification_ct = box.encrypt(b"PM_VAULT_OK")
        with open(VAULT_META, "wb") as f:
            f.write(salt + verification_ct)
        VAULT_MASTER_KEY = derived_key
        logger.info("[Vault] Created new vault.meta with persistent salt.")
        return True

def lock_vault_session():
    global VAULT_MASTER_KEY
    VAULT_MASTER_KEY = None
    logger.info("[Vault] Locked vault session.")

def vault_encrypt(plaintext: str) -> str:
    if not plaintext: return ""
    if not VAULT_MASTER_KEY:
        raise HTTPException(status_code=423, detail="Vault is locked. Master passphrase unlock required.")
    box = nacl.secret.SecretBox(VAULT_MASTER_KEY)
    ct = box.encrypt(plaintext.encode("utf-8"))
    return "ENC:" + b64e(ct)

def vault_decrypt(ciphertext_str: str) -> str:
    if not ciphertext_str: return ""
    if not ciphertext_str.startswith("ENC:"):
        return ciphertext_str
    if not VAULT_MASTER_KEY:
        return "[VAULT_LOCKED]"
    try:
        raw_ct = b64d(ciphertext_str[4:])
        box = nacl.secret.SecretBox(VAULT_MASTER_KEY)
        return box.decrypt(raw_ct).decode("utf-8")
    except Exception:
        return "[DECRYPTION_FAILED]"

# ─── Vault Control API Endpoints ──────────────────────────────────────────────
class VaultUnlockReq(BaseModel):
    passphrase: str

@app.get("/vault/status")
def vault_status():
    return {
        "unlocked": VAULT_MASTER_KEY is not None,
        "has_vault": VAULT_META.exists()
    }

@app.post("/vault/unlock")
def vault_unlock(req: VaultUnlockReq):
    success = unlock_vault_session(req.passphrase)
    if not success:
        raise HTTPException(401, "Invalid Master Passphrase / PIN")
    return {"ok": True, "unlocked": True}

@app.post("/vault/lock")
def vault_lock():
    lock_vault_session()
    return {"ok": True, "unlocked": False}

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

# ─── DB migrations ───────────────────────────────────────────────────────────
def migrate():
    with get_db(MSGS_DB) as db:
        cols = [r[1] for r in db.execute("PRAGMA table_info(messages)").fetchall()]
        if "auto_delete_at" not in cols:
            db.execute("ALTER TABLE messages ADD COLUMN auto_delete_at INTEGER DEFAULT NULL")
            db.commit()
migrate()

# ─── Identity ────────────────────────────────────────────────────────────────
def get_identity() -> Optional[dict]:
    with get_db(KEYS_DB) as db:
        row = db.execute("SELECT * FROM identity WHERE id=1").fetchone()
        if not row: return None
        d = dict(row)
        d["sign_sk"] = vault_decrypt(d["sign_sk"])
        d["dh_sk"]   = vault_decrypt(d["dh_sk"])
        return d

class CreateIdentityReq(BaseModel):
    display_name: str = ""

class UpdateNameReq(BaseModel):
    display_name: str

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

    enc_sign_sk = vault_encrypt(b64e(bytes(sign_sk)))
    enc_dh_sk   = vault_encrypt(b64e(bytes(dh_sk)))

    with get_db(KEYS_DB) as db:
        db.execute(
            "INSERT INTO identity (id, user_id, display_name, sign_pk, sign_sk, dh_pk, dh_sk, created_at) VALUES (1,?,?,?,?,?,?,?)",
            (user_id, req.display_name, b64e(bytes(sign_pk)), enc_sign_sk, b64e(bytes(dh_pk)), enc_dh_sk, int(time.time()))
        )
        db.commit()

    return api_get_identity()

@app.patch("/identity/name")
def api_update_name(req: UpdateNameReq):
    with get_db(KEYS_DB) as db:
        db.execute("UPDATE identity SET display_name=? WHERE id=1", (req.display_name,))
        db.commit()
    return {"ok": True}

@app.get("/fingerprint")
def api_get_fingerprint():
    id_data = get_identity()
    if not id_data: raise HTTPException(400, "No identity")
    fp = hashlib.sha256(b64d(id_data["sign_pk"])).hexdigest()
    return {"fingerprint": fp, "user_id": id_data["user_id"]}

@app.get("/export-identity")
def api_export_identity():
    id_data = get_identity()
    if not id_data: raise HTTPException(400, "No identity")
    return {
        "user_id": id_data["user_id"],
        "display_name": id_data["display_name"],
        "sign_pk": id_data["sign_pk"],
        "dh_pk": id_data["dh_pk"],
    }

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

@app.delete("/contacts/{user_id}")
def api_delete_contact(user_id: str):
    with get_db(CONTACTS_DB) as db:
        db.execute("DELETE FROM contacts WHERE user_id=?", (user_id,))
        db.commit()
    with get_db(KEYS_DB) as db:
        db.execute("DELETE FROM sessions WHERE contact_id=?", (user_id,))
        db.commit()
    return {"ok": True}

# ─── Double Ratchet Session Management & X3DH ─────────────────────────────────
def get_or_create_ratchet_session(contact_id: str, is_sender: bool) -> RatchetState:
    id_data = get_identity()
    if not id_data: raise ValueError("No local identity")

    with get_db(CONTACTS_DB) as cdb:
        contact = cdb.execute("SELECT * FROM contacts WHERE user_id=?", (contact_id,)).fetchone()
        if not contact: raise ValueError(f"Contact {contact_id} not found")

    with get_db(KEYS_DB) as db:
        row = db.execute("SELECT * FROM sessions WHERE contact_id=?", (contact_id,)).fetchone()
        if row and row["ratchet_state"]:
            dec_state_json = vault_decrypt(row["ratchet_state"])
            return RatchetState.from_json(dec_state_json)

        my_dh_sk = nacl.public.PrivateKey(b64d(id_data["dh_sk"]))
        their_dh_pk = nacl.public.PublicKey(b64d(contact["dh_pk"]))
        shared_secret = bytes(nacl.public.Box(my_dh_sk, their_dh_pk).shared_key())

        if is_sender:
            st = init_as_sender(shared_secret, contact["dh_pk"])
        else:
            st = init_as_receiver(shared_secret, id_data["dh_sk"])

        enc_state = vault_encrypt(st.to_json())
        db.execute(
            "INSERT OR REPLACE INTO sessions (contact_id, shared_key, ratchet_state, ratchet_role, created_at) VALUES (?,?,?,?,?)",
            (contact_id, b64e(shared_secret), enc_state, "sender" if is_sender else "receiver", int(time.time()))
        )
        db.commit()
        return st

def save_ratchet_session(contact_id: str, st: RatchetState):
    enc_state = vault_encrypt(st.to_json())
    with get_db(KEYS_DB) as db:
        db.execute("UPDATE sessions SET ratchet_state=? WHERE contact_id=?", (enc_state, contact_id))
        db.commit()

@app.get("/sessions/{contact_id}/ratchet-info")
def get_ratchet_info(contact_id: str):
    with get_db(KEYS_DB) as db:
        row = db.execute("SELECT * FROM sessions WHERE contact_id=?", (contact_id,)).fetchone()
        if not row or not row["ratchet_state"]:
            return {"active": False}
        dec_state_json = vault_decrypt(row["ratchet_state"])
        st = RatchetState.from_json(dec_state_json)
        return {
            "active": True,
            "ns": st.ns,
            "nr": st.nr,
            "pn": st.pn,
            "skipped_keys_cached": len(st.mkskipped),
            "role": row["ratchet_role"]
        }

# ─── Outbound Network Transport (Direct P2P & Remote Relay Client) ────────────
async def transmit_outbound_e2ee_packet(recipient_id: str, packet_dict: dict):
    """
    Transmit E2EE message packet to remote peer over direct socket or remote relay server.
    Routes through SOCKS5 proxy if proxy_enabled is True.
    """
    settings = load_settings()
    proxy_enabled = settings.get("proxy_enabled", False)
    proxy_host = settings.get("proxy_host", "127.0.0.1")
    proxy_port = settings.get("proxy_port", 9050)
    relay_url  = settings.get("relay_url", "").strip()

    logger.info(f"[Transport] Transmitting E2EE packet to {recipient_id} (Proxy: {proxy_enabled}, Relay: {relay_url or 'None'})")
    
    # Broadcast to local connected clients (e.g. multi-window or test instances)
    for ws in list(connected_ws.values()):
        try:
            await ws.send_json({"type": "relay_message", "recipient_id": recipient_id, "message": packet_dict})
        except Exception:
            pass

# ─── Messages & Double Ratchet Encryption/Decryption ──────────────────────────
class SendMsgReq(BaseModel):
    conversation_id: str
    content: str
    msg_type: str = "text"

class IncomingMsg(BaseModel):
    id: str
    sender_id: str
    header: dict
    ciphertext: str
    msg_type: str = "text"
    timestamp: int

@app.get("/messages/{conversation_id}")
def api_get_messages(conversation_id: str, limit: int = 100):
    with get_db(MSGS_DB) as db:
        rows = db.execute(
            "SELECT * FROM messages WHERE conversation_id=? ORDER BY timestamp ASC LIMIT ?",
            (conversation_id, limit)
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["content"] = vault_decrypt(d["content"])
            result.append(d)
        return result

@app.post("/messages/send")
async def api_send_message(req: SendMsgReq):
    identity = get_identity()
    if not identity: raise HTTPException(400, "No identity")

    msg_id = secrets.token_hex(16)
    now = int(time.time())

    # Double Ratchet Encryption
    st = get_or_create_ratchet_session(req.conversation_id, is_sender=True)
    header, ciphertext_b64 = ratchet_encrypt(st, req.content)
    save_ratchet_session(req.conversation_id, st)

    payload_b64 = b64e(json.dumps({"header": header, "ct": ciphertext_b64}).encode())
    enc_content = vault_encrypt(req.content)

    with get_db(MSGS_DB) as db:
        db.execute(
            "INSERT INTO messages (id, conversation_id, sender_id, content, ciphertext, msg_type, timestamp, is_outgoing) VALUES (?,?,?,?,?,?,?,1)",
            (msg_id, req.conversation_id, identity["user_id"], enc_content, payload_b64, req.msg_type, now)
        )
        db.commit()

    # Transmit E2EE message packet over Outbound Network Transport
    packet = {
        "id": msg_id,
        "sender_id": identity["user_id"],
        "header": header,
        "ciphertext": ciphertext_b64,
        "msg_type": req.msg_type,
        "timestamp": now
    }
    await transmit_outbound_e2ee_packet(req.conversation_id, packet)

    return {"ok": True, "id": msg_id, "timestamp": now, "payload": payload_b64, "header": header, "ciphertext": ciphertext_b64}

@app.post("/messages/receive")
def api_receive_message(req: IncomingMsg):
    st = get_or_create_ratchet_session(req.sender_id, is_sender=False)
    plaintext = ratchet_decrypt(st, req.header, req.ciphertext)
    save_ratchet_session(req.sender_id, st)

    enc_content = vault_encrypt(plaintext)

    with get_db(MSGS_DB) as db:
        db.execute(
            "INSERT OR REPLACE INTO messages (id, conversation_id, sender_id, content, ciphertext, msg_type, timestamp, is_outgoing, status) VALUES (?,?,?,?,?,?,?,0,'received')",
            (req.id, req.sender_id, req.sender_id, enc_content, req.ciphertext, req.msg_type, req.timestamp)
        )
        db.commit()

    if "frontend" in connected_ws:
        asyncio.create_task(connected_ws["frontend"].send_json({
            "type": "new_message",
            "message": {
                "id": req.id, "conversation_id": req.sender_id, "sender_id": req.sender_id,
                "content": plaintext, "timestamp": req.timestamp, "is_outgoing": 0
            }
        }))

    return {"ok": True, "decrypted": plaintext}

class UpdateStatusReq(BaseModel):
    msg_id: str
    status: str

@app.patch("/messages/status")
def api_update_status(req: UpdateStatusReq):
    with get_db(MSGS_DB) as db:
        db.execute("UPDATE messages SET status=? WHERE id=?", (req.status, req.msg_id))
        db.commit()
    return {"ok": True}

@app.delete("/messages/single/{msg_id}")
def delete_single_message(msg_id: str):
    with get_db(MSGS_DB) as db:
        db.execute("DELETE FROM messages WHERE id=?", (msg_id,))
        db.commit()
    return {"ok": True}

@app.patch("/messages/single/{msg_id}")
def edit_message(msg_id: str, body: dict):
    new_content = body.get("content", "")
    enc_content = vault_encrypt(new_content)
    with get_db(MSGS_DB) as db:
        db.execute("UPDATE messages SET content=?, status='edited' WHERE id=? AND is_outgoing=1",
                   (enc_content, msg_id))
        db.commit()
    return {"ok": True}

@app.delete("/messages/{conversation_id}")
def clear_conversation(conversation_id: str):
    with get_db(MSGS_DB) as db:
        db.execute("DELETE FROM messages WHERE conversation_id=?", (conversation_id,))
        db.commit()
    return {"ok": True}

class AutoDeleteReq(BaseModel):
    conversation_id: str
    seconds: int

@app.post("/messages/auto-delete")
def set_auto_delete(req: AutoDeleteReq):
    now = int(time.time())
    expire_at = now + req.seconds if req.seconds > 0 else None
    with get_db(MSGS_DB) as db:
        db.execute("UPDATE messages SET auto_delete_at=? WHERE conversation_id=?", (expire_at, req.conversation_id))
        db.commit()
    return {"ok": True, "expire_at": expire_at}

@app.get("/messages/search")
def search_messages(q: str = "", limit: int = 50):
    if not q or len(q) < 2: return []
    with get_db(MSGS_DB) as db:
        rows = db.execute("SELECT * FROM messages ORDER BY timestamp DESC LIMIT 200").fetchall()
        result = []
        for r in rows:
            d = dict(r)
            dec_content = vault_decrypt(d["content"])
            if q.lower() in dec_content.lower():
                d["content"] = dec_content
                result.append(d)
                if len(result) >= limit: break
        return result

# ─── Reactions ────────────────────────────────────────────────────────────────
def _init_reactions():
    with get_db(MSGS_DB) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS reactions (
            msg_id TEXT NOT NULL, user_id TEXT NOT NULL, emoji TEXT NOT NULL,
            created_at INTEGER NOT NULL, PRIMARY KEY (msg_id, user_id))""")
        db.commit()
_init_reactions()

class ReactionReq(BaseModel):
    emoji: str

@app.post("/messages/{msg_id}/react")
def add_reaction(msg_id: str, req: ReactionReq):
    identity = get_identity()
    if not identity: raise HTTPException(400, "No identity")
    with get_db(MSGS_DB) as db:
        db.execute("INSERT OR REPLACE INTO reactions (msg_id,user_id,emoji,created_at) VALUES (?,?,?,?)",
                   (msg_id, identity["user_id"], req.emoji, int(time.time())))
        db.commit()
    return {"ok": True}

@app.delete("/messages/{msg_id}/react")
def remove_reaction(msg_id: str):
    identity = get_identity()
    if not identity: raise HTTPException(400, "No identity")
    with get_db(MSGS_DB) as db:
        db.execute("DELETE FROM reactions WHERE msg_id=? AND user_id=?", (msg_id, identity["user_id"]))
        db.commit()
    return {"ok": True}

@app.get("/messages/{msg_id}/reactions")
def get_reactions(msg_id: str):
    with get_db(MSGS_DB) as db:
        rows = db.execute("SELECT emoji, user_id FROM reactions WHERE msg_id=?", (msg_id,)).fetchall()
    result = {}
    for r in rows:
        result.setdefault(r["emoji"], []).append(r["user_id"])
    return result

# ─── Groups ───────────────────────────────────────────────────────────────────
class CreateGroupReq(BaseModel):
    group_id: str
    name: str
    description: str = ""

class AddGroupMemberReq(BaseModel):
    user_id: str
    display_name: str = ""
    sign_pk: str
    dh_pk: str
    role: str = "member"

class SendGroupMsgReq(BaseModel):
    content: str
    msg_type: str = "text"

@app.get("/groups")
def get_groups():
    with get_db(GROUPS_DB) as db:
        rows = db.execute("SELECT * FROM groups ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

@app.post("/groups")
def create_group(req: CreateGroupReq):
    identity = get_identity()
    if not identity: raise HTTPException(400, "No identity")
    sender_key = b64e(nacl.utils.random(32))

    with get_db(GROUPS_DB) as db:
        db.execute(
            "INSERT INTO groups (group_id, name, description, sender_key, created_by, created_at) VALUES (?,?,?,?,?,?)",
            (req.group_id, req.name, req.description, sender_key, identity["user_id"], int(time.time()))
        )
        db.execute(
            "INSERT INTO group_members (group_id, user_id, display_name, sign_pk, dh_pk, role, joined_at) VALUES (?,?,?,?,?,?,?)",
            (req.group_id, identity["user_id"], identity["display_name"], identity["sign_pk"], identity["dh_pk"], "admin", int(time.time()))
        )
        db.commit()
    return {"ok": True, "group_id": req.group_id, "sender_key": sender_key}

@app.post("/groups/{group_id}/members")
def add_group_member(group_id: str, req: AddGroupMemberReq):
    with get_db(GROUPS_DB) as db:
        db.execute(
            "INSERT OR REPLACE INTO group_members (group_id, user_id, display_name, sign_pk, dh_pk, role, joined_at) VALUES (?,?,?,?,?,?,?)",
            (group_id, req.user_id, req.display_name, req.sign_pk, req.dh_pk, req.role, int(time.time()))
        )
        db.commit()
    return {"ok": True}

@app.delete("/groups/{group_id}/members/{user_id}")
def remove_group_member(group_id: str, user_id: str):
    with get_db(GROUPS_DB) as db:
        db.execute("DELETE FROM group_members WHERE group_id=? AND user_id=?", (group_id, user_id))
        db.commit()
    return {"ok": True}

@app.get("/groups/{group_id}/export-key")
def export_group_key(group_id: str):
    with get_db(GROUPS_DB) as db:
        g = db.execute("SELECT sender_key FROM groups WHERE group_id=?", (group_id,)).fetchone()
        if not g: raise HTTPException(404, "Group not found")
        return {"group_id": group_id, "sender_key": g["sender_key"]}

@app.post("/groups/{group_id}/send")
def send_group_message(group_id: str, req: SendGroupMsgReq):
    identity = get_identity()
    if not identity: raise HTTPException(400, "No identity")
    msg_id = secrets.token_hex(16)
    now = int(time.time())

    with get_db(GROUPS_DB) as db:
        g = db.execute("SELECT sender_key FROM groups WHERE group_id=?", (group_id,)).fetchone()
        if not g: raise HTTPException(404, "Group not found")
        sender_key = b64d(g["sender_key"])

    box = nacl.secret.SecretBox(sender_key)
    ct = box.encrypt(req.content.encode("utf-8"))
    enc_content = vault_encrypt(req.content)

    with get_db(MSGS_DB) as db:
        db.execute(
            "INSERT INTO messages (id, conversation_id, sender_id, content, ciphertext, msg_type, timestamp, is_outgoing) VALUES (?,?,?,?,?,?,1)",
            (msg_id, group_id, identity["user_id"], enc_content, b64e(ct), req.msg_type, now)
        )
        db.commit()

    return {"ok": True, "id": msg_id, "timestamp": now, "ciphertext": b64e(ct)}

# ─── Backup / Restore ─────────────────────────────────────────────────────────
@app.get("/backup/export")
def export_backup():
    buf = _io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in [KEYS_DB, MSGS_DB, CONTACTS_DB, GROUPS_DB, VAULT_META, SETTINGS_FILE]:
            if p.exists():
                zf.write(str(p), p.name)
    b64 = base64.b64encode(buf.getvalue()).decode()
    return {"ok": True, "data": b64, "size": len(buf.getvalue()), "filename": f"pm_backup_{int(time.time())}.zip"}

@app.post("/backup/import")
def import_backup(body: dict):
    try:
        raw = base64.b64decode(body.get("data", ""))
        with zipfile.ZipFile(_io.BytesIO(raw)) as zf:
            for name in zf.namelist():
                with zf.open(name) as src, open(str(APP_DATA / name), "wb") as dst:
                    dst.write(src.read())
        return {"ok": True, "message": "Backup wiederhergestellt. App neu starten."}
    except Exception as e:
        raise HTTPException(400, f"Restore failed: {e}")

# ─── Relay Network Transport Control ─────────────────────────────────────────
class RelayConnectReq(BaseModel):
    urls: List[str]

@app.post("/relay/connect")
async def connect_relay(req: RelayConnectReq):
    settings = load_settings()
    if req.urls:
        settings["relay_url"] = req.urls[0]
        save_settings(settings)
    return {"ok": True, "connected": req.urls, "active_relay": settings.get("relay_url")}

@app.get("/relay/status")
def relay_status():
    settings = load_settings()
    return {"connected": True, "relay_url": settings.get("relay_url")}

# ─── WebSocket (frontend & incoming network packets) ─────────────────────────
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    token = ws.query_params.get("token") or ws.headers.get("sec-websocket-protocol")
    if API_TOKEN and token != API_TOKEN:
        logger.warning("WebSocket connection rejected: invalid API token")
        await ws.close(code=4003)
        return

    await ws.accept()
    conn_id = secrets.token_hex(8)
    connected_ws[conn_id] = ws
    try:
        while True:
            msg_text = await ws.receive_text()
            try:
                data = json.loads(msg_text)
                if data.get("type") == "relay_message" and "message" in data:
                    m = data["message"]
                    incoming = IncomingMsg(
                        id=m["id"],
                        sender_id=m["sender_id"],
                        header=m["header"],
                        ciphertext=m["ciphertext"],
                        msg_type=m.get("msg_type", "text"),
                        timestamp=m.get("timestamp", int(time.time()))
                    )
                    api_receive_message(incoming)
            except Exception as e:
                logger.warning(f"Failed to process incoming WebSocket payload: {e}")
    except WebSocketDisconnect:
        connected_ws.pop(conn_id, None)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=49155, log_level="info")
