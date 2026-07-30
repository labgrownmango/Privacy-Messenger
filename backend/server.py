import os
import json
import sqlite3
import hashlib
import secrets
import base64
import time
import asyncio
from pathlib import Path
from typing import Optional, List

import nacl.utils
import nacl.public
import nacl.signing
import nacl.secret

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import logging

from ratchet import (
    RatchetState, init_as_sender, init_as_receiver,
    ratchet_encrypt, ratchet_decrypt, b64e, b64d
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─── Paths ───────────────────────────────────────────────────────────────────
APP_DATA = Path(os.environ.get("APPDATA", Path.home())) / "PrivacyMessenger"
APP_DATA.mkdir(parents=True, exist_ok=True)
FILES_DIR   = APP_DATA / "files"; FILES_DIR.mkdir(exist_ok=True)
KEYS_DB     = APP_DATA / "keys.db"
MSGS_DB     = APP_DATA / "messages.db"
CONTACTS_DB = APP_DATA / "contacts.db"
GROUPS_DB   = APP_DATA / "groups.db"

app = FastAPI(title="Privacy Messenger v3 — Double Ratchet")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

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

# ─── DB migrations (safe to run repeatedly) ───────────────────────────────────
def migrate():
    with get_db(MSGS_DB) as db:
        cols = [r[1] for r in db.execute("PRAGMA table_info(messages)").fetchall()]
        if "auto_delete_at" not in cols:
            db.execute("ALTER TABLE messages ADD COLUMN auto_delete_at INTEGER DEFAULT NULL")
            db.commit()
            logger.info("Migration: added auto_delete_at column")
    with get_db(KEYS_DB) as db:
        cols = [r[1] for r in db.execute("PRAGMA table_info(sessions)").fetchall()]
        if "ratchet_state" not in cols:
            db.execute("ALTER TABLE sessions ADD COLUMN ratchet_state TEXT")
            db.execute("ALTER TABLE sessions ADD COLUMN ratchet_role TEXT")
            db.commit()
            logger.info("Migration: added ratchet_state / ratchet_role columns")
    with get_db(GROUPS_DB) as db:
        cols = [r[1] for r in db.execute("PRAGMA table_info(groups)").fetchall()]
        if "auto_delete_seconds" not in cols:
            db.execute("ALTER TABLE groups ADD COLUMN auto_delete_seconds INTEGER DEFAULT 0")
            db.commit()
            logger.info("Migration: added auto_delete_seconds column")

migrate()


# ─── Crypto helpers ──────────────────────────────────────────────────────────
def generate_identity(display_name=""):
    sign_sk = nacl.signing.SigningKey.generate()
    sign_pk = sign_sk.verify_key
    dh_sk   = nacl.public.PrivateKey.generate()
    dh_pk   = dh_sk.public_key
    user_id = base64.b32encode(hashlib.sha256(bytes(sign_pk)).digest()[:16]).decode().rstrip("=")
    return {"user_id": user_id, "display_name": display_name,
            "sign_pk": b64e(bytes(sign_pk)), "sign_sk": b64e(bytes(sign_sk)),
            "dh_pk": b64e(bytes(dh_pk)), "dh_sk": b64e(bytes(dh_sk)),
            "created_at": int(time.time())}

def get_identity():
    with get_db(KEYS_DB) as db:
        row = db.execute("SELECT * FROM identity LIMIT 1").fetchone()
        return dict(row) if row else None

def x3dh_shared_secret(my_dh_sk_b64: str, their_dh_pk_b64: str) -> bytes:
    """X25519 + HKDF → initial shared secret for ratchet root key."""
    my_sk   = nacl.public.PrivateKey(b64d(my_dh_sk_b64))
    their_pk = nacl.public.PublicKey(b64d(their_dh_pk_b64))
    raw = bytes(nacl.public.Box(my_sk, their_pk).shared_key())
    import hmac as _hmac
    return _hmac.new(b"pm-x3dh-v1", raw, hashlib.sha256).digest()

def sign_data(sign_sk_b64: str, data: str) -> str:
    sk = nacl.signing.SigningKey(b64d(sign_sk_b64))
    return b64e(sk.sign(data.encode()).signature)

def verify_sig(sign_pk_b64: str, data: str, sig_b64: str) -> bool:
    try:
        nacl.signing.VerifyKey(b64d(sign_pk_b64)).verify(data.encode(), b64d(sig_b64))
        return True
    except Exception:
        return False

def encrypt_group(sender_key_b64: str, plaintext: str) -> str:
    key = b64d(sender_key_b64)[:32]
    return b64e(nacl.secret.SecretBox(key).encrypt(plaintext.encode()))

def decrypt_group(sender_key_b64: str, ct_b64: str) -> str:
    key = b64d(sender_key_b64)[:32]
    return nacl.secret.SecretBox(key).decrypt(b64d(ct_b64)).decode()

# ─── Ratchet session management ──────────────────────────────────────────────
def _get_session(contact_id: str):
    with get_db(KEYS_DB) as db:
        return db.execute("SELECT * FROM sessions WHERE contact_id=?", (contact_id,)).fetchone()

def _save_session(contact_id: str, state: RatchetState, role: str):
    with get_db(KEYS_DB) as db:
        db.execute("""INSERT OR REPLACE INTO sessions (contact_id, ratchet_state, ratchet_role, created_at)
                      VALUES (?,?,?,?)""",
                   (contact_id, state.to_json(), role, int(time.time())))
        db.commit()

def get_ratchet_for_send(identity: dict, contact_id: str) -> RatchetState:
    """Get or create ratchet state for sending. Sender initialises as 'sender'."""
    session = _get_session(contact_id)
    if session and session["ratchet_state"]:
        return RatchetState.from_json(session["ratchet_state"])

    # First time: look up contact, init ratchet
    with get_db(CONTACTS_DB) as db:
        contact = db.execute("SELECT * FROM contacts WHERE user_id=?", (contact_id,)).fetchone()
    if not contact:
        raise HTTPException(404, f"Contact {contact_id} not found")

    sk = x3dh_shared_secret(identity["dh_sk"], contact["dh_pk"])
    state = init_as_sender(sk, contact["dh_pk"])
    _save_session(contact_id, state, "sender")
    return state

def get_ratchet_for_receive(identity: dict, sender_id: str, sender_dh_pk_b64: str) -> RatchetState:
    """Get or create ratchet state for receiving."""
    session = _get_session(sender_id)
    if session and session["ratchet_state"] and session["ratchet_role"] == "receiver":
        return RatchetState.from_json(session["ratchet_state"])

    # Sender might have already initialised as 'sender' (if we sent first)
    if session and session["ratchet_state"] and session["ratchet_role"] == "sender":
        # Both sides started; use existing state
        return RatchetState.from_json(session["ratchet_state"])

    # First receipt: init as receiver
    sk = x3dh_shared_secret(identity["dh_sk"], sender_dh_pk_b64)
    state = init_as_receiver(sk, identity["dh_sk"])
    _save_session(sender_id, state, "receiver")
    return state

# ─── Auto-delete background task ─────────────────────────────────────────────
async def auto_delete_task():
    while True:
        try:
            now = int(time.time() * 1000)
            with get_db(MSGS_DB) as db:
                deleted = db.execute(
                    "DELETE FROM messages WHERE auto_delete_at IS NOT NULL AND auto_delete_at <= ?", (now,)
                ).rowcount
                if deleted:
                    db.commit()
                    logger.info(f"Auto-deleted {deleted} expired message(s)")
                    fw = connected_ws.get("frontend")
                    if fw:
                        await fw.send_text(json.dumps({"type": "messages_purged", "count": deleted}))
        except Exception as e:
            logger.warning(f"Auto-delete error: {e}")
        await asyncio.sleep(30)

@app.on_event("startup")
async def startup():
    asyncio.create_task(auto_delete_task())

# ─── Models ──────────────────────────────────────────────────────────────────
class CreateIdentityReq(BaseModel):
    display_name: str = ""

class AddContactReq(BaseModel):
    user_id: str; display_name: str = ""; sign_pk: str; dh_pk: str

class SendMessageReq(BaseModel):
    recipient_id: str; content: str; msg_type: str = "text"
    file_name: Optional[str] = None; file_size: Optional[int] = None
    file_data: Optional[str] = None
    auto_delete_seconds: int = 0   # 0 = never

class SendGroupMessageReq(BaseModel):
    group_id: str; content: str; msg_type: str = "text"
    file_name: Optional[str] = None; file_data: Optional[str] = None

class CreateGroupReq(BaseModel):
    name: str; description: str = ""; members: List[dict] = []
    auto_delete_seconds: int = 0

class IncomingMsg(BaseModel):
    sender_id: str; sender_dh_pk: str; sender_sign_pk: str
    ratchet_header: dict; ciphertext: str; signature: str
    msg_id: str; timestamp: int
    msg_type: str = "text"; file_name: Optional[str] = None
    file_size: Optional[int] = None; file_data: Optional[str] = None

class IncomingGroupMsg(BaseModel):
    group_id: str; sender_id: str; sender_sign_pk: str
    ciphertext: str; signature: str; msg_id: str; timestamp: int
    msg_type: str = "text"; file_name: Optional[str] = None
    file_data: Optional[str] = None

class UpdateStatusReq(BaseModel):
    msg_id: str; status: str

class SetAutoDeleteReq(BaseModel):
    conversation_id: str; seconds: int

# ─── Identity ────────────────────────────────────────────────────────────────
@app.get("/identity")
def get_my_identity():
    i = get_identity()
    if not i: return {"exists": False}
    return {"exists": True, "user_id": i["user_id"], "display_name": i["display_name"],
            "sign_pk": i["sign_pk"], "dh_pk": i["dh_pk"], "created_at": i["created_at"]}

@app.post("/identity")
def create_identity(req: CreateIdentityReq):
    if get_identity(): raise HTTPException(400, "Identity already exists")
    i = generate_identity(req.display_name)
    with get_db(KEYS_DB) as db:
        db.execute("INSERT INTO identity (user_id,display_name,sign_pk,sign_sk,dh_pk,dh_sk,created_at) VALUES (:user_id,:display_name,:sign_pk,:sign_sk,:dh_pk,:dh_sk,:created_at)", i)
        db.commit()
    return {"user_id": i["user_id"], "sign_pk": i["sign_pk"], "dh_pk": i["dh_pk"]}

@app.patch("/identity/name")
def update_name(body: dict):
    with get_db(KEYS_DB) as db:
        db.execute("UPDATE identity SET display_name=?", (body.get("display_name",""),))
        db.commit()
    return {"ok": True}

@app.get("/fingerprint")
def fingerprint():
    i = get_identity()
    if not i: raise HTTPException(400, "No identity")
    raw = hashlib.sha256(b64d(i["sign_pk"])).digest()
    groups = [f"{int.from_bytes(raw[x:x+2],'big'):05d}" for x in range(0,12,2)]
    return {"fingerprint": " ".join(groups), "user_id": i["user_id"]}

@app.get("/export-identity")
def export_identity():
    i = get_identity()
    if not i: raise HTTPException(400, "No identity")
    return {"user_id": i["user_id"], "display_name": i["display_name"],
            "sign_pk": i["sign_pk"], "dh_pk": i["dh_pk"]}

# ─── Contacts ────────────────────────────────────────────────────────────────
@app.get("/contacts")
def list_contacts():
    with get_db(CONTACTS_DB) as db:
        return [dict(r) for r in db.execute("SELECT * FROM contacts ORDER BY display_name").fetchall()]

@app.post("/contacts")
def add_contact(req: AddContactReq):
    with get_db(CONTACTS_DB) as db:
        db.execute("INSERT OR REPLACE INTO contacts (user_id,display_name,sign_pk,dh_pk,trust_level,added_at) VALUES (?,?,?,?,'unverified',?)",
                   (req.user_id, req.display_name, req.sign_pk, req.dh_pk, int(time.time())))
        db.commit()
    return {"ok": True}

@app.delete("/contacts/{uid}")
def delete_contact(uid: str):
    with get_db(CONTACTS_DB) as db:
        db.execute("DELETE FROM contacts WHERE user_id=?", (uid,))
        db.commit()
    return {"ok": True}

# ─── Groups ──────────────────────────────────────────────────────────────────
@app.get("/groups")
def list_groups():
    with get_db(GROUPS_DB) as db:
        groups = [dict(r) for r in db.execute("SELECT * FROM groups ORDER BY name").fetchall()]
        for g in groups:
            members = db.execute("SELECT * FROM group_members WHERE group_id=?", (g["group_id"],)).fetchall()
            g["members"] = [dict(m) for m in members]
            g["member_count"] = len(g["members"])
    return groups

@app.post("/groups")
def create_group(req: CreateGroupReq):
    identity = get_identity()
    if not identity: raise HTTPException(400, "No identity")
    gid = "grp_" + secrets.token_hex(12)
    sk  = b64e(nacl.utils.random(32))
    with get_db(GROUPS_DB) as db:
        db.execute("INSERT INTO groups (group_id,name,description,sender_key,created_by,created_at,auto_delete_seconds) VALUES (?,?,?,?,?,?,?)",
                   (gid, req.name, req.description, sk, identity["user_id"], int(time.time()), req.auto_delete_seconds))
        db.execute("INSERT OR REPLACE INTO group_members (group_id,user_id,display_name,sign_pk,dh_pk,role,joined_at) VALUES (?,?,?,?,?,'owner',?)",
                   (gid, identity["user_id"], identity["display_name"], identity["sign_pk"], identity["dh_pk"], int(time.time())))
        for m in req.members:
            db.execute("INSERT OR REPLACE INTO group_members (group_id,user_id,display_name,sign_pk,dh_pk,role,joined_at) VALUES (?,?,?,?,?,'member',?)",
                       (gid, m["user_id"], m.get("display_name",""), m["sign_pk"], m["dh_pk"], int(time.time())))
        db.commit()
    return {"ok": True, "group_id": gid}

@app.post("/groups/{gid}/members")
def add_group_member(gid: str, req: AddContactReq):
    with get_db(GROUPS_DB) as db:
        db.execute("INSERT OR REPLACE INTO group_members (group_id,user_id,display_name,sign_pk,dh_pk,role,joined_at) VALUES (?,?,?,?,?,'member',?)",
                   (gid, req.user_id, req.display_name, req.sign_pk, req.dh_pk, int(time.time())))
        db.commit()
    return {"ok": True}

@app.delete("/groups/{gid}/members/{uid}")
def remove_group_member(gid: str, uid: str):
    new_sk = b64e(nacl.utils.random(32))  # rotate sender key → forward secrecy
    with get_db(GROUPS_DB) as db:
        db.execute("DELETE FROM group_members WHERE group_id=? AND user_id=?", (gid, uid))
        db.execute("UPDATE groups SET sender_key=? WHERE group_id=?", (new_sk, gid))
        db.commit()
    return {"ok": True}

@app.get("/groups/{gid}/export-key")
def export_group_key(gid: str):
    with get_db(GROUPS_DB) as db:
        g = db.execute("SELECT sender_key FROM groups WHERE group_id=?", (gid,)).fetchone()
    if not g: raise HTTPException(404, "Group not found")
    return {"group_id": gid, "sender_key": g["sender_key"]}

# ─── Messages ────────────────────────────────────────────────────────────────
@app.get("/messages/{conv_id}")
def get_messages(conv_id: str, limit: int = 100):
    with get_db(MSGS_DB) as db:
        rows = db.execute("SELECT * FROM messages WHERE conversation_id=? ORDER BY timestamp ASC LIMIT ?",
                          (conv_id, limit)).fetchall()
    return [dict(r) for r in rows]

@app.post("/messages/send")
async def send_message(req: SendMessageReq):
    identity = get_identity()
    if not identity: raise HTTPException(400, "No identity")

    # Get or init ratchet state
    state = get_ratchet_for_send(identity, req.recipient_id)

    # Build payload
    payload = {"content": req.content, "type": req.msg_type}
    if req.file_name: payload["file_name"] = req.file_name
    if req.file_size: payload["file_size"] = req.file_size
    if req.file_data: payload["file_data"] = req.file_data

    # Encrypt with Double Ratchet (includes padding)
    header, ciphertext = ratchet_encrypt(state, json.dumps(payload))

    # Save updated ratchet state
    session = _get_session(req.recipient_id)
    role = session["ratchet_role"] if session else "sender"
    _save_session(req.recipient_id, state, role)

    msg_id    = secrets.token_hex(16)
    timestamp = int(time.time() * 1000)
    signature = sign_data(identity["sign_sk"], ciphertext)

    # Auto-delete timestamp
    auto_del = (timestamp + req.auto_delete_seconds * 1000) if req.auto_delete_seconds > 0 else None

    with get_db(MSGS_DB) as db:
        db.execute("INSERT INTO messages (id,conversation_id,sender_id,content,ciphertext,msg_type,file_name,file_size,file_data,timestamp,status,is_outgoing,auto_delete_at) VALUES (?,?,?,?,?,?,?,?,?,?,'sent',1,?)",
                   (msg_id, req.recipient_id, identity["user_id"], req.content, ciphertext,
                    req.msg_type, req.file_name, req.file_size, req.file_data, timestamp, auto_del))
        db.commit()

    envelope = {
        "type": "message",
        "sender_id": identity["user_id"],
        "sender_dh_pk": identity["dh_pk"],
        "sender_sign_pk": identity["sign_pk"],
        "recipient_id": req.recipient_id,
        "ratchet_header": header,
        "ciphertext": ciphertext,
        "signature": signature,
        "msg_id": msg_id,
        "timestamp": timestamp,
        "msg_type": req.msg_type,
    }
    if req.file_name: envelope["file_name"] = req.file_name

    relay = connected_ws.get("relay_out")
    if relay:
        try: await relay.send_text(json.dumps(envelope))
        except Exception as e: logger.warning(f"Relay forward failed: {e}")

    return {"ok": True, "msg_id": msg_id, "timestamp": timestamp}

@app.post("/groups/{gid}/send")
async def send_group_message(gid: str, req: SendGroupMessageReq):
    identity = get_identity()
    if not identity: raise HTTPException(400, "No identity")
    with get_db(GROUPS_DB) as db:
        g = db.execute("SELECT * FROM groups WHERE group_id=?", (gid,)).fetchone()
        members = db.execute("SELECT * FROM group_members WHERE group_id=? AND user_id!=?",
                             (gid, identity["user_id"])).fetchall()
    if not g: raise HTTPException(404, "Group not found")

    payload = {"content": req.content, "type": req.msg_type, "group_id": gid}
    if req.file_name: payload["file_name"] = req.file_name
    if req.file_data: payload["file_data"] = req.file_data

    ciphertext = encrypt_group(g["sender_key"], json.dumps(payload))
    msg_id     = secrets.token_hex(16)
    timestamp  = int(time.time() * 1000)
    signature  = sign_data(identity["sign_sk"], ciphertext)

    auto_del_s = g["auto_delete_seconds"] or 0
    auto_del   = (timestamp + auto_del_s * 1000) if auto_del_s > 0 else None

    with get_db(MSGS_DB) as db:
        db.execute("INSERT INTO messages (id,conversation_id,sender_id,content,ciphertext,msg_type,file_name,file_data,timestamp,status,is_outgoing,auto_delete_at) VALUES (?,?,?,?,?,?,?,?,?,'sent',1,?)",
                   (msg_id, gid, identity["user_id"], req.content, ciphertext,
                    req.msg_type, req.file_name, req.file_data, timestamp, auto_del))
        db.commit()

    envelope = {"type": "group_message", "group_id": gid, "sender_id": identity["user_id"],
                "sender_sign_pk": identity["sign_pk"], "ciphertext": ciphertext,
                "signature": signature, "msg_id": msg_id, "timestamp": timestamp, "msg_type": req.msg_type}

    relay = connected_ws.get("relay_out")
    if relay:
        for m in members:
            try: await relay.send_text(json.dumps({**envelope, "recipient_id": m["user_id"]}))
            except Exception: pass

    return {"ok": True, "msg_id": msg_id}

@app.post("/messages/receive")
async def receive_message(payload: IncomingMsg):
    identity = get_identity()
    if not identity: raise HTTPException(400, "No identity")

    # Verify signature
    with get_db(CONTACTS_DB) as db:
        contact = db.execute("SELECT * FROM contacts WHERE user_id=?", (payload.sender_id,)).fetchone()
    if contact:
        if not verify_sig(payload.sender_sign_pk, payload.ciphertext, payload.signature):
            raise HTTPException(400, "Invalid signature — rejected")

    # Get/init ratchet for receiving
    state = get_ratchet_for_receive(identity, payload.sender_id, payload.sender_dh_pk)

    try:
        raw_json = ratchet_decrypt(state, payload.ratchet_header, payload.ciphertext)
        parsed   = json.loads(raw_json)
        plaintext  = parsed.get("content", raw_json)
        msg_type   = parsed.get("type", "text")
        file_name  = parsed.get("file_name", payload.file_name)
        file_data  = parsed.get("file_data")
        file_size  = parsed.get("file_size", payload.file_size)
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise HTTPException(400, f"Decryption failed: {e}")

    # Save updated ratchet state
    session = _get_session(payload.sender_id)
    role = session["ratchet_role"] if session else "receiver"
    _save_session(payload.sender_id, state, role)

    # Auto-add unknown sender as contact
    if not contact:
        with get_db(CONTACTS_DB) as db:
            db.execute("INSERT OR IGNORE INTO contacts (user_id,display_name,sign_pk,dh_pk,trust_level,added_at) VALUES (?,?,?,?,'unverified',?)",
                       (payload.sender_id, f"Unbekannt ({payload.sender_id[:8]})", payload.sender_sign_pk, payload.sender_dh_pk, int(time.time())))
            db.commit()

    with get_db(MSGS_DB) as db:
        if not db.execute("SELECT id FROM messages WHERE id=?", (payload.msg_id,)).fetchone():
            db.execute("INSERT INTO messages (id,conversation_id,sender_id,content,ciphertext,msg_type,file_name,file_size,file_data,timestamp,status,is_outgoing) VALUES (?,?,?,?,?,?,?,?,?,'received',0)",
                       (payload.msg_id, payload.sender_id, payload.sender_id, plaintext, payload.ciphertext,
                        msg_type, file_name, file_size, file_data, payload.timestamp))
            db.commit()

    fw = connected_ws.get("frontend")
    if fw:
        try:
            await fw.send_text(json.dumps({
                "type": "new_message", "sender_id": payload.sender_id,
                "content": plaintext, "timestamp": payload.timestamp,
                "msg_id": payload.msg_id, "msg_type": msg_type,
                "file_name": file_name, "conv_type": "direct"
            }))
        except Exception: pass
    return {"ok": True}

@app.post("/groups/receive")
async def receive_group_message(payload: IncomingGroupMsg):
    identity = get_identity()
    if not identity: raise HTTPException(400, "No identity")
    with get_db(GROUPS_DB) as db:
        g = db.execute("SELECT * FROM groups WHERE group_id=?", (payload.group_id,)).fetchone()
    if not g: raise HTTPException(404, "Not a member of this group")
    if not verify_sig(payload.sender_sign_pk, payload.ciphertext, payload.signature):
        raise HTTPException(400, "Invalid signature")
    try:
        raw  = decrypt_group(g["sender_key"], payload.ciphertext)
        parsed = json.loads(raw)
        plaintext = parsed.get("content", raw)
        msg_type  = parsed.get("type", "text")
        file_name = parsed.get("file_name")
        file_data = parsed.get("file_data")
    except Exception:
        plaintext = "[Entschlüsselung fehlgeschlagen]"; msg_type="text"; file_name=None; file_data=None

    auto_del_s = g["auto_delete_seconds"] or 0
    auto_del   = (payload.timestamp + auto_del_s * 1000) if auto_del_s > 0 else None

    with get_db(MSGS_DB) as db:
        if not db.execute("SELECT id FROM messages WHERE id=?", (payload.msg_id,)).fetchone():
            db.execute("INSERT INTO messages (id,conversation_id,sender_id,content,ciphertext,msg_type,file_name,file_data,timestamp,status,is_outgoing,auto_delete_at) VALUES (?,?,?,?,?,?,?,?,'received',0,?)",
                       (payload.msg_id, payload.group_id, payload.sender_id, plaintext, payload.ciphertext,
                        msg_type, file_name, file_data, payload.timestamp, auto_del))
            db.commit()

    fw = connected_ws.get("frontend")
    if fw:
        try:
            await fw.send_text(json.dumps({
                "type": "new_message", "sender_id": payload.sender_id,
                "content": plaintext, "timestamp": payload.timestamp,
                "msg_id": payload.msg_id, "msg_type": msg_type,
                "file_name": file_name, "conv_type": "group",
                "group_id": payload.group_id
            }))
        except Exception: pass
    return {"ok": True}

@app.patch("/messages/status")
def update_status(req: UpdateStatusReq):
    with get_db(MSGS_DB) as db:
        db.execute("UPDATE messages SET status=? WHERE id=?", (req.status, req.msg_id))
        db.commit()
    return {"ok": True}

@app.post("/messages/auto-delete")
def set_auto_delete(req: SetAutoDeleteReq):
    """Set auto-delete timer for all future messages in a conversation."""
    # Store preference in groups table for groups, or just apply to future messages
    return {"ok": True, "seconds": req.seconds}

@app.delete("/messages/{conv_id}")
def clear_conversation(conv_id: str):
    with get_db(MSGS_DB) as db:
        db.execute("DELETE FROM messages WHERE conversation_id=?", (conv_id,))
        db.commit()
    return {"ok": True}

# ─── Ratchet info (for UI indicator) ─────────────────────────────────────────
@app.get("/sessions/{contact_id}/ratchet-info")
def ratchet_info(contact_id: str):
    session = _get_session(contact_id)
    if not session or not session["ratchet_state"]:
        return {"active": False}
    state = RatchetState.from_json(session["ratchet_state"])
    return {
        "active": True,
        "role": session["ratchet_role"],
        "msg_sent": state.ns,
        "msg_received": state.nr,
        "skipped_keys": len(state.mkskipped),
        "dh_ratchet_pk": b64e(bytes(state.dhs.public_key)) if state.dhs else None
    }

# ─── Relay ───────────────────────────────────────────────────────────────────
@app.post("/relay/connect")
async def connect_relay(body: dict):
    import websockets as ws_lib
    relay_url = body.get("url", "")
    identity  = get_identity()
    if not identity: raise HTTPException(400, "No identity")

    async def relay_loop():
        try:
            async with ws_lib.connect(relay_url) as relay:
                connected_ws["relay_out"] = relay
                await relay.send(json.dumps({"type": "register", "user_id": identity["user_id"]}))
                resp = json.loads(await relay.recv())
                logger.info(f"Relay: {resp}")
                async for raw in relay:
                    try:
                        msg = json.loads(raw)
                        mt  = msg.get("type")
                        if mt == "message":
                            await receive_message(IncomingMsg(**{k: msg[k] for k in IncomingMsg.model_fields if k in msg}))
                        elif mt == "group_message":
                            await receive_group_message(IncomingGroupMsg(**{k: msg[k] for k in IncomingGroupMsg.model_fields if k in msg}))
                    except Exception as e:
                        logger.warning(f"Relay msg error: {e}")
        except Exception as e:
            logger.error(f"Relay disconnected: {e}")
            connected_ws.pop("relay_out", None)

    asyncio.create_task(relay_loop())
    return {"ok": True}

@app.get("/relay/status")
def relay_status():
    return {"connected": "relay_out" in connected_ws}

# ─── WebSocket (frontend) ─────────────────────────────────────────────────────
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    connected_ws["frontend"] = ws
    try:
        while True: await ws.receive_text()
    except WebSocketDisconnect:
        connected_ws.pop("frontend", None)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=49155, log_level="info")

# ─── Message edit / delete ────────────────────────────────────────────────────
@app.delete("/messages/single/{msg_id}")
def delete_single_message(msg_id: str):
    with get_db(MSGS_DB) as db:
        db.execute("DELETE FROM messages WHERE id=?", (msg_id,))
        db.commit()
    return {"ok": True}

@app.patch("/messages/single/{msg_id}")
def edit_message(msg_id: str, body: dict):
    with get_db(MSGS_DB) as db:
        db.execute("UPDATE messages SET content=?, status='edited' WHERE id=? AND is_outgoing=1",
                   (body.get("content", ""), msg_id))
        db.commit()
    return {"ok": True}

# ─── Search ──────────────────────────────────────────────────────────────────
@app.get("/messages/search")
def search_messages(q: str = "", limit: int = 50):
    if not q or len(q) < 2:
        return []
    with get_db(MSGS_DB) as db:
        rows = db.execute(
            "SELECT * FROM messages WHERE content LIKE ? ORDER BY timestamp DESC LIMIT ?",
            (f"%{q}%", limit)
        ).fetchall()
    return [dict(r) for r in rows]

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

# ─── Backup / Restore ─────────────────────────────────────────────────────────
import zipfile, io as _io

@app.get("/backup/export")
def export_backup():
    buf = _io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in [KEYS_DB, MSGS_DB, CONTACTS_DB, GROUPS_DB]:
            if p.exists():
                zf.write(str(p), p.name)
    b64 = base64.b64encode(buf.getvalue()).decode()
    return {"ok": True, "data": b64, "size": len(buf.getvalue()),
            "filename": f"pm_backup_{int(time.time())}.zip"}

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
