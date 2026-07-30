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
    ratchet_encrypt, ratchet_decrypt, b64e, b64d,
    x3dh_sender_derive, x3dh_receiver_derive
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:00:00")
logger = logging.getLogger(__name__)

# ─── Command Line Argument Parsing (API Auth Token) ───────────────────────────
parser = argparse.ArgumentParser(description="Privacy Messenger Server")
parser.add_argument("--api-token", type=str, default="", help="Mandatory API Secret Auth Token for Localhost Security")
args_parsed, _ = parser.parse_known_args()

# Strictly enforce API_TOKEN: generate random 32-byte secret fallback if omitted
API_TOKEN = args_parsed.api_token or os.environ.get("PM_API_TOKEN", "") or secrets.token_hex(32)

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

app = FastAPI(title="Privacy Messenger v1.0.8 — Synchronized Relay Token Rotation & Vault Fix")

# ─── Hardened Security Middleware (Strict Mandatory API Auth Token) ───────────
@app.middleware("http")
async def enforce_auth_token(request: Request, call_next):
    if request.method == "OPTIONS":
        return await call_next(request)
    
    token = request.headers.get("X-API-Token")
    if not token or token != API_TOKEN:
        logger.warning("Unauthorized HTTP request blocked: Missing or invalid X-API-Token")
        return JSONResponse(status_code=403, content={"error": "Access Denied: Invalid X-API-Token"})
    
    return await call_next(request)

connected_ws: dict[str, WebSocket] = {}
relay_writer_stream: Optional[asyncio.StreamWriter] = None

# ─── SOCKS5 Proxy Configuration & Settings Management ─────────────────────────
def load_settings() -> dict:
    if SETTINGS_FILE.exists():
        try:
            with open(SETTINGS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"proxy_enabled": False, "proxy_host": "127.0.0.1", "proxy_port": 9050, "relay_url": "ws://127.0.0.1:49156"}

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

# ─── Real Outbound Network Transport with SOCKS5 Protocol (RFC 1928) ────────
async def connect_tcp_or_socks5(dest_host: str, dest_port: int, proxy_enabled: bool = False, proxy_host: str = "127.0.0.1", proxy_port: int = 9050):
    if proxy_enabled:
        logger.info(f"[Transport] Connecting to {dest_host}:{dest_port} via SOCKS5 Proxy {proxy_host}:{proxy_port}")
        try:
            reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await reader.read(2)
            if resp != b"\x05\x00":
                writer.close()
                raise ConnectionError("SOCKS5 Proxy authentication failed or unsupported")

            host_bytes = dest_host.encode("utf-8")
            req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + dest_port.to_bytes(2, "big")
            writer.write(req)
            await writer.drain()

            reply = await reader.read(10)
            if len(reply) < 4 or reply[1] != 0:
                writer.close()
                raise ConnectionError(f"SOCKS5 Proxy connection to {dest_host}:{dest_port} failed")

            return reader, writer
        except Exception as e:
            raise ConnectionError(f"SOCKS5 Proxy unreachable at {proxy_host}:{proxy_port}: {e}")
    else:
        logger.info(f"[Transport] Connecting directly to {dest_host}:{dest_port}")
        return await asyncio.open_connection(dest_host, dest_port)

async def register_delivery_token_on_relay(token: str):
    """
    Immediately registers a newly rotated Delivery Token on the active Relay WebSocket stream.
    Synchronizes local token rotation with the Relay Server.
    """
    global relay_writer_stream
    if relay_writer_stream and not relay_writer_stream.is_closing():
        try:
            reg_payload = json.dumps({"type": "register_token", "delivery_token": token}).encode("utf-8")
            reg_len = len(reg_payload)
            reg_hdr = bytearray([0x81])
            reg_mask = secrets.token_bytes(4)
            if reg_len < 126: reg_hdr.append(0x80 | reg_len)
            else: reg_hdr.extend([0x80 | 126] + list(reg_len.to_bytes(2, "big")))
            reg_hdr.extend(reg_mask)
            reg_masked = bytearray(reg_len)
            for i in range(reg_len): reg_masked[i] = reg_payload[i] ^ reg_mask[i % 4]
            
            relay_writer_stream.write(reg_hdr + reg_masked)
            await relay_writer_stream.drain()
            logger.info(f"[RelayWorker] Dynamically registered rotated token on open stream: {token[:12]}...")
        except Exception as e:
            logger.warning(f"[RelayWorker] Failed to register rotated token: {e}")

async def transmit_outbound_e2ee_packet(recipient_id: str, packet_dict: dict) -> bool:
    global relay_writer_stream
    settings = load_settings()
    proxy_enabled = settings.get("proxy_enabled", False)
    proxy_host = settings.get("proxy_host", "127.0.0.1")
    proxy_port = settings.get("proxy_port", 9050)

    with get_db(CONTACTS_DB) as db:
        contact = db.execute("SELECT * FROM contacts WHERE user_id=?", (recipient_id,)).fetchone()
    
    if contact and contact["host"] and contact["port"]:
        dest_host = contact["host"]
        dest_port = contact["port"]
        logger.info(f"[Transport] Attempting direct P2P transmission to {dest_host}:{dest_port}")
        try:
            reader, writer = await connect_tcp_or_socks5(dest_host, dest_port, proxy_enabled, proxy_host, proxy_port)
            body = json.dumps(packet_dict).encode("utf-8")
            http_req = (
                f"POST /messages/receive HTTP/1.1\r\n"
                f"Host: {dest_host}:{dest_port}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("utf-8") + body

            writer.write(http_req)
            await writer.drain()
            resp = await reader.read(1024)
            writer.close()
            await writer.wait_closed()

            if b"200 OK" in resp or b"\"ok\":true" in resp or b"\"ok\": true" in resp:
                logger.info(f"[Transport] Direct P2P packet delivered successfully to {recipient_id}")
                return True
        except Exception as e:
            logger.warning(f"[Transport] Direct P2P transmission to {dest_host}:{dest_port} failed: {e}. Falling back to Relay.")

    # Deliverable Token Fallback to recipient_id if no token exists yet
    recipient_delivery_token = contact["delivery_token"] if (contact and contact["delivery_token"]) else recipient_id

    if relay_writer_stream and not relay_writer_stream.is_closing():
        try:
            payload = json.dumps({
                "type": "sealed_packet",
                "delivery_token": recipient_delivery_token,
                "packet": packet_dict
            })
            payload_bytes = payload.encode("utf-8")
            length = len(payload_bytes)
            
            header = bytearray([0x81])
            mask_key = secrets.token_bytes(4)
            if length < 126:
                header.append(0x80 | length)
            elif length < 65536:
                header.append(0x80 | 126)
                header.extend(length.to_bytes(2, "big"))
            else:
                header.append(0x80 | 127)
                header.extend(length.to_bytes(8, "big"))
            
            header.extend(mask_key)
            masked_payload = bytearray(length)
            for i in range(length):
                masked_payload[i] = payload_bytes[i] ^ mask_key[i % 4]
            
            relay_writer_stream.write(header + masked_payload)
            await relay_writer_stream.drain()
            logger.info(f"[Transport] Transmitted Sealed E2EE packet to delivery token {recipient_delivery_token[:12]}...")
            return True
        except Exception as e:
            logger.error(f"[Transport] Failed to transmit sealed packet over Relay stream: {e}")

    logger.warning(f"[Transport] Packet for {recipient_id} queued (No active Relay or P2P route available)")
    return False

# ─── Outbound Background Relay Client Worker (True Sealed Sender & Token Registration) ───
async def start_relay_client_worker():
    global relay_writer_stream
    await asyncio.sleep(2)
    
    while True:
        try:
            identity = get_identity()
            settings = load_settings()
            relay_url = settings.get("relay_url", "").strip()

            if identity and relay_url:
                my_delivery_token = identity.get("delivery_token")
                if not my_delivery_token:
                    my_delivery_token = b64e(secrets.token_bytes(32))
                    with get_db(KEYS_DB) as db:
                        db.execute("UPDATE identity SET delivery_token=? WHERE id=1", (my_delivery_token,))
                        db.commit()

                proxy_enabled = settings.get("proxy_enabled", False)
                proxy_host = settings.get("proxy_host", "127.0.0.1")
                proxy_port = settings.get("proxy_port", 9050)

                clean_url = relay_url.replace("ws://", "").replace("wss://", "")
                parts = clean_url.split("/")
                host_port = parts[0].split(":")
                r_host = host_port[0]
                r_port = int(host_port[1]) if len(host_port) > 1 else 49156

                logger.info(f"[RelayWorker] Connecting ANONYMOUSLY to Relay Server {r_host}:{r_port}...")
                reader, writer = await connect_tcp_or_socks5(r_host, r_port, proxy_enabled, proxy_host, proxy_port)

                # ANONYMOUS WebSocket Handshake (NO user_id in URL!)
                handshake = (
                    f"GET /relay/stream HTTP/1.1\r\n"
                    f"Host: {r_host}:{r_port}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {b64e(secrets.token_bytes(16))}\r\n"
                    f"Sec-WebSocket-Version: 13\r\n\r\n"
                ).encode("utf-8")

                writer.write(handshake)
                await writer.drain()

                resp = await reader.readuntil(b"\r\n\r\n")
                if b"101" in resp or b"Switching Protocols" in resp:
                    logger.info(f"[RelayWorker] Connected anonymously. Registering Delivery Token {my_delivery_token[:12]}...")
                    relay_writer_stream = writer

                    # Register current 32-byte delivery token
                    await register_delivery_token_on_relay(my_delivery_token)

                    while not reader.at_eof():
                        head = await reader.read(2)
                        if len(head) < 2: break
                        
                        pay_len = head[1] & 0x7F
                        if pay_len == 126:
                            len_bytes = await reader.read(2)
                            pay_len = int.from_bytes(len_bytes, "big")
                        elif pay_len == 127:
                            len_bytes = await reader.read(8)
                            pay_len = int.from_bytes(len_bytes, "big")
                        
                        is_masked = bool(head[1] & 0x80)
                        mask = await reader.read(4) if is_masked else b""
                        raw_payload = await reader.read(pay_len)

                        if is_masked:
                            unmasked = bytearray(pay_len)
                            for i in range(pay_len):
                                unmasked[i] = raw_payload[i] ^ mask[i % 4]
                            payload_str = unmasked.decode("utf-8")
                        else:
                            payload_str = raw_payload.decode("utf-8")

                        try:
                            msg_data = json.loads(payload_str)
                            if msg_data.get("type") == "incoming_sealed_packet" and "packet" in msg_data:
                                p = msg_data["packet"]
                                incoming = IncomingMsg(
                                    id=p["id"],
                                    sender_id=p["sender_id"],
                                    header=p["header"],
                                    ciphertext=p["ciphertext"],
                                    msg_type=p.get("msg_type", "text"),
                                    timestamp=p.get("timestamp", int(time.time()))
                                )
                                api_receive_message(incoming)
                        except Exception as ex:
                            logger.warning(f"[RelayWorker] Error processing incoming sealed packet: {ex}")
                else:
                    logger.warning(f"[RelayWorker] Relay Handshake rejected: {resp[:100]}")

        except Exception as e:
            logger.warning(f"[RelayWorker] Relay connection lost: {e}. Reconnecting in 10s...")
            relay_writer_stream = None
        
        await asyncio.sleep(10)

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
            sign_pk TEXT, sign_sk TEXT, dh_pk TEXT, dh_sk TEXT,
            spk_pk TEXT, spk_sk TEXT, spk_sig TEXT, delivery_token TEXT DEFAULT NULL, created_at INTEGER)""")
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
            sign_pk TEXT, dh_pk TEXT, spk_pk TEXT DEFAULT NULL, spk_sig TEXT DEFAULT NULL,
            delivery_token TEXT DEFAULT NULL, trust_level TEXT DEFAULT 'unverified', host TEXT DEFAULT NULL, port INTEGER DEFAULT NULL,
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
        if "msg_type" not in cols:
            db.execute("ALTER TABLE messages ADD COLUMN msg_type TEXT DEFAULT 'text'")
        db.commit()

    with get_db(CONTACTS_DB) as db:
        cols = [r[1] for r in db.execute("PRAGMA table_info(contacts)").fetchall()]
        if "host" not in cols:
            db.execute("ALTER TABLE contacts ADD COLUMN host TEXT DEFAULT NULL")
            db.execute("ALTER TABLE contacts ADD COLUMN port INTEGER DEFAULT NULL")
        if "spk_pk" not in cols:
            db.execute("ALTER TABLE contacts ADD COLUMN spk_pk TEXT DEFAULT NULL")
            db.execute("ALTER TABLE contacts ADD COLUMN spk_sig TEXT DEFAULT NULL")
        if "delivery_token" not in cols:
            db.execute("ALTER TABLE contacts ADD COLUMN delivery_token TEXT DEFAULT NULL")
        db.commit()

    with get_db(KEYS_DB) as db:
        cols = [r[1] for r in db.execute("PRAGMA table_info(identity)").fetchall()]
        if "spk_pk" not in cols:
            db.execute("ALTER TABLE identity ADD COLUMN spk_pk TEXT DEFAULT NULL")
            db.execute("ALTER TABLE identity ADD COLUMN spk_sk TEXT DEFAULT NULL")
            db.execute("ALTER TABLE identity ADD COLUMN spk_sig TEXT DEFAULT NULL")
        if "delivery_token" not in cols:
            db.execute("ALTER TABLE identity ADD COLUMN delivery_token TEXT DEFAULT NULL")
        db.commit()
migrate()

# ─── Identity & Signed Prekeys for Real X3DH ─────────────────────────────────
def get_identity() -> Optional[dict]:
    with get_db(KEYS_DB) as db:
        row = db.execute("SELECT * FROM identity WHERE id=1").fetchone()
        if not row: return None
        d = dict(row)
        d["sign_sk"] = vault_decrypt(d["sign_sk"])
        d["dh_sk"]   = vault_decrypt(d["dh_sk"])
        if d.get("spk_sk"):
            d["spk_sk"] = vault_decrypt(d["spk_sk"])
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
        "spk_pk": id_data.get("spk_pk"),
        "spk_sig": id_data.get("spk_sig"),
        "delivery_token": id_data.get("delivery_token"),
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

    spk_sk = nacl.public.PrivateKey.generate()
    spk_pk = spk_sk.public_key
    spk_sig = sign_sk.sign(bytes(spk_pk)).signature

    user_id = b64e(hashlib.sha256(bytes(sign_pk)).digest()[:16])
    delivery_token = b64e(secrets.token_bytes(32))

    enc_sign_sk = vault_encrypt(b64e(bytes(sign_sk)))
    enc_dh_sk   = vault_encrypt(b64e(bytes(dh_sk)))
    enc_spk_sk  = vault_encrypt(b64e(bytes(spk_sk)))

    with get_db(KEYS_DB) as db:
        db.execute(
            """INSERT INTO identity (id, user_id, display_name, sign_pk, sign_sk, dh_pk, dh_sk, spk_pk, spk_sk, spk_sig, delivery_token, created_at)
               VALUES (1,?,?,?,?,?,?,?,?,?,?,?)""",
            (user_id, req.display_name, b64e(bytes(sign_pk)), enc_sign_sk, b64e(bytes(dh_pk)), enc_dh_sk,
             b64e(bytes(spk_pk)), enc_spk_sk, b64e(spk_sig), delivery_token, int(time.time()))
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
        "spk_pk": id_data.get("spk_pk"),
        "spk_sig": id_data.get("spk_sig"),
        "delivery_token": id_data.get("delivery_token"),
    }

# ─── Contacts ────────────────────────────────────────────────────────────────
class AddContactReq(BaseModel):
    user_id: str
    display_name: str = ""
    sign_pk: str
    dh_pk: str
    spk_pk: Optional[str] = None
    spk_sig: Optional[str] = None
    delivery_token: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None

@app.get("/contacts")
def api_get_contacts():
    with get_db(CONTACTS_DB) as db:
        rows = db.execute("SELECT * FROM contacts ORDER BY added_at DESC").fetchall()
        return [dict(r) for r in rows]

@app.post("/contacts")
def api_add_contact(req: AddContactReq):
    token = req.delivery_token or req.user_id
    with get_db(CONTACTS_DB) as db:
        db.execute(
            """INSERT OR REPLACE INTO contacts (user_id, display_name, sign_pk, dh_pk, spk_pk, spk_sig, delivery_token, host, port, added_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (req.user_id, req.display_name, req.sign_pk, req.dh_pk, req.spk_pk, req.spk_sig, token, req.host, req.port, int(time.time()))
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

# ─── Double Ratchet Session Management & Real X3DH ────────────────────────────
def get_or_create_ratchet_session(contact_id: str, is_sender: bool, incoming_header: Optional[dict] = None) -> RatchetState:
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
        their_sign_pk = nacl.signing.VerifyKey(b64d(contact["sign_pk"]))
        ek_a = None

        if is_sender and contact["spk_pk"] and contact["spk_sig"]:
            their_spk_pk = nacl.public.PublicKey(b64d(contact["spk_pk"]))
            their_spk_sig = b64d(contact["spk_sig"])

            shared_secret, ek_a = x3dh_sender_derive(
                alice_ik_sk=my_dh_sk,
                bob_ik_pk=their_dh_pk,
                bob_spk_pk=their_spk_pk,
                bob_spk_sig=their_spk_sig,
                bob_sign_pk=their_sign_pk
            )
            logger.info(f"[X3DH] Derived Sender Master Shared Secret with Ephemeral Key EK_A for {contact_id}")
        elif not is_sender and incoming_header and incoming_header.get("ek"):
            alice_ek_pk = nacl.public.PublicKey(b64d(incoming_header["ek"]))
            my_spk_sk = nacl.public.PrivateKey(b64d(id_data["spk_sk"]))
            shared_secret = x3dh_receiver_derive(
                bob_ik_sk=my_dh_sk,
                bob_spk_sk=my_spk_sk,
                alice_ik_pk=their_dh_pk,
                alice_ek_pk=alice_ek_pk
            )
            logger.info(f"[X3DH] Derived Receiver Master Shared Secret using received Ephemeral Key EK_A from {contact_id}")
        else:
            shared_secret = bytes(nacl.public.Box(my_dh_sk, their_dh_pk).shared_key())

        if is_sender:
            st = init_as_sender(shared_secret, contact["dh_pk"], ek_a=ek_a)
        else:
            st = init_as_receiver(shared_secret, id_data["dh_sk"])

        enc_shared_secret = vault_encrypt(b64e(shared_secret))
        enc_state = vault_encrypt(st.to_json())

        db.execute(
            "INSERT OR REPLACE INTO sessions (contact_id, shared_key, ratchet_state, ratchet_role, created_at) VALUES (?,?,?,?,?)",
            (contact_id, enc_shared_secret, enc_state, "sender" if is_sender else "receiver", int(time.time()))
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

# ─── Messages & Automatic In-Band Token Rotation ──────────────────────────────
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

    # Generate fresh 32-byte Delivery Token for In-Band Rotation
    my_next_token = b64e(secrets.token_bytes(32))

    # Package message and rotated delivery token into Double Ratchet encrypted payload
    inner_payload_dict = {
        "text": req.content,
        "next_delivery_token": my_next_token
    }

    st = get_or_create_ratchet_session(req.conversation_id, is_sender=True)
    header, ciphertext_b64 = ratchet_encrypt(st, json.dumps(inner_payload_dict))
    save_ratchet_session(req.conversation_id, st)

    # Rotate local identity delivery token in DB and re-register on active Relay WebSocket stream
    with get_db(KEYS_DB) as db:
        db.execute("UPDATE identity SET delivery_token=? WHERE id=1", (my_next_token,))
        db.commit()
    await register_delivery_token_on_relay(my_next_token)

    payload_b64 = b64e(json.dumps({"header": header, "ct": ciphertext_b64}).encode())
    enc_content = vault_encrypt(req.content)

    packet = {
        "id": msg_id,
        "sender_id": identity["user_id"],
        "header": header,
        "ciphertext": ciphertext_b64,
        "msg_type": req.msg_type,
        "timestamp": now
    }
    
    delivered = await transmit_outbound_e2ee_packet(req.conversation_id, packet)
    initial_status = "sent" if delivered else "queued"

    with get_db(MSGS_DB) as db:
        db.execute(
            "INSERT INTO messages (id, conversation_id, sender_id, content, ciphertext, msg_type, timestamp, is_outgoing, status) VALUES (?,?,?,?,?,?,?,?,?)",
            (msg_id, req.conversation_id, identity["user_id"], enc_content, payload_b64, req.msg_type, now, 1, initial_status)
        )
        db.commit()

    if "frontend" in connected_ws:
        try:
            await connected_ws["frontend"].send_json({"type": "sent_message_confirm", "msg_id": msg_id, "status": initial_status})
        except Exception:
            pass

    return {"ok": True, "id": msg_id, "status": initial_status, "timestamp": now, "payload": payload_b64}

@app.post("/messages/receive")
def api_receive_message(req: IncomingMsg):
    st = get_or_create_ratchet_session(req.sender_id, is_sender=False, incoming_header=req.header)
    plaintext_raw = ratchet_decrypt(st, req.header, req.ciphertext)
    save_ratchet_session(req.sender_id, st)

    # Process In-Band Delivery Token Rotation from sender
    msg_text = plaintext_raw
    try:
        inner_data = json.loads(plaintext_raw)
        if isinstance(inner_data, dict) and "text" in inner_data:
            msg_text = inner_data["text"]
            if inner_data.get("next_delivery_token"):
                new_token = inner_data["next_delivery_token"]
                with get_db(CONTACTS_DB) as db:
                    db.execute("UPDATE contacts SET delivery_token=? WHERE user_id=?", (new_token, req.sender_id))
                    db.commit()
                logger.info(f"[TokenRotation] Automatically rotated delivery_token for contact {req.sender_id}")
    except Exception:
        pass

    enc_content = vault_encrypt(msg_text)

    with get_db(MSGS_DB) as db:
        db.execute(
            "INSERT OR REPLACE INTO messages (id, conversation_id, sender_id, content, ciphertext, msg_type, timestamp, is_outgoing, status) VALUES (?,?,?,?,?,?,?,?,?)",
            (req.id, req.sender_id, req.sender_id, enc_content, req.ciphertext, req.msg_type, req.timestamp, 0, "received")
        )
        db.commit()

    if "frontend" in connected_ws:
        asyncio.create_task(connected_ws["frontend"].send_json({
            "type": "new_message",
            "message": {
                "id": req.id, "conversation_id": req.sender_id, "sender_id": req.sender_id,
                "content": msg_text, "timestamp": req.timestamp, "is_outgoing": 0
            }
        }))

    return {"ok": True, "decrypted": msg_text}

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

# ─── Groups & Cryptographic Sender Authentication ──────────────────────────────
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
    enc_sender_key = vault_encrypt(sender_key)

    with get_db(GROUPS_DB) as db:
        db.execute(
            "INSERT INTO groups (group_id, name, description, sender_key, created_by, created_at) VALUES (?,?,?,?,?,?)",
            (req.group_id, req.name, req.description, enc_sender_key, identity["user_id"], int(time.time()))
        )
        db.execute(
            "INSERT INTO group_members (group_id, user_id, display_name, sign_pk, dh_pk, role, joined_at) VALUES (?,?,?,?,?,?,?)",
            (req.group_id, identity["user_id"], identity["display_name"], identity["sign_pk"], identity["dh_pk"], "admin", int(time.time()))
        )
        db.commit()
    return {"ok": True, "group_id": req.group_id}

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
def export_group_key(group_id: str, recipient_id: str):
    with get_db(GROUPS_DB) as db:
        g = db.execute("SELECT sender_key FROM groups WHERE group_id=?", (group_id,)).fetchone()
        if not g: raise HTTPException(404, f"Group {group_id} not found")
        dec_sender_key = vault_decrypt(g["sender_key"])

    st = get_or_create_ratchet_session(recipient_id, is_sender=True)
    header, ciphertext_b64 = ratchet_encrypt(st, dec_sender_key)
    save_ratchet_session(recipient_id, st)

    return {"group_id": group_id, "header": header, "encrypted_key": ciphertext_b64}

@app.post("/groups/{group_id}/send")
def send_group_message(group_id: str, req: SendGroupMsgReq):
    identity = get_identity()
    if not identity: raise HTTPException(400, "No identity")
    msg_id = secrets.token_hex(16)
    now = int(time.time())

    with get_db(GROUPS_DB) as db:
        g = db.execute("SELECT sender_key FROM groups WHERE group_id=?", (group_id,)).fetchone()
        if not g: raise HTTPException(404, f"Group {group_id} not found")
        sender_key = b64d(vault_decrypt(g["sender_key"]))

    sign_sk = nacl.signing.SigningKey(b64d(identity["sign_sk"]))
    signature = sign_sk.sign(req.content.encode("utf-8")).signature

    box = nacl.secret.SecretBox(sender_key)
    payload_data = json.dumps({"content": req.content, "signature": b64e(signature), "sender_id": identity["user_id"]})
    ct = box.encrypt(payload_data.encode("utf-8"))
    enc_content = vault_encrypt(req.content)

    with get_db(MSGS_DB) as db:
        db.execute(
            "INSERT INTO messages (id, conversation_id, sender_id, content, ciphertext, msg_type, timestamp, is_outgoing, status) VALUES (?,?,?,?,?,?,?,?,?)",
            (msg_id, group_id, identity["user_id"], enc_content, b64e(ct), req.msg_type, now, 1, "sent")
        )
        db.commit()

    return {"ok": True, "id": msg_id, "timestamp": now, "ciphertext": b64e(ct)}

class ReceiveGroupMsgReq(BaseModel):
    group_id: str
    ciphertext: str

@app.post("/groups/{group_id}/receive")
def receive_group_message(group_id: str, req: ReceiveGroupMsgReq):
    with get_db(GROUPS_DB) as db:
        g = db.execute("SELECT sender_key FROM groups WHERE group_id=?", (group_id,)).fetchone()
        if not g: raise HTTPException(404, f"Group {group_id} not found")
        sender_key = b64d(vault_decrypt(g["sender_key"]))

    try:
        box = nacl.secret.SecretBox(sender_key)
        raw_payload = box.decrypt(b64d(req.ciphertext)).decode("utf-8")
        payload_data = json.loads(raw_payload)
        
        content = payload_data["content"]
        signature_b64 = payload_data["signature"]
        sender_id = payload_data["sender_id"]

        with get_db(GROUPS_DB) as db:
            member = db.execute("SELECT sign_pk FROM group_members WHERE group_id=? AND user_id=?", (group_id, sender_id)).fetchone()
        
        if not member:
            raise HTTPException(403, f"Group member {sender_id} not registered in group")

        sender_sign_pk = nacl.signing.VerifyKey(b64d(member["sign_pk"]))
        sender_sign_pk.verify(content.encode("utf-8"), b64d(signature_b64))

        logger.info(f"[Group] Cryptographic signature verified for message from {sender_id} in group {group_id}")

        msg_id = secrets.token_hex(16)
        now = int(time.time())
        enc_content = vault_encrypt(content)

        with get_db(MSGS_DB) as db:
            db.execute(
                "INSERT INTO messages (id, conversation_id, sender_id, content, ciphertext, msg_type, timestamp, is_outgoing, status) VALUES (?,?,?,?,?,?,?,?,?)",
                (msg_id, group_id, sender_id, enc_content, req.ciphertext, "text", now, 0, "received")
            )
            db.commit()

        return {"ok": True, "decrypted": content, "sender_id": sender_id, "signature_verified": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[Group] Group message signature verification failed: {e}")
        raise HTTPException(400, f"Group message signature verification failed: {e}")

# ─── Hardened Backup / Restore (Anti Zip-Slip Path Traversal Protection) ─────
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
        base_dir = APP_DATA.resolve()
        with zipfile.ZipFile(_io.BytesIO(raw)) as zf:
            for name in zf.namelist():
                target_path = (base_dir / name).resolve()
                if not str(target_path).startswith(str(base_dir)):
                    raise ValueError(f"Zip-Slip path traversal attempt detected in filename: {name}")
                with zf.open(name) as src, open(str(target_path), "wb") as dst:
                    dst.write(src.read())
        return {"ok": True, "message": "Backup wiederhergestellt. App neu starten."}
    except Exception as e:
        logger.error(f"[Backup] Import failed: {e}")
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
        asyncio.create_task(start_relay_client_worker())
    return {"ok": True, "connected": req.urls, "active_relay": settings.get("relay_url")}

@app.get("/relay/status")
def relay_status():
    settings = load_settings()
    is_connected = relay_writer_stream is not None and not relay_writer_stream.is_closing()
    return {"connected": is_connected, "relay_url": settings.get("relay_url")}

# ─── Startup Background Workers ───────────────────────────────────────────────
@app.on_event("startup")
async def on_startup():
    asyncio.create_task(start_relay_client_worker())

# ─── WebSocket (frontend UI) ──────────────────────────────────────────────────
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    token = ws.query_params.get("token") or ws.headers.get("sec-websocket-protocol")
    if token != API_TOKEN:
        logger.warning("WebSocket connection rejected: invalid API token")
        await ws.close(code=4003)
        return

    await ws.accept()
    connected_ws["frontend"] = ws
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        connected_ws.pop("frontend", None)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=49155, log_level="info")
