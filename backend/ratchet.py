"""
Double Ratchet Algorithm
========================
Based on Signal's Double Ratchet specification.
Provides Forward Secrecy + Post-Compromise Security.

Reference: https://signal.org/docs/specifications/doubleratchet/
"""
import base64
import hashlib
import hmac as hmac_lib
import json
import struct
from typing import Dict, Optional, Tuple

import nacl.public
import nacl.secret
import nacl.utils

# ─── Constants ────────────────────────────────────────────────────────────────
MAX_SKIP = 100          # max skipped message keys to cache
RATCHET_INFO_ROOT = b"pm-ratchet-root-v1"
RATCHET_INFO_MSG  = b"pm-ratchet-msg-v1"
BUCKET_SIZES = [256, 512, 1024, 2048, 4096, 8192]  # padding buckets (bytes)


# ─── Encoding helpers ─────────────────────────────────────────────────────────
def b64e(b: bytes) -> str: return base64.b64encode(b).decode()
def b64d(s: str)  -> bytes: return base64.b64decode(s)


# ─── KDF primitives ───────────────────────────────────────────────────────────
def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256: extract-and-expand key derivation."""
    if not salt:
        salt = bytes(32)
    prk = hmac_lib.new(salt, ikm, hashlib.sha256).digest()
    t, okm = b"", b""
    for i in range(1, -(-length // 32) + 1):
        t = hmac_lib.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def kdf_rk(rk: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
    """Derive new root key and new chain key from root key + DH output."""
    out = _hkdf(dh_out, rk, RATCHET_INFO_ROOT, 64)
    return out[:32], out[32:]   # (new_rk, new_ck)


def kdf_ck(ck: bytes) -> Tuple[bytes, bytes]:
    """Advance chain key: returns (new_chain_key, message_key)."""
    mk     = hmac_lib.new(ck, b"\x01", hashlib.sha256).digest()
    new_ck = hmac_lib.new(ck, b"\x02", hashlib.sha256).digest()
    return new_ck, mk


def _dh(sk: nacl.public.PrivateKey, pk: nacl.public.PublicKey) -> bytes:
    """X25519 DH exchange."""
    return bytes(nacl.public.Box(sk, pk).shared_key())


# ─── Padding ──────────────────────────────────────────────────────────────────
def pad_plaintext(plaintext: bytes) -> bytes:
    """Pad plaintext to next bucket size to hide message length."""
    n = len(plaintext)
    for size in BUCKET_SIZES:
        if n + 4 <= size:
            padding = size - n - 4
            return struct.pack(">I", n) + plaintext + b"\x00" * padding
    # Larger than all buckets: pad to next 4096-byte boundary
    target = ((n + 4 + 4095) // 4096) * 4096
    return struct.pack(">I", n) + plaintext + b"\x00" * (target - n - 4)


def unpad_plaintext(padded: bytes) -> bytes:
    """Remove padding, recover original plaintext."""
    n = struct.unpack(">I", padded[:4])[0]
    return padded[4:4 + n]


# ─── Message encryption/decryption ───────────────────────────────────────────
def _encrypt_msg(mk: bytes, plaintext: bytes) -> bytes:
    """Encrypt message with derived per-message key (ChaCha20-Poly1305 via NaCl SecretBox)."""
    enc_key = _hkdf(mk, b"", RATCHET_INFO_MSG, 32)
    return nacl.secret.SecretBox(enc_key).encrypt(plaintext)


def _decrypt_msg(mk: bytes, ciphertext: bytes) -> bytes:
    enc_key = _hkdf(mk, b"", RATCHET_INFO_MSG, 32)
    return nacl.secret.SecretBox(enc_key).decrypt(ciphertext)


# ─── Ratchet State ────────────────────────────────────────────────────────────
class RatchetState:
    """Mutable Double Ratchet session state. Serialisable to/from JSON for DB storage."""

    __slots__ = ("dhs", "dhr", "rk", "cks", "ckr", "ns", "nr", "pn", "mkskipped")

    def __init__(self):
        self.dhs: Optional[nacl.public.PrivateKey] = None   # our DH ratchet key pair
        self.dhr: Optional[nacl.public.PublicKey]  = None   # their DH ratchet public key
        self.rk:  Optional[bytes] = None                     # root key (32 B)
        self.cks: Optional[bytes] = None                     # sending chain key
        self.ckr: Optional[bytes] = None                     # receiving chain key
        self.ns:  int = 0                                    # sending message counter
        self.nr:  int = 0                                    # receiving message counter
        self.pn:  int = 0                                    # previous chain length
        self.mkskipped: Dict[str, bytes] = {}               # {dh_pk_b64:n -> mk}

    # ── Serialisation ──────────────────────────────────────────────────────
    def to_json(self) -> str:
        return json.dumps({
            "dhs_sk": b64e(bytes(self.dhs)) if self.dhs else None,
            "dhr":    b64e(bytes(self.dhr)) if self.dhr else None,
            "rk":     b64e(self.rk)         if self.rk  else None,
            "cks":    b64e(self.cks)         if self.cks else None,
            "ckr":    b64e(self.ckr)         if self.ckr else None,
            "ns": self.ns, "nr": self.nr, "pn": self.pn,
            "mkskipped": {k: b64e(v) for k, v in self.mkskipped.items()}
        })

    @classmethod
    def from_json(cls, s: str) -> "RatchetState":
        d = json.loads(s)
        st = cls()
        if d.get("dhs_sk"): st.dhs = nacl.public.PrivateKey(b64d(d["dhs_sk"]))
        if d.get("dhr"):     st.dhr = nacl.public.PublicKey(b64d(d["dhr"]))
        if d.get("rk"):      st.rk  = b64d(d["rk"])
        if d.get("cks"):     st.cks = b64d(d["cks"])
        if d.get("ckr"):     st.ckr = b64d(d["ckr"])
        st.ns = d.get("ns", 0)
        st.nr = d.get("nr", 0)
        st.pn = d.get("pn", 0)
        st.mkskipped = {k: b64d(v) for k, v in d.get("mkskipped", {}).items()}
        return st


# ─── Ratchet initialisation ───────────────────────────────────────────────────
def init_as_sender(shared_secret: bytes, their_dh_pk_b64: str) -> RatchetState:
    """
    Initialise Double Ratchet as the session INITIATOR.
    Caller has already performed X3DH to derive shared_secret.
    """
    their_pk = nacl.public.PublicKey(b64d(their_dh_pk_b64))
    st = RatchetState()
    st.dhs = nacl.public.PrivateKey.generate()
    st.dhr = their_pk
    st.rk, st.cks = kdf_rk(shared_secret, _dh(st.dhs, st.dhr))
    return st


def init_as_receiver(shared_secret: bytes, my_dh_sk_b64: str) -> RatchetState:
    """
    Initialise Double Ratchet as the session RECEIVER.
    The first message's header will trigger the first DH ratchet step.
    """
    st = RatchetState()
    st.dhs = nacl.public.PrivateKey(b64d(my_dh_sk_b64))
    st.rk  = shared_secret
    return st


# ─── Encrypt / Decrypt ────────────────────────────────────────────────────────
def ratchet_encrypt(state: RatchetState, plaintext: str) -> Tuple[dict, str]:
    """
    Encrypt plaintext, advance sending chain.
    Returns (header_dict, ciphertext_b64).
    Pads plaintext before encrypting to hide length.
    """
    if state.cks is None:
        raise RuntimeError("Ratchet not ready: sending chain key is None (call init_as_sender first)")

    state.cks, mk = kdf_ck(state.cks)

    header = {
        "dh": b64e(bytes(state.dhs.public_key)),
        "pn": state.pn,
        "n":  state.ns,
    }
    state.ns += 1

    padded = pad_plaintext(plaintext.encode("utf-8"))
    ct = _encrypt_msg(mk, padded)
    # Immediately overwrite mk in memory (best-effort in Python)
    mk = b"\x00" * len(mk)

    return header, b64e(ct)


def ratchet_decrypt(state: RatchetState, header: dict, ciphertext_b64: str) -> str:
    """
    Decrypt ciphertext, potentially performing a DH ratchet step.
    Returns plaintext string.
    """
    their_dh_pk_b64 = header["dh"]
    pn = header["pn"]
    n  = header["n"]
    their_pk = nacl.public.PublicKey(b64d(their_dh_pk_b64))

    ct = b64d(ciphertext_b64)

    # 1. Check skipped message keys
    skip_key = f"{their_dh_pk_b64}:{n}"
    if skip_key in state.mkskipped:
        mk = state.mkskipped.pop(skip_key)
        return unpad_plaintext(_decrypt_msg(mk, ct)).decode("utf-8")

    # 2. DH ratchet step if sender used a new DH key
    if state.dhr is None or bytes(their_pk) != bytes(state.dhr):
        _skip_message_keys(state, pn)      # skip ahead in old chain
        _dh_ratchet(state, their_pk)       # perform ratchet step

    # 3. Skip ahead to message n in new chain
    _skip_message_keys(state, n)

    state.ckr, mk = kdf_ck(state.ckr)
    state.nr += 1

    plaintext = unpad_plaintext(_decrypt_msg(mk, ct)).decode("utf-8")
    mk = b"\x00" * len(mk)   # overwrite
    return plaintext


def _skip_message_keys(state: RatchetState, until: int):
    if state.nr + MAX_SKIP < until:
        raise ValueError(f"Too many skipped messages ({until - state.nr} > {MAX_SKIP})")
    if state.ckr is not None:
        dhr_b64 = b64e(bytes(state.dhr)) if state.dhr else "none"
        while state.nr < until:
            state.ckr, mk = kdf_ck(state.ckr)
            state.mkskipped[f"{dhr_b64}:{state.nr}"] = mk
            state.nr += 1
        # Prune oldest keys to prevent unbounded growth
        if len(state.mkskipped) > MAX_SKIP:
            oldest = list(state.mkskipped.keys())[:len(state.mkskipped) - MAX_SKIP]
            for k in oldest: del state.mkskipped[k]


def _dh_ratchet(state: RatchetState, their_pk: nacl.public.PublicKey):
    """Perform a DH ratchet step: derive new root/chain keys, generate new DH pair."""
    state.pn = state.ns
    state.ns = 0
    state.nr = 0
    state.dhr = their_pk
    state.rk, state.ckr = kdf_rk(state.rk, _dh(state.dhs, state.dhr))
    state.dhs = nacl.public.PrivateKey.generate()
    state.rk, state.cks = kdf_rk(state.rk, _dh(state.dhs, state.dhr))
