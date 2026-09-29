"""
Double Ratchet & X3DH Algorithm
===============================
Based on Signal's Double Ratchet and X3DH (Extended Triple Diffie-Hellman) specifications.
Provides Forward Secrecy, Post-Compromise Security, and Cryptographic Deniability.

References:
- https://signal.org/docs/specifications/doubleratchet/
- https://signal.org/docs/specifications/x3dh/
"""
import base64
import hashlib
import hmac as hmac_lib
import json
import struct
from typing import Dict, Optional, Tuple

import nacl.public
import nacl.signing
import nacl.secret
import nacl.utils
import nacl.bindings
import nacl.exceptions

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


# ─── Real X3DH Protocol (Extended Triple Diffie-Hellman) ─────────────────────
def x3dh_sender_derive(
    alice_ik_sk: nacl.public.PrivateKey,
    bob_ik_pk: nacl.public.PublicKey,
    bob_spk_pk: nacl.public.PublicKey,
    bob_spk_sig: bytes,
    bob_sign_pk: nacl.signing.VerifyKey,
    bob_opk_pk: Optional[nacl.public.PublicKey] = None
) -> Tuple[bytes, nacl.public.PrivateKey]:
    """
    Perform X3DH (Extended Triple Diffie-Hellman) as Sender (Alice).
    1. Verify Bob's Signed Prekey (SPK_B) signature using Bob's Signing Identity Key.
    2. Generate Alice's Ephemeral Keypair (EK_A).
    3. Compute DH1 = DH(IK_A, SPK_B), DH2 = DH(EK_A, IK_B), DH3 = DH(EK_A, SPK_B), and optional DH4 = DH(EK_A, OPK_B).
    4. Derive Master Shared Secret via HKDF.
    Returns (shared_secret, ek_a).
    """
    # Signature Verification of Signed Prekey
    bob_sign_pk.verify(bytes(bob_spk_pk), bob_spk_sig)

    ek_a = nacl.public.PrivateKey.generate()
    dh1 = _dh(alice_ik_sk, bob_spk_pk)
    dh2 = _dh(ek_a, bob_ik_pk)
    dh3 = _dh(ek_a, bob_spk_pk)
    dh4 = _dh(ek_a, bob_opk_pk) if bob_opk_pk else b""

    master_ikm = dh1 + dh2 + dh3 + dh4
    shared_secret = _hkdf(master_ikm, b"", b"pm-x3dh-protocol-v1", 32)
    return shared_secret, ek_a


def x3dh_receiver_derive(
    bob_ik_sk: nacl.public.PrivateKey,
    bob_spk_sk: nacl.public.PrivateKey,
    alice_ik_pk: nacl.public.PublicKey,
    alice_ek_pk: nacl.public.PublicKey,
    bob_opk_sk: Optional[nacl.public.PrivateKey] = None
) -> bytes:
    """
    Perform X3DH (Extended Triple Diffie-Hellman) as Receiver (Bob).
    Computes DH1 = DH(SPK_B, IK_A), DH2 = DH(IK_B, EK_A), DH3 = DH(SPK_B, EK_A), and optional DH4 = DH(OPK_B, EK_A).
    Derives identical Master Shared Secret.
    """
    dh1 = _dh(bob_spk_sk, alice_ik_pk)
    dh2 = _dh(bob_ik_sk, alice_ek_pk)
    dh3 = _dh(bob_spk_sk, alice_ek_pk)
    dh4 = _dh(bob_opk_sk, alice_ek_pk) if bob_opk_sk else b""

    master_ikm = dh1 + dh2 + dh3 + dh4
    return _hkdf(master_ikm, b"", b"pm-x3dh-protocol-v1", 32)


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


# ─── Message AEAD Encryption/Decryption with Header AAD Authentication ────────
def _encrypt_msg(mk: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """
    Encrypt message with ChaCha20-Poly1305 IETF AEAD binding the Header as Associated Data (AAD).
    Prevents active MitM header tampering.
    """
    enc_key = _hkdf(mk, b"", RATCHET_INFO_MSG, 32)
    nonce = nacl.utils.random(12)
    ciphertext = nacl.bindings.crypto_aead_chacha20poly1305_ietf_encrypt(plaintext, aad, nonce, enc_key)
    return nonce + ciphertext


def _decrypt_msg(mk: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """
    Decrypt message and verify Associated Data (AAD Header).
    Raises CryptoError if header or ciphertext was tampered with.
    """
    enc_key = _hkdf(mk, b"", RATCHET_INFO_MSG, 32)
    if len(ciphertext) < 12:
        raise nacl.exceptions.CryptoError("Invalid ciphertext length")
    nonce = ciphertext[:12]
    raw_ct = ciphertext[12:]
    return nacl.bindings.crypto_aead_chacha20poly1305_ietf_decrypt(raw_ct, aad, nonce, enc_key)


# ─── Ratchet State ────────────────────────────────────────────────────────────
class RatchetState:
    """Mutable Double Ratchet session state. Serialisable to/from JSON for DB storage."""

    __slots__ = ("dhs", "dhr", "rk", "cks", "ckr", "ns", "nr", "pn", "mkskipped", "ek_a_pk")

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
        self.ek_a_pk: Optional[str] = None                   # Ephemeral Public Key for initial X3DH header

    # ── Serialisation ──────────────────────────────────────────────────────
    def to_json(self) -> str:
        return json.dumps({
            "dhs_sk": b64e(bytes(self.dhs)) if self.dhs else None,
            "dhr":    b64e(bytes(self.dhr)) if self.dhr else None,
            "rk":     b64e(self.rk)         if self.rk  else None,
            "cks":    b64e(self.cks)         if self.cks else None,
            "ckr":    b64e(self.ckr)         if self.ckr else None,
            "ns": self.ns, "nr": self.nr, "pn": self.pn,
            "mkskipped": {k: b64e(v) for k, v in self.mkskipped.items()},
            "ek_a_pk": self.ek_a_pk
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
        st.ek_a_pk = d.get("ek_a_pk")
        return st


# ─── Ratchet initialisation ───────────────────────────────────────────────────
def init_as_sender(shared_secret: bytes, their_dh_pk_b64: str, ek_a: Optional[nacl.public.PrivateKey] = None) -> RatchetState:
    """
    Initialise Double Ratchet as the session INITIATOR.
    Caller has already performed X3DH to derive shared_secret.
    """
    their_pk = nacl.public.PublicKey(b64d(their_dh_pk_b64))
    st = RatchetState()
    st.dhs = nacl.public.PrivateKey.generate()
    st.dhr = their_pk
    st.rk, st.cks = kdf_rk(shared_secret, _dh(st.dhs, st.dhr))
    if ek_a:
        st.ek_a_pk = b64e(bytes(ek_a.public_key))
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
    Pads plaintext before encrypting and binds header as AAD for AEAD integrity.
    Includes X3DH Ephemeral Key (ek) in header on initial message.
    """
    if state.cks is None:
        raise RuntimeError("Ratchet not ready: sending chain key is None (call init_as_sender first)")

    state.cks, mk = kdf_ck(state.cks)

    header = {
        "dh": b64e(bytes(state.dhs.public_key)),
        "pn": state.pn,
        "n":  state.ns,
    }

    # Attach Ephemeral Key ek to header on first X3DH message
    if state.ek_a_pk:
        header["ek"] = state.ek_a_pk
        state.ek_a_pk = None # Clear after first transmission

    state.ns += 1

    aad_str = f"{header['dh']}:{header['pn']}:{header['n']}"
    if "ek" in header:
        aad_str += f":{header['ek']}"
    aad = aad_str.encode("utf-8")

    padded = pad_plaintext(plaintext.encode("utf-8"))
    ct = _encrypt_msg(mk, padded, aad)

    # Immediately overwrite mk in memory (best-effort in Python)
    mk = b"\x00" * len(mk)

    return header, b64e(ct)


def ratchet_decrypt(state: RatchetState, header: dict, ciphertext_b64: str) -> str:
    """
    Decrypt ciphertext, potentially performing a DH ratchet step.
    Verifies Associated Data (Header AAD) to prevent MitM header tampering.
    Returns plaintext string.
    """
    their_dh_pk_b64 = header["dh"]
    pn = header["pn"]
    n  = header["n"]

    aad_str = f"{their_dh_pk_b64}:{pn}:{n}"
    if "ek" in header:
        aad_str += f":{header['ek']}"
    aad = aad_str.encode("utf-8")

    their_pk = nacl.public.PublicKey(b64d(their_dh_pk_b64))
    ct = b64d(ciphertext_b64)

    # 1. Check skipped message keys
    skip_key = f"{their_dh_pk_b64}:{n}"
    if skip_key in state.mkskipped:
        mk = state.mkskipped.pop(skip_key)
        return unpad_plaintext(_decrypt_msg(mk, ct, aad)).decode("utf-8")

    # 2. DH ratchet step if sender used a new DH key
    if state.dhr is None or bytes(their_pk) != bytes(state.dhr):
        _skip_message_keys(state, pn)      # skip ahead in old chain
        _dh_ratchet(state, their_pk)       # perform ratchet step

    # 3. Skip ahead to message n in new chain
    _skip_message_keys(state, n)

    state.ckr, mk = kdf_ck(state.ckr)
    state.nr += 1

    plaintext = unpad_plaintext(_decrypt_msg(mk, ct, aad)).decode("utf-8")
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
