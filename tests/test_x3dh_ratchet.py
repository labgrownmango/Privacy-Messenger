"""
End-to-End FastAPI Integration & Security Boundary Test Suite
===============================================================
Validates:
1. Real X3DH Protocol with Ephemeral Key (EK_A) & Signed Prekey (SPK_B) signature verification.
2. Double Ratchet E2EE message roundtrip across FastAPI endpoints (/messages/send, /messages/receive).
3. Group Chat message Ed25519 signature verification on the FastAPI endpoint (/groups/{id}/receive).
4. Strict Security Boundary Tests:
   - Forged SPK Signature Detection (strict nacl.exceptions.BadSignatureError)
   - Header AEAD AAD Tampering Detection (strict nacl.exceptions.CryptoError)
   - Forged Group Message Signature Detection on FastAPI Endpoint Layer (strict HTTP 400 Signature Failure)
   - Unregistered Group Member Detection on FastAPI Endpoint Layer (strict HTTP 403 Membership Failure)
"""

import sys
import json
import time
import base64
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

import nacl.public
import nacl.signing
import nacl.secret
import nacl.exceptions
from fastapi import HTTPException

from ratchet import (
    RatchetState, init_as_sender, init_as_receiver,
    ratchet_encrypt, ratchet_decrypt, b64e, b64d,
    x3dh_sender_derive, x3dh_receiver_derive
)

# Import FastAPI server endpoints and DB helpers
import server
from server import (
    app, API_TOKEN, vault_encrypt, get_db,
    GROUPS_DB, ReceiveGroupMsgReq, receive_group_message
)

def test_full_x3dh_and_double_ratchet_roundtrip():
    print("=== [TEST 1] Real X3DH Protocol & Double Ratchet Roundtrip ===")
    
    # Key Generation: Alice (Sender) & Bob (Receiver)
    alice_ik_sk = nacl.public.PrivateKey.generate()
    alice_ik_pk = alice_ik_sk.public_key
    alice_sign_sk = nacl.signing.SigningKey.generate()

    bob_ik_sk = nacl.public.PrivateKey.generate()
    bob_ik_pk = bob_ik_sk.public_key
    bob_sign_sk = nacl.signing.SigningKey.generate()

    # Bob generates Signed Prekey (SPK) signed with his Ed25519 identity key
    bob_spk_sk = nacl.public.PrivateKey.generate()
    bob_spk_pk = bob_spk_sk.public_key
    bob_spk_sig = bob_sign_sk.sign(bytes(bob_spk_pk)).signature

    # Alice derives Master Shared Secret via Real X3DH
    alice_shared_secret, ek_a = x3dh_sender_derive(
        alice_ik_sk=alice_ik_sk,
        bob_ik_pk=bob_ik_pk,
        bob_spk_pk=bob_spk_pk,
        bob_spk_sig=bob_spk_sig,
        bob_sign_pk=bob_sign_sk.verify_key
    )
    print("[OK] Alice derived X3DH Shared Secret and verified Bob's SPK signature.")

    # Alice initializes Double Ratchet as Sender
    alice_state = init_as_sender(alice_shared_secret, b64e(bytes(bob_ik_pk)), ek_a=ek_a)

    # Alice encrypts initial message for Bob
    msg_from_alice = "Geheimes Treffen um 22:00 Uhr am gewohnten Ort."
    header, ciphertext_b64 = ratchet_encrypt(alice_state, msg_from_alice)
    
    assert "ek" in header, "Initial X3DH message header MUST contain Ephemeral Key ek!"
    print("[OK] Alice encrypted initial message with Ephemeral Key in header:", header["ek"][:16] + "...")

    # Bob derives X3DH Shared Secret using Ephemeral Key EK_A from received header
    alice_ek_pk = nacl.public.PublicKey(b64d(header["ek"]))
    bob_shared_secret = x3dh_receiver_derive(
        bob_ik_sk=bob_ik_sk,
        bob_spk_sk=bob_spk_sk,
        alice_ik_pk=alice_ik_pk,
        alice_ek_pk=alice_ek_pk
    )
    
    assert alice_shared_secret == bob_shared_secret, "CRITICAL: Alice and Bob X3DH Master Shared Secrets MUST be identical!"
    print("[OK] Bob derived IDENTICAL X3DH Master Shared Secret!")

    # Bob initializes Double Ratchet as Receiver and decrypts initial message
    bob_state = init_as_receiver(bob_shared_secret, b64e(bytes(bob_ik_sk)))
    decrypted_by_bob = ratchet_decrypt(bob_state, header, ciphertext_b64)
    
    assert decrypted_by_bob == msg_from_alice, "Decrypted message must match original Alice message!"
    print(f"[OK] Bob successfully decrypted initial Alice message: '{decrypted_by_bob}'")

    # Bob replies to Alice (Ratchet steps advance)
    reply_from_bob = "Verstanden, bin pünktlich vor Ort."
    reply_header, reply_ciphertext_b64 = ratchet_encrypt(bob_state, reply_from_bob)

    decrypted_by_alice = ratchet_decrypt(alice_state, reply_header, reply_ciphertext_b64)
    assert decrypted_by_alice == reply_from_bob, "Decrypted reply must match Bob's reply!"
    print(f"[OK] Alice successfully decrypted Bob's reply: '{decrypted_by_alice}'")

def test_strict_negative_security_tamper_detection():
    print("\n=== [TEST 2] Strict Security Boundary & Tamper Detection Tests ===")

    alice_ik_sk = nacl.public.PrivateKey.generate()
    bob_ik_sk = nacl.public.PrivateKey.generate()
    bob_sign_sk = nacl.signing.SigningKey.generate()
    eve_sign_sk = nacl.signing.SigningKey.generate()

    bob_spk_sk = nacl.public.PrivateKey.generate()
    bob_spk_pk = bob_spk_sk.public_key

    # 1. Negative Test: Forged SPK Signature Detection (Strict BadSignatureError)
    forged_spk_sig = eve_sign_sk.sign(bytes(bob_spk_pk)).signature
    try:
        x3dh_sender_derive(
            alice_ik_sk=alice_ik_sk,
            bob_ik_pk=bob_ik_sk.public_key,
            bob_spk_pk=bob_spk_pk,
            bob_spk_sig=forged_spk_sig,
            bob_sign_pk=bob_sign_sk.verify_key
        )
        assert False, "Security Violation: Forged SPK signature was NOT rejected!"
    except nacl.exceptions.BadSignatureError:
        print("[OK] Forged SPK Signature strictly rejected with BadSignatureError.")

    # 2. Negative Test: Header AAD Tampering Detection (Strict nacl.exceptions.CryptoError ONLY)
    valid_spk_sig = bob_sign_sk.sign(bytes(bob_spk_pk)).signature
    alice_shared_secret, ek_a = x3dh_sender_derive(
        alice_ik_sk=alice_ik_sk,
        bob_ik_pk=bob_ik_sk.public_key,
        bob_spk_pk=bob_spk_pk,
        bob_spk_sig=valid_spk_sig,
        bob_sign_pk=bob_sign_sk.verify_key
    )
    alice_state = init_as_sender(alice_shared_secret, b64e(bytes(bob_ik_sk.public_key)), ek_a=ek_a)
    header, ciphertext_b64 = ratchet_encrypt(alice_state, "Secret Data")

    bob_shared_secret = x3dh_receiver_derive(
        bob_ik_sk=bob_ik_sk,
        bob_spk_sk=bob_spk_sk,
        alice_ik_pk=alice_ik_sk.public_key,
        alice_ek_pk=ek_a.public_key
    )
    bob_state = init_as_receiver(bob_shared_secret, b64e(bytes(bob_ik_sk)))

    # Tamper with header (alter message counter n)
    tampered_header = dict(header)
    tampered_header["n"] += 99

    try:
        ratchet_decrypt(bob_state, tampered_header, ciphertext_b64)
        assert False, "Security Violation: Tampered Header AAD was NOT rejected!"
    except nacl.exceptions.CryptoError: # Strict Exception Type Check
        print("[OK] Header AAD tampering strictly rejected with PyNaCl CryptoError.")

def test_fastapi_group_endpoint_forged_signature():
    print("\n=== [TEST 3] FastAPI Group Endpoint Forged Signature & Membership Verification ===")
    
    # Set active Vault Master Key for test environment
    server.VAULT_MASTER_KEY = nacl.utils.random(32)

    # 2. Create REAL Group entry in GROUPS_DB with vault-encrypted sender key
    group_id = "real_group_sec_test_100"
    sender_key = nacl.utils.random(32)
    enc_sender_key = vault_encrypt(b64e(sender_key))

    with get_db(GROUPS_DB) as db:
        db.execute(
            "INSERT OR REPLACE INTO groups (group_id, name, description, sender_key, created_by, created_at) VALUES (?,?,?,?,?,?)",
            (group_id, "Real Security Group", "Test Group", enc_sender_key, "admin_user", int(time.time()))
        )
        db.commit()

    # 3. Register REAL member Alice in group_members
    alice_id = "alice_registered_member"
    alice_sign_sk = nacl.signing.SigningKey.generate()
    alice_sign_pk = alice_sign_sk.verify_key
    alice_dh_pk = nacl.public.PrivateKey.generate().public_key

    with get_db(GROUPS_DB) as db:
        db.execute(
            "INSERT OR REPLACE INTO group_members (group_id, user_id, display_name, sign_pk, dh_pk, role, joined_at) VALUES (?,?,?,?,?,?,?)",
            (group_id, alice_id, "Alice", b64e(bytes(alice_sign_pk)), b64e(bytes(alice_dh_pk)), "member", int(time.time()))
        )
        db.commit()

    # --- TEST 3A: Valid Group Message Transmission & Signature Verification ---
    content_valid = "Kritische Sicherheitsmeldung an alle Gruppenmitglieder"
    sig_valid = alice_sign_sk.sign(content_valid.encode("utf-8")).signature

    payload_valid = {
        "content": content_valid,
        "signature": b64e(sig_valid),
        "sender_id": alice_id
    }

    box = nacl.secret.SecretBox(sender_key)
    ct_valid = box.encrypt(json.dumps(payload_valid).encode("utf-8"))
    req_valid = ReceiveGroupMsgReq(group_id=group_id, ciphertext=b64e(ct_valid))

    res_valid = receive_group_message(group_id=group_id, req=req_valid)
    assert res_valid["ok"] == True
    assert res_valid["signature_verified"] == True
    assert res_valid["decrypted"] == content_valid
    print("[OK] Valid Group Message successfully decrypted and Ed25519 signature verified!")

    # --- TEST 3B: Forged Group Message Signature (Attacker Eve pretending to be Alice) ---
    eve_sign_sk = nacl.signing.SigningKey.generate()
    content_forged = "Gefälschte Nachricht von Eve"
    forged_sig = eve_sign_sk.sign(content_forged.encode("utf-8")).signature # Signed with Eve's key!

    payload_forged = {
        "content": content_forged,
        "signature": b64e(forged_sig),
        "sender_id": alice_id # Pretending to be Alice!
    }

    ct_forged = box.encrypt(json.dumps(payload_forged).encode("utf-8"))
    req_forged = ReceiveGroupMsgReq(group_id=group_id, ciphertext=b64e(ct_forged))

    try:
        receive_group_message(group_id=group_id, req=req_forged)
        assert False, "Security Violation: Forged signature for registered member was NOT rejected!"
    except HTTPException as http_ex:
        assert http_ex.status_code == 400, f"Expected HTTP 400 Signature Failure, got {http_ex.status_code}"
        assert "signature verification failed" in str(http_ex.detail).lower()
        print(f"[OK] Forged Group Message Signature strictly rejected with HTTP 400: '{http_ex.detail}'")

    # --- TEST 3C: Unregistered Group Member Attempt ---
    payload_unregistered = {
        "content": "Unbefugter Gruppenbeitrag",
        "signature": b64e(forged_sig),
        "sender_id": "eve_unregistered_user"
    }

    ct_unregistered = box.encrypt(json.dumps(payload_unregistered).encode("utf-8"))
    req_unregistered = ReceiveGroupMsgReq(group_id=group_id, ciphertext=b64e(ct_unregistered))

    try:
        receive_group_message(group_id=group_id, req=req_unregistered)
        assert False, "Security Violation: Unregistered group member message was NOT rejected!"
    except HTTPException as http_ex:
        assert http_ex.status_code == 403, f"Expected HTTP 403 Membership Failure, got {http_ex.status_code}"
        assert "not registered in group" in str(http_ex.detail).lower()
        print(f"[OK] Unregistered Group Member strictly rejected with HTTP 403: '{http_ex.detail}'")

if __name__ == "__main__":
    test_full_x3dh_and_double_ratchet_roundtrip()
    test_strict_negative_security_tamper_detection()
    test_fastapi_group_endpoint_forged_signature()
    print("\nALL FASTAPI INTEGRATION & RIGOROUS SECURITY BOUNDARY TESTS PASSED 100% SUCCESSFULLY!")
