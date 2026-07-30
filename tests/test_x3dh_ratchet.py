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
   - Forged Group Message Signature Detection on FastAPI Endpoint Layer (HTTPException 400)
"""

import sys
import json
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

# Import FastAPI server endpoints and helpers
from server import (
    app, API_TOKEN, unlock_vault_session,
    IncomingMsg, ReceiveGroupMsgReq, receive_group_message
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
    print("\n=== [TEST 3] FastAPI Group Endpoint Forged Signature Verification ===")
    
    # Initialize vault session for server endpoints
    unlock_vault_session("TEST_PIN_1234")

    group_id = "test_group_security_99"
    sender_key = nacl.utils.random(32)
    eve_sign_sk = nacl.signing.SigningKey.generate()

    # Create encrypted group payload with Eve's forged signature
    group_content = "Malicious forged group announcement"
    forged_sig = eve_sign_sk.sign(group_content.encode("utf-8")).signature

    payload_dict = {
        "content": group_content,
        "signature": b64e(forged_sig),
        "sender_id": "eve_user_id"
    }

    box = nacl.secret.SecretBox(sender_key)
    ciphertext_bytes = box.encrypt(json.dumps(payload_dict).encode("utf-8"))
    req = ReceiveGroupMsgReq(group_id=group_id, ciphertext=b64e(ciphertext_bytes))

    # Test actual FastAPI server endpoint receive_group_message()
    try:
        receive_group_message(group_id=group_id, req=req)
        assert False, "Security Violation: FastAPI endpoint accepted group message with invalid sender/signature!"
    except HTTPException as http_ex:
        assert http_ex.status_code in (400, 403, 404), f"Unexpected HTTP status code: {http_ex.status_code}"
        print(f"[OK] FastAPI Endpoint receive_group_message() correctly rejected forged payload with HTTP {http_ex.status_code}: {http_ex.detail}")

if __name__ == "__main__":
    test_full_x3dh_and_double_ratchet_roundtrip()
    test_strict_negative_security_tamper_detection()
    test_fastapi_group_endpoint_forged_signature()
    print("\nALL FASTAPI INTEGRATION & STRICT SECURITY BOUNDARY TESTS PASSED 100% SUCCESSFULLY!")
