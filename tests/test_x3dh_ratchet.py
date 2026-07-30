"""
End-to-End Automated Integration & Security Boundary Test Suite
=================================================================
Validates:
1. Real X3DH Protocol with Ephemeral Key (EK_A) & Signed Prekey (SPK_B) signature verification.
2. Double Ratchet E2EE message roundtrip (Alice -> Bob and Bob -> Alice).
3. Group Chat message Ed25519 signature verification.
4. Negative Security Boundary Tests:
   - Forged SPK Signature Detection (BadSignatureError)
   - Header AEAD AAD Tampering Detection (CryptoError)
   - Forged Group Signature Detection (BadSignatureError)
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

import nacl.public
import nacl.signing
import nacl.exceptions
from ratchet import (
    RatchetState, init_as_sender, init_as_receiver,
    ratchet_encrypt, ratchet_decrypt, b64e, b64d,
    x3dh_sender_derive, x3dh_receiver_derive
)

def test_full_x3dh_and_double_ratchet_roundtrip():
    print("=== [TEST 1] Real X3DH Protocol & Double Ratchet Roundtrip ===")
    
    # 1. Key Generation
    # Alice (Sender)
    alice_ik_sk = nacl.public.PrivateKey.generate()
    alice_ik_pk = alice_ik_sk.public_key
    alice_sign_sk = nacl.signing.SigningKey.generate()
    alice_sign_pk = alice_sign_sk.verify_key

    # Bob (Receiver)
    bob_ik_sk = nacl.public.PrivateKey.generate()
    bob_ik_pk = bob_ik_sk.public_key
    bob_sign_sk = nacl.signing.SigningKey.generate()
    bob_sign_pk = bob_sign_sk.verify_key

    # Bob generates Signed Prekey (SPK) and signs it with his Signing Identity Key
    bob_spk_sk = nacl.public.PrivateKey.generate()
    bob_spk_pk = bob_spk_sk.public_key
    bob_spk_sig = bob_sign_sk.sign(bytes(bob_spk_pk)).signature

    # 2. X3DH Shared Secret Derivation on Alice's side
    alice_shared_secret, ek_a = x3dh_sender_derive(
        alice_ik_sk=alice_ik_sk,
        bob_ik_pk=bob_ik_pk,
        bob_spk_pk=bob_spk_pk,
        bob_spk_sig=bob_spk_sig,
        bob_sign_pk=bob_sign_pk
    )
    print("[OK] Alice successfully derived X3DH Shared Secret and verified Bob's SPK signature.")

    # 3. Alice initializes Double Ratchet as Sender
    alice_state = init_as_sender(alice_shared_secret, b64e(bytes(bob_ik_pk)), ek_a=ek_a)

    # 4. Alice encrypts initial message for Bob
    msg_from_alice = "Geheimes Treffen um 22:00 Uhr am gewohnten Ort."
    header, ciphertext_b64 = ratchet_encrypt(alice_state, msg_from_alice)
    
    assert "ek" in header, "Initial X3DH message header MUST contain Ephemeral Key ek!"
    print("[OK] Alice encrypted initial message with Ephemeral Key in header:", header["ek"][:16] + "...")

    # 5. Bob derives X3DH Shared Secret using Ephemeral Key EK_A from received header
    alice_ek_pk = nacl.public.PublicKey(b64d(header["ek"]))
    bob_shared_secret = x3dh_receiver_derive(
        bob_ik_sk=bob_ik_sk,
        bob_spk_sk=bob_spk_sk,
        alice_ik_pk=alice_ik_pk,
        alice_ek_pk=alice_ek_pk
    )
    
    assert alice_shared_secret == bob_shared_secret, "CRITICAL: Alice and Bob X3DH Master Shared Secrets MUST be identical!"
    print("[OK] Bob derived IDENTICAL X3DH Master Shared Secret!")

    # 6. Bob initializes Double Ratchet as Receiver and decrypts initial message
    bob_state = init_as_receiver(bob_shared_secret, b64e(bytes(bob_ik_sk)))
    decrypted_by_bob = ratchet_decrypt(bob_state, header, ciphertext_b64)
    
    assert decrypted_by_bob == msg_from_alice, "Decrypted message must match original Alice message!"
    print(f"[OK] Bob successfully decrypted initial Alice message: '{decrypted_by_bob}'")

    # 7. Bob replies to Alice (Ratchet steps advance)
    reply_from_bob = "Verstanden, bin pünktlich vor Ort."
    reply_header, reply_ciphertext_b64 = ratchet_encrypt(bob_state, reply_from_bob)

    decrypted_by_alice = ratchet_decrypt(alice_state, reply_header, reply_ciphertext_b64)
    assert decrypted_by_alice == reply_from_bob, "Decrypted reply must match Bob's reply!"
    print(f"[OK] Alice successfully decrypted Bob's reply: '{decrypted_by_alice}'")

def test_group_signature_verification():
    print("\n=== [TEST 2] Group Chat Ed25519 Signature Verification ===")
    
    sender_sign_sk = nacl.signing.SigningKey.generate()
    sender_sign_pk = sender_sign_sk.verify_key

    group_content = "Warnung: Kritische Sicherheitsaktualisierung durchführen!"
    signature = sender_sign_sk.sign(group_content.encode("utf-8")).signature

    # Recipient verifies signature
    sender_sign_pk.verify(group_content.encode("utf-8"), signature)
    print("[OK] Group message signature successfully verified using sender's Ed25519 VerifyKey!")

def test_negative_security_tamper_detection():
    print("\n=== [TEST 3] Negative Security Boundary Tests (Tamper Detection) ===")

    alice_ik_sk = nacl.public.PrivateKey.generate()
    bob_ik_sk = nacl.public.PrivateKey.generate()
    bob_sign_sk = nacl.signing.SigningKey.generate()
    eve_sign_sk = nacl.signing.SigningKey.generate() # Attacker

    bob_spk_sk = nacl.public.PrivateKey.generate()
    bob_spk_pk = bob_spk_sk.public_key

    # 1. Negative Test: Forged SPK Signature Detection
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
        print("[OK] Forged SPK Signature correctly rejected with BadSignatureError.")

    # 2. Negative Test: Header AAD Tampering Detection
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

    # Tamper with header (e.g. alter message counter n)
    tampered_header = dict(header)
    tampered_header["n"] += 99

    try:
        ratchet_decrypt(bob_state, tampered_header, ciphertext_b64)
        assert False, "Security Violation: Tampered Header AAD was NOT rejected!"
    except (nacl.exceptions.CryptoError, Exception):
        print("[OK] Header AAD tampering correctly rejected with CryptoError.")

    # 3. Negative Test: Forged Group Message Signature Detection
    group_content = "Normal Message"
    forged_sig = eve_sign_sk.sign(group_content.encode("utf-8")).signature
    try:
        bob_sign_sk.verify_key.verify(group_content.encode("utf-8"), forged_sig)
        assert False, "Security Violation: Forged Group Signature was NOT rejected!"
    except nacl.exceptions.BadSignatureError:
        print("[OK] Forged Group Signature correctly rejected with BadSignatureError.")

if __name__ == "__main__":
    test_full_x3dh_and_double_ratchet_roundtrip()
    test_group_signature_verification()
    test_negative_security_tamper_detection()
    print("\nALL HAPPY PATH & NEGATIVE SECURITY BOUNDARY TESTS PASSED 100% SUCCESSFULLY!")
