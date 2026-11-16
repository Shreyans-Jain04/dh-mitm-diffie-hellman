"""
dh_core.py - Core logic for the Diffie-Hellman MITM demo.

Contains:
  * DH parameters (RFC 3526 Group 14, 2048-bit, plus a small "toy" group for display)
  * Key generation / shared secret / key derivation
  * AES-GCM message encryption helpers
  * simulate_unauthenticated(): Alice <-> Mallory <-> Bob, plain DH (VULNERABLE)
  * simulate_authenticated():   Alice <-> Mallory <-> Bob, DH + Ed25519 signatures (SECURE)

Educational use only.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

# --------------------------------------------------------------------------- #
# Parameters
# --------------------------------------------------------------------------- #
# RFC 3526, 2048-bit MODP Group (Group 14), generator g = 2
RFC3526_G14_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
RFC3526_G14_G = 2

# Toy group (64-bit prime) - ONLY so numbers are readable on screen. Insecure!
TOY_P = 18446744073709551557  # largest prime below 2**64
TOY_G = 5

GROUPS = {
    "Toy 64-bit (readable numbers, insecure)": (TOY_P, TOY_G),
    "RFC 3526 Group 14 (2048-bit, realistic)": (RFC3526_G14_P, RFC3526_G14_G),
}


# --------------------------------------------------------------------------- #
# Primitive helpers
# --------------------------------------------------------------------------- #
def gen_dh_keypair(p: int, g: int) -> tuple[int, int]:
    """Return (private, public) with private in [2, p-2]."""
    priv = secrets.randbelow(p - 3) + 2
    pub = pow(g, priv, p)
    return priv, pub


def shared_secret(priv: int, peer_pub: int, p: int) -> int:
    """Compute peer_pub ** priv mod p (with basic public value validation)."""
    if not (1 < peer_pub < p - 1):
        raise ValueError("Invalid DH public value")
    return pow(peer_pub, priv, p)


def derive_key(secret: int, p: int) -> bytes:
    """SHA-256 of the shared secret (fixed length) -> 32-byte AES key."""
    length = (p.bit_length() + 7) // 8
    return hashlib.sha256(secret.to_bytes(length, "big")).digest()


def fingerprint(key: bytes) -> str:
    """Short human-readable fingerprint of a key."""
    return hashlib.sha256(key).hexdigest()[:16]


def encrypt(key: bytes, plaintext: str) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext.encode(), None)


def decrypt(key: bytes, blob: bytes) -> Optional[str]:
    """Return plaintext or None if the key is wrong / data was tampered."""
    try:
        return AESGCM(key).decrypt(blob[:12], blob[12:], None).decode()
    except (InvalidTag, UnicodeDecodeError, ValueError):
        return None


def int_to_bytes(x: int, p: int) -> bytes:
    return x.to_bytes((p.bit_length() + 7) // 8, "big")


def short(x: int, n: int = 18) -> str:
    """Shorten a big integer for display."""
    s = str(x)
    return s if len(s) <= n * 2 else f"{s[:n]}...{s[-n:]}  ({len(s)} digits)"


# --------------------------------------------------------------------------- #
# Result containers
# --------------------------------------------------------------------------- #
@dataclass
class Step:
    who: str          # e.g. "Alice -> Mallory"
    text: str         # description
    ok: bool = True   # False = something failed / was rejected


@dataclass
class MitmResult:
    p: int
    g: int
    steps: list[Step] = field(default_factory=list)
    # keys
    alice_key: Optional[bytes] = None
    bob_key: Optional[bytes] = None
    mallory_key_with_alice: Optional[bytes] = None
    mallory_key_with_bob: Optional[bytes] = None
    # public values
    values: dict = field(default_factory=dict)
    # outcome
    attack_succeeded: bool = False
    alice_accepted: bool = True
    bob_accepted: bool = True


# --------------------------------------------------------------------------- #
# 1) UNAUTHENTICATED DH  -> Mallory wins
# --------------------------------------------------------------------------- #
def simulate_unauthenticated(p: int, g: int) -> MitmResult:
    r = MitmResult(p=p, g=g)

    a, A = gen_dh_keypair(p, g)           # Alice
    b, B = gen_dh_keypair(p, g)           # Bob
    m1, M1 = gen_dh_keypair(p, g)         # Mallory (talks to Bob, pretends to be Alice)
    m2, M2 = gen_dh_keypair(p, g)         # Mallory (talks to Alice, pretends to be Bob)
    r.values = {"A": A, "B": B, "M1 (fake A for Bob)": M1, "M2 (fake B for Alice)": M2}

    r.steps.append(Step("Alice -> (network)", f"Alice sends A = g^a mod p = {short(A)}"))
    r.steps.append(Step("Mallory intercepts", "Mallory blocks A and keeps a copy."))
    r.steps.append(Step("Mallory -> Bob", f"Mallory sends her own M1 = g^m1 mod p = {short(M1)} pretending to be Alice."))
    r.steps.append(Step("Bob -> (network)", f"Bob sends B = g^b mod p = {short(B)}"))
    r.steps.append(Step("Mallory intercepts", "Mallory blocks B and keeps a copy."))
    r.steps.append(Step("Mallory -> Alice", f"Mallory sends her own M2 = g^m2 mod p = {short(M2)} pretending to be Bob."))

    # Alice computes with M2, Bob with M1
    r.alice_key = derive_key(shared_secret(a, M2, p), p)
    r.bob_key = derive_key(shared_secret(b, M1, p), p)
    # Mallory computes both
    r.mallory_key_with_alice = derive_key(shared_secret(m2, A, p), p)
    r.mallory_key_with_bob = derive_key(shared_secret(m1, B, p), p)

    r.steps.append(Step("Alice", f"Computes K_A = M2^a mod p. Key fingerprint: {fingerprint(r.alice_key)}"))
    r.steps.append(Step("Bob", f"Computes K_B = M1^b mod p. Key fingerprint: {fingerprint(r.bob_key)}"))
    r.steps.append(Step("Mallory", f"Computes K_A = A^m2 and K_B = B^m1 -> fingerprints "
                                   f"{fingerprint(r.mallory_key_with_alice)} / {fingerprint(r.mallory_key_with_bob)}"))

    r.attack_succeeded = (
        r.alice_key == r.mallory_key_with_alice and r.bob_key == r.mallory_key_with_bob
    )
    r.steps.append(Step(
        "Result",
        "Alice and Bob each believe they share a key with each other, but really share one with Mallory. "
        "Nothing in plain DH let them detect this -> ATTACK SUCCEEDED." if r.attack_succeeded else "Attack failed.",
        ok=not r.attack_succeeded,
    ))
    return r


def relay_messages(r: MitmResult, message: str, tamper_text: Optional[str] = None) -> dict:
    """Alice sends `message` to Bob through Mallory (after an unauthenticated exchange)."""
    ct_from_alice = encrypt(r.alice_key, message)
    # Mallory decrypts with the key she shares with Alice
    read = decrypt(r.mallory_key_with_alice, ct_from_alice)
    forwarded_text = tamper_text if tamper_text else read
    ct_to_bob = encrypt(r.mallory_key_with_bob, forwarded_text)
    bob_reads = decrypt(r.bob_key, ct_to_bob)
    return {
        "sent_by_alice": message,
        "ciphertext_from_alice": ct_from_alice.hex(),
        "mallory_reads": read,
        "mallory_forwards": forwarded_text,
        "ciphertext_to_bob": ct_to_bob.hex(),
        "bob_receives": bob_reads,
        "tampered": bool(tamper_text),
    }


# --------------------------------------------------------------------------- #
# 2) AUTHENTICATED (SIGNED) DH -> Mallory is detected
# --------------------------------------------------------------------------- #
def gen_identity() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key()


def pub_to_hex(pk: Ed25519PublicKey) -> str:
    raw = pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw.hex()


def _signed_payload(sender: str, receiver: str, dh_pub: int, p: int) -> bytes:
    """Sign: identity labels + DH public value (binds value to the sender & intended peer)."""
    return b"DH-AUTH|" + sender.encode() + b"|" + receiver.encode() + b"|" + int_to_bytes(dh_pub, p)


def verify_signed(pk: Ed25519PublicKey, sig: bytes, sender: str, receiver: str, dh_pub: int, p: int) -> bool:
    try:
        pk.verify(sig, _signed_payload(sender, receiver, dh_pub, p))
        return True
    except InvalidSignature:
        return False


def simulate_authenticated(p: int, g: int, mallory_active: bool = True) -> MitmResult:
    """
    Alice and Bob already know each other's long-term Ed25519 PUBLIC keys
    (via a CA / pre-shared / fingerprint check). Each signs its DH public value.
    """
    r = MitmResult(p=p, g=g)

    # Long-term identities
    alice_sk, alice_pk = gen_identity()
    bob_sk, bob_pk = gen_identity()
    mal_sk, mal_pk = gen_identity()  # Mallory's own identity key (useless to impersonate Alice/Bob)

    a, A = gen_dh_keypair(p, g)
    b, B = gen_dh_keypair(p, g)
    sigA = alice_sk.sign(_signed_payload("Alice", "Bob", A, p))
    sigB = bob_sk.sign(_signed_payload("Bob", "Alice", B, p))

    r.values = {
        "A": A, "B": B,
        "Alice identity pubkey": pub_to_hex(alice_pk),
        "Bob identity pubkey": pub_to_hex(bob_pk),
        "Sig_A": sigA.hex(), "Sig_B": sigB.hex(),
    }

    r.steps.append(Step("Setup", "Alice & Bob hold each other's authentic long-term public keys (Ed25519)."))
    r.steps.append(Step("Alice -> (network)", f"Alice sends (A, Sig_A) where A = {short(A)} and Sig_A = Sign_Alice(A)."))

    if not mallory_active:
        # Passive: everything passes
        okB = verify_signed(alice_pk, sigA, "Alice", "Bob", A, p)
        okA = verify_signed(bob_pk, sigB, "Bob", "Alice", B, p)
        r.steps.append(Step("Bob", f"Verifies Sig_A with Alice's public key -> {'VALID' if okB else 'INVALID'}", ok=okB))
        r.steps.append(Step("Alice", f"Verifies Sig_B with Bob's public key -> {'VALID' if okA else 'INVALID'}", ok=okA))
        r.alice_key = derive_key(shared_secret(a, B, p), p)
        r.bob_key = derive_key(shared_secret(b, A, p), p)
        r.attack_succeeded = False
        r.steps.append(Step("Result", f"Keys match (fingerprint {fingerprint(r.alice_key)}). No attacker present.",
                            ok=r.alice_key == r.bob_key))
        return r

    # Active Mallory
    m1, M1 = gen_dh_keypair(p, g)
    m2, M2 = gen_dh_keypair(p, g)
    # Mallory cannot produce Alice's/Bob's signature -> best she can do:
    #   (a) reuse Alice's old signature on her own value, or (b) sign with her own key
    forged_sig_to_bob = mal_sk.sign(_signed_payload("Alice", "Bob", M1, p))
    forged_sig_to_alice = mal_sk.sign(_signed_payload("Bob", "Alice", M2, p))

    r.values.update({"M1": M1, "M2": M2})

    r.steps.append(Step("Mallory intercepts", "Mallory blocks (A, Sig_A) and substitutes her own value M1."))
    r.steps.append(Step("Mallory -> Bob", f"Sends (M1, forged signature). M1 = {short(M1)}; she signs with HER key since she lacks Alice's private key."))

    ok_forged_bob = verify_signed(alice_pk, forged_sig_to_bob, "Alice", "Bob", M1, p)
    ok_replay_bob = verify_signed(alice_pk, sigA, "Alice", "Bob", M1, p)  # old Sig_A on new value
    r.steps.append(Step("Bob", f"Verify(Alice_pub, forged sig over M1) -> {'VALID' if ok_forged_bob else 'INVALID -> REJECTED'}", ok=ok_forged_bob))
    r.steps.append(Step("Bob (variant)", f"Mallory retries by attaching Alice's real Sig_A to M1 -> {'VALID' if ok_replay_bob else 'INVALID -> REJECTED (signature covers A, not M1)'}", ok=ok_replay_bob))

    r.steps.append(Step("Mallory -> Alice", f"Sends (M2, forged signature) pretending to be Bob. M2 = {short(M2)}"))
    ok_forged_alice = verify_signed(bob_pk, forged_sig_to_alice, "Bob", "Alice", M2, p)
    ok_replay_alice = verify_signed(bob_pk, sigB, "Bob", "Alice", M2, p)
    r.steps.append(Step("Alice", f"Verify(Bob_pub, forged sig over M2) -> {'VALID' if ok_forged_alice else 'INVALID -> REJECTED'}", ok=ok_forged_alice))
    r.steps.append(Step("Alice (variant)", f"Bob's real Sig_B attached to M2 -> {'VALID' if ok_replay_alice else 'INVALID -> REJECTED'}", ok=ok_replay_alice))

    r.bob_accepted = ok_forged_bob or ok_replay_bob
    r.alice_accepted = ok_forged_alice or ok_replay_alice
    r.attack_succeeded = r.bob_accepted or r.alice_accepted

    if not r.attack_succeeded:
        r.steps.append(Step("Result", "Both parties aborted the handshake. No session key is established with Mallory -> ATTACK PREVENTED.", ok=True))
    else:
        r.steps.append(Step("Result", "Unexpected: a forged value was accepted.", ok=False))
    return r


def tamper_demo(p: int, g: int) -> dict:
    """Show that even modifying the DH value in transit (no key substitution trick) is caught."""
    sk, pk = gen_identity()
    _, A = gen_dh_keypair(p, g)
    sig = sk.sign(_signed_payload("Alice", "Bob", A, p))
    flipped = A ^ 1  # flip lowest bit
    return {
        "original_valid": verify_signed(pk, sig, "Alice", "Bob", A, p),
        "modified_valid": verify_signed(pk, sig, "Alice", "Bob", flipped, p),
    }
