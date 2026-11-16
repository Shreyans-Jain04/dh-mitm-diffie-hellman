# Man-in-the-Middle Attack on Diffie-Hellman & Its Prevention

**Course project:** CSL-G09 | **Experiment:** Exp 2 – Diffie-Hellman Key Exchange
**Student:** Shreyans Jain (23ESKCS814)

A Streamlit mini project that **simulates Mallory intercepting an unauthenticated Diffie-Hellman
exchange**, then **fixes it with signed (authenticated) DH** using Ed25519 signatures.

## Features
- Plain DH between Alice and Bob with an active attacker, Mallory, who substitutes public values
  and ends up with a separate key for each victim.
- Live message demo: Mallory reads and optionally modifies an AES-GCM encrypted message while Bob suspects nothing.
- Signed DH: each side signs its DH public value (bound to sender and receiver identity), so forged
  or substituted values are rejected and the handshake aborts.
- Bit-flip tamper test, 20-run experiment, side-by-side comparison, theory tab.
- Two groups: a 64-bit toy group (readable numbers) and RFC 3526 Group 14 (2048-bit, realistic).
- Unit tests (pytest).

## Project structure
```
dh_mitm_project/
├── app.py                  # Streamlit UI
├── dh_core.py              # DH, AES-GCM, MITM simulation, signed DH
├── tests/test_dh_core.py   # pytest tests
├── requirements.txt
├── .gitignore
└── README.md
```

## Run
```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```
Run tests: `pytest -q`

## How it works
**Attack (plain DH):**
1. Alice sends `A`; Mallory drops it and sends `M1` to Bob.
2. Bob sends `B`; Mallory drops it and sends `M2` to Alice.
3. Alice computes `M2^a`, Bob computes `M1^b`; Mallory computes `A^m2` and `B^m1`.
   Result: Alice↔Mallory and Mallory↔Bob keys, so Mallory reads and modifies all traffic.

**Prevention (signed DH):** Alice sends `(A, Sign_Alice(A))` and Bob sends `(B, Sign_Bob(B))`.
Each side verifies using the peer's trusted long-term public key. Mallory cannot forge the
signatures, so her substituted values fail verification. This is the principle behind TLS, SSH and
the Station-to-Station protocol.

## Notes
- Educational simulation only; it is not a production protocol.
- Real protocols add nonces/transcript hashing, replay protection and ephemeral keys for forward secrecy.
- Security of signed DH depends on both sides having the correct public keys beforehand (PKI/CA).
