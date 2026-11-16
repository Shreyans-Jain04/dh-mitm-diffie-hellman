"""
Man-in-the-Middle Attack on Diffie-Hellman & Its Prevention
Exp 2 - Diffie-Hellman Key Exchange | CSL-G09
Student: Shreyans Jain (23ESKCS814)

Run:  streamlit run app.py
"""
import streamlit as st

import dh_core as dh

st.set_page_config(page_title="MITM on Diffie-Hellman", page_icon="🔐", layout="wide")

st.title("🔐 Man-in-the-Middle Attack on Diffie-Hellman & Its Prevention")
st.caption("Exp 2 – Diffie-Hellman Key Exchange  |  CSL-G09  |  Shreyans Jain (23ESKCS814)")

# ----------------------------------------------------------------------------- #
# Sidebar
# ----------------------------------------------------------------------------- #
with st.sidebar:
    st.header("⚙️ Settings")
    group_name = st.selectbox("DH group", list(dh.GROUPS.keys()), index=0)
    p, g = dh.GROUPS[group_name]
    st.write(f"**Generator g** = `{g}`")
    st.write(f"**Prime p** ({p.bit_length()} bits)")
    st.code(dh.short(p, 20), language="text")
    st.divider()
    st.markdown(
        "**Actors**\n- 👩 Alice\n- 👨 Bob\n- 😈 Mallory (active attacker who can intercept, "
        "modify and inject messages)"
    )
    st.info("Use the *toy* group to read the numbers easily; use the *2048-bit* group for a realistic run.")


def render_steps(result: dh.MitmResult):
    for i, s in enumerate(result.steps, 1):
        icon = "✅" if s.ok else "❌"
        if s.who == "Result":
            (st.error if (s.ok is False) else st.success)(f"**{s.who}:** {s.text}")
        else:
            st.markdown(f"{icon} **{i}. {s.who}** — {s.text}")


def key_table(result: dh.MitmResult):
    rows = {
        "Alice's session key": result.alice_key,
        "Bob's session key": result.bob_key,
        "Mallory ↔ Alice key": result.mallory_key_with_alice,
        "Mallory ↔ Bob key": result.mallory_key_with_bob,
    }
    data = [{"Key": k, "Fingerprint": dh.fingerprint(v) if v else "— (none established)"} for k, v in rows.items()]
    st.table(data)


tab_theory, tab_attack, tab_fix, tab_compare = st.tabs(
    ["📘 Theory", "😈 Part 1: Attack", "🛡️ Part 2: Prevention", "📊 Comparison & Tests"]
)

# ----------------------------------------------------------------------------- #
# Theory
# ----------------------------------------------------------------------------- #
with tab_theory:
    st.subheader("Diffie-Hellman key exchange")
    st.markdown(
        """
Two parties agree on public values **p** (prime) and **g** (generator).

| Step | Alice | Bob |
|---|---|---|
| 1 | picks secret `a`, sends `A = gᵃ mod p` | picks secret `b`, sends `B = gᵇ mod p` |
| 2 | computes `K = Bᵃ mod p` | computes `K = Aᵇ mod p` |

Both get `K = gᵃᵇ mod p`. An eavesdropper who only sees `A` and `B` must solve the
**discrete logarithm problem**, which is infeasible for large `p`.
"""
    )
    st.subheader("Why is it vulnerable to MITM?")
    st.markdown(
        """
DH gives **confidentiality against passive attackers only**. It does **not** authenticate who
sent `A` or `B`. An **active** attacker (Mallory) can run *two separate* DH exchanges:

* with Alice (pretending to be Bob) → key `K₁`
* with Bob (pretending to be Alice) → key `K₂`

She then decrypts, reads/modifies and re-encrypts every message. Neither victim notices.

### Fix: authenticated DH
Each party has a long-term **signing key pair** (e.g. Ed25519) whose public key the other side
already trusts (via a CA/certificate, pre-shared key or fingerprint check). Each side **signs its
DH public value** (together with the identities of sender and receiver). Mallory cannot forge
the signature, so substituted values are **rejected** and the handshake aborts.
This is the principle behind TLS handshakes, SSH, IKE/IPsec and the Station-to-Station protocol.
"""
    )

# ----------------------------------------------------------------------------- #
# Attack
# ----------------------------------------------------------------------------- #
with tab_attack:
    st.subheader("😈 Mallory intercepts an unauthenticated DH exchange")
    st.write("Plain DH with no signatures. Click to run the attack.")
    if st.button("▶ Run MITM attack", type="primary", key="run_attack"):
        st.session_state["attack"] = dh.simulate_unauthenticated(p, g)
        st.session_state.pop("relay", None)

    res = st.session_state.get("attack")
    if res and (res.p, res.g) != (p, g):
        st.warning("Group changed - please re-run the attack.")
        res = None
    if res:
        c1, c2 = st.columns([3, 2])
        with c1:
            st.markdown("#### Protocol trace")
            render_steps(res)
        with c2:
            st.markdown("#### Keys")
            key_table(res)
            st.caption("Alice's key = Mallory↔Alice key, Bob's key = Mallory↔Bob key; Alice ≠ Bob.")
            with st.expander("Public values on the wire"):
                for k, v in res.values.items():
                    st.write(f"**{k}**")
                    st.code(str(v) if p.bit_length() <= 64 else dh.short(v, 30), language="text")

        st.markdown("---")
        st.markdown("#### 💬 Now Alice sends a secret message to Bob (through Mallory)")
        msg = st.text_input("Alice's message", "Transfer ₹5000 to account 1234", key="msg_attack")
        tamper = st.text_input("Mallory's modified message (leave empty to just eavesdrop)", "", key="tamper_attack")
        if st.button("Send message", key="send_msg"):
            st.session_state["relay"] = dh.relay_messages(res, msg, tamper or None)
        rel = st.session_state.get("relay")
        if rel:
            a1, a2, a3 = st.columns(3)
            with a1:
                st.markdown("**👩 Alice sends**")
                st.info(rel["sent_by_alice"])
                st.caption("Ciphertext: " + rel["ciphertext_from_alice"][:48] + "…")
            with a2:
                st.markdown("**😈 Mallory**")
                st.error(f"Reads: {rel['mallory_reads']}")
                if rel["tampered"]:
                    st.error(f"Forwards (modified): {rel['mallory_forwards']}")
                else:
                    st.warning("Forwards unchanged (silent eavesdropping)")
            with a3:
                st.markdown("**👨 Bob receives**")
                st.success(rel["bob_receives"])
                st.caption("Bob's decryption succeeds - he suspects nothing.")

# ----------------------------------------------------------------------------- #
# Prevention
# ----------------------------------------------------------------------------- #
with tab_fix:
    st.subheader("🛡️ Signed (authenticated) Diffie-Hellman")
    st.write(
        "Alice and Bob sign their DH public values with long-term **Ed25519** keys. "
        "Run it with and without Mallory."
    )
    col_a, col_b = st.columns(2)
    run_pass = col_a.button("▶ Run without attacker (honest run)")
    run_act = col_b.button("▶ Run with Mallory attacking", type="primary")

    if run_pass:
        st.session_state["auth"] = dh.simulate_authenticated(p, g, mallory_active=False)
        st.session_state["auth_mode"] = "honest"
    if run_act:
        st.session_state["auth"] = dh.simulate_authenticated(p, g, mallory_active=True)
        st.session_state["auth_mode"] = "attack"

    ares = st.session_state.get("auth")
    if ares and (ares.p, ares.g) != (p, g):
        st.warning("Group changed - please re-run.")
        ares = None
    if ares:
        c1, c2 = st.columns([3, 2])
        with c1:
            st.markdown("#### Protocol trace")
            render_steps(ares)
        with c2:
            st.markdown("#### Outcome")
            if st.session_state.get("auth_mode") == "honest":
                st.success("Handshake completed. Alice and Bob share the same key.")
                st.table([
                    {"Key": "Alice", "Fingerprint": dh.fingerprint(ares.alice_key)},
                    {"Key": "Bob", "Fingerprint": dh.fingerprint(ares.bob_key)},
                ])
                m = st.text_input("Secure message Alice → Bob", "Hello Bob, this is secure!", key="msg_ok")
                blob = dh.encrypt(ares.alice_key, m)
                st.caption("Ciphertext: " + blob.hex()[:48] + "…")
                st.success(f"Bob decrypts: {dh.decrypt(ares.bob_key, blob)}")
            else:
                if ares.attack_succeeded:
                    st.error("Attack succeeded (unexpected).")
                else:
                    st.success("✅ Mallory's forged values were rejected. Both sides aborted; no key shared with Mallory.")
                st.caption("Mallory lacks Alice's and Bob's private signing keys, so she cannot produce valid signatures.")
            with st.expander("Identity keys & signatures"):
                for k in ("Alice identity pubkey", "Bob identity pubkey", "Sig_A", "Sig_B"):
                    st.write(f"**{k}**")
                    st.code(ares.values[k], language="text")

    st.markdown("---")
    st.markdown("#### 🔬 Tamper test")
    st.write("Flip one bit of a signed DH value in transit and verify the signature.")
    if st.button("Run tamper test"):
        t = dh.tamper_demo(p, g)
        st.write(f"Original value → signature **{'VALID ✅' if t['original_valid'] else 'INVALID ❌'}**")
        st.write(f"Modified value → signature **{'VALID ✅' if t['modified_valid'] else 'INVALID ❌ (tampering detected)'}**")

# ----------------------------------------------------------------------------- #
# Comparison
# ----------------------------------------------------------------------------- #
with tab_compare:
    st.subheader("Side-by-side comparison")
    st.table([
        {"Property": "Protects against passive eavesdropper", "Plain DH": "✅ Yes", "Signed DH": "✅ Yes"},
        {"Property": "Authenticates peers", "Plain DH": "❌ No", "Signed DH": "✅ Yes (signatures)"},
        {"Property": "Resists active MITM", "Plain DH": "❌ No", "Signed DH": "✅ Yes"},
        {"Property": "Needs trusted long-term public keys", "Plain DH": "No", "Signed DH": "Yes (CA / pre-shared)"},
        {"Property": "Extra cost", "Plain DH": "-", "Signed DH": "1 sign + 1 verify per side"},
    ])

    st.subheader("Live experiment: 20 random runs")
    if st.button("Run 20 trials"):
        n = 20
        attacks = [dh.simulate_unauthenticated(p, g).attack_succeeded for _ in range(n)]
        fixes = [dh.simulate_authenticated(p, g, True).attack_succeeded for _ in range(n)]
        st.bar_chart({"Attack success (of 20)": {"Plain DH": sum(attacks), "Signed DH": sum(fixes)}})
        st.write(f"Plain DH: Mallory succeeded **{sum(attacks)}/{n}** times.")
        st.write(f"Signed DH: Mallory succeeded **{sum(fixes)}/{n}** times.")

    st.subheader("Limitations / notes")
    st.markdown(
        """
* The security of signed DH relies on Alice and Bob having the **correct** public keys in the first place (PKI/CA).
* Production protocols add **nonces/transcript hashes** for freshness and replay protection, and use ephemeral keys for forward secrecy (as in TLS 1.3).
* The toy 64-bit group is breakable and only for display; Group 14 (2048-bit) is the realistic option.
"""
    )
