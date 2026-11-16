import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dh_core as dh  # noqa: E402


def is_probable_prime(n, k=20):
    import random
    if n < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n % sp == 0:
            return n == sp
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def test_primes_are_valid():
    assert is_probable_prime(dh.TOY_P)
    assert is_probable_prime(dh.RFC3526_G14_P)
    assert is_probable_prime((dh.RFC3526_G14_P - 1) // 2)  # safe prime
    assert dh.RFC3526_G14_P.bit_length() == 2048


def test_plain_dh_agreement():
    for p, g in dh.GROUPS.values():
        a, A = dh.gen_dh_keypair(p, g)
        b, B = dh.gen_dh_keypair(p, g)
        assert dh.shared_secret(a, B, p) == dh.shared_secret(b, A, p)


def test_mitm_succeeds_without_auth():
    for p, g in dh.GROUPS.values():
        r = dh.simulate_unauthenticated(p, g)
        assert r.attack_succeeded
        assert r.alice_key != r.bob_key
        assert r.alice_key == r.mallory_key_with_alice
        assert r.bob_key == r.mallory_key_with_bob


def test_mallory_reads_and_modifies():
    p, g = dh.GROUPS["Toy 64-bit (readable numbers, insecure)"]
    r = dh.simulate_unauthenticated(p, g)
    out = dh.relay_messages(r, "pay 100")
    assert out["mallory_reads"] == "pay 100" and out["bob_receives"] == "pay 100"
    out = dh.relay_messages(r, "pay 100", "pay 9999")
    assert out["mallory_reads"] == "pay 100" and out["bob_receives"] == "pay 9999"


def test_signed_dh_blocks_mitm():
    for p, g in dh.GROUPS.values():
        for _ in range(5):
            r = dh.simulate_authenticated(p, g, mallory_active=True)
            assert not r.attack_succeeded
            assert not r.alice_accepted and not r.bob_accepted


def test_signed_dh_honest_run():
    for p, g in dh.GROUPS.values():
        r = dh.simulate_authenticated(p, g, mallory_active=False)
        assert r.alice_key == r.bob_key
        blob = dh.encrypt(r.alice_key, "hi")
        assert dh.decrypt(r.bob_key, blob) == "hi"


def test_tamper_detected():
    p, g = dh.GROUPS["Toy 64-bit (readable numbers, insecure)"]
    t = dh.tamper_demo(p, g)
    assert t["original_valid"] and not t["modified_valid"]


def test_wrong_key_cannot_decrypt():
    k1, k2 = b"\x01" * 32, b"\x02" * 32
    assert dh.decrypt(k2, dh.encrypt(k1, "secret")) is None


def test_invalid_public_value_rejected():
    p, g = dh.GROUPS["Toy 64-bit (readable numbers, insecure)"]
    for bad in (0, 1, p - 1, p):
        try:
            dh.shared_secret(5, bad, p)
            assert False, "should have raised"
        except ValueError:
            pass
