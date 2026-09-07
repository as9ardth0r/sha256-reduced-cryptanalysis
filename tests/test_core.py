import hashlib
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.sha256_reduced import sha256_reduced_hex

NIST_VECTORS = {
    b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    b"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq":
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
}


def test_nist_vectors():
    for msg, expected in NIST_VECTORS.items():
        got = sha256_reduced_hex(msg, num_rounds=64)
        assert got == expected, f"mismatch for {msg!r}: {got} != {expected}"
    print(f"[OK] {len(NIST_VECTORS)} NIST test vectors match at 64 rounds")


def test_matches_hashlib_random():
    random.seed(42)
    n = 200
    for _ in range(n):
        msg = os.urandom(random.randint(0, 200))
        expected = hashlib.sha256(msg).hexdigest()
        got = sha256_reduced_hex(msg, num_rounds=64)
        assert got == expected, f"mismatch for {msg!r}"
    print(f"[OK] {n} random messages match hashlib.sha256 at 64 rounds")


def test_reduced_rounds_are_deterministic_and_diverge():
    # Sanity check only -- no external ground truth exists for reduced
    # rounds. We check: (a) determinism, (b) different round counts give
    # different digests (diffusion hasn't finished), (c) round 64 differs
    # from all reduced rounds for a generic message.
    msg = b"sha256-reduced-cryptanalysis"
    digests = {r: sha256_reduced_hex(msg, num_rounds=r) for r in (1, 4, 8, 16, 32, 48, 64)}
    for r, d in digests.items():
        d2 = sha256_reduced_hex(msg, num_rounds=r)
        assert d == d2, f"non-deterministic at {r} rounds"
    assert len(set(digests.values())) == len(digests), "round counts collided unexpectedly"
    print("[OK] reduced-round outputs are deterministic and distinct across round counts:")
    for r, d in digests.items():
        print(f"     rounds={r:2d}  {d}")


if __name__ == "__main__":
    test_nist_vectors()
    test_matches_hashlib_random()
    test_reduced_rounds_are_deterministic_and_diverge()
    print("\nAll core tests passed.")
