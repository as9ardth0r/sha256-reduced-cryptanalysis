"""
z3_preimage.py

Encodes the round-reduced SHA-256 *compression function* as a bit-vector
SMT problem and asks Z3 to find a 512-bit block that hashes to a chosen
target, for a given number of rounds.

Important scope note (documented honestly, not glossed over):
this searches the full compression-function domain -- any 512-bit
block -- not messages that are validly padded short ASCII strings.
Finding *some* 512-bit preimage of the compression function for N
rounds is the right first target for SAT/SMT-based cryptanalysis; it
is a different (larger, easier) search space than "find a short
message whose padded SHA-256 equals this digest," which would need
extra constraints on the last two words (length field) and padding
byte. That's a natural next step once this baseline works.

Usage:
    python3 z3_preimage.py --rounds 8
    python3 z3_preimage.py --rounds 12 --timeout 60000
"""
import argparse
import os
import sys
import time

from z3 import BitVec, BitVecVal, RotateRight, LShR, Solver, sat, unknown

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.sha256_reduced import H0, K, compress


def sym_rotr(x, n):
    return RotateRight(x, n)


def build_symbolic_compression(num_rounds: int):
    """Returns (w_vars[0..15], final_words[0..7]) where w_vars are the 16
    free BitVec(32) message words and final_words are Z3 expressions for
    the 8-word digest after num_rounds, all in terms of w_vars."""
    w = [BitVec(f"w{i}", 32) for i in range(16)]
    full_w = list(w)
    for i in range(16, num_rounds):
        s0 = sym_rotr(full_w[i - 15], 7) ^ sym_rotr(full_w[i - 15], 18) ^ LShR(full_w[i - 15], 3)
        s1 = sym_rotr(full_w[i - 2], 17) ^ sym_rotr(full_w[i - 2], 19) ^ LShR(full_w[i - 2], 10)
        full_w.append(full_w[i - 16] + s0 + full_w[i - 7] + s1)

    iv = [BitVecVal(x, 32) for x in H0]
    a, b, c, d, e, f, g, hh = iv

    for i in range(num_rounds):
        s1 = sym_rotr(e, 6) ^ sym_rotr(e, 11) ^ sym_rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        temp1 = hh + s1 + ch + BitVecVal(K[i], 32) + full_w[i]
        s0 = sym_rotr(a, 2) ^ sym_rotr(a, 13) ^ sym_rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = s0 + maj

        hh, g, f = g, f, e
        e = d + temp1
        d, c, b = c, b, a
        a = temp1 + temp2

    final = [iv[0] + a, iv[1] + b, iv[2] + c, iv[3] + d,
             iv[4] + e, iv[5] + f, iv[6] + g, iv[7] + hh]
    return w, final


def random_target_block(num_rounds: int, seed: int = 0):
    """Pick a random 64-byte block and hash it (no padding logic --
    matches the raw-block domain the solver searches) to get a target
    digest we know a solution exists for."""
    import random
    rng = random.Random(seed)
    block = bytes(rng.randrange(256) for _ in range(64))
    digest_words = compress(list(H0), block, num_rounds)
    return block, digest_words


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rounds", type=int, default=6,
                     help="number of compression rounds. With Z3's default QF_BV solver "
                          "(no custom CNF encoding), rounds<=6 solve in well under a second; "
                          "rounds>=7 currently time out -- see README for what that gap means")
    ap.add_argument("--timeout", type=int, default=120_000, help="Z3 timeout in ms")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    print(f"Building symbolic model for {args.rounds}-round compression...")
    w_vars, final_expr = build_symbolic_compression(args.rounds)

    known_block, target_words = random_target_block(args.rounds, args.seed)
    print(f"Target digest (from a known random block, not shown to the solver): "
          f"{''.join(f'{x:08x}' for x in target_words)}")

    s = Solver()
    s.set("timeout", args.timeout)
    for expr, target in zip(final_expr, target_words):
        s.add(expr == BitVecVal(target, 32))

    print(f"Solving ({args.rounds} rounds, timeout={args.timeout/1000:.0f}s)...")
    t0 = time.time()
    result = s.check()
    elapsed = time.time() - t0

    if result == sat:
        m = s.model()
        # model_completion=True: at low round counts several w_vars never
        # feed into the target equations (e.g. rounds=4 only touches
        # w0..w3), so Z3 leaves them unassigned in the model unless we
        # ask it to fill in an arbitrary value -- any value is valid there.
        found_words = [m.eval(wv, model_completion=True).as_long() for wv in w_vars]
        found_block = b"".join(x.to_bytes(4, "big") for x in found_words)
        verify = compress(list(H0), found_block, args.rounds)
        ok = verify == target_words
        print(f"SAT in {elapsed:.2f}s. Found block hashes to target: {ok}")
        print(f"  Found block is the original random block: {found_block == known_block} "
              f"(False is expected and fine -- compression functions are many-to-one, "
              f"any preimage counts)")
    elif result == unknown:
        print(f"UNKNOWN after {elapsed:.2f}s (timeout hit) -- this round count is currently out of reach")
        print("  Next step, not yet implemented here: export to DIMACS CNF and try a dedicated "
              "SAT solver (e.g. CryptoMiniSat via python-sat/pysat) instead of Z3's general QF_BV "
              "engine -- that's the setup used in most published SAT-based hash cryptanalysis.")
    else:
        print(f"UNSAT after {elapsed:.2f}s -- should not happen, a solution exists by construction")


if __name__ == "__main__":
    main()
