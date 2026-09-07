"""
cnf_preimage.py

Same round-reduced compression function as core/sha256_reduced.py and
sat/z3_preimage.py, but compiled down to a raw CNF (DIMACS) circuit via
sat/cnf_builder.py, then handed to a dedicated SAT solver (Cadical /
Kissat, via python-sat) instead of Z3's general-purpose QF_BV engine.
This is the standard setup in published SAT-based hash cryptanalysis.

Correctness strategy: build_compression_circuit() is used two ways --
1. With the 16 message words as free CNF variables -> real preimage search.
2. With the 16 message words as concrete constants (a real message block)
   -> every gate constant-folds, no CNF variables are ever created, and
   the output can be compared bit-for-bit against core.compress() with
   zero involvement from any SAT solver. See verify_circuit_matches_core()
   below and tests/test_cnf_circuit.py. This isolates "is the circuit
   correct" from "can the solver find an assignment," which matters
   because a wrong circuit can silently produce a plausible-looking but
   meaningless SAT/UNSAT result.
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.sha256_reduced import H0, K, compress
from sat.cnf_builder import (
    CNFBuilder, XOR, AND, NOT, add_words, add_words_n,
    rotr_word, lshr_word, int_to_bits, bits_to_int, write_dimacs,
)


def build_compression_circuit(cnf: CNFBuilder, w_words, num_rounds: int):
    """w_words: list of 16 words, each a list of 32 signals (CNF literals
    for unknowns, or bools for a concrete message). Returns the 8-word
    final digest as a list of lists of signals."""
    full_w = list(w_words)
    for i in range(16, num_rounds):
        s0 = [XOR(cnf, p, q) for p, q in zip(
            [XOR(cnf, p, q) for p, q in zip(rotr_word(full_w[i - 15], 7), rotr_word(full_w[i - 15], 18))],
            lshr_word(full_w[i - 15], 3))]
        s1 = [XOR(cnf, p, q) for p, q in zip(
            [XOR(cnf, p, q) for p, q in zip(rotr_word(full_w[i - 2], 17), rotr_word(full_w[i - 2], 19))],
            lshr_word(full_w[i - 2], 10))]
        full_w.append(add_words_n(cnf, full_w[i - 16], s0, full_w[i - 7], s1))

    iv = [int_to_bits(x) for x in H0]
    a, b, c, d, e, f, g, hh = iv

    for i in range(num_rounds):
        s1 = [XOR(cnf, p, q) for p, q in zip(
            [XOR(cnf, p, q) for p, q in zip(rotr_word(e, 6), rotr_word(e, 11))],
            rotr_word(e, 25))]
        ch = [XOR(cnf, AND(cnf, ei, fi), AND(cnf, NOT(ei), gi)) for ei, fi, gi in zip(e, f, g)]
        temp1 = add_words_n(cnf, hh, s1, ch, int_to_bits(K[i]), full_w[i])

        s0 = [XOR(cnf, p, q) for p, q in zip(
            [XOR(cnf, p, q) for p, q in zip(rotr_word(a, 2), rotr_word(a, 13))],
            rotr_word(a, 22))]
        maj = [XOR(cnf, XOR(cnf, AND(cnf, ai, bi), AND(cnf, ai, ci)), AND(cnf, bi, ci))
               for ai, bi, ci in zip(a, b, c)]
        temp2 = add_words(cnf, s0, maj)

        hh, g, f = g, f, e
        e = add_words(cnf, d, temp1)
        d, c, b = c, b, a
        a = add_words(cnf, temp1, temp2)

    state = [a, b, c, d, e, f, g, hh]
    return [add_words(cnf, iv_word, st_word) for iv_word, st_word in zip(iv, state)]


def verify_circuit_matches_core(num_rounds: int, block: bytes) -> bool:
    """Constant-only pass: no CNF variables created, pure Python bool
    evaluation of the same circuit code path used for real solving."""
    cnf = CNFBuilder()
    w_words = [int_to_bits(int.from_bytes(block[i:i + 4], "big")) for i in range(0, 64, 4)]
    final_bits = build_compression_circuit(cnf, w_words, num_rounds)
    assert cnf.nvars == 0 and len(cnf.clauses) == 0, "expected pure constant folding, got real CNF variables"
    circuit_words = [bits_to_int(w) for w in final_bits]
    reference_words = compress(list(H0), block, num_rounds)
    return circuit_words == reference_words


def solve_preimage(num_rounds: int, target_words, solver_name: str = "cadical195", timeout: float = None):
    """Allocates w0..w15 as free CNF variables, fixes the output to
    target_words, solves with a dedicated SAT backend, and returns
    (found_block_bytes_or_None, elapsed_seconds, cnf_stats)."""
    from pysat.solvers import Solver

    cnf = CNFBuilder()
    w_words = [[cnf.new_var() for _ in range(32)] for _ in range(16)]
    final_bits = build_compression_circuit(cnf, w_words, num_rounds)
    for word_bits, target in zip(final_bits, target_words):
        for i, bit in enumerate(word_bits):
            cnf.fix(bit, bool((target >> i) & 1))

    stats = {"nvars": cnf.nvars, "nclauses": len(cnf.clauses)}

    s = Solver(name=solver_name, bootstrap_with=cnf.clauses, use_timer=True)
    t0 = time.time()
    if timeout is not None and hasattr(s, "conf_budget"):
        pass  # per-solver timeouts aren't uniformly supported by pysat; caller enforces a wall clock instead
    result = s.solve()
    elapsed = time.time() - t0

    found_block = None
    if result:
        model = set(s.get_model())
        found_words = []
        for word_bits in w_words:
            val = 0
            for i, lit in enumerate(word_bits):
                if lit in model:
                    val |= (1 << i)
            found_words.append(val)
        found_block = b"".join(x.to_bytes(4, "big") for x in found_words)
    s.delete()
    return found_block, elapsed, stats, result


def random_target_block(num_rounds: int, seed: int = 0):
    import random
    rng = random.Random(seed)
    block = bytes(rng.randrange(256) for _ in range(64))
    return block, compress(list(H0), block, num_rounds)


if __name__ == "__main__":
    import argparse
    import random

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check-only", action="store_true", help="only run the constant-folding self-check")
    ap.add_argument("--rounds", type=int, default=None, help="solve a single round count")
    ap.add_argument("--sweep", action="store_true", help="benchmark increasing round counts")
    ap.add_argument("--solver", default="cadical195", choices=[
        "cadical195", "kissat404", "glucose4", "minisat22", "maplechrono"])
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    if args.check_only or (args.rounds is None and not args.sweep):
        rng = random.Random(1)
        print("Constant-folding self-check (circuit vs core.compress, no SAT solver involved):")
        for rounds in (1, 4, 6, 8, 16, 24, 32, 48, 64):
            ok_all = all(
                verify_circuit_matches_core(rounds, bytes(rng.randrange(256) for _ in range(64)))
                for _ in range(10)
            )
            print(f"  rounds={rounds:2d}  {'OK' if ok_all else 'MISMATCH'}")

    def run_one(rounds):
        block, target = random_target_block(rounds, args.seed)
        found, elapsed, stats, result = solve_preimage(rounds, target, args.solver)
        status = "SAT" if result else "UNSAT"
        verified = found is not None and compress(list(H0), found, rounds) == target
        print(f"  rounds={rounds:3d}  {status:5s}  {elapsed:8.2f}s  "
              f"vars={stats['nvars']:6d}  clauses={stats['nclauses']:7d}  "
              f"verified={verified if found else 'n/a'}")
        return elapsed

    if args.rounds is not None:
        print(f"Solving with {args.solver}...")
        run_one(args.rounds)

    if args.sweep:
        print(f"Sweep with {args.solver}:")
        for rounds in (6, 7, 8, 9, 10, 12, 14, 16, 20, 24):
            elapsed = run_one(rounds)
            if elapsed > 90:
                print("  (stopping sweep, this round count is already slow)")
                break

