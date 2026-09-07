import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sat.cnf_preimage import verify_circuit_matches_core


def test_cnf_circuit_matches_core_reference():
    """Pure constant-folding check: with all 16 message words given as
    known constants, the CNF circuit builder creates zero CNF variables
    and its output must equal core.compress() exactly. This validates
    the bit-level circuit logic (gates, adders, rotations, schedule
    expansion) with no SAT solver involved at all -- if this fails, no
    SAT result downstream can be trusted regardless of what it reports."""
    rng = random.Random(1)
    round_counts = (1, 4, 6, 8, 16, 17, 24, 32, 48, 64)
    trials_per_round = 15
    for rounds in round_counts:
        for _ in range(trials_per_round):
            block = bytes(rng.randrange(256) for _ in range(64))
            assert verify_circuit_matches_core(rounds, block), \
                f"CNF circuit diverges from core.compress at rounds={rounds}"
    print(f"[OK] CNF circuit matches core.compress across {len(round_counts)} round counts "
          f"({trials_per_round} random blocks each)")


if __name__ == "__main__":
    test_cnf_circuit_matches_core_reference()
    print("\nAll CNF circuit tests passed.")
