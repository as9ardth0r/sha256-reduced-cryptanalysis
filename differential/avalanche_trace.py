"""
avalanche_trace.py

Differential-cryptanalysis starting point: flip a single input bit,
run both messages through the (possibly round-reduced) compression
function, and measure how the Hamming distance between the two
internal states grows round by round.

This is the concrete, falsifiable form of the "invariant de phase /
faille de diffusion locale" idea from the original brief: if such an
invariant existed, it would show up here as a state subspace whose
Hamming distance stops growing (or grows unevenly) for many input
pairs, long before round 64. If none appears across many trials and
many bit positions, that itself is worth documenting -- it's the
empirical form of the "no local diffusion flaw" claim, rather than
just citing that nobody has published one.
"""
import argparse
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.sha256_reduced import single_block_trace


def hamming_distance_words(state_a, state_b):
    return sum(bin(x ^ y).count("1") for x, y in zip(state_a, state_b))


def flip_bit(message: bytes, bit_index: int) -> bytes:
    byte_i, bit_i = divmod(bit_index, 8)
    b = bytearray(message)
    b[byte_i] ^= (1 << (7 - bit_i))
    return bytes(b)


def trace_single_pair(message: bytes, bit_index: int, num_rounds: int):
    m2 = flip_bit(message, bit_index)
    trace_a = single_block_trace(message, num_rounds)
    trace_b = single_block_trace(m2, num_rounds)
    return [hamming_distance_words(a, b) for a, b in zip(trace_a, trace_b)]


def average_over_trials(message_len: int, num_rounds: int, trials: int, seed: int = 0):
    """Random message, random single flipped bit, repeated `trials` times.
    Returns the average Hamming distance (out of 256 state bits) after
    each round, plus the min/max seen at each round."""
    rng = random.Random(seed)
    sums = [0] * num_rounds
    mins = [256] * num_rounds
    maxs = [0] * num_rounds

    for _ in range(trials):
        msg = bytes(rng.randrange(256) for _ in range(message_len))
        bit_index = rng.randrange(message_len * 8)
        distances = trace_single_pair(msg, bit_index, num_rounds)
        for r, d in enumerate(distances):
            sums[r] += d
            mins[r] = min(mins[r], d)
            maxs[r] = max(maxs[r], d)

    avg = [s / trials for s in sums]
    return avg, mins, maxs


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rounds", type=int, default=32, help="number of compression rounds to trace")
    ap.add_argument("--trials", type=int, default=500, help="number of random (message, bit) pairs")
    ap.add_argument("--msg-len", type=int, default=16, help="message length in bytes (<=55 for one block)")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    avg, mins, maxs = average_over_trials(args.msg_len, args.rounds, args.trials, args.seed)

    print(f"Avalanche trace: {args.trials} random single-bit-flip pairs, "
          f"{args.msg_len}-byte messages, {args.rounds} rounds")
    print(f"{'round':>6}  {'avg Hd':>8}  {'min':>5}  {'max':>5}   (out of 256 bits)")
    for r in range(args.rounds):
        print(f"{r + 1:6d}  {avg[r]:8.2f}  {mins[r]:5d}  {maxs[r]:5d}")

    # A crude "did diffusion stall anywhere?" flag: ideal avalanche settles
    # near 128/256 quickly. Flag any round where the average barely moved
    # from the previous round, this deep into the schedule -- a candidate
    # spot to look at more closely, not proof of anything on its own.
    print("\nRounds where avg Hamming distance changed by <1.0 from the previous round:")
    stalled = [r + 1 for r in range(1, args.rounds) if abs(avg[r] - avg[r - 1]) < 1.0]
    print(stalled if stalled else "  none")


if __name__ == "__main__":
    main()
