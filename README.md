# sha256-reduced-cryptanalysis

Two parallel, hands-on tracks for studying SHA-256 by attacking
**round-reduced** versions of it (fewer than the standard 64 rounds of
the compression function). Full SHA-256 is not threatened by anything
here or realistically by anything short of a structural break -- the
point is to build real tools, get real (including negative) results,
and understand precisely where and why each approach stops working.

## Layout

```
core/sha256_reduced.py    Shared foundation: SHA-256 from scratch (FIPS 180-4),
                           parameterized by num_rounds. At num_rounds=64 it is
                           checked against hashlib and official NIST test vectors.
differential/               Track 1: avalanche / differential tracing
sat/                         Track 2: SMT/SAT-based preimage search
  z3_preimage.py               - Z3's general QF_BV solver (baseline -- hits a wall fast)
  cnf_builder.py                - generic Tseitin CNF circuit compiler (gates, adders)
  cnf_preimage.py               - SHA-256 compiled to raw CNF, solved with Cadical/Kissat
tests/                       Correctness tests: core primitive + the CNF circuit
```

Run `python3 tests/test_core.py` and `python3 tests/test_cnf_circuit.py` first
-- everything else depends on `core` and the CNF circuit being correct.

## Track 1: avalanche / differential tracing (`differential/avalanche_trace.py`)

Flips one random input bit, runs both messages through N rounds, and
measures the Hamming distance between the two internal states after
each round. This is the concrete, testable form of "is there a local
diffusion flaw / phase invariant" -- if one existed, it would show up
here as a state subspace where the distance stops growing, or grows
unevenly, for many trials.

**Result so far** (16-byte random messages, 300 random single-bit-flip
trials, 24 rounds): average Hamming distance climbs from ~1/256 bits
at round 1 to a plateau around 128/256 (i.e. 50%, the theoretical ideal
for a well-diffused function) by **round 9**, and stays flat and noisy
around 128 through round 24. No stalled subspace, no asymmetry, across
this experiment. That's consistent with SHA-256 having no known
practical diffusion weakness -- it's also exactly the negative result
worth having actual data for instead of just citing that nobody's
published a break.

Next steps: track individual output bits instead of the aggregate
Hamming distance (an aggregate near 128 can hide a handful of bits
that never flip); try structured input differences (not just single
bit flips) the way real differential cryptanalysis does; extend past
24 rounds.

```
python3 differential/avalanche_trace.py --rounds 24 --trials 500
```

## Track 2: SAT-based preimage search

**Scope, stated plainly, applies to both tools below:** this searches
over *all* 512-bit blocks, not "short ASCII messages with valid
SHA-256 padding." Finding *a* preimage of the compression function is
the right first target for SAT/SMT tooling; constraining the search to
validly-padded short messages (fixed length field, `0x80` padding
byte, printable-ASCII message bytes) is a solvable but separate next
step.

### Baseline: Z3's general QF_BV solver (`sat/z3_preimage.py`)

Encodes the compression function directly as Z3 bit-vector constraints
and asks Z3 to solve. Rounds ≤ 6 solve in well under a second, but
**round 7 does not solve within 30-45s** -- and neither Z3's `qfbv`
tactic nor an explicit `bit-blast` → `sat` tactic chain changed that.
That's far below the 10-20+ rounds reported in published SAT-based
hash cryptanalysis, which points at Z3's own general-purpose
bit-vector reasoning as the bottleneck, not the underlying problem.

```
python3 sat/z3_preimage.py --rounds 6
python3 sat/z3_preimage.py --rounds 7 --timeout 60000   # times out
```

### Dedicated CNF + SAT solver (`sat/cnf_builder.py`, `sat/cnf_preimage.py`)

The compression function is compiled by hand down to raw boolean
gates (Tseitin transform: AND/OR/XOR gates, a ripple-carry adder for
the mod 2³² additions, rotation as free wire-relabeling) and handed to
a dedicated SAT solver -- Cadical or Kissat, both state-of-the-art,
via `python-sat`. This is the actual setup used in the published
attacks the original brief referenced. Before trusting any solver
result, `verify_circuit_matches_core()` runs the identical circuit
code with all message words as *known constants*: every gate then
folds to a plain Python bool with zero CNF variables created, so the
circuit's correctness is checked completely independently of the SAT
solver (`tests/test_cnf_circuit.py`).

**Result -- a real jump, not a marginal one:**

| rounds | Z3 (QF_BV) | Cadical | Kissat |
|-------:|:-----------|:--------|:-------|
| 6      | <1s        | <1s     | --     |
| 7      | **timeout (45s+)** | <1s | -- |
| 9–16   | not tried  | <1s (all) | -- |
| 17     | not tried  | 0.31s   | -- |
| 18     | not tried  | **69s** | **100s** |
| 20     | not tried  | not solved in 90s | not solved in 90s |

Dedicated CNF + Cadical pushes the wall from **round 6-7** to
**round 17-18** -- more than double, and a genuinely steep cliff
(0.3s → 69s in one round). Interestingly Kissat, generally the
stronger solver in competition benchmarks, was *slower* than Cadical
on this exact instance (100s vs 69s) -- a reminder that solver choice
isn't predictable in advance for a given circuit and has to be tried,
not assumed.

```
python3 sat/cnf_preimage.py --rounds 17 --solver cadical195
python3 sat/cnf_preimage.py --sweep --solver cadical195   # rounds 6..24, stops when slow
```

Next steps: round 19 (between the fast 17 and slow 18) is unexplored;
try `maplechrono` and `minisat22` (both installed) for comparison;
add symmetry-breaking or unit-propagation hints derived from the
differential track's round-9 saturation finding; profile *which*
clauses blow up the search between round 17 and 18 rather than only
timing the outcome.

## On the three "beyond classical" ideas from the original brief

Energy-based/Langevin dynamics, Hamming-space phase invariants, and
QAOA/QUBO were the starting theoretical framing. Track 1 above *is*
the phase-invariant idea, made concrete and testable instead of
staying abstract -- and so far it turns up nothing, which is worth
having on record. The EBM and QAOA ideas aren't implemented here:
EBM has no gradient signal to exploit by construction (SHA-256's
confusion property is designed to make input/output statistically
independent), and QAOA can't beat Grover's quadratic bound without a
structural weakness that hasn't been found -- so both would currently
be building infrastructure with no reason to expect it to do anything
that unstructured brute force doesn't already do. If Track 1 or 2 ever
turns up a genuine local anomaly, that would be the point to revisit
whether an energy-landscape or QUBO formulation of *that specific
anomaly* is worth building.
