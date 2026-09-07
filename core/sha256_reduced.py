"""
sha256_reduced.py

A from-scratch SHA-256 implementation (FIPS 180-4) with a `num_rounds`
parameter that lets the compression function stop after N of the normal
64 rounds. At num_rounds=64 this must match hashlib.sha256 exactly --
that equivalence is the whole basis for trusting results on reduced
versions, so it is checked in tests/test_core.py.

Round reduction here means: run the message-schedule expansion fully
(you still need w[0..63] defined), but only iterate the compression
loop `num_rounds` times using k[0..num_rounds-1] and w[0..num_rounds-1].
This is the standard reduction used in the cryptanalysis literature
(e.g. reduced-round SHA-2 attacks), as opposed to e.g. shrinking the
word size or the number of message blocks.
"""

MASK32 = 0xFFFFFFFF

H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK32


def pad_message(message: bytes) -> bytes:
    ml = len(message) * 8
    message += b"\x80"
    while len(message) % 64 != 56:
        message += b"\x00"
    message += ml.to_bytes(8, "big")
    return message


def message_schedule(block: bytes):
    w = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
    for i in range(16, 64):
        s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK32)
    return w


def compress(h, block: bytes, num_rounds: int = 64, trace: list = None):
    """If `trace` is a list, the 8-word state after each round is appended
    to it (trace[0] = state after round 1, etc.) -- used by the
    differential/avalanche tooling to watch diffusion round by round."""
    w = message_schedule(block)
    a, b, c, d, e, f, g, hh = h

    for i in range(num_rounds):
        s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        temp1 = (hh + s1 + ch + K[i] + w[i]) & MASK32
        s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (s0 + maj) & MASK32

        hh, g, f = g, f, e
        e = (d + temp1) & MASK32
        d, c, b = c, b, a
        a = (temp1 + temp2) & MASK32

        if trace is not None:
            trace.append([a, b, c, d, e, f, g, hh])

    return [
        (h[0] + a) & MASK32, (h[1] + b) & MASK32, (h[2] + c) & MASK32, (h[3] + d) & MASK32,
        (h[4] + e) & MASK32, (h[5] + f) & MASK32, (h[6] + g) & MASK32, (h[7] + hh) & MASK32,
    ]


def sha256_reduced(message: bytes, num_rounds: int = 64) -> bytes:
    if not (1 <= num_rounds <= 64):
        raise ValueError("num_rounds must be in [1, 64]")
    padded = pad_message(message)
    h = list(H0)
    for i in range(0, len(padded), 64):
        h = compress(h, padded[i:i + 64], num_rounds)
    return b"".join(x.to_bytes(4, "big") for x in h)


def sha256_reduced_hex(message: bytes, num_rounds: int = 64) -> str:
    return sha256_reduced(message, num_rounds).hex()


def single_block_trace(message: bytes, num_rounds: int = 64):
    """For messages that pad to exactly one 512-bit block: returns the
    round-by-round internal state list (see compress()'s `trace` arg).
    Raises if the message needs more than one block, since the tracer
    is meant for small controlled inputs used in avalanche experiments."""
    padded = pad_message(message)
    if len(padded) != 64:
        raise ValueError("single_block_trace only supports messages that pad to one block (<=55 bytes)")
    trace = []
    compress(list(H0), padded, num_rounds, trace=trace)
    return trace
