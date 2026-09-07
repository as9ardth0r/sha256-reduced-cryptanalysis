"""
cnf_builder.py

A tiny Tseitin-transform circuit-to-CNF compiler: build boolean circuits
out of AND/OR/XOR/NOT gates over "signals", where each signal is either
a concrete Python bool (a known constant) or a CNF literal (int, DIMACS
convention: positive = variable, negative = its negation).

Constant folding is done at every gate: if an operand is already a
known bool, the gate short-circuits in plain Python instead of
allocating a fresh CNF variable and clauses. This matters a lot here --
early in a low-round SHA-256 circuit, most of the state is still pure
IV constants, so folding avoids emitting thousands of pointless gates
for values that are already fully determined.
"""


class CNFBuilder:
    def __init__(self):
        self.clauses = []
        self.nvars = 0

    def new_var(self) -> int:
        self.nvars += 1
        return self.nvars

    def add_clause(self, *lits):
        self.clauses.append(list(lits))

    def fix(self, signal, value: bool):
        """Constrain a signal to a known value. If the signal is already
        a constant, just check consistency instead of adding a clause."""
        if isinstance(signal, bool):
            if signal != value:
                # Contradiction baked in at circuit-construction time --
                # make the CNF trivially UNSAT rather than silently wrong.
                self.add_clause(1)
                self.add_clause(-1)
            return
        self.add_clause(signal if value else -signal)


def NOT(a):
    if isinstance(a, bool):
        return not a
    return -a


def AND(cnf: CNFBuilder, a, b):
    if isinstance(a, bool):
        return b if a else False
    if isinstance(b, bool):
        return a if b else False
    z = cnf.new_var()
    cnf.add_clause(-z, a)
    cnf.add_clause(-z, b)
    cnf.add_clause(z, -a, -b)
    return z


def OR(cnf: CNFBuilder, a, b):
    if isinstance(a, bool):
        return True if a else b
    if isinstance(b, bool):
        return True if b else a
    z = cnf.new_var()
    cnf.add_clause(z, -a)
    cnf.add_clause(z, -b)
    cnf.add_clause(-z, a, b)
    return z


def XOR(cnf: CNFBuilder, a, b):
    if isinstance(a, bool):
        return NOT(b) if a else b
    if isinstance(b, bool):
        return NOT(a) if b else a
    z = cnf.new_var()
    cnf.add_clause(-z, a, b)
    cnf.add_clause(-z, -a, -b)
    cnf.add_clause(z, -a, b)
    cnf.add_clause(z, a, -b)
    return z


def full_adder(cnf: CNFBuilder, a, b, cin):
    """Returns (sum, carry_out)."""
    a_xor_b = XOR(cnf, a, b)
    s = XOR(cnf, a_xor_b, cin)
    carry = OR(cnf, AND(cnf, a, b), AND(cnf, cin, a_xor_b))
    return s, carry


def add_words(cnf: CNFBuilder, a_bits, b_bits):
    """32-bit ripple-carry addition mod 2**32. Bit lists are LSB-first
    (index i has weight 2**i). The final carry-out is discarded, which
    is exactly modular addition."""
    assert len(a_bits) == len(b_bits) == 32
    result = []
    carry = False
    for i in range(32):
        s, carry = full_adder(cnf, a_bits[i], b_bits[i], carry)
        result.append(s)
    return result


def add_words_n(cnf: CNFBuilder, *word_lists):
    acc = word_lists[0]
    for w in word_lists[1:]:
        acc = add_words(cnf, acc, w)
    return acc


def xor_words(cnf: CNFBuilder, a_bits, b_bits):
    return [XOR(cnf, x, y) for x, y in zip(a_bits, b_bits)]


def and_words(cnf: CNFBuilder, a_bits, b_bits):
    return [AND(cnf, x, y) for x, y in zip(a_bits, b_bits)]


def not_words(bits):
    return [NOT(x) for x in bits]


def rotr_word(bits, n):
    """Circular rotate right by n. Free (pure wiring, no gates): with
    LSB-first indexing, result[i] = bits[(i + n) % 32]."""
    return [bits[(i + n) % 32] for i in range(32)]


def lshr_word(bits, n):
    """Logical shift right by n, zero-filled at the top."""
    return [bits[i + n] if i + n < 32 else False for i in range(32)]


def int_to_bits(x: int, width: int = 32):
    return [bool((x >> i) & 1) for i in range(width)]


def bits_to_int(bits) -> int:
    v = 0
    for i, b in enumerate(bits):
        if b:
            v |= (1 << i)
    return v


def write_dimacs(cnf: CNFBuilder, path: str):
    with open(path, "w") as f:
        f.write(f"p cnf {cnf.nvars} {len(cnf.clauses)}\n")
        for clause in cnf.clauses:
            f.write(" ".join(str(l) for l in clause) + " 0\n")
