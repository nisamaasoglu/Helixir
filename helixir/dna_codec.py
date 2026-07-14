"""
DNA codec — a reversible binary <-> nucleotide representation layer.

This module maps arbitrary bytes to a string over the DNA alphabet {A, C, G, T}
using a fixed 2-bits-per-base encoding, and back. It also implements the
Watson-Crick complement (A<->T, G<->C), which is a real base-pairing rule and a
fully reversible transform.

IMPORTANT (honesty note): this layer is a *representation / obfuscation* layer,
not a security boundary. The 2-bit mapping and the complement are fixed and
trivially reversible on their own. All confidentiality and integrity in Helixir
come from the AES-256-GCM layer in ``crypto.py``. The DNA layer exists to give
the ciphertext a genetic representation (exportable as FASTA) and is defensible
as an encoding technique, not as encryption.
"""

from __future__ import annotations

# Fixed 2-bit encoding: 2 bases per byte-nibble, 4 bases per byte.
# 00 -> A, 01 -> C, 10 -> G, 11 -> T
_BITS_TO_BASE = {"00": "A", "01": "C", "10": "G", "11": "T"}
_BASE_TO_BITS = {base: bits for bits, base in _BITS_TO_BASE.items()}

# Watson-Crick base pairing (biological complement).
_COMPLEMENT = {"A": "T", "T": "A", "G": "C", "C": "G"}

VALID_BASES = frozenset("ACGT")


def encode(data: bytes) -> str:
    """Encode raw bytes into a DNA string (4 nucleotides per byte)."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("encode() expects bytes")
    out = []
    for byte in data:
        bits = format(byte, "08b")
        out.append(_BITS_TO_BASE[bits[0:2]])
        out.append(_BITS_TO_BASE[bits[2:4]])
        out.append(_BITS_TO_BASE[bits[4:6]])
        out.append(_BITS_TO_BASE[bits[6:8]])
    return "".join(out)


def decode(sequence: str) -> bytes:
    """Decode a DNA string back into the original bytes."""
    seq = sequence.strip().upper()
    if len(seq) % 4 != 0:
        raise ValueError("DNA sequence length must be a multiple of 4")
    invalid = set(seq) - VALID_BASES
    if invalid:
        raise ValueError(f"Sequence contains non-nucleotide symbols: {sorted(invalid)}")

    out = bytearray()
    for i in range(0, len(seq), 4):
        bits = "".join(_BASE_TO_BITS[b] for b in seq[i:i + 4])
        out.append(int(bits, 2))
    return bytes(out)


def complement(sequence: str) -> str:
    """Return the Watson-Crick complement (A<->T, G<->C). Self-inverse."""
    seq = sequence.strip().upper()
    invalid = set(seq) - VALID_BASES
    if invalid:
        raise ValueError(f"Sequence contains non-nucleotide symbols: {sorted(invalid)}")
    return "".join(_COMPLEMENT[b] for b in seq)


def gc_content(sequence: str) -> float:
    """Fraction of G and C bases (0.0-1.0). A common DNA composition metric."""
    seq = sequence.strip().upper()
    if not seq:
        return 0.0
    gc = sum(1 for b in seq if b in ("G", "C"))
    return gc / len(seq)


def to_fasta(sequence: str, header: str = "helixir", line_width: int = 70) -> str:
    """Wrap a DNA sequence as a FASTA record (60-70 chars per line by convention)."""
    seq = sequence.strip().upper()
    lines = [seq[i:i + line_width] for i in range(0, len(seq), line_width)] or [""]
    return f">{header}\n" + "\n".join(lines) + "\n"


def from_fasta(fasta_text: str) -> str:
    """Extract a raw DNA sequence from FASTA text (ignores header lines)."""
    seq = "".join(
        line.strip()
        for line in fasta_text.splitlines()
        if line and not line.startswith(">")
    )
    return seq.upper()
