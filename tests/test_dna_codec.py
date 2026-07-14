import os

import pytest

from helixir import dna_codec


def test_encode_length_is_four_bases_per_byte():
    assert len(dna_codec.encode(b"A")) == 4
    assert len(dna_codec.encode(b"hello")) == 20


def test_encode_decode_roundtrip_random():
    for size in (0, 1, 2, 15, 256, 1000):
        data = os.urandom(size)
        assert dna_codec.decode(dna_codec.encode(data)) == data


def test_encode_uses_only_valid_bases():
    seq = dna_codec.encode(os.urandom(64))
    assert set(seq) <= dna_codec.VALID_BASES


def test_complement_is_self_inverse():
    seq = dna_codec.encode(os.urandom(128))
    assert dna_codec.complement(dna_codec.complement(seq)) == seq


def test_complement_pairs_are_correct():
    assert dna_codec.complement("ACGT") == "TGCA"


def test_decode_rejects_bad_symbols():
    with pytest.raises(ValueError):
        dna_codec.decode("ACGX")


def test_decode_rejects_bad_length():
    with pytest.raises(ValueError):
        dna_codec.decode("ACG")


def test_gc_content_bounds():
    assert dna_codec.gc_content("") == 0.0
    assert dna_codec.gc_content("GCGC") == 1.0
    assert dna_codec.gc_content("ATAT") == 0.0
    assert dna_codec.gc_content("AGCT") == 0.5


def test_fasta_roundtrip():
    seq = dna_codec.encode(os.urandom(50))
    fasta = dna_codec.to_fasta(seq, header="test")
    assert fasta.startswith(">test\n")
    assert dna_codec.from_fasta(fasta) == seq
