import os

import pytest

from helixir import crypto


def test_encrypt_decrypt_roundtrip():
    for size in (0, 1, 16, 4096):
        data = os.urandom(size)
        result = crypto.encrypt(data, "correct horse battery staple")
        assert crypto.decrypt(result.container, "correct horse battery staple") == data


def test_wrong_passphrase_fails():
    result = crypto.encrypt(b"secret", "right-key")
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(result.container, "wrong-key")


def test_tampered_ciphertext_is_detected():
    result = crypto.encrypt(b"secret payload", "pw")
    tampered = bytearray(result.container)
    tampered[-1] ^= 0x01  # flip one bit in the tag/ciphertext
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(bytes(tampered), "pw")


def test_tampered_header_is_detected():
    # header is authenticated as GCM associated data
    result = crypto.encrypt(b"secret payload", "pw")
    tampered = bytearray(result.container)
    tampered[4] ^= 0x01  # flip a bit in the version/params region
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(bytes(tampered), "pw")


def test_empty_passphrase_rejected():
    with pytest.raises(ValueError):
        crypto.encrypt(b"x", "")


def test_salt_and_nonce_are_unique_per_call():
    a = crypto.encrypt(b"same", "pw")
    b = crypto.encrypt(b"same", "pw")
    assert a.salt_hex != b.salt_hex
    assert a.nonce_hex != b.nonce_hex
    assert a.container != b.container  # semantic security


def test_not_a_container():
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(b"not-a-helixir-blob", "pw")


def test_dna_pipeline_roundtrip_with_complement():
    data = os.urandom(200)
    dna, result = crypto.encrypt_to_dna(data, "pw", apply_complement=True)
    assert set(dna) <= {"A", "C", "G", "T"}
    assert crypto.decrypt_from_dna(dna, "pw", apply_complement=True) == data


def test_dna_pipeline_roundtrip_without_complement():
    data = os.urandom(200)
    dna, _ = crypto.encrypt_to_dna(data, "pw", apply_complement=False)
    assert crypto.decrypt_from_dna(dna, "pw", apply_complement=False) == data


def test_dna_pipeline_wrong_passphrase_fails():
    dna, _ = crypto.encrypt_to_dna(b"secret", "pw")
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_from_dna(dna, "nope")
