"""
Crypto core — authenticated encryption for Helixir.

Security design:
  * Cipher:  AES-256-GCM (confidentiality + integrity; tampering is detected).
  * KDF:     scrypt (memory-hard) derives the 32-byte key from a passphrase.
  * Salt:    16 random bytes per encryption (defeats precomputed/rainbow attacks).
  * Nonce:   12 random bytes per encryption (never reused with the same key).

The output is a single self-describing container so a file can be decrypted
later with only the passphrase:

    MAGIC(4) | VERSION(1) | N_LOG2(1) | R(1) | P(1) | SALT(16) | NONCE(12) | CIPHERTEXT+TAG

No secret (passphrase or derived key) is ever stored by this module. Salt and
nonce are not secret and are meant to be stored alongside the ciphertext.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import dna_codec

MAGIC = b"HLXR"
VERSION = 1

# scrypt cost parameters. n must be a power of two; stored as its log2.
_SCRYPT_N = 2 ** 14  # 16384
_SCRYPT_R = 8
_SCRYPT_P = 1

KEY_LEN = 32   # AES-256
SALT_LEN = 16
NONCE_LEN = 12

_HEADER = struct.Struct(">4sBBBB")  # magic, version, log2(n), r, p
_HEADER_LEN = _HEADER.size + SALT_LEN + NONCE_LEN


class DecryptionError(Exception):
    """Raised when a passphrase is wrong or the container has been tampered with."""


@dataclass(frozen=True)
class EncryptionResult:
    container: bytes          # full self-describing blob (safe to store/export)
    salt_hex: str
    nonce_hex: str
    algorithm: str = "AES-256-GCM"
    kdf: str = "scrypt"


def _derive_key(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=n, r=r, p=p)
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt(plaintext: bytes, passphrase: str) -> EncryptionResult:
    """Encrypt bytes with a passphrase. Returns a self-describing container."""
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    if not passphrase:
        raise ValueError("passphrase must not be empty")

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(passphrase, salt, _SCRYPT_N, _SCRYPT_R, _SCRYPT_P)

    n_log2 = _SCRYPT_N.bit_length() - 1  # log2 of a power of two
    header = _HEADER.pack(MAGIC, VERSION, n_log2, _SCRYPT_R, _SCRYPT_P)

    ciphertext = AESGCM(key).encrypt(nonce, bytes(plaintext), header)
    container = header + salt + nonce + ciphertext
    return EncryptionResult(
        container=container,
        salt_hex=salt.hex(),
        nonce_hex=nonce.hex(),
    )


def decrypt(container: bytes, passphrase: str) -> bytes:
    """Recover the original bytes. Raises DecryptionError on wrong key/tampering."""
    if len(container) < _HEADER_LEN:
        raise DecryptionError("Container too short or corrupted")

    header = container[: _HEADER.size]
    magic, version, n_log2, r, p = _HEADER.unpack(header)
    if magic != MAGIC:
        raise DecryptionError("Not a Helixir container (bad magic)")
    if version != VERSION:
        raise DecryptionError(f"Unsupported container version: {version}")

    offset = _HEADER.size
    salt = container[offset:offset + SALT_LEN]
    offset += SALT_LEN
    nonce = container[offset:offset + NONCE_LEN]
    offset += NONCE_LEN
    ciphertext = container[offset:]

    key = _derive_key(passphrase, salt, 2 ** n_log2, r, p)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, header)
    except Exception as exc:  # cryptography raises InvalidTag
        raise DecryptionError("Wrong passphrase or corrupted/tampered data") from exc


# --- Helixir pipeline: encryption + DNA representation --------------------

def encrypt_to_dna(plaintext: bytes, passphrase: str, apply_complement: bool = True):
    """Full pipeline: AES-256-GCM encrypt -> DNA encode -> optional complement.

    Returns (dna_sequence, EncryptionResult). The complement step is a reversible
    biological transform (Watson-Crick pairing); it is representation, not security.
    """
    result = encrypt(plaintext, passphrase)
    dna = dna_codec.encode(result.container)
    if apply_complement:
        dna = dna_codec.complement(dna)
    return dna, result


def decrypt_from_dna(dna_sequence: str, passphrase: str, apply_complement: bool = True) -> bytes:
    """Inverse of :func:`encrypt_to_dna`."""
    dna = dna_sequence
    if apply_complement:
        dna = dna_codec.complement(dna)  # complement is self-inverse
    container = dna_codec.decode(dna)
    return decrypt(container, passphrase)
