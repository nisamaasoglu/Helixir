"""
Visual scramble — a NON-SECURE, reversible image block shuffle.

This exists only to produce an eye-catching live-preview for the demo (a webcam
frame whose 16x16 blocks are permuted by a key-seeded ordering). It is NOT
encryption and provides NO confidentiality: the histogram is unchanged and the
content stays statistically exposed. It is kept strictly as a visual effect and
is labelled as such in the UI. For real protection, use ``crypto.py``.

Depends on numpy only (no OpenCV), so it stays testable without a camera.
"""

from __future__ import annotations

import hashlib

import numpy as np


def _permutation(key: str, count: int) -> np.ndarray:
    seed = int(hashlib.sha256(key.encode("utf-8")).hexdigest(), 16) % (2 ** 32)
    return np.random.RandomState(seed).permutation(count)


def scramble_blocks(image: np.ndarray, key: str, block_size: int = 16) -> np.ndarray:
    """Reversibly permute the image's blocks. NON-SECURE visual effect only."""
    h, w = image.shape[:2]
    hc = (h // block_size) * block_size
    wc = (w // block_size) * block_size
    if hc == 0 or wc == 0:
        return image

    coords = [
        (i, j)
        for i in range(0, hc, block_size)
        for j in range(0, wc, block_size)
    ]
    order = _permutation(key, len(coords))

    out = image.copy()
    region = image[:hc, :wc]
    blocks = [region[i:i + block_size, j:j + block_size].copy() for i, j in coords]
    for dst_idx, (i, j) in enumerate(coords):
        src = blocks[order[dst_idx]]
        out[i:i + block_size, j:j + block_size] = src
    return out


def unscramble_blocks(image: np.ndarray, key: str, block_size: int = 16) -> np.ndarray:
    """Invert :func:`scramble_blocks`."""
    h, w = image.shape[:2]
    hc = (h // block_size) * block_size
    wc = (w // block_size) * block_size
    if hc == 0 or wc == 0:
        return image

    coords = [
        (i, j)
        for i in range(0, hc, block_size)
        for j in range(0, wc, block_size)
    ]
    order = _permutation(key, len(coords))
    inverse = np.argsort(order)

    out = image.copy()
    region = image[:hc, :wc]
    blocks = [region[i:i + block_size, j:j + block_size].copy() for i, j in coords]
    for dst_idx, (i, j) in enumerate(coords):
        src = blocks[inverse[dst_idx]]
        out[i:i + block_size, j:j + block_size] = src
    return out
