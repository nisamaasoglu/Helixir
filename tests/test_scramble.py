import numpy as np

from helixir import scramble


def test_scramble_unscramble_roundtrip():
    rng = np.random.RandomState(0)
    img = rng.randint(0, 256, size=(64, 48, 3), dtype=np.uint8)
    scrambled = scramble.scramble_blocks(img, key="demo", block_size=16)
    restored = scramble.unscramble_blocks(scrambled, key="demo", block_size=16)
    assert np.array_equal(restored, img)


def test_scramble_actually_changes_image():
    rng = np.random.RandomState(1)
    img = rng.randint(0, 256, size=(64, 64, 3), dtype=np.uint8)
    scrambled = scramble.scramble_blocks(img, key="demo")
    assert not np.array_equal(scrambled, img)
    # histogram is preserved -> demonstrates it is NOT encryption
    assert np.array_equal(np.sort(img.ravel()), np.sort(scrambled.ravel()))
