"""Synthetic-only negative and round-trip tests; no personal imagery."""
import io
import json
import struct

import pytest
from PIL import Image
from invisimark_capsule import CapsuleError, MAGIC, MAX_IMAGE, seal, unseal


def fixture_png():
    canvas = Image.new("RGB", (16, 16), color=(30, 70, 150))
    stream = io.BytesIO()
    canvas.save(stream, format="PNG")
    return stream.getvalue()


def test_round_trip():
    picture = fixture_png()
    packet = seal(picture, "test only passphrase")
    assert unseal(packet, "test only passphrase") == picture
    assert picture not in packet


def test_wrong_password_fails_closed():
    packet = seal(fixture_png(), "good passphrase")
    with pytest.raises(CapsuleError):
        unseal(packet, "bad passphrase")


@pytest.mark.parametrize("index", [0, 8, 12, -1, -7, -22])
def test_single_byte_edit_fails_closed(index):
    packet = bytearray(seal(fixture_png(), "correct"))
    packet[index] ^= 1
    with pytest.raises(CapsuleError):
        unseal(bytes(packet), "correct")


@pytest.mark.parametrize("cut", [0, 1, 8, 11, 12, 22, 40, 99])
def test_truncated_capsule_fails_closed(cut):
    packet = seal(fixture_png(), "correct")
    with pytest.raises(CapsuleError):
        unseal(packet[:cut], "correct")


def test_header_substitution_fails_closed():
    packet = bytearray(seal(fixture_png(), "correct"))
    n = struct.unpack(">I", packet[8:12])[0]
    assert n > 0
    packet[13] ^= 1
    with pytest.raises(CapsuleError):
        unseal(bytes(packet), "correct")


def test_rejects_unrecognized_image_and_empty_password():
    with pytest.raises(ValueError):
        seal(b"not an image", "good")
    with pytest.raises(ValueError):
        seal(fixture_png(), "")


def test_rejects_oversize():
    with pytest.raises(ValueError):
        seal(b"\x89PNG\r\n\x1a\n" + b"x" * MAX_IMAGE, "secret")


def test_nondeterministic_encryption():
    image = fixture_png()
    assert seal(image, "pass") != seal(image, "pass")
