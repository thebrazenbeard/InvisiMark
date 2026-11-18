"""Offline InvisiMark research prototype. Not a standalone executable or DRM."""
from __future__ import annotations

import base64
import getpass
import io
import json
import os
from pathlib import Path
import struct
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"IVMKCAP1"
MAX_IMAGE = 12 * 1024 * 1024
MAX_CAPSULE = MAX_IMAGE + 2048
MAX_HEADER = 1024
PNG_MAGIC = b"\\x89PNG\\r\\n\\x1a\\n"
JPEG_MAGIC = b"\\xff\\xd8\\xff"


class CapsuleError(Exception):
    """Invalid, corrupt, or unauthorized capsule. Does not disclose which."""


def _key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("A nonempty passphrase is required")
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password.encode("utf-8"))


def seal(image: bytes, password: str) -> bytes:
    """Produce an authenticated encrypted capsule from a PNG/JPEG image."""
    if not image or len(image) > MAX_IMAGE:
        raise ValueError("Image is empty or exceeds the 12 MiB prototype limit")
    if image.startswith(PNG_MAGIC):
        media = "image/png"
    elif image.startswith(JPEG_MAGIC):
        media = "image/jpeg"
    else:
        raise ValueError("Prototype accepts PNG and JPEG only")
    salt = os.urandom(16)
    nonce = os.urandom(12)
    header = json.dumps({"version": 1, "alg": "AES-256-GCM", "kdf": "scrypt-16384-8-1",
                         "media": media, "salt": base64.b64encode(salt).decode("ascii"),
                         "nonce": base64.b64encode(nonce).decode("ascii")},
                        sort_keys=True, separators=(",", ":")).encode("ascii")
    aad = MAGIC + struct.pack(">I", len(header)) + header
    return aad + AESGCM(_key(password, salt)).encrypt(nonce, image, aad)


def unseal(capsule: bytes, password: str) -> bytes:
    """Authenticate before returning plaintext. On failure returns no pixels."""
    try:
        if not isinstance(capsule, bytes) or not (len(MAGIC) + 4 + 16 <= len(capsule) <= MAX_CAPSULE):
            raise CapsuleError()
        if capsule[:len(MAGIC)] != MAGIC:
            raise CapsuleError()
        header_size = struct.unpack(">I", capsule[len(MAGIC):len(MAGIC) + 4])[0]
        if not (1 <= header_size <= MAX_HEADER):
            raise CapsuleError()
        offset = len(MAGIC) + 4 + header_size
        if offset + 16 > len(capsule):
            raise CapsuleError()
        header = json.loads(capsule[len(MAGIC) + 4:offset])
        if set(header) != {"version", "alg", "kdf", "media", "salt", "nonce"}:
            raise CapsuleError()
        if header["version"] != 1 or header["alg"] != "AES-256-GCM" or header["kdf"] != "scrypt-16384-8-1":
            raise CapsuleError()
        if header["media"] not in {"image/png", "image/jpeg"}:
            raise CapsuleError()
        salt = base64.b64decode(header["salt"], validate=True)
        nonce = base64.b64decode(header["nonce"], validate=True)
        if len(salt) != 16 or len(nonce) != 12:
            raise CapsuleError()
        if not password:
            raise CapsuleError()
        image = AESGCM(_key(password, salt)).decrypt(nonce, capsule[offset:], capsule[:offset])
        if not image or len(image) > MAX_IMAGE:
            raise CapsuleError()
        if header["media"] == "image/png" and not image.startswith(PNG_MAGIC):
            raise CapsuleError()
        if header["media"] == "image/jpeg" and not image.startswith(JPEG_MAGIC):
            raise CapsuleError()
        return image
    except (ValueError, TypeError, KeyError, UnicodeError, json.JSONDecodeError, InvalidTag, struct.error, CapsuleError) as exc:
        raise CapsuleError("INTEGRITY OR AUTHORIZATION FAILURE") from None


def show_capsule(capsule: bytes, password: str) -> None:
    """Prototype GUI: no plaintext file; show opaque failure on tampering."""
    import tkinter as tk
    from PIL import Image, ImageTk

    root = tk.Tk()
    root.title("InvisiMark research viewer — not copy-proof")
    root.configure(bg="black")
    try:
        data = unseal(capsule, password)
        image = Image.open(io.BytesIO(data))
        image.verify()  # Reject malformed inputs before display.
        image = Image.open(io.BytesIO(data))
        image.load()
        if image.width * image.height > 30_000_000:
            raise CapsuleError()
        image.thumbnail((1200, 900))
        tk_image = ImageTk.PhotoImage(image, master=root)
        label = tk.Label(root, image=tk_image, bg="black")
        label.image = tk_image
        label.pack(fill="both", expand=True)
    except (CapsuleError, OSError, ValueError):
        tk.Label(root, text="INTEGRITY OR AUTHORIZATION FAILURE", bg="black", fg="white",
                 padx=40, pady=40).pack(fill="both", expand=True)
    root.mainloop()


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="InvisiMark offline research capsule (not DRM)")
    parser.add_argument("action", choices=["pack", "verify", "view"])
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path, nargs="?", help="Output capsule for pack only")
    args = parser.parse_args(argv)
    if args.action == "pack" and not args.output:
        parser.error("pack requires an output .ivmk file")
    if args.action != "pack" and args.output:
        parser.error("verify/view do not write an output image")
    password = getpass.getpass("Passphrase: ")
    try:
        if args.input.stat().st_size > (MAX_IMAGE if args.action == "pack" else MAX_CAPSULE):
            raise ValueError("Input too large")
        if args.action == "pack":
            packed = seal(args.input.read_bytes(), password)
            with args.output.open("xb") as f:
                f.write(packed)
            print("Capsule written. The original image is not deleted.")
        elif args.action == "verify":
            unseal(args.input.read_bytes(), password)
            print("Authenticated; no image exported")
        else:
            show_capsule(args.input.read_bytes(), password)
        return 0
    except (CapsuleError, ValueError, OSError) as exc:
        print("Failed: image not released; verify authorization and file integrity", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
