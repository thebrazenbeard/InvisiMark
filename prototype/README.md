# InvisiMark capsule proof of concept (source only)

This is an **offline research prototype**, not a production privacy tool, a single-file executable, DRM, or a guarantee against screenshots. It accepts a PNG/JPEG, wraps it in authenticated AES-256-GCM encryption using a passphrase-derived scrypt key, and verifies before rendering. Tampering or wrong credentials produces a fail-closed response. Nothing uploads to a network. No private images are included.

Requires Python 3.11+, `cryptography`, `Pillow` (for viewer only), and Tkinter (viewer only). To run from the project directory:

```text
python invisimark_capsule.py pack picture.png picture.ivmk
python invisimark_capsule.py verify picture.ivmk
python invisimark_capsule.py view picture.ivmk
python -m pytest tests
```

The passphrase is prompted rather than supplied on the command line. The original source file remains on disk; **packing does not delete or secure existing copies**. No image plaintext is written by `verify` or `view`, but screen capture and process memory remain outside the prototype's protection. There is no Windows screenshot exclusion yet, no key recovery, no signed binaries, no format-hardening audit, and no external security review. For any real personal photos, these are material blockers to claiming protection.

This source is a minimal cryptographic and tamper-evidence experiment only. Use synthetic test images; do not entrust sensitive personal images to it. Avoid distributing self-running image executables until they are clearly labeled, reproducibly built, signed, and independently reviewed.
