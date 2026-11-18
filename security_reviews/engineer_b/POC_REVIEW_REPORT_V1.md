# Engineer B ? tested POC report, pinned source (private repository)

The following is a report from Lappy's original pinned POC test. The reusable test script is located beside it. The original test logs remain in the separate Lappy evidence directory. Passing adversarial assertions is not proof of safe deployment.

# InvisiMark POC ? Engineer B independent hostile review, 2026-11-18

**Scope:** private InvisiMark draft PR #1, pinned `ec39d95049e0987f7fdbcfe22089ffa8f6ce5f6c`, original blob `6c7d318e8c7d0df9442c5c2967bae1988549f337`. Windows 11 on Lappy, Python 3.12.9, cryptography 50.0.1, Pillow 13.0.0, pytest 9.0.3. Original POC and A-owned branch **unchanged**.

**Actual tests:** baseline **20/20 PASS** and adversarial **26/26 assertions PASS**; passing reviewer tests means intended observations reproduced, **not 26 security properties**. Logs, JUnit and exact source+test hashes in adjacent JSON receipt. No independent third-party model/lab.

## Source + execution findings

- **B-POC-01 / Medium:** A very small authenticated synthetic PNG containing 300-million-pixel dimensions triggers real Pillow `DecompressionBombError` during `show_capsule()`. `show_capsule` catches `CapsuleError, OSError, ValueError`, not this error class. The normal warning UI is not shown; `main(view)` propagates the exception. Test allocates no huge raster, so it does not quantify OS memory exhaustion. A's viewer should enforce conservative image pixel/dimension limits *before loading* and normalize image parser failures, plus preserve nonzero status.
- **B-POC-02 / Medium:** With fake Tk GUI, a wrong-password view displays the failure warning yet `main(view)` returns `0`. Contrast `main(verify)` returns `2`. The fake GUI isolates business status logic; this is not evidence of actual Windows window behavior. A should separate presentation result from UI loop close status.
- **B-POC-03 / Low?Medium:** Magic-only PNG junk survives `seal`, `unseal`, and authentication, but Pillow rejects it. This is distinct from AEAD forgery: the owner can create an authenticated but invalid image. Validate full syntax within a bounded resource policy before accepting an image, and distinguish authentication from decodability.
- **Design limits, not security defects:** Single-character passphrase accepted; original plaintext source is deliberately left on disk; recipient with the key obtains plaintext in memory; capsules are replayable; no screenshot-avoidance policy exists. Cryptographic protection at rest is not enforcement against a malicious recipient endpoint or screen camera.

## Verified normal behavior

The synthetic 16?16 PNG round-trip and all tested wrong-key, tamper, malformed-header, truncation, oversize-capsule and output-overwrite scenarios behaved as expected. An initial malformed-base64 exception hypothesis was explicitly **falsified**: `binascii.Error` is caught by the `ValueError` handler and becomes `CapsuleError`.

## Not run / not qualified

No actual Windows screen capture, native executable build or signature, memory/framebuffer adversary, original user image, credential, symlink/TOCTOU race, OS security policy change, network telemetry, high-memory decompression, independent third-party review or future A candidate test. The 300M pixel case tests **metadata rejection**, not true memory exhaustion. Do not infer a universal noncopyability claim.

**Verdict: HOLD** for any production or capture-proof claim. Keep source-only synthetic POC as a research prototype. Return exact counterexamples to Engineer A owner (#2) and retest the later A candidate separately when an exact immutable head is posted.
