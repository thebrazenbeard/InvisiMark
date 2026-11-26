# InvisiMark — General Personal-Image Protection Scope v0.1

Status: proposed extension, not implemented or verified. 2026-11-18.
Origin: Patrick's idea to let any consenting person package their *own real photograph* into an encrypted self-contained image viewer. Applicable to people of any gender. This supplements, not replaces, the original synthetic-art provenance scope. No actual photographs are included.

## Two separate product objectives

**A. Provenance for synthetic images.** Clearly identify synthetic media and preserve verifiable origin/alteration history. Fictional/AI-generated claims must not be applied to authentic photographs.

**B. Privacy for photographs of real people.** Let a person with the relevant rights and permissions choose an image and create a protected viewing capsule, so unauthorized users cannot simply open a conventional image file and automated screenshot tools are hindered where supported. Images may be personal, professional, sensitive, or otherwise private; no assumption that an image is sexual.

The same packaging engine can serve both purposes, but disclosure labels, consent rules, authentication and permissions differ. No automatic claim that pictured people have consented merely because a package exists.

## Proposed workflow for a real photograph

1. **Local-only input by default:** user selects an existing photograph on their own device; no upload, telemetry, or cloud transfer.
2. **Rights and consent:** clarify who owns the image and whether the depicted person(s) have authorized its intended sharing and protection. No claim that packaging verifies legal rights or grants permission by itself.
3. **Encrypt locally** with authenticated encryption (for example AES-256-GCM), a fresh random nonce and key material; avoid storing an unrestricted decryption key in the same untrusted executable. Key/passphrase, recipient/device authorization and recovery choices are separate from the encrypted payload.
4. **Package** an appropriately identified standalone viewer executable or supported secure-container format with signed manifest and tamper-checking logic; do not disguise an executable as .jpg/.png.
5. **Display** only after verification and authorized decryption. Wrong credentials or tampered payload yield no plaintext image; optionally show an opaque error screen. Protect sensitive pixels in memory where reasonably possible; document when unsupported.
6. **Capture mitigation, platform dependent:** Windows WDA_EXCLUDEFROMCAPTURE on compatible top-level application windows; Android FLAG_SECURE where applicable; validate actual screen-capture APIs, Snipping Tool, recordings, remote-desktop paths and OS versions. These can block many common captures; they are not universal.
7. **Recipient access:** an offline or device-bound recipient option; a safe method to handle loss of access and revocation limitations. Offline distributed content cannot reliably be remotely revoked once keys are shared.
8. **Optional attribution:** a user-chosen visible or invisible owner mark. A real photograph must never be automatically labeled 'not a real person' or 'AI-generated'. Vera's corner logo is specific to Vera's own synthetic stickers.

## Truthful guarantees and non-guarantees

- **Meaningful goal:** encrypt the at-rest image in the packaged file, authenticate before reveal, and reduce ordinary re-sharing/capture.
- **Not guaranteed:** preventing photographs of the screen, camera capture, all framebuffer capture, an authorized recipient's manual copying, all platform-level capture paths, or key extraction from a compromised device.
- A **self-contained offline executable containing its own unrestricted key does not provide strong confidentiality** from a motivated person who can inspect or patch the executable.
- If only a standard image export is shared, any viewer can display/copy it and no private viewer rule survives.
- Signing and checksum failure detection can establish tampering when trusted software checks them, but cannot universally prevent transformation of displayed pixels.
- Executable attachments carry malware/trust/usability tradeoffs; consider an open-source auditable viewer + encrypted capsule file as a safer alternative, while preserving the single-file-executable hypothesis for comparison.

## Prototype acceptance tests (synthetic test patterns only)

- Local pack/open round trip on the specified platform with no network use.
- Wrong key, altered ciphertext, altered manifest and truncated capsule fail closed (no image rendered).
- Verify key is not recoverable from the package alone in the external-key design.
- Verify common OS screenshot and screen-recording behavior and record pass/fail per API/version; test an external camera as an explicit bypass.
- Quantify packaging size, startup time, accessibility, usability and key-recovery failure modes.
- Verify synthetic media and real-person metadata/labels are separated.
- No real-person private input images committed to GitHub or test artifacts.

**Decision:** broaden research to an optional user-controlled privacy tool for real photographs. This is a requirements note only; no completed software, protection certification, rights verification, image ingestion, deployment or universal capture prevention is claimed.
