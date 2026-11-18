# InvisiMark — Sealed Image Capsule Concept v0.1

Status: research proposal; NOT a delivered tamper-proof product. 2026-11-18.
Origin: Patrick's idea, refined in conversation with Vera. This is a design hypothesis, not a verified implementation.
Scope: synthetic-image provenance and protection of personal artwork, including fictional Vera stickers. No private image files are included.

## Exact desired behavior

A single distributable file that *happens to contain an image*, but functions as a self-contained executable viewer. If anyone modifies its contents (including an attempt to remove its authenticity/disclosure mark), the image becomes unusable or is replaced with a solid opaque warning automatically, without dependence on a separate installed image editor. The owner also wants an optional visible Vera corner signature on Vera imagery.

This is stronger than ordinary PNG/JPEG/PSD watermarking. Do not quietly represent a standard hash checker or controlled viewer as achieving universal unbypassable enforcement.

## Candidate architecture: a sealed image capsule

- A signed, platform-specific executable contains a viewer, encrypted image payload, signed manifest (creator statement, synthetic-art label, asset/version identifier, content digest), and visible mark styling.
- On launch, the viewer authenticates the manifest and image payload **before** decrypting or showing the picture. Failed authentication yields an opaque tamper screen; no image pixels should be displayed before verification.
- Keep decryption keys separate from untrusted capsule data when a strong adversarial integrity guarantee is claimed. A key embedded in the same executable can be extracted and the checks patched.
- Use code signing and, where supported, trusted platform validation to distinguish an authentic viewer from a modified one. Platform-specific trust and distribution friction must be documented.
- The visible Vera mark is an attribution/design choice; signed provenance is evidence of claimed creation history; neither proves the subject is not a real person.
- Investigate optional C2PA-compatible metadata and an imperceptible pixel mark **separately** for conventional image exports. Those are not themselves universal edit prevention.

## Adversarial reality / falsifiers

1. An executable does **not** automatically run when opened by a normal PNG/JPEG image viewer; its instructions are meaningful only if the platform executes the viewer.
2. Self-verification alone is not enough against an adversary who can edit the executable and its verification code. Signature enforcement must be rooted in something the attacker does not control.
3. Even a perfectly authenticated capsule must eventually display pixels. A screenshot, photograph of a display, or capture of displayed framebuffer pixels can create a new ordinary image not governed by the capsule. **Universal uncopyable/uneditable imagery is not achievable on an untrusted endpoint.**
4. There is no guaranteed immediate reaction to bytes being edited while the executable is not running. The viewer can detect tampering when it checks; a separate trusted monitor would be needed for event-driven checks.
5. Untrusted executable attachments can trigger antivirus warnings and are less usable/portable than ordinary image files. Avoid any executable disguised as a PNG, autorun tricks, or exploit-based behavior.
6. The file name/extension and tamper screen must not falsely claim consent, actual identity, or unbreakability.

## Bounded proof of concept and evaluation

Use synthetic non-private test graphics, never the original private stickers without fresh purpose-bound permission. Build a benign, plainly labeled local viewer. No network calls, telemetry, persistence, autorun, credential access, hidden commands, or OS hooks. On supported test platforms:
- pristine capsule opens and displays its embedded test image;
- one-byte edit of payload or signed manifest -> opaque tamper result on **next verified launch**;
- changed verification code -> code-signature or trusted-distribution check FAIL when supported;
- attempted screenshot and exported/captured pixel copy -> reproduce the bypass, honestly;
- measure filesize, startup latency, usability, and platform compatibility.

No protected original replacement, public repo publication, software installation on Lappy, signature key creation, or deployment is authorized by this design note. Preserve the user's universal-enforcement target as **not yet met**.
