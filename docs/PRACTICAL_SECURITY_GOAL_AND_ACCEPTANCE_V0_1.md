# InvisiMark — Practical Security Goal and Acceptance Criteria v0.1

Status: research design correction; not implementation or test evidence. 2026-11-18.
Authority: Patrick's explicit correction in voice conversation, applied to InvisiMark requirements; preserve the earlier ambitious protective intent without recasting it as a promise of perfection.

## Corrected aim

**Strive for the strongest practical protection of an image, while acknowledging that absolute prevention of every possible unauthorized copy or capture is not achievable.** A solution must not be rejected merely because a determined attacker with physical access or control of an endpoint can eventually circumvent it. Equally, a partial mechanism must not be advertised as universally unbreakable.

The distinction is *risk reduction and measurable friction* versus *universal denial*. Earlier language that implied “nobody can ever copy it” was an invalid pass/fail requirement, not Patrick's intended product claim.

## Candidate layers, with evidence boundaries

- **Confidentiality at rest:** authenticated encryption of image data, with recipient-controlled key management. A key hardcoded into the same untrusted executable would undercut this claim.
- **Integrity:** verify package and image authenticity *before rendering*. Failure visibly blocks in a trusted viewer. This is a testable local property, not a guarantee of action by every editor.
- **Ordinary capture deterrence:** where permitted by the OS, opt the viewer window out of standard screenshot/recording APIs (e.g., Windows WDA_EXCLUDEFROMCAPTURE on supported Windows versions; Android FLAG_SECURE in a native Android app). These are optional, platform-scoped mitigations; report observed API behavior by version and capture application.
- **Traceability:** synthetic art can carry provenance/AI-generation disclosure; real-person photos must not be mislabeled AI. Visible corner authorship marks are opt-in and separate from access protection.
- **User safety:** no undisclosed file execution, autorun, OS-wide screenshot interference, covert monitoring, credential access, or private photo upload. Clear indication that a capsule is an executable. Prefer offline operation.

## Realistic threat/test matrix

For every supported platform and version, evaluate rather than assume:
1. Modify ciphertext or manifest: does a supported capsule refuse to render image bytes?
2. Try wrong/missing key and truncation: does failure remain closed?
3. Try routine Snipping Tool, Print Screen, built-in recording, and common screen sharing: what is blocked, blanked, or captured?
4. Test copy/paste, export, app memory exposure and standard file preview: what actually persists or leaks?
5. Test an external camera or compromised OS: expect remaining bypass paths; disclose them rather than requiring a magical fix.
6. Evaluate false positives, accessibility, install friction, antivirus warning, security of recipient key exchange, and usability against ordinary encrypted file sharing.

## Decision gate

Advance from research to a tested prototype only when actual executable source and synthetic fixtures exist, with reproducible results and threat-model-specific claims. Do not declare comprehensive privacy or copyright protection on the basis of a diagram, hash, signed metadata, Windows API name, or single demo.

**Design principle:** make the common unauthorized actions harder, make modifications detectable under supported checks, preserve honest evidence about bypasses, and keep legitimate recipient viewing usable.

This document supersedes any interpretation of earlier InvisiMark notes that treats absolute worldwide capture prevention as the sole release criterion. It does not overwrite their recorded concept or imply any completed protection.
