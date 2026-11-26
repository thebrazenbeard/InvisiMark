# Engineer B ? InvisiMark pinned independent-review regression suite

**Ownership:** B-only synthetic tests and report, no edits to A-owned
`prototype/invisimark_capsule.py`. Private repo. Source subject: draft
PR #1 at `ec39d95049e0987f7fdbcfe22089ffa8f6ce5f6c` and Python
module blob `6c7d318e8c7d0df9442c5c2967bae1988549f337`.

The full observational suite `test_poc_adversarial.py` contains 26
assertions under pytest 9.0.3 with Pillow 13.0.0 and cryptography 50.0.1.
These tests **describe actual current behavior**, including defects.
The independent review in `POC_REVIEW_REPORT_V1.md` records the source,
failure examples, limitations, and what was not measured.

The separate `test_remediation_gate.py` applies two strict acceptance
checks on wrong-key `view` exit status and benign-sized authenticated
decompression-bomb metadata handling. By default these are marked
XFAIL on the exact known-bad PR1 source to avoid a green false claim.
With `INVISIMARK_B_REQUIRE_FIXED=1`, they must pass. That is a
**reference source-compatible test**, not certification of a future A
candidate with potentially different interfaces. Review any changed
contract before adapting the source-path override or expected UI text.

Use the isolated development venv in this repo; installation/test setup
does not require real photographs or external telemetry:

```powershell
$env:PYTHONPATH='prototype'
python -B -m pytest -q -p no:cacheprovider prototype/tests security_reviews/engineer_b
$env:INVISIMARK_B_REQUIRE_FIXED='1'
python -B -m pytest -q -p no:cacheprovider security_reviews/engineer_b/test_remediation_gate.py
Remove-Item Env:\INVISIMARK_B_REQUIRE_FIXED
```

The first command is expected to show two XFAILs on PR1; the second
is expected to FAIL those two defects. A report that passes only after
turning off the strict gate is invalid. If A supplies a **new exact
source candidate** with a similar API, use
`INVISIMARK_B_POC_SOURCE=<exact pinned candidate module path>`, first
verifying its Git blob and every status/effect claim. The original
adversarial suite intentionally pins PR1's blob and may need a new
versioned suite for a new A source; don't edit history to make it green.

**Known counterexamples:** authenticated synthetic 69-byte PNG header
claiming 300M pixels gives Pillow `DecompressionBombError` outside the
visible failure handler; `main(view)` reports status zero after showing
wrong-key failure; `seal/unseal` accept authenticated magic-prefixed
nondecodable bytes, which is *not* an AES-GCM forgery.

**Source-only scratch repair evidence:** The B reviewer privately tried
a disposable 64-line unified diff against the pinned POC. It changed
only the viewer status propagation and image parser error handling, and
both strict red checks passed 5/5 on Lappy. That scratch source remains
outside this Git branch because A owns all implementation.
It has **not** received A review, been installed, or tested for real
Windows screenshot exclusion, secure client boundary or production.
Ask A to assess the root causes rather than blindly copying the patch.

Release/capture-proof claims remain on HOLD. Sender and recipient can
still copy after pixels are available, and the original source image
file persists. No runtime model agent, private image, executable signing,
OS-wide hooks, deployment or merge was used.
