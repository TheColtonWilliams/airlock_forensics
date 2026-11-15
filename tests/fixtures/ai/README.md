# AI fixtures (tasks 4B.12, 4G.10, 4G.11)

Neutral, generated test material only (hard rule 2.3.5). No photographs, no people, nothing
sexual or violent, and no EICAR file (decision log 2026-11-15).

* `neutral/`: made by `make-neutral-fixtures.py` (standard library only, deterministic):
  shapes, a text render, a procedural landscape, two text PDFs (one with a planted instruction
  for the data-not-instructions tests), a "scanned" PDF page (a picture of text), a sine tone.
  `tests/functional/test_ai_neutral.sh` checks the committed files equal a fresh run.
* `stub-scores.json`: fixed scores for `AIRLOCK_SCREEN_BACKEND=stub:<file>`. The flagged and
  error entries point at the neutral shapes by SHA-256; the "flag" is a test value, not a
  property of the picture.
* `stub_llama_server.py`: stand-in for `llama-server` on 127.0.0.1 (describe, decline, empty,
  echo) that logs what the model was sent.
* `make-fake-siglip.py`: a SigLIP-shaped ONNX model with fixed logits for plumbing tests when
  the real export is not staged (needs `onnx` in a scratch venv; never on the image).
* `lib-ai.sh`: helpers for the functional tests.
