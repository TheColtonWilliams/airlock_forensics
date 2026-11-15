"""Local AI triage: tier probe, content screening, and descriptions of cleared files.

Contract: docs/dev/contract.md section 8a (AI helpers). Everything here is standard-library
Python. The classifiers and the speech model run in their own virtual environments
(``/opt/triage``, ``/opt/whisper``) through the runner scripts in this package, always as a
sandboxed child process with no network.

AI output is triage, never evidence. Every AI row carries the model file's SHA-256 and the
fixed prompt's SHA-256, and is labelled "AI-generated".
"""

AI_LABEL = "AI-generated"
