"""AIRLOCK session helpers (tasks 4.10, 4.11, 4.15, 4F.6, 3A.3, 2B.14).

One module per command, installed as thin wrappers in ``/usr/local/bin``:

* ``forensic-session-start``  -> :mod:`airlock_session.start`
* ``evidence-unlock-output``  -> :mod:`airlock_session.unlock`
* ``evidence-mount``          -> :mod:`airlock_session.mount`
* ``evidence-hash``           -> :mod:`airlock_session.hashcmd`
* ``evidence-triage``         -> :mod:`airlock_session.triage`

Every command appends JSON lines to the session log (``airlock_common.sessionlog``). Nothing
here writes to an evidence device; targets are opened read-only.
"""
