"""Hash sets and signatures on the AIRLOCK image (Milestone 4A).

* ``config``: where the applied hash sets live (``/etc/airlock/hashsets.json``) and what each
  one is (name, version, snapshot date), read from the metadata the provisioning step wrote.
* ``nsrl``: read-only lookups in an NSRL RDSv3 SQLite database (SHA-256 first).
* ``scanners``: ``clamscan``, ``yara``, and ``ssdeep`` run with argument lists over aliased
  file names, so names that came from evidence never reach a tool or its output parser.
* ``build``: provisioning steps run by the ``tools_hashsets`` role (MalwareBazaar export to a
  ClamAV ``.hsb``, ClamAV database check with ``sigtool``, YARA pack compile, NSRL extract).
* ``triage``: ``triage_paths(paths, out_csv)``, wrapped by ``evidence-triage-hash``.
"""

from __future__ import annotations

TOOL = "evidence-triage-hash"
VERSION = "1"
