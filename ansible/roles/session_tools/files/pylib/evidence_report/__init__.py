"""evidence-report: the run report (Milestone 4E; task 4B.11 points here).

Code fills every factual section from ``run.json`` and ``case.sqlite``. When a local model is
reachable on 127.0.0.1, it drafts the narrative sections from rows of the SQLite views, using
the fixed prompts in ``prompts/``; ``verify.py`` (code, not a model) removes every drafted
sentence it cannot match to the finding rows it cites. See docs/workflows/report.md.
"""

__version__ = "0.2.0"
TOOL_NAME = "evidence-report"
