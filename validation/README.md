# Validation suite

Host-side tools that build images with known contents, run the whole `forensic-analyze` wizard
on them, score every artifact class against ground truth, and publish a signed report per
release (Milestone 4F). Never run on the AIRLOCK drive. Full guide: `docs/validation.md`.
What the results cannot show: `docs/known-limitations.md`.

| Path | Task | What it does |
|---|---|---|
| `synthetic/build.sh` | 4F.1 | NTFS and exFAT images with a ground-truth manifest |
| `reference/sets.json`, `reference/fetch.sh` | 4F.2 | public reference sets, fetched by hash |
| `run.sh`, `scoring.py` | 4F.3 | run the wizard on every set, score each artifact class |
| `report/build.py` | 4F.4 | per-release report, Markdown and JSON, signed |
| `scale/scale.py`, `scale/baseline.json` | 4G.15 | run time and peak memory per module, baseline |
| `cftt/` | 3A.8 | software read-only policy test method and results (needs a person) |
| `classifiers/` | 4B.16 | classifier error rates (needs a person) |

Results go to `validation/out/` (ignored by git). No media of people, no evidence, and no
downloaded reference data is ever committed here.
