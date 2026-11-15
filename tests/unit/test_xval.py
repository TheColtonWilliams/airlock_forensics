"""Cross-validation (4C.28): agree, disagree, single_source; disagreements listed, not resolved."""

from __future__ import annotations

from forensic_analyze import findings, xval
from forensic_analyze.xval import Observation

BASE = {"run_id": "R-20261115T000000Z-abcdef", "evidence_id": "E", "evidence_sha256": "a" * 64}


def obs(parser: str, key: int, **values: object) -> Observation:
    return Observation(parser, (0, key), values, f"modules/x/{parser}.csv#L{key}")


def test_statuses() -> None:
    res = xval.join(
        [
            obs("tsk", 1, size=5, path="/a"),
            obs("mftecmd", 1, size=5, path="/a"),
            obs("tsk", 2, size=5, path="/b"),
            obs("mftecmd", 2, size=7, path="/b"),
            obs("tsk", 3, size=1),
            obs("mftecmd", 4, size=None, path="/d"),
            obs("dissect", 4, size=9, path="/d"),
        ],
        fields=("size", "path"),
    )
    assert {k[1]: r.status for k, r in res.items()} == {
        1: "agree",
        2: "disagree",
        3: "single_source",
        4: "agree",  # a field one parser does not report is not compared
    }
    diff = res[(0, 2)].differences
    assert [(d.field, d.values) for d in diff] == [("size", {"mftecmd": 7, "tsk": 5})]
    assert xval.counts(res) == {"agree": 2, "disagree": 1, "single_source": 1}
    assert xval.status_of(res, (0, 99)) == "single_source"


def test_custom_equality_and_duplicates() -> None:
    res = xval.join(
        [
            obs("a", 1, t="2026-01-01T00:00:00.9Z", names=frozenset({"/x", "/y"})),
            obs("b", 1, t="2026-01-01T00:00:00Z", names=frozenset({"/y"})),
            obs("b", 1, t="1999-01-01T00:00:00Z"),
        ],
        fields=("t", "names"),
        equal={"t": xval.same_second, "names": xval.overlap},
    )
    r = res[(0, 1)]
    assert r.status == "agree" and r.duplicates == 1
    assert xval.same_text_ci("C:\\A", "c:\\a")


def test_rows_are_valid_and_never_pick_a_side() -> None:
    res = xval.join(
        [obs("tsk", 2, size=5), obs("mftecmd", 2, size=7), obs("tsk", 3, size=1)],
        fields=("size",),
    )
    summary = xval.summary_row(
        "MFT file entries",
        res,
        volume_index=0,
        parsers_run=["tsk", "mftecmd"],
        parsers_missing={"dissect": "not installed"},
    )
    assert "0 agree, 1 disagree, 1 seen by one parser only" in summary["message"]
    assert "no value was chosen" in summary["message"]
    assert summary["text"] == "Parsers not run: dissect: not installed"
    rows = xval.disagreement_rows("MFT file entry", res, describe=lambda r: {"inode_ref": "v0:2"})
    assert len(rows) == 1
    assert rows[0]["text"] == "size: mftecmd=7, tsk=5"
    assert rows[0]["xval_status"] == "disagree"
    assert rows[0]["source_record"].startswith("modules/x/")
    for row in (summary, rows[0]):
        assert row["category"] == "xval"
        assert not findings.validate_row({**BASE, **row}, part=True)


def test_single_parser_says_so() -> None:
    res = xval.join([obs("tsk", 1, size=1), obs("tsk", 2, size=2)], fields=("size",))
    row = xval.summary_row(
        "MFT file entries",
        res,
        volume_index=None,
        parsers_run=["tsk"],
        parsers_missing={"mftecmd": "not installed"},
    )
    assert "only one parser was available (tsk)" in row["message"]
    assert "every record is single_source (2 records)" in row["message"]
