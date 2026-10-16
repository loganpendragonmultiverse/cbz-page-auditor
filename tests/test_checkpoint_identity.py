import json

import pytest
from test_batch_review import archive

from cbz_auditor import batch


def test_identity_limits_engine_and_malformed_records(tmp_path, monkeypatch):
    source, state = tmp_path / "one.cbz", tmp_path / "state.json"
    archive(source)
    batch.audit_batch([source], state)
    original = batch.audit_archive
    calls = []

    def audit(path, *limits):
        calls.append(limits)
        return original(path, *limits)

    monkeypatch.setattr(batch, "audit_archive", audit)
    batch.audit_batch([source], state, resume=True)
    assert not calls
    batch.audit_batch([source], state, resume=True, max_pages=1)
    assert calls == [(1, 2000)]
    monkeypatch.setattr(batch, "__version__", "future-engine")
    batch.audit_batch([source], state, resume=True, max_pages=1)
    assert len(calls) == 2
    batch.audit_batch([source], state, resume=True, max_pages=1, max_uncompressed_mb=1)
    assert calls[-1] == (1, 1)
    payload = json.loads(state.read_text())
    payload["records"][str(source.resolve())]["result"] = None
    state.write_text(json.dumps(payload))
    batch.audit_batch([source], state, resume=True, max_pages=1, max_uncompressed_mb=1)
    assert len(calls) == 4


@pytest.mark.parametrize(
    "content", ["{", '{"tool":"cbz-page-auditor","schema":1,"records":{}}', "[]"]
)
def test_bad_checkpoint_is_preserved(tmp_path, content):
    source, state = tmp_path / "one.cbz", tmp_path / "state.json"
    archive(source)
    state.write_text(content)
    with pytest.raises(ValueError):
        batch.audit_batch([source], state, resume=True)
    assert state.read_text() == content


def test_changed_during_audit_does_not_advance(tmp_path, monkeypatch):
    source, state = tmp_path / "one.cbz", tmp_path / "state.json"
    archive(source)
    original = batch.audit_archive

    def changed(path, *limits):
        result = original(path, *limits)
        path.write_bytes(b"changed")
        return result

    monkeypatch.setattr(batch, "audit_archive", changed)
    with pytest.raises(ValueError, match="changed during audit"):
        batch.audit_batch([source], state)
    assert not state.exists()


def test_raised_limits_render_html_and_resume_with_matching_identity(
    tmp_path, monkeypatch
):
    from zipfile import ZipFile

    from cbz_auditor.cli import main

    source, state, output = (
        tmp_path / "large.cbz",
        tmp_path / "state.json",
        tmp_path / "report.html",
    )
    archive(source)
    with ZipFile(source, "a") as target:
        for index in range(10_000):
            target.writestr(f"meta/{index}/.ds_store", b"")
    before = source.read_bytes()
    original = batch._read_entries
    limits_seen = []

    def read_entries(path, max_pages, max_uncompressed_mb):
        limits_seen.append((max_pages, max_uncompressed_mb))
        return original(path, max_pages, max_uncompressed_mb)

    monkeypatch.setattr(batch, "_read_entries", read_entries)
    args = [
        str(source),
        "--state",
        str(state),
        "--format",
        "html",
        "--max-pages",
        "10001",
        "--max-uncompressed-mb",
        "2001",
    ]
    assert main(args + ["--output", str(output)]) == 0
    assert "data:image/jpeg;base64," in output.read_text()
    assert limits_seen == [(10001, 2001)]
    assert json.loads(state.read_text())["identity"]["configuration"] == {
        "max_pages": 10001,
        "max_uncompressed_mb": 2001,
    }
    resumed = tmp_path / "resumed.html"
    assert main(args + ["--resume", "--output", str(resumed)]) == 0
    assert limits_seen == [(10001, 2001), (10001, 2001)]
    default_state = tmp_path / "defaults.json"
    assert main([str(source), "--state", str(default_state), "--format", "html"]) == 1
    assert json.loads(default_state.read_text())["identity"]["configuration"] == {
        "max_pages": 10000,
        "max_uncompressed_mb": 2000,
    }
    assert source.read_bytes() == before
