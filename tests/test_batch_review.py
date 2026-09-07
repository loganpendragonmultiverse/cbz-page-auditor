import io
import json
from pathlib import Path
from zipfile import ZipFile

import pytest
from PIL import Image

import cbz_auditor.batch as batch
from cbz_auditor.cli import main


def archive(path: Path) -> None:
    out = io.BytesIO()
    Image.new("RGB", (64, 80), "white").save(out, "PNG")
    with ZipFile(path, "w") as target:
        target.writestr("001.png", out.getvalue())


def test_interrupted_batch_resumes_unchanged_and_reaudits_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    one, two = tmp_path / "one.cbz", tmp_path / "two.cbz"
    archive(one)
    archive(two)
    state = tmp_path / "checkpoint.json"
    original = batch.audit_archive
    calls = []

    def interrupted(path: Path):
        calls.append(path.name)
        if path == two:
            raise RuntimeError("simulated interruption")
        return original(path)

    monkeypatch.setattr(batch, "audit_archive", interrupted)
    with pytest.raises(RuntimeError):
        batch.audit_batch([one, two], state)
    assert len(json.loads(state.read_text(encoding="utf-8"))["records"]) == 1
    calls.clear()

    def resumed(path: Path):
        calls.append(path.name)
        return original(path)

    monkeypatch.setattr(batch, "audit_archive", resumed)
    assert len(batch.audit_batch([one, two], state, resume=True)) == 2
    assert calls == ["two.cbz"]
    two.write_bytes(b"damaged archive")
    calls.clear()
    result = batch.audit_batch([one, two], state, resume=True)
    assert calls == ["two.cbz"] and result[1].status == "failed"
    assert one.read_bytes()[:2] == b"PK"


def test_doctor_contact_sheet_and_state_guards(tmp_path: Path) -> None:
    source = tmp_path / "one.cbz"
    archive(source)
    output = tmp_path / "report.html"
    assert main([str(source), "--format", "html", "--output", str(output)]) == 0
    html = output.read_text(encoding="utf-8")
    assert "data:image/jpeg;base64," in html
    assert 'href="#archive-0-page-0"' in html
    assert "nearly-blank" in html
    assert main([str(source), "--output", str(output)]) == 2
    assert main(["--doctor"]) == 0
    assert "executables_found" in batch.doctor()["rar"]
    state = tmp_path / "state.json"
    with pytest.raises(ValueError, match="existing"):
        batch.audit_batch([source], state, resume=True)
    state.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported"):
        batch.audit_batch([source], state, resume=True)
    with pytest.raises(ValueError, match="already exists"):
        batch.audit_batch([source], state)
