import json
import os
import stat
import zipfile
from pathlib import Path
from types import SimpleNamespace

import py7zr
import pytest
from PIL import Image
from test_audit import image_bytes, make_cbz

from cbz_auditor import audit, batch
from cbz_auditor.cli import main


@pytest.mark.parametrize("value", [True, False, 0, -1, 1.5, "2", None])
def test_typed_limits_even_for_empty_batch(value):
    with pytest.raises(ValueError, match="positive integers"):
        batch.audit_batch([], max_pages=value)


def test_one_member_consumed_at_a_time(tmp_path, monkeypatch):
    path = make_cbz(tmp_path / "pages.cbz", {"001.png": image_bytes()})
    original = audit._audit_entry
    calls = []

    def entries(*args):
        yield audit.ArchiveEntry("001.png", 1, image_bytes())
        assert calls == ["001.png"]
        yield audit.ArchiveEntry("002.png", 1, image_bytes())

    def page(entry, pages, findings):
        calls.append(entry.name)
        original(entry, pages, findings)

    monkeypatch.setattr(audit, "_read_entries", entries)
    monkeypatch.setattr(audit, "_audit_entry", page)
    assert len(audit.audit_archive(path).pages) == 2


def test_unsafe_and_nonimage_members_do_not_read_payload(tmp_path, monkeypatch):
    path = make_cbz(
        tmp_path / "pages.cbz",
        {"../001.png": b"bad", "metadata.txt": b"no read", "large.png": b"x" * 20},
    )
    original = zipfile.ZipExtFile.read
    seen = []

    def opened(self, *args, **kwargs):
        seen.append(self.name)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipExtFile, "read", opened)
    monkeypatch.setattr(audit, "MAX_MEMBER_BYTES", 10)
    result = audit.audit_archive(path)
    assert {x.rule for x in result.findings} >= {
        "unsafe-path",
        "unreadable-member",
        "non-image-entry",
    }
    assert seen == []


def test_pixel_budget_precedes_decode_and_next_page_survives(tmp_path, monkeypatch):
    path = make_cbz(
        tmp_path / "pages.cbz",
        {"huge.png": image_bytes((30, 30)), "valid.png": image_bytes((5, 5))},
    )
    monkeypatch.setattr(audit, "MAX_IMAGE_PIXELS", 100)
    original = Image.Image.convert

    def convert(self, *args, **kwargs):
        assert self.width * self.height <= 100
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Image.Image, "convert", convert)
    result = audit.audit_archive(path)
    assert [p.name for p in result.pages] == ["valid.png"]
    assert any(x.rule == "unreadable-image" and x.page == "huge.png" for x in result.findings)


def test_crc_failure_is_per_member(tmp_path):
    path = make_cbz(
        tmp_path / "pages.cbz",
        {"broken.png": image_bytes(), "valid.png": image_bytes(color=(40, 50, 60))},
    )
    with zipfile.ZipFile(path) as z:
        item = z.getinfo("broken.png")
        offset = item.header_offset + 30 + len(item.filename.encode()) + len(item.extra)
    with path.open("r+b") as f:
        f.seek(offset)
        byte = f.read(1)
        f.seek(offset)
        f.write(bytes([byte[0] ^ 1]))
    result = audit.audit_archive(path)
    assert [p.name for p in result.pages] == ["valid.png"]
    assert any(x.rule == "unreadable-member" for x in result.findings)


def test_link_and_unsupported_version_actionable(tmp_path):
    path = tmp_path / "link.cbz"
    with zipfile.ZipFile(path, "w") as z:
        item = zipfile.ZipInfo("link.png")
        item.create_system = 3
        item.external_attr = (stat.S_IFLNK | 0o777) << 16
        z.writestr(item, b"target")
    assert any(x.rule == "unreadable-member" for x in audit.audit_archive(path).findings)
    with zipfile.ZipFile(path, "w") as z:
        item = zipfile.ZipInfo("page.png")
        item.extract_version = 99
        item.create_version = 99
        z.writestr(item, b"bad")
    assert audit.audit_archive(path).findings[0].rule == "invalid-archive"


def test_actual_seven_decoder_budget(tmp_path, monkeypatch):
    page = tmp_path / "page.png"
    page.write_bytes(b"x" * (2 * 1024 * 1024))
    path = tmp_path / "pages.cb7"
    with py7zr.SevenZipFile(path, "w") as z:
        z.write(page, "page.png")
    original = py7zr.SevenZipFile.list

    def misleading(self):
        return [
            SimpleNamespace(
                filename=x.filename,
                uncompressed=1,
                is_directory=x.is_directory,
                is_file=x.is_file,
                is_symlink=x.is_symlink,
            )
            for x in original(self)
        ]

    monkeypatch.setattr(py7zr.SevenZipFile, "list", misleading)
    result = audit.audit_archive(path, max_uncompressed_mb=1)
    assert result.status == "failed" and any(x.rule == "invalid-archive" for x in result.findings)


def test_missing_archive_does_not_abort_later_item(tmp_path):
    good = make_cbz(tmp_path / "good.cbz", {"page.png": image_bytes()})
    results = batch.audit_batch([tmp_path / "missing.cbz", good], tmp_path / "state.json")
    assert results[0].status == "failed" and len(results[1].pages) == 1
    assert len(json.loads((tmp_path / "state.json").read_text())["records"]) == 1


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_nonregular_checkpoint_refused_before_read(tmp_path, kind):
    state = tmp_path / "state.json"
    if kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFO unavailable")
        os.mkfifo(state)
    else:
        try:
            state.symlink_to(tmp_path / "missing")
        except (OSError, NotImplementedError):
            pytest.skip("symlink creation unavailable")
    with pytest.raises(ValueError, match="non-symlink regular"):
        batch.audit_batch([], state, resume=True)
    assert os.path.lexists(state)


def test_native_identity_reaudits_and_raced_state_preserved(tmp_path, monkeypatch):
    source = make_cbz(tmp_path / "good.cbz", {"page.png": image_bytes()})
    state = tmp_path / "state.json"
    batch.audit_batch([source], state)
    original = batch._identity
    monkeypatch.setattr(
        batch,
        "_identity",
        lambda *args: {**original(*args), "native_rar_backends": {"changed": "backend"}},
    )
    called = []
    old_audit = batch.audit_archive

    def actual(*args):
        called.append(True)
        return old_audit(*args)

    monkeypatch.setattr(batch, "audit_archive", actual)
    batch.audit_batch([source], state, resume=True)
    assert called
    newstate = tmp_path / "raced.json"

    def raced(*args):
        newstate.write_text("other writer")
        return old_audit(*args)

    monkeypatch.setattr(batch, "audit_archive", raced)
    with pytest.raises(FileExistsError):
        batch.audit_batch([source], newstate)
    assert newstate.read_text() == "other writer"


def test_checkpoint_hardlink_cannot_replace_archive(tmp_path):
    source = make_cbz(tmp_path / "good.cbz", {"page.png": image_bytes()})
    state = tmp_path / "state.json"
    os.link(source, state)
    before = source.read_bytes()
    with pytest.raises(ValueError):
        batch.audit_batch([source], state, resume=True)
    assert source.read_bytes() == before


def test_preview_refuses_changed_content(tmp_path):
    source = make_cbz(tmp_path / "good.cbz", {"page.png": image_bytes()})
    result = audit.audit_archive(source)
    make_cbz(source, {"page.png": image_bytes(color=(50, 60, 70))})
    with pytest.raises(ValueError, match="changed"):
        batch.thumbnails(result)


def test_report_exclusive_create(tmp_path, monkeypatch):
    source = make_cbz(tmp_path / "good.cbz", {"page.png": image_bytes()})
    output = tmp_path / "report.json"
    from cbz_auditor import cli

    original = cli._render

    def rendered(*args, **kwargs):
        output.write_text("other writer")
        return original(*args, **kwargs)

    monkeypatch.setattr(cli, "_render", rendered)
    assert main([str(source), "--format", "json", "--output", str(output)]) == 2
    assert output.read_text() == "other writer"


def test_directory_stat_failure_not_skipped(tmp_path, monkeypatch):
    source = make_cbz(tmp_path / "good.cbz", {"page.png": image_bytes()})
    original = Path.stat

    def statted(self, *args, **kwargs):
        if self == source:
            raise PermissionError("inaccessible archive")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", statted)
    assert main([str(tmp_path)]) == 2


def test_doctor_version_and_cli_formats(tmp_path, capsys):
    from cbz_auditor import __version__

    source = make_cbz(tmp_path / "good.cbz", {"long" * 150 + ".png": image_bytes()})
    assert main(["--doctor"]) == 0
    assert "executables_found" in capsys.readouterr().out
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0 and __version__ in capsys.readouterr().out
    assert main([str(source), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["archives"][0]["page_count"] == 1
    assert main([str(source)]) == 0
    assert "readable pages" in capsys.readouterr().out
    out = tmp_path / "review.html"
    assert main([str(source), "--format", "html", "--output", str(out)]) == 0
    assert "data:image/jpeg;base64," in out.read_text()


def test_backend_binary_content_is_part_of_checkpoint_identity(tmp_path, monkeypatch):
    backend = tmp_path / "backend"
    backend.write_bytes(b"first")
    monkeypatch.setattr(batch.shutil, "which", lambda name: str(backend) if name == "7zz" else None)
    first = batch._identity(1, 1)
    backend.write_bytes(b"second")
    assert batch._identity(1, 1) != first


def test_existing_dangling_report_link_preserved(tmp_path):
    source = make_cbz(tmp_path / "good.cbz", {"page.png": image_bytes()})
    output = tmp_path / "report.json"
    target = tmp_path / "missing"
    try:
        output.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    assert main([str(source), "--output", str(output)]) == 2
    assert output.is_symlink() and not target.exists()


def test_backend_fifo_refused_before_fingerprint_open(tmp_path, monkeypatch):
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO unavailable")
    backend = tmp_path / "backend"
    os.mkfifo(backend)
    monkeypatch.setattr(batch.shutil, "which", lambda name: str(backend) if name == "7zz" else None)

    original_open = Path.open

    def forbidden(path, *args, **kwargs):
        if path == backend:
            raise AssertionError("nonregular backend must not be opened")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", forbidden)
    with pytest.raises(ValueError, match="regular file"):
        batch._identity(1, 1)
