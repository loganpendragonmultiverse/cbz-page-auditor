import io
import zipfile
from pathlib import Path

from PIL import Image

from cbz_auditor.audit import audit_archive


def image_bytes(size=(800, 1200), color=(90, 120, 150)) -> bytes:
    stream = io.BytesIO()
    Image.new("RGB", size, color).save(stream, "PNG")
    return stream.getvalue()


def make_cbz(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return path


def test_clean_archive_passes(tmp_path: Path) -> None:
    target = make_cbz(tmp_path / "clean.cbz", {f"{number:03}.png": image_bytes(color=(number * 20, 80, 100)) for number in range(1, 5)})
    result = audit_archive(target)
    assert len(result.pages) == 4
    assert result.status == "passed"


def test_duplicate_gap_and_small_page_are_reported(tmp_path: Path) -> None:
    same = image_bytes()
    target = make_cbz(tmp_path / "issues.cbz", {"001.png": same, "002.png": same, "004.png": image_bytes(color=(1, 2, 3)), "005.png": image_bytes((100, 100), (50, 50, 50))})
    rules = {item.rule for item in audit_archive(target).findings}
    assert {"duplicate-page", "numbering-gap", "small-page"} <= rules


def test_corrupt_image_is_an_error(tmp_path: Path) -> None:
    target = make_cbz(tmp_path / "broken.cbz", {"001.png": b"not an image"})
    result = audit_archive(target)
    assert result.status == "failed"
    assert any(item.rule == "unreadable-image" for item in result.findings)


def test_non_zip_is_reported_without_crashing(tmp_path: Path) -> None:
    target = tmp_path / "not-a-zip.cbz"
    target.write_text("nope", encoding="utf-8")
    assert audit_archive(target).findings[0].rule == "invalid-archive"
