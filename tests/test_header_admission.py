import zipfile

import py7zr
import pytest
from test_audit import image_bytes

from cbz_auditor.audit import audit_archive


@pytest.mark.parametrize("family", ["cbz", "cb7"])
@pytest.mark.parametrize(
    "name",
    [
        "pages/COM¹.png",
        "pages/COM².png",
        "pages/COM³.png",
        "pages/LPT¹.png",
        "pages/LPT².png",
        "pages/LPT³.png",
        "pages/a:stream.png",
        "pages/trailing. /one.png",
        "pages/CON/one.png",
        "pages/control\n.png",
    ],
)
def test_portable_nested_image_names_refused_before_decode(tmp_path, monkeypatch, family, name):
    source = tmp_path / ("unsafe." + family)
    if family == "cbz":
        with zipfile.ZipFile(source, "w") as z:
            z.writestr(name, image_bytes())
    else:
        with py7zr.SevenZipFile(source, "w") as z:
            z.writestr(image_bytes(), "fixture.png")
            assert z.header.files_info is not None
            assert len(z.header.files_info.files) == 1
            z.header.files_info.files[0]["filename"] = name
        with py7zr.SevenZipFile(source) as z:
            assert [item.filename for item in z.list()] == [name]

    def forbidden(*args, **kwargs):
        raise AssertionError("unsafe target must not be extracted")

    monkeypatch.setattr(py7zr.SevenZipFile, "extract", forbidden)
    result = audit_archive(source)
    assert result.status == "failed" and not result.pages
    assert any(f.rule == "unsafe-path" for f in result.findings)


@pytest.mark.parametrize("family", ["cbz", "cb7"])
def test_directory_headers_count_toward_entry_limit_before_decode(tmp_path, monkeypatch, family):
    source = tmp_path / ("headers." + family)
    if family == "cbz":
        with zipfile.ZipFile(source, "w") as z:
            z.writestr("one/", b"")
            z.writestr("two/", b"")
            z.writestr("page.png", image_bytes())
    else:
        one, two = tmp_path / "one", tmp_path / "two"
        one.mkdir()
        two.mkdir()
        with py7zr.SevenZipFile(source, "w") as z:
            z.write(one, "one")
            z.write(two, "two")
            z.writestr(image_bytes(), "page.png")

    def forbidden(*args, **kwargs):
        raise AssertionError("over-budget archive must not decode")

    monkeypatch.setattr(py7zr.SevenZipFile, "extract", forbidden)
    result = audit_archive(source, max_pages=2)
    assert result.status == "failed" and any("3 entries" in f.message for f in result.findings)


def test_directory_declared_data_is_refused(tmp_path):
    source = tmp_path / "headers.cbz"
    with zipfile.ZipFile(source, "w") as z:
        z.writestr("directory/", b"unexpected")
        z.writestr("page.png", image_bytes())
    result = audit_archive(source)
    assert result.status == "failed" and any(
        "directory declares" in f.message for f in result.findings
    )


def test_canonical_unicode_header_aliases_are_refused(tmp_path):
    source = tmp_path / "headers.cbz"
    with zipfile.ZipFile(source, "w") as z:
        z.writestr("é.png", image_bytes())
        z.writestr("é.png", image_bytes())
    assert any("duplicate" in f.message for f in audit_archive(source).findings)


def test_max_entries_cli_alias_counts_directory_records(tmp_path):
    from cbz_auditor.cli import main

    source = tmp_path / "headers.cbz"
    with zipfile.ZipFile(source, "w") as z:
        z.writestr("directory/", b"")
        z.writestr("page.png", image_bytes())
    assert main([str(source), "--max-entries", "1"]) == 1


@pytest.mark.parametrize("name", ["pages/back\\slash.png", "pages/page\x00hidden.png"])
def test_raw_zip_names_are_validated_before_reader_normalization(tmp_path, monkeypatch, name):
    source = tmp_path / "raw.cbz"
    with zipfile.ZipFile(source, "w") as archive:
        info = zipfile.ZipInfo("fixture")
        info.filename = name
        archive.writestr(info, image_bytes())
    with zipfile.ZipFile(source) as archive:
        assert [info.orig_filename for info in archive.infolist()] == [name]

    def forbidden(*args, **kwargs):
        raise AssertionError("raw unsafe names must be refused before payload reads")

    monkeypatch.setattr(zipfile.ZipFile, "open", forbidden)
    result = audit_archive(source)
    assert result.status == "failed" and not result.pages
    assert any(finding.rule == "unsafe-path" for finding in result.findings)
