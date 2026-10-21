import struct
import zipfile
import zlib

import pytest

from cbz_auditor.audit import audit_archive

CODECS = [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA]


def forged_prefix(path, codec, name="page.txt", payload=b"AB", declared=b"A"):
    with zipfile.ZipFile(path, "w", compression=codec) as z:
        z.writestr(name, payload)
    with zipfile.ZipFile(path) as z:
        central = z.start_dir
    data = bytearray(path.read_bytes())
    struct.pack_into("<I", data, 14, zlib.crc32(declared))
    struct.pack_into("<I", data, 22, len(declared))
    struct.pack_into("<I", data, central + 16, zlib.crc32(declared))
    struct.pack_into("<I", data, central + 24, len(declared))
    path.write_bytes(data)


@pytest.mark.parametrize("codec", CODECS, ids=["stored", "deflate", "bzip2", "lzma"])
def test_full_stream_prefix_forgery_is_an_integrity_error(tmp_path, codec):
    source = tmp_path / "forged.cbz"
    forged_prefix(source, codec)
    result = audit_archive(source)
    assert result.status == "failed"
    assert any(f.rule == "unreadable-member" for f in result.findings)


@pytest.mark.parametrize("codec", CODECS, ids=["stored", "deflate", "bzip2", "lzma"])
def test_directory_stream_is_validated(tmp_path, codec):
    source = tmp_path / "forged.cbz"
    forged_prefix(source, codec, "empty/", declared=b"")
    result = audit_archive(source)
    assert any(f.rule == "unreadable-member" and f.page == "empty/" for f in result.findings)
