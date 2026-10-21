from __future__ import annotations

import hashlib
import io
import lzma
import re
import stat
import statistics
import tempfile
import unicodedata
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import IO, Any, cast

import py7zr
import rarfile  # type: ignore[import-untyped]
from PIL import Image, ImageStat, UnidentifiedImageError

from .zip_streams import verify_compressed_stream

IMAGE_EXTENSIONS = {
    ".avif",
    ".bmp",
    ".gif",
    ".jpeg",
    ".jpg",
    ".png",
    ".tif",
    ".tiff",
    ".webp",
}
ARCHIVE_EXTENSIONS = {".cbz", ".zip", ".cb7", ".7z", ".cbr", ".rar"}
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_IMAGE_PIXELS = 40_000_000
ARCHIVE_ERRORS = (
    OSError,
    ValueError,
    RuntimeError,
    NotImplementedError,
    EOFError,
    UnicodeError,
    zipfile.BadZipFile,
    py7zr.exceptions.ArchiveError,
    py7zr.exceptions.AbsolutePathError,
    rarfile.Error,
    lzma.LZMAError,
    zlib.error,
)
NUMBER = re.compile(r"(?<!\d)(\d{1,6})(?!\d)")


@dataclass(frozen=True, slots=True)
class ArchiveEntry:
    name: str
    size: int
    data: bytes
    error: str | None = None


@dataclass(frozen=True, slots=True)
class Page:
    name: str
    width: int
    height: int
    format: str
    sha256: str
    mean_brightness: float

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Finding:
    severity: str
    rule: str
    message: str
    page: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Result:
    archive: str
    pages: tuple[Page, ...]
    findings: tuple[Finding, ...]

    @property
    def status(self) -> str:
        return (
            "failed"
            if any(item.severity == "error" for item in self.findings)
            else "warning"
            if self.findings
            else "passed"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "archive": self.archive,
            "status": self.status,
            "page_count": len(self.pages),
            "pages": [page.to_dict() for page in self.pages],
            "findings": [item.to_dict() for item in self.findings],
        }


def audit_archive(path: Path, max_pages: int = 10_000, max_uncompressed_mb: int = 2_000) -> Result:
    validate_limits(max_pages, max_uncompressed_mb)
    archive = path.expanduser().resolve(strict=True)
    if not stat.S_ISREG(archive.stat().st_mode):
        raise ValueError(f"Not a regular file: {archive}")
    findings: list[Finding] = []
    pages: list[Page] = []
    try:
        # Consume one bounded member at a time; never retain archive payloads.
        for entry in _read_entries(archive, max_pages, max_uncompressed_mb):
            _audit_entry(entry, pages, findings)
    except ARCHIVE_ERRORS as exc:
        findings.append(Finding("error", "invalid-archive", f"Archive cannot be read: {exc}"))

    if not pages:
        findings.append(Finding("error", "no-pages", "No readable page images were found."))
    findings.extend(_duplicates(pages))
    findings.extend(_dimension_outliers(pages))
    findings.extend(_numbering_gaps(pages))
    for page in pages:
        if page.width < 500 or page.height < 500:
            findings.append(
                Finding(
                    "warning",
                    "small-page",
                    f"Page is unusually small at {page.width}×{page.height}.",
                    page.name,
                )
            )
        if page.mean_brightness <= 2 or page.mean_brightness >= 253:
            findings.append(
                Finding(
                    "warning",
                    "nearly-blank",
                    f"Page is nearly uniform at mean brightness {page.mean_brightness:.1f}.",
                    page.name,
                )
            )
        ratio = page.width / page.height
        if ratio >= 1.35:
            findings.append(
                Finding(
                    "info",
                    "possible-spread",
                    f"Wide page may be a double-page spread ({page.width}×{page.height}).",
                    page.name,
                )
            )
    findings.sort(
        key=lambda item: (
            {"error": 0, "warning": 1, "info": 2}[item.severity],
            item.page or "",
            item.rule,
        )
    )
    return Result(str(archive), tuple(pages), tuple(findings))


def _check_pixels(image: Image.Image) -> None:
    if image.width < 1 or image.height < 1 or image.width * image.height > MAX_IMAGE_PIXELS:
        raise ValueError(f"image exceeds {MAX_IMAGE_PIXELS} decoded pixels")


def validate_limits(max_pages: int, max_uncompressed_mb: int) -> None:
    if any(type(v) is not int or v < 1 for v in (max_pages, max_uncompressed_mb)):
        raise ValueError("audit limits must be positive integers")


def _audit_entry(entry: ArchiveEntry, pages: list[Page], findings: list[Finding]) -> None:
    if entry.error is not None:
        findings.append(Finding("error", "unreadable-member", entry.error, entry.name))
        return
    pure = _safe_name(entry.name)
    if pure is None:
        findings.append(
            Finding(
                "error",
                "unsafe-path",
                "Archive entry uses an unsafe path.",
                entry.name,
            )
        )
        return
    if pure.suffix.casefold() not in IMAGE_EXTENSIONS:
        if (
            pure.name.casefold() not in {"comicinfo.xml", ".ds_store"}
            and "__MACOSX" not in pure.parts
        ):
            findings.append(
                Finding(
                    "warning",
                    "non-image-entry",
                    "Unexpected non-image file in archive.",
                    entry.name,
                )
            )
        return
    try:
        if not entry.data:
            raise OSError("empty file")
        with Image.open(io.BytesIO(entry.data)) as image:
            _check_pixels(image)
            image.verify()
        with Image.open(io.BytesIO(entry.data)) as image:
            _check_pixels(image)
            converted = image.convert("L")
            brightness = float(ImageStat.Stat(converted).mean[0])
            pages.append(
                Page(
                    entry.name,
                    image.width,
                    image.height,
                    image.format or "unknown",
                    hashlib.sha256(entry.data).hexdigest(),
                    round(brightness, 2),
                )
            )
    except (OSError, ValueError, UnidentifiedImageError, Image.DecompressionBombError) as exc:
        findings.append(
            Finding(
                "error",
                "unreadable-image",
                f"Image cannot be decoded: {exc}",
                entry.name,
            )
        )


def _payload(reader: IO[bytes], size: int) -> bytes:
    if size > MAX_MEMBER_BYTES:
        raise ValueError(f"page exceeds {MAX_MEMBER_BYTES} compressed-member expanded bytes")
    data = reader.read(min(size, MAX_MEMBER_BYTES) + 1)
    if len(data) != size:
        raise ValueError("actual member size differs from its declared size")
    return data


def _read_entries(path: Path, max_entries: int, max_uncompressed_mb: int) -> Iterator[ArchiveEntry]:
    validate_limits(max_entries, max_uncompressed_mb)
    suffix = path.suffix.casefold()
    max_bytes = max_uncompressed_mb * 1024 * 1024
    if suffix in {".cbz", ".zip", ".cbr", ".rar"}:
        is_zip = suffix in {".cbz", ".zip"}
        factory = zipfile.ZipFile if is_zip else rarfile.RarFile
        with cast(Any, factory(path)) as source:
            all_infos = source.infolist()

            def is_directory(item: Any) -> bool:
                return bool(item.is_dir() if is_zip else item.isdir())

            _enforce_limits(
                (
                    (
                        item.orig_filename if is_zip else item.filename,
                        _member_size(item.file_size, is_directory(item)),
                    )
                    for item in all_infos
                ),
                max_entries,
                max_bytes,
            )
            if not is_zip and any(
                is_directory(item)
                and (item.is_symlink() or getattr(item, "file_redir", None) is not None)
                for item in all_infos
            ):
                raise ValueError("RAR directory links are not accepted")
            infos = [item for item in all_infos if not is_directory(item)]
            if is_zip:
                for directory in source.infolist():
                    if directory.is_dir():
                        if _safe_name(directory.orig_filename) is None:
                            yield ArchiveEntry(directory.orig_filename, directory.file_size, b"")
                            continue
                        if stat.S_IFMT(directory.external_attr >> 16) not in {0, stat.S_IFDIR}:
                            yield ArchiveEntry(
                                directory.filename,
                                directory.file_size,
                                b"",
                                "Links and non-regular directory entries are not accepted",
                            )
                            continue
                        try:
                            verify_compressed_stream(source, directory)
                        except ARCHIVE_ERRORS as exc:
                            yield ArchiveEntry(
                                directory.filename,
                                directory.file_size,
                                b"",
                                f"Directory stream cannot be read: {exc}",
                            )
            for item in infos:
                raw_name = item.orig_filename if is_zip else item.filename
                name = _safe_name(raw_name)
                if name is None:
                    yield ArchiveEntry(raw_name, item.file_size, b"")
                    continue
                if is_zip:
                    mode = item.external_attr >> 16
                    irregular = stat.S_IFMT(mode) not in {0, stat.S_IFREG}
                else:
                    irregular = item.is_symlink() or getattr(item, "file_redir", None) is not None
                if irregular:
                    yield ArchiveEntry(
                        item.filename,
                        item.file_size,
                        b"",
                        "Links and non-regular entries are not accepted",
                    )
                    continue
                if name is not None and is_zip:
                    try:
                        verify_compressed_stream(source, item)
                    except ARCHIVE_ERRORS as exc:
                        yield ArchiveEntry(
                            item.filename, item.file_size, b"", f"Member cannot be read: {exc}"
                        )
                        continue
                if (
                    name is not None
                    and not is_zip
                    and name.suffix.casefold() not in IMAGE_EXTENSIONS
                ):
                    try:
                        count = 0
                        with source.open(item) as reader:
                            while block := reader.read(min(65536, item.file_size - count + 1)):
                                count += len(block)
                                if count > item.file_size:
                                    raise ValueError("actual expanded member exceeds declared size")
                        if count != item.file_size:
                            raise ValueError("actual expanded member size differs from declaration")
                    except ARCHIVE_ERRORS as exc:
                        yield ArchiveEntry(
                            item.filename, item.file_size, b"", f"Member cannot be read: {exc}"
                        )
                        continue
                if name is None or name.suffix.casefold() not in IMAGE_EXTENSIONS:
                    yield ArchiveEntry(item.filename, item.file_size, b"")
                    continue
                try:
                    with source.open(item) as reader:
                        data = _payload(reader, item.file_size)
                    yield ArchiveEntry(item.filename, item.file_size, data)
                except ARCHIVE_ERRORS as exc:
                    yield ArchiveEntry(
                        item.filename, item.file_size, b"", f"Member cannot be read: {exc}"
                    )
        return
    if suffix in {".cb7", ".7z"}:
        with py7zr.SevenZipFile(path, mode="r", max_extract_size=max_bytes) as source:
            all_infos = source.list()
            # Only explicit safe image targets are extracted (recursive=False).
            # Unselected directory records are never materialized by py7zr.
            if any(item.is_symlink for item in all_infos):
                raise ValueError("7Z links are not accepted")
            infos = [item for item in all_infos if not item.is_directory]
            _enforce_limits(
                (
                    (item.filename, _member_size(item.uncompressed, item.is_directory))
                    for item in all_infos
                ),
                max_entries,
                max_bytes,
            )
            if any(not item.is_file or item.is_symlink for item in infos):
                raise ValueError("7Z links and non-regular entries are not accepted")
            targets = []
            for item in infos:
                pure = _safe_name(item.filename)
                if pure is None or pure.suffix.casefold() not in IMAGE_EXTENSIONS:
                    yield ArchiveEntry(item.filename, item.uncompressed, b"")
                elif item.uncompressed > MAX_MEMBER_BYTES:
                    yield ArchiveEntry(
                        item.filename,
                        item.uncompressed,
                        b"",
                        f"page exceeds {MAX_MEMBER_BYTES} expanded bytes",
                    )
                else:
                    targets.append(item.filename)
            if not targets:
                return
            with tempfile.TemporaryDirectory(prefix="cbz-audit-") as temporary:
                root = Path(temporary).resolve()
                source.extract(path=root, targets=targets)
                for item in infos:
                    if item.filename not in targets:
                        continue
                    extracted = root.joinpath(*PurePosixPath(item.filename).parts)
                    if not extracted.resolve().is_relative_to(root) or not stat.S_ISREG(
                        extracted.lstat().st_mode
                    ):
                        raise ValueError(
                            f"7Z entry did not extract to a safe regular file: {item.filename}"
                        )
                    try:
                        with extracted.open("rb") as reader:
                            data = _payload(reader, item.uncompressed)
                        yield ArchiveEntry(item.filename, item.uncompressed, data)
                    except ARCHIVE_ERRORS as exc:
                        yield ArchiveEntry(
                            item.filename, item.uncompressed, b"", f"Member cannot be read: {exc}"
                        )
        return
    raise ValueError("Supported archives are .cbz, .zip, .cb7, .7z, .cbr, and .rar")


_RESERVED = {"con", "prn", "aux", "nul"} | {
    f"{p}{n}" for p in ("com", "lpt") for n in (*range(1, 10), "¹", "²", "³")
}


def _unsafe_name(name: str) -> bool:
    normalized = PurePosixPath(name.replace("\\", "/"))
    return (
        normalized.is_absolute()
        or ".." in normalized.parts
        or not normalized.parts
        or bool(PureWindowsPath(name).drive)
        or "\\" in name
        or name.rstrip("/") != normalized.as_posix()
        or any(
            any(ord(c) < 32 or c in '<>:"|?*' for c in part)
            or part.endswith((" ", "."))
            or part.split(".")[0].casefold() in _RESERVED
            for part in normalized.parts
        )
    )


def _safe_name(name: str) -> PurePosixPath | None:
    return None if _unsafe_name(name) else PurePosixPath(name)


def _member_size(size: object, directory: bool) -> int:
    if directory and size is None:
        return 0
    if type(size) is not int or size < 0:
        raise ValueError("Archive contains unavailable or invalid expanded member sizes")
    if directory and size != 0:
        raise ValueError("Archive directory declares unexpected expanded member data")
    return size


def _enforce_limits(entries: Iterator[tuple[str, int]], max_entries: int, max_bytes: int) -> None:
    values = list(entries)
    if len(values) > max_entries:
        raise ValueError(f"Archive has {len(values)} entries; limit is {max_entries}.")
    if any(type(size) is not int or size < 0 for _, size in values):
        raise ValueError("Archive contains unavailable or invalid expanded member sizes")
    names = [
        unicodedata.normalize("NFC", name.replace("\\", "/")).casefold().rstrip("/")
        for name, _ in values
    ]
    if len(names) != len(set(names)):
        raise ValueError("Archive contains ambiguous duplicate member names")
    total = sum(size for _, size in values)
    if total > max_bytes:
        raise ValueError(
            f"Uncompressed archive size exceeds {max_bytes // (1024 * 1024)} MB limit."
        )


def _duplicates(pages: list[Page]) -> list[Finding]:
    by_hash: dict[str, list[str]] = {}
    for page in pages:
        by_hash.setdefault(page.sha256, []).append(page.name)
    return [
        Finding(
            "warning",
            "duplicate-page",
            "Identical page data also appears as: " + ", ".join(names[1:]),
            names[0],
        )
        for names in by_hash.values()
        if len(names) > 1
    ]


def _dimension_outliers(pages: list[Page]) -> list[Finding]:
    if len(pages) < 4:
        return []  # placeholder-detector: ignore -- fewer than four pages cannot establish an outlier baseline
    median_area = statistics.median(page.width * page.height for page in pages)
    return [
        Finding(
            "warning",
            "dimension-outlier",
            f"Page area differs substantially from the archive median ({page.width}×{page.height}).",
            page.name,
        )
        for page in pages
        if (page.width * page.height) < median_area * 0.35
        or (page.width * page.height) > median_area * 3
    ]


def _numbering_gaps(pages: list[Page]) -> list[Finding]:
    numbered = []
    for page in pages:
        match = NUMBER.search(PurePosixPath(page.name).stem)
        if match:
            numbered.append((int(match.group(1)), page.name))
    values = sorted({number for number, _ in numbered})
    if len(values) < 3:
        return []  # placeholder-detector: ignore -- fewer than three numbered pages cannot establish a gap
    gaps = [number for number in range(values[0], values[-1] + 1) if number not in values]
    return (
        [
            Finding(
                "warning",
                "numbering-gap",
                "Possible missing page numbers: "
                + ", ".join(map(str, gaps[:25]))
                + ("…" if len(gaps) > 25 else ""),
            )
        ]
        if gaps
        else []
    )
