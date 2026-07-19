from __future__ import annotations

import hashlib
import io
import re
import statistics
import tempfile
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Iterator

import py7zr
import rarfile
from PIL import Image, ImageStat, UnidentifiedImageError

IMAGE_EXTENSIONS = {".avif", ".bmp", ".gif", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".webp"}
ARCHIVE_EXTENSIONS = {".cbz", ".zip", ".cb7", ".7z", ".cbr", ".rar"}
NUMBER = re.compile(r"(?<!\d)(\d{1,6})(?!\d)")


@dataclass(frozen=True, slots=True)
class ArchiveEntry:
    name: str
    size: int
    data: bytes


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
        return "failed" if any(item.severity == "error" for item in self.findings) else "warning" if self.findings else "passed"

    def to_dict(self) -> dict[str, object]:
        return {"archive": self.archive, "status": self.status, "page_count": len(self.pages), "pages": [page.to_dict() for page in self.pages], "findings": [item.to_dict() for item in self.findings]}


def audit_archive(path: Path, max_pages: int = 10_000, max_uncompressed_mb: int = 2_000) -> Result:
    archive = path.expanduser().resolve()
    if not archive.is_file():
        raise ValueError(f"Not a file: {archive}")
    findings: list[Finding] = []
    pages: list[Page] = []
    try:
        entries = tuple(_read_entries(archive, max_pages, max_uncompressed_mb))
    except (OSError, ValueError, zipfile.BadZipFile, py7zr.Bad7zFile, rarfile.Error) as exc:
        return Result(str(archive), (), (Finding("error", "invalid-archive", f"Archive cannot be read: {exc}"),))

    for entry in entries:
        pure = _safe_name(entry.name)
        if pure is None:
            findings.append(Finding("error", "unsafe-path", "Archive entry uses an unsafe path.", entry.name))
            continue
        if pure.suffix.casefold() not in IMAGE_EXTENSIONS:
            if pure.name.casefold() not in {"comicinfo.xml", ".ds_store"} and "__MACOSX" not in pure.parts:
                findings.append(Finding("warning", "non-image-entry", "Unexpected non-image file in archive.", entry.name))
            continue
        try:
            if not entry.data:
                raise OSError("empty file")
            with Image.open(io.BytesIO(entry.data)) as image:
                image.verify()
            with Image.open(io.BytesIO(entry.data)) as image:
                converted = image.convert("L")
                brightness = float(ImageStat.Stat(converted).mean[0])
                pages.append(Page(entry.name, image.width, image.height, image.format or "unknown", hashlib.sha256(entry.data).hexdigest(), round(brightness, 2)))
        except (OSError, UnidentifiedImageError) as exc:
            findings.append(Finding("error", "unreadable-image", f"Image cannot be decoded: {exc}", entry.name))

    if not pages:
        findings.append(Finding("error", "no-pages", "No readable page images were found."))
    findings.extend(_duplicates(pages))
    findings.extend(_dimension_outliers(pages))
    findings.extend(_numbering_gaps(pages))
    for page in pages:
        if page.width < 500 or page.height < 500:
            findings.append(Finding("warning", "small-page", f"Page is unusually small at {page.width}×{page.height}.", page.name))
        if page.mean_brightness <= 2 or page.mean_brightness >= 253:
            findings.append(Finding("warning", "nearly-blank", f"Page is nearly uniform at mean brightness {page.mean_brightness:.1f}.", page.name))
        ratio = page.width / page.height
        if ratio >= 1.35:
            findings.append(Finding("info", "possible-spread", f"Wide page may be a double-page spread ({page.width}×{page.height}).", page.name))
    findings.sort(key=lambda item: ({"error": 0, "warning": 1, "info": 2}[item.severity], item.page or "", item.rule))
    return Result(str(archive), tuple(pages), tuple(findings))


def _read_entries(path: Path, max_entries: int, max_uncompressed_mb: int) -> Iterator[ArchiveEntry]:
    suffix = path.suffix.casefold()
    max_bytes = max_uncompressed_mb * 1024 * 1024
    if suffix in {".cbz", ".zip"}:
        with zipfile.ZipFile(path) as source:
            infos = [item for item in source.infolist() if not item.is_dir()]
            _enforce_limits(((item.filename, item.file_size) for item in infos), max_entries, max_bytes)
            for item in infos:
                yield ArchiveEntry(item.filename, item.file_size, source.read(item))
        return
    if suffix in {".cbr", ".rar"}:
        with rarfile.RarFile(path) as source:
            infos = [item for item in source.infolist() if not item.isdir()]
            _enforce_limits(((item.filename, item.file_size) for item in infos), max_entries, max_bytes)
            for item in infos:
                try:
                    yield ArchiveEntry(item.filename, item.file_size, source.read(item))
                except rarfile.RarCannotExec as exc:
                    raise ValueError("RAR/CBR needs UnRAR, 7-Zip, unar, or bsdtar installed and available on PATH") from exc
        return
    if suffix in {".cb7", ".7z"}:
        with py7zr.SevenZipFile(path, mode="r") as source:
            infos = [item for item in source.list() if not item.is_directory]
            _enforce_limits(((item.filename, int(item.uncompressed or 0)) for item in infos), max_entries, max_bytes)
            if any(not item.is_file or item.is_symlink for item in infos):
                raise ValueError("7Z links and non-regular entries are not accepted")
            unsafe = [item.filename for item in infos if _safe_name(item.filename) is None]
            targets = [item.filename for item in infos if _safe_name(item.filename) is not None]
        for name in unsafe:
            yield ArchiveEntry(name, 0, b"")
        with tempfile.TemporaryDirectory(prefix="cbz-audit-") as temporary:
            root = Path(temporary).resolve()
            with py7zr.SevenZipFile(path, mode="r") as source:
                source.extract(path=root, targets=targets)
            for name in targets:
                pure = _safe_name(name)
                if pure is None:
                    yield ArchiveEntry(name, 0, b"")
                    continue
                extracted = (root / Path(*pure.parts)).resolve()
                if root not in extracted.parents or not extracted.is_file():
                    raise ValueError(f"7Z entry did not extract to a safe regular file: {name}")
                data = extracted.read_bytes()
                yield ArchiveEntry(name, len(data), data)
        return
    raise ValueError("Supported archives are .cbz, .zip, .cb7, .7z, .cbr, and .rar")


def _safe_name(name: str) -> PurePosixPath | None:
    pure = PurePosixPath(name.replace("\\", "/"))
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        return None
    if re.match(r"^[A-Za-z]:", pure.parts[0]):
        return None
    return pure


def _enforce_limits(entries: Iterator[tuple[str, int]], max_entries: int, max_bytes: int) -> None:
    values = list(entries)
    if len(values) > max_entries:
        raise ValueError(f"Archive has {len(values)} entries; limit is {max_entries}.")
    total = sum(size for _, size in values)
    if total > max_bytes:
        raise ValueError(f"Uncompressed archive size exceeds {max_bytes // (1024 * 1024)} MB limit.")


def _duplicates(pages: list[Page]) -> list[Finding]:
    by_hash: dict[str, list[str]] = {}
    for page in pages:
        by_hash.setdefault(page.sha256, []).append(page.name)
    return [Finding("warning", "duplicate-page", "Identical page data also appears as: " + ", ".join(names[1:]), names[0]) for names in by_hash.values() if len(names) > 1]


def _dimension_outliers(pages: list[Page]) -> list[Finding]:
    if len(pages) < 4:
        return []  # placeholder-detector: ignore -- fewer than four pages cannot establish an outlier baseline
    median_area = statistics.median(page.width * page.height for page in pages)
    return [Finding("warning", "dimension-outlier", f"Page area differs substantially from the archive median ({page.width}×{page.height}).", page.name) for page in pages if (page.width * page.height) < median_area * 0.35 or (page.width * page.height) > median_area * 3]


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
    return [Finding("warning", "numbering-gap", "Possible missing page numbers: " + ", ".join(map(str, gaps[:25])) + ("…" if len(gaps) > 25 else ""))] if gaps else []
