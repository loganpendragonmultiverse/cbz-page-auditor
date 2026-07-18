from __future__ import annotations

import hashlib
import io
import re
import statistics
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath

from PIL import Image, ImageStat, UnidentifiedImageError

IMAGE_EXTENSIONS = {".avif", ".bmp", ".gif", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".webp"}
NUMBER = re.compile(r"(?<!\d)(\d{1,6})(?!\d)")


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
        with zipfile.ZipFile(archive) as source:
            entries = [item for item in source.infolist() if not item.is_dir()]
            if len(entries) > max_pages:
                raise ValueError(f"Archive has {len(entries)} entries; limit is {max_pages}.")
            total_size = sum(item.file_size for item in entries)
            if total_size > max_uncompressed_mb * 1024 * 1024:
                raise ValueError(f"Uncompressed archive size exceeds {max_uncompressed_mb} MB limit.")
            for entry in entries:
                pure = PurePosixPath(entry.filename.replace("\\", "/"))
                if pure.is_absolute() or ".." in pure.parts:
                    findings.append(Finding("error", "unsafe-path", "Archive entry uses an unsafe path.", entry.filename))
                    continue
                if pure.suffix.casefold() not in IMAGE_EXTENSIONS:
                    if pure.name.casefold() not in {"comicinfo.xml", ".ds_store"} and not pure.name.startswith("__MACOSX"):
                        findings.append(Finding("warning", "non-image-entry", "Unexpected non-image file in archive.", entry.filename))
                    continue
                try:
                    data = source.read(entry)
                    if not data:
                        raise OSError("empty file")
                    with Image.open(io.BytesIO(data)) as image:
                        image.verify()
                    with Image.open(io.BytesIO(data)) as image:
                        converted = image.convert("L")
                        brightness = float(ImageStat.Stat(converted).mean[0])
                        pages.append(Page(entry.filename, image.width, image.height, image.format or "unknown", hashlib.sha256(data).hexdigest(), round(brightness, 2)))
                except (OSError, UnidentifiedImageError, zipfile.BadZipFile) as exc:
                    findings.append(Finding("error", "unreadable-image", f"Image cannot be decoded: {exc}", entry.filename))
    except zipfile.BadZipFile as exc:
        return Result(str(archive), (), (Finding("error", "invalid-archive", f"CBZ is not a readable ZIP archive: {exc}"),))

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
