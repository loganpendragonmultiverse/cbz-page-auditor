"""Per-archive checkpoints and read-only decoder diagnostics."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
import tempfile
from importlib.metadata import version
from pathlib import Path
from typing import Any

from PIL import Image

from . import __version__
from .audit import Finding, Page, Result, _read_entries, audit_archive


def doctor() -> dict[str, Any]:
    return {
        "zip": "Python standard library",
        "7z": {
            "py7zr": version("py7zr"),
            "note": "Decoder installed; archive-specific codec support still requires a real test",
        },
        "rar": {
            "rarfile": version("rarfile"),
            "executables_found": [
                name
                for name in ("unrar", "7z", "7zz", "unar", "bsdtar")
                if shutil.which(name)
            ],
            "note": "PATH discovery only, not successful decompression proof",
        },
    }


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


CHECKPOINT_SCHEMA = 2


def _identity(max_pages: int, max_uncompressed_mb: int) -> dict[str, Any]:
    return {
        "engine": __version__,
        "decoders": {name: version(name) for name in ("Pillow", "py7zr", "rarfile")},
        "configuration": {
            "max_pages": max_pages,
            "max_uncompressed_mb": max_uncompressed_mb,
        },
    }


def audit_batch(
    paths: list[Path],
    state: Path | None = None,
    *,
    resume: bool = False,
    max_pages: int = 10_000,
    max_uncompressed_mb: int = 2_000,
) -> list[Result]:
    if max_pages < 1 or max_uncompressed_mb < 1:
        raise ValueError("audit limits must be positive")
    identity = _identity(max_pages, max_uncompressed_mb)
    if resume and (state is None or not state.is_file()):
        raise ValueError("resume requires an existing checkpoint file")
    payload: dict[str, Any] = {
        "tool": "cbz-page-auditor",
        "schema": CHECKPOINT_SCHEMA,
        "identity": identity,
        "records": {},
    }
    if state and state.exists():
        if not resume:
            raise ValueError("checkpoint already exists; use --resume explicitly")
        payload = json.loads(state.read_text(encoding="utf-8"))
        if (
            not isinstance(payload, dict)
            or payload.get("tool") != "cbz-page-auditor"
            or payload.get("schema") != CHECKPOINT_SCHEMA
            or not isinstance(payload.get("records"), dict)
        ):
            raise ValueError("unsupported checkpoint; start a new checkpoint file")
        if payload.get("identity") != identity:
            payload = {
                "tool": "cbz-page-auditor",
                "schema": CHECKPOINT_SCHEMA,
                "identity": identity,
                "records": {},
            }
    if state and state.resolve() in {p.resolve() for p in paths}:
        raise ValueError("checkpoint cannot replace an archive")
    results = []
    for path in paths:
        key = str(path.resolve())
        digest = _digest(path)
        previous = payload["records"].get(key)
        result = None
        if isinstance(previous, dict) and previous.get("sha256") == digest:
            try:
                value = previous["result"]
                result = Result(
                    key,
                    tuple(Page(**page) for page in value["pages"]),
                    tuple(Finding(**finding) for finding in value["findings"]),
                )
                if (
                    not isinstance(value["pages"], list)
                    or not isinstance(value["findings"], list)
                    or any(
                        not isinstance(page.name, str)
                        or type(page.width) is not int
                        or page.width < 1
                        or type(page.height) is not int
                        or page.height < 1
                        or not isinstance(page.format, str)
                        or not isinstance(page.sha256, str)
                        or len(page.sha256) != 64
                        or any(c not in "0123456789abcdef" for c in page.sha256)
                        or type(page.mean_brightness) not in {int, float}
                        or not 0 <= page.mean_brightness <= 255
                        for page in result.pages
                    )
                    or any(
                        f.severity not in {"error", "warning", "info"}
                        or not isinstance(f.rule, str)
                        or not isinstance(f.message, str)
                        or (f.page is not None and not isinstance(f.page, str))
                        for f in result.findings
                    )
                ):
                    result = None
            except (KeyError, TypeError, ValueError):
                result = None
        if result is None:
            result = audit_archive(path, max_pages, max_uncompressed_mb)
        if _digest(path) != digest:
            raise ValueError("archive changed during audit; checkpoint not advanced")
        results.append(result)
        payload["records"][key] = {"sha256": digest, "result": result.to_dict()}
        if state:
            state.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=state.parent, delete=False
            ) as handle:
                json.dump(payload, handle, indent=2)
                temporary = Path(handle.name)
            try:
                os.replace(temporary, state)
            finally:
                temporary.unlink(missing_ok=True)
    return results


def thumbnails(result: Result, limit: int = 200) -> dict[str, str]:
    selected = {page.name for page in result.pages[:limit]}
    output: dict[str, str] = {}
    if not selected:
        return output
    for entry in _read_entries(Path(result.archive), 10_000, 2_000):
        if entry.name not in selected:
            continue
        with Image.open(io.BytesIO(entry.data)) as source:
            image = source.convert("RGB")
            image.thumbnail((320, 440))
            buffer = io.BytesIO()
            image.save(buffer, "JPEG", quality=80)
        output[entry.name] = base64.b64encode(buffer.getvalue()).decode("ascii")
        if len(output) == len(selected):
            break
    return output
