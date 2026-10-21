"""Per-archive checkpoints and read-only decoder diagnostics."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
import stat
import tempfile
from importlib.metadata import version
from pathlib import Path
from typing import Any

from PIL import Image

from . import __version__
from .audit import (
    Finding,
    Page,
    Result,
    _check_pixels,
    _read_entries,
    audit_archive,
    validate_limits,
)


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
                name for name in ("unrar", "7z", "7zz", "unar", "bsdtar") if shutil.which(name)
            ],
            "note": "PATH discovery only, not successful decompression proof",
        },
    }


def _digest(path: Path) -> str:
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError(f"fingerprint requires a regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _state_signature(path: Path) -> tuple[int, int, int, int, str]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("checkpoint must be a non-symlink regular file")
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, _digest(path)


CHECKPOINT_SCHEMA = 2


def _identity(max_pages: int, max_uncompressed_mb: int) -> dict[str, Any]:
    return {
        "engine": __version__,
        "decoders": {name: version(name) for name in ("Pillow", "py7zr", "rarfile")},
        "native_rar_backends": {
            name: {"path": str(Path(found).resolve()), "sha256": _digest(Path(found))}
            for name in ("unrar", "7z", "7zz", "unar", "bsdtar")
            if (found := shutil.which(name))
        },
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
    validate_limits(max_pages, max_uncompressed_mb)
    identity = _identity(max_pages, max_uncompressed_mb)
    state_signature = _state_signature(state) if state and os.path.lexists(state) else None
    if resume and state_signature is None:
        raise ValueError("resume requires an existing checkpoint file")
    payload: dict[str, Any] = {
        "tool": "cbz-page-auditor",
        "schema": CHECKPOINT_SCHEMA,
        "identity": identity,
        "records": {},
    }
    if state_signature is not None and state:
        if not resume:
            raise ValueError("checkpoint already exists; use --resume explicitly")
        payload = json.loads(state.read_text(encoding="utf-8"))
        if (
            not isinstance(payload, dict)
            or payload.get("tool") != "cbz-page-auditor"
            or type(payload.get("schema")) is not int
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
    if state and any(
        state.absolute() == p.absolute()
        or state.resolve() == p.resolve()
        or (state_signature is not None and p.exists() and os.path.samefile(state, p))
        for p in paths
    ):
        raise ValueError("checkpoint cannot replace an archive")
    results = []
    for path in paths:
        try:
            resolved = path.resolve(strict=True)
            if not stat.S_ISREG(resolved.stat().st_mode):
                raise ValueError("archive must be a regular file")
            key = str(resolved)
            digest = _digest(resolved)
        except (OSError, RuntimeError, ValueError) as exc:
            results.append(
                Result(
                    str(path.absolute()), (), (Finding("error", "unreadable-archive", str(exc)),)
                )
            )
            continue
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
                handle.flush()
                os.fsync(handle.fileno())
                temporary = Path(handle.name)
            try:
                if state_signature is None:
                    os.link(temporary, state)
                else:
                    if _state_signature(state) != state_signature:
                        raise ValueError("checkpoint changed during audit; refusing to replace it")
                    os.replace(temporary, state)
                state_signature = _state_signature(state)
            finally:
                temporary.unlink(missing_ok=True)
    return results


def thumbnails(
    result: Result,
    limit: int = 200,
    *,
    max_pages: int = 10_000,
    max_uncompressed_mb: int = 2_000,
) -> dict[str, str]:
    validate_limits(max_pages, max_uncompressed_mb)
    if type(limit) is not int or not 0 <= limit <= 200:
        raise ValueError("preview limit must be an integer from 0 through 200")
    selected = {page.name: page.sha256 for page in result.pages[:limit]}
    output: dict[str, str] = {}
    if not selected:
        return output
    for entry in _read_entries(Path(result.archive), max_pages, max_uncompressed_mb):
        if entry.name not in selected:
            continue
        if entry.error or hashlib.sha256(entry.data).hexdigest() != selected[entry.name]:
            raise ValueError("archive page changed or became unreadable before preview rendering")
        with Image.open(io.BytesIO(entry.data)) as source:
            _check_pixels(source)
            image = source.convert("RGB")
            image.thumbnail((320, 440))
            buffer = io.BytesIO()
            image.save(buffer, "JPEG", quality=80)
        output[entry.name] = base64.b64encode(buffer.getvalue()).decode("ascii")
        if len(output) == len(selected):
            break
    return output
