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


def audit_batch(
    paths: list[Path], state: Path | None = None, *, resume: bool = False
) -> list[Result]:
    if resume and (state is None or not state.is_file()):
        raise ValueError("resume requires an existing checkpoint file")
    payload: dict[str, Any] = {"tool": "cbz-page-auditor", "schema": 1, "records": {}}
    if state and state.exists():
        if not resume:
            raise ValueError("checkpoint already exists; use --resume explicitly")
        payload = json.loads(state.read_text(encoding="utf-8"))
        if (
            not isinstance(payload, dict)
            or payload.get("tool") != "cbz-page-auditor"
            or payload.get("schema") != 1
            or not isinstance(payload.get("records"), dict)
        ):
            raise ValueError("unsupported checkpoint")
    if state and state.resolve() in {p.resolve() for p in paths}:
        raise ValueError("checkpoint cannot replace an archive")
    results = []
    for path in paths:
        key = str(path.resolve())
        digest = _digest(path)
        previous = payload["records"].get(key)
        if previous and previous.get("sha256") == digest:
            value = previous["result"]
            result = Result(
                key,
                tuple(Page(**page) for page in value["pages"]),
                tuple(Finding(**finding) for finding in value["findings"]),
            )
        else:
            result = audit_archive(path)
            if _digest(path) != digest:
                raise ValueError(
                    "archive changed during audit; checkpoint not advanced"
                )
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
