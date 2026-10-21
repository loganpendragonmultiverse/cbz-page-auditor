from __future__ import annotations

import argparse
import html
import json
import os
import stat
import sys
from pathlib import Path

from . import __version__
from .audit import ARCHIVE_EXTENSIONS, Result
from .batch import audit_batch, doctor, thumbnails


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cbz-audit",
        description="Audit ZIP, 7Z, and RAR comic archives without modifying them.",
    )
    parser.add_argument(
        "target", nargs="?", help="comic archive or directory containing comic archives"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--doctor", action="store_true")
    parser.add_argument("--state", type=Path, help="Per-archive checkpoint JSON")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--max-pages",
        "--max-entries",
        dest="max_pages",
        type=int,
        default=10_000,
        help="maximum archive records, including directories and metadata",
    )
    parser.add_argument("--max-uncompressed-mb", type=int, default=2_000)
    parser.add_argument("--format", choices=("text", "json", "html"), default="text")
    parser.add_argument(
        "--output",
        type=Path,
        help="new report file for one archive or a batch",
    )
    parser.add_argument("--fail-on-warnings", action="store_true")
    args = parser.parse_args(argv)
    if args.doctor:
        print(json.dumps(doctor(), indent=2))
        return 0
    if not args.target:
        parser.error("provide an archive/directory or --doctor")
    try:
        target = Path(args.target)
        if stat.S_ISDIR(target.stat().st_mode):
            archives = []
            for path in sorted(target.iterdir()):
                if path.suffix.casefold() in ARCHIVE_EXTENSIONS:
                    if not stat.S_ISREG(path.stat().st_mode):
                        raise ValueError(f"not a regular archive: {path}")
                    archives.append(path)
        else:
            archives = [target]
        if not archives:
            raise ValueError("no supported comic archive target found")
        if args.output and (
            os.path.lexists(args.output)
            or args.state
            and args.output.resolve() == args.state.resolve()
        ):
            raise ValueError("report must be a new file distinct from the checkpoint")
        results = audit_batch(
            archives,
            args.state,
            resume=args.resume,
            max_pages=args.max_pages,
            max_uncompressed_mb=args.max_uncompressed_mb,
        )
        report = _render(
            results,
            args.format,
            max_pages=args.max_pages,
            max_uncompressed_mb=args.max_uncompressed_mb,
        )
        if args.output:
            with args.output.open("x", encoding="utf-8") as handle:
                handle.write(report)
            print(f"Wrote {args.format} report to {args.output}")
        else:
            print(report)
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
        print(f"cbz-audit: {exc}", file=sys.stderr)
        return 2
    if any(result.status == "failed" for result in results):
        return 1
    if args.fail_on_warnings and any(result.status == "warning" for result in results):
        return 1
    return 0


def _render(
    results: list[Result],
    format_name: str,
    *,
    max_pages: int = 10_000,
    max_uncompressed_mb: int = 2_000,
) -> str:
    if format_name == "json":
        return (
            json.dumps(
                {"archives": [result.to_dict() for result in results]},
                indent=2,
                ensure_ascii=False,
            )
            + "\n"
        )
    if format_name == "html":
        sections: list[str] = []
        for result in results:
            previews = thumbnails(
                result, max_pages=max_pages, max_uncompressed_mb=max_uncompressed_mb
            )
            prefix = f"archive-{len(sections)}"
            anchors = {
                page.name: f"{prefix}-page-{index}" for index, page in enumerate(result.pages)
            }
            rows = (
                "".join(
                    f"<tr><td>{html.escape(item.severity.upper())}</td><td>{html.escape(item.page or 'Archive')}</td><td>{html.escape(item.message)}</td></tr>"
                    for item in result.findings
                )
                or "<tr><td>PASS</td><td>Archive</td><td>No audit findings.</td></tr>"
            )
            gallery = []
            navigation = []
            for page in result.pages:
                findings = [f for f in result.findings if f.page == page.name]
                if findings and page.name in previews:
                    navigation.append(
                        f'<a href="#{anchors[page.name]}">{html.escape(page.name)}</a>'
                    )
                if page.name in previews:
                    labels = "; ".join(f.rule for f in findings) or "No page-level finding"
                    gallery.append(
                        f'<figure id="{anchors[page.name]}"><div class="preview"><img alt="Local page preview" src="data:image/jpeg;base64,{previews[page.name]}"><span>{html.escape(labels)}</span></div><figcaption>{html.escape(page.name)}</figcaption></figure>'
                    )
            sections.append(
                f"<section><h2>{html.escape(Path(result.archive).name)}</h2><p>{len(result.pages)} readable pages · {result.status}</p><p>Finding navigation: {' · '.join(navigation)}</p><table><tr><th>Status</th><th>Page</th><th>Finding</th></tr>{rows}</table><p>Contact sheet: {len(previews)} of {len(result.pages)} pages (maximum 200 previews). Overlays label whole-page findings; they do not claim pixel-level localization.</p><div class=gallery>{''.join(gallery)}</div></section>"
            )
        return (
            '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CBZ audit</title><style>body{font:16px/1.5 system-ui;background:#171311;color:#f5eee6;margin:0}main{overflow-wrap:anywhere;max-width:1100px;margin:auto;padding:3rem 1rem}section{background:#241e1a;padding:1.5rem;margin:1rem 0;border-radius:16px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:.7rem;border-bottom:1px solid #4b3d34}th,a{color:#ffb36b}td{overflow-wrap:anywhere}table{table-layout:fixed}.gallery{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,230px),1fr));gap:15px}figure{margin:10px 0;overflow-wrap:anywhere}.preview{position:relative}.preview img{width:100%;display:block}.preview span{position:absolute;bottom:0;left:0;right:0;padding:8px;background:#300d;color:white;font-size:14px}</style></head><body><main><h1>CBZ Page Audit</h1>'
            + "".join(sections)
            + "</main></body></html>"
        )
    lines: list[str] = []
    for result in results:
        lines.extend(
            (
                Path(result.archive).name,
                f"{len(result.pages)} readable pages · {result.status.upper()}",
            )
        )
        if result.findings:
            for item in result.findings:
                lines.append(
                    f"  {item.severity.upper():7} {item.page or 'Archive'} — {item.message}"
                )
        else:
            lines.append("  PASS    No audit findings.")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
