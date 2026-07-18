from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path

from .audit import Result, audit_archive


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cbz-audit", description="Audit CBZ comic pages without modifying the archive.")
    parser.add_argument("target", help="CBZ file or directory containing CBZ files")
    parser.add_argument("--format", choices=("text", "json", "html"), default="text")
    parser.add_argument("--output", type=Path, help="output file for one archive or output directory for a batch")
    parser.add_argument("--fail-on-warnings", action="store_true")
    args = parser.parse_args(argv)
    target = Path(args.target)
    archives = sorted(target.glob("*.cbz")) if target.is_dir() else [target]
    if not archives or any(not path.is_file() for path in archives):
        print("cbz-audit: no readable CBZ target found", file=sys.stderr)
        return 2
    results = [audit_archive(path) for path in archives]
    report = _render(results, args.format)
    if args.output:
        args.output.write_text(report, encoding="utf-8")
        print(f"Wrote {args.format} report to {args.output}")
    else:
        print(report)
    if any(result.status == "failed" for result in results):
        return 1
    if args.fail_on_warnings and any(result.status == "warning" for result in results):
        return 1
    return 0


def _render(results: list[Result], format_name: str) -> str:
    if format_name == "json":
        return json.dumps({"archives": [result.to_dict() for result in results]}, indent=2, ensure_ascii=False) + "\n"
    if format_name == "html":
        sections = []
        for result in results:
            rows = "".join(f"<tr><td>{html.escape(item.severity.upper())}</td><td>{html.escape(item.page or 'Archive')}</td><td>{html.escape(item.message)}</td></tr>" for item in result.findings) or '<tr><td>PASS</td><td>Archive</td><td>No audit findings.</td></tr>'
            sections.append(f"<section><h2>{html.escape(Path(result.archive).name)}</h2><p>{len(result.pages)} readable pages · {result.status}</p><table><tr><th>Status</th><th>Page</th><th>Finding</th></tr>{rows}</table></section>")
        return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>CBZ audit</title><style>body{font:16px/1.5 system-ui;background:#171311;color:#f5eee6;margin:0}main{max-width:1100px;margin:auto;padding:3rem 1rem}section{background:#241e1a;padding:1.5rem;margin:1rem 0;border-radius:16px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:.7rem;border-bottom:1px solid #4b3d34}th{color:#ffb36b}</style></head><body><main><h1>CBZ Page Audit</h1>" + "".join(sections) + "</main></body></html>"
    lines = []
    for result in results:
        lines.extend((Path(result.archive).name, f"{len(result.pages)} readable pages · {result.status.upper()}"))
        if result.findings:
            for item in result.findings:
                lines.append(f"  {item.severity.upper():7} {item.page or 'Archive'} — {item.message}")
        else:
            lines.append("  PASS    No audit findings.")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
