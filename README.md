# CBZ Page Auditor

CBZ Page Auditor inspects comic archives without extracting or rewriting them. It catches damaged images, duplicate pages, suspicious numbering, unusual dimensions, nearly blank pages, and likely double-page spreads before they become library surprises.

## Checks

- ZIP/CBZ integrity and conservative archive safety limits
- Decodability of every supported page image
- Exact duplicate page data
- Possible gaps in numeric page filenames
- Small pages and substantial dimension outliers
- Nearly black or white pages
- Wide pages that may be double-page spreads
- Unexpected non-image files and unsafe archive paths

## Install

Python 3.10 or newer is required.

```bash
python -m venv .venv
python -m pip install -e .
```

## Usage

```bash
cbz-audit "Batman 404.cbz"
cbz-audit "C:\Comics\Incoming" --format html --output audit.html
cbz-audit collection --format json --output audit.json --fail-on-warnings
```

Directories are scanned non-recursively for `.cbz` files. Reports contain image dimensions and SHA-256 fingerprints, not extracted pages.

## Privacy and safety

Archives remain local and are opened read-only. The auditor does not contact metadata services or permanently extract images. Entry count and total uncompressed-size limits reduce exposure to archive bombs, but untrusted archives should still be handled cautiously.

## Limitations

- CBR/RAR and 7z archives are not supported in v1.0.
- Duplicate detection is byte-exact; visually identical recompressed pages will not match.
- Blank-page and spread detection are useful review hints, not editorial conclusions.
- Filename gap detection works best with simple numeric page names.

## Development

```bash
python -m pip install -e . pytest build
python -m pytest
python -m build
```

## Project status

**Feature complete for v1.0.** Bug reports and focused pull requests are welcome.

Released under the [MIT License](LICENSE).
