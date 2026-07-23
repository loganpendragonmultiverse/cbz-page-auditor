# CBZ Page Auditor

CBZ Page Auditor inspects ZIP/CBZ, 7Z/CB7, and RAR/CBR comic archives without rewriting them. It catches damaged images, duplicate pages, suspicious numbering, unusual dimensions, nearly blank pages, and likely double-page spreads before they become library surprises.

## Checks

- ZIP/CBZ, 7Z/CB7, and RAR/CBR integrity with conservative archive safety limits
- Decodability of every supported page image
- Exact duplicate page data
- Possible gaps in numeric page filenames
- Small pages and substantial dimension outliers
- Nearly black or white pages
- Wide pages that may be double-page spreads
- Unexpected non-image files and unsafe archive paths

## Install

Python 3.10 or newer is required. ZIP/CBZ and 7Z/CB7 work from the installed Python dependencies. RAR/CBR additionally requires one compatible local backend on `PATH`: UnRAR, 7-Zip, `unar`, or `bsdtar`.

```bash
python -m venv .venv
python -m pip install -e .
```

## Usage

```bash
cbz-audit "Batman 404.cbz"
cbz-audit "Incoming/Archive.cb7"
cbz-audit "Incoming/Archive.cbr"
cbz-audit "C:\Comics\Incoming" --format html --output audit.html
cbz-audit collection --format json --output audit.json --fail-on-warnings
```

Directories are scanned non-recursively for `.cbz`, `.zip`, `.cb7`, `.7z`, `.cbr`, and `.rar` files. Reports contain image dimensions and SHA-256 fingerprints, not extracted pages.

## Privacy and safety

Archives remain local and are opened read-only. The auditor does not contact metadata services or permanently retain extracted images. 7Z members are decoded inside an automatically deleted temporary directory; ZIP and RAR members are read through their archive libraries. Entry count and total uncompressed-size limits reduce exposure to archive bombs, but untrusted archives should still be handled cautiously.

## Limitations

- RAR/CBR decompression depends on an installed local backend because Python's RAR reader does not ship the proprietary decompressor.
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

**Feature complete for v1.1.** Bug reports and focused pull requests are welcome.

Released under the [MIT License](LICENSE).

## More open-source projects

This project is part of the [Logan Pendragon Forge open-source collection](https://www.loganpendragonforge.com/open-source/). Browse the catalog for other released tools, source repositories, live demos, and downloads.
