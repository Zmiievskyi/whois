#!/usr/bin/env python3
"""
Utility script to assemble an extended subdomain wordlist.

Features:
- Downloads curated subdomain lists from public sources
- Accepts local files (plain text, .gz) to merge into the list
- Deduplicates, normalises and optionally sorts output
- Writes back to src/provider_discovery/data/common_subdomains.txt by default

Example:
    python scripts/update_subdomain_wordlist.py \\
        --output src/provider_discovery/data/common_subdomains.txt \\
        --include-existing --sort
"""

from __future__ import annotations

import argparse
import gzip
import io
import logging
from pathlib import Path
from typing import Iterable, Iterator, List, Set

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("wordlist-updater")

# Curated default sources (moderate size to avoid huge downloads)
DEFAULT_REMOTE_SOURCES: List[str] = [
    # SecLists top 5k - most common subdomains
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
    # SecLists top 20k - extended coverage
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
    # SecLists Jhaddix DNS list - comprehensive collection
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt",
    # n0kovo subdomains (small) - high-quality SSL cert harvested list
    "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_small.txt",
    # SecLists combined subdomains - merged from multiple sources
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/combined_subdomains.txt",
    # Bug bounty programs subdomains - real-world tested
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/bug-bounty-program-subdomains-trickest-inventory.txt",
]

ALLOWED_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-.")


def load_remote_wordlist(url: str, timeout: int = 30) -> Iterator[str]:
    """Download a remote wordlist and yield individual entries."""
    logger.info("Downloading %s", url)
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()

    data = response.content
    if url.endswith(".gz"):
        data = gzip.decompress(data)
    elif url.endswith(".zip"):
        # Basic zip support: iterate through contained files
        import zipfile

        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for name in archive.namelist():
                if name.endswith("/"):
                    continue
                logger.debug("Reading %s from archive %s", name, url)
                with archive.open(name) as handle:
                    for line in io.TextIOWrapper(handle, encoding="utf-8", errors="ignore"):
                        yield line.rstrip("\n")
        return

    text_stream = io.TextIOWrapper(io.BytesIO(data), encoding="utf-8", errors="ignore")
    for line in text_stream:
        yield line.rstrip("\n")


def load_local_wordlist(path: Path) -> Iterator[str]:
    """Load entries from a local wordlist (supports .gz)."""
    logger.info("Reading local file %s", path)
    if not path.exists():
        logger.warning("Local wordlist %s does not exist; skipping", path)
        return iter(())

    if path.suffix == ".gz":
        with gzip.open(path, mode="rt", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                yield line.rstrip("\n")
    else:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                yield line.rstrip("\n")


def normalise_entry(entry: str) -> str | None:
    """Normalise entries: lowercase, strip dots, validate allowed characters."""
    candidate = entry.strip().lower()
    if not candidate:
        return None

    # Remove trailing domain if someone pasted full hostname (e.g., www.example.com)
    # We're interested in prefix part only for wordlist purposes.
    if "." in candidate:
        candidate = candidate.split(".")[0]

    # Strip wildcards
    candidate = candidate.lstrip("*")

    if not candidate or len(candidate) > 128:
        return None

    if not set(candidate).issubset(ALLOWED_CHARS):
        return None

    # Avoid entries that start with hyphen or dot
    if candidate[0] in "-.":
        candidate = candidate.lstrip("-.")

    # Avoid entries that are purely numeric (rarely useful)
    if candidate.isdigit():
        return None

    return candidate or None


def merge_wordlists(
    remote_sources: Iterable[str],
    local_sources: Iterable[Path],
    include_existing: bool,
    existing_path: Path,
) -> Set[str]:
    """Fetch/merge data from sources and return a set of unique prefixes."""
    unique_entries: Set[str] = set()

    def _consume(iterable: Iterable[str], label: str) -> None:
        count_before = len(unique_entries)
        for raw_entry in iterable:
            normalised = normalise_entry(raw_entry)
            if normalised:
                unique_entries.add(normalised)
        logger.info("Added %d entries from %s", len(unique_entries) - count_before, label)

    for url in remote_sources:
        try:
            _consume(load_remote_wordlist(url), url)
        except Exception as exc:
            logger.warning("Failed to load %s: %s", url, exc)

    for path in local_sources:
        _consume(load_local_wordlist(path), str(path))

    if include_existing and existing_path.exists():
        _consume(load_local_wordlist(existing_path), f"existing:{existing_path}")

    return unique_entries


def write_output(entries: Iterable[str], output_path: Path, sort_output: bool) -> None:
    """Write entries to output file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    items = sorted(entries) if sort_output else list(entries)

    with output_path.open("w", encoding="utf-8") as handle:
        handle.write("# Auto-generated subdomain prefix list\n")
        handle.write("# Last updated: generated by scripts/update_subdomain_wordlist.py\n")
        handle.write("# Total entries: {}\n".format(len(items)))
        handle.write("\n")
        for entry in items:
            handle.write(f"{entry}\n")

    logger.info("Wrote %d unique prefixes to %s", len(items), output_path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Assemble a consolidated subdomain wordlist.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("src/provider_discovery/data/common_subdomains.txt"),
        help="Destination file for the merged wordlist (default: %(default)s)",
    )
    parser.add_argument(
        "--source",
        dest="sources",
        action="append",
        default=[],
        help="Additional remote source URL (can be specified multiple times)",
    )
    parser.add_argument(
        "--local",
        dest="local_files",
        action="append",
        type=Path,
        default=[],
        help="Additional local wordlist file (plain text or .gz)",
    )
    parser.add_argument(
        "--include-existing",
        action="store_true",
        help="Include current content of the output file in the merge",
    )
    parser.add_argument(
        "--no-default-sources",
        action="store_true",
        help="Do not use the curated default remote sources",
    )
    parser.add_argument(
        "--sort",
        action="store_true",
        help="Sort the final wordlist alphabetically before writing",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Download and merge but do not write the output file",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    remote_sources: List[str] = []
    if not args.no_default_sources:
        remote_sources.extend(DEFAULT_REMOTE_SOURCES)
    if args.sources:
        remote_sources.extend(args.sources)

    # Deduplicate URLs while preserving order
    seen_urls = set()
    ordered_sources: List[str] = []
    for url in remote_sources:
        if url not in seen_urls:
            ordered_sources.append(url)
            seen_urls.add(url)

    logger.info("Using %d remote sources, %d local files", len(ordered_sources), len(args.local_files))

    entries = merge_wordlists(
        remote_sources=ordered_sources,
        local_sources=args.local_files,
        include_existing=args.include_existing,
        existing_path=args.output,
    )

    if args.dry_run:
        logger.info("Dry run: collected %d unique entries (no file written)", len(entries))
        return

    write_output(entries, args.output, sort_output=args.sort)


if __name__ == "__main__":
    main()
