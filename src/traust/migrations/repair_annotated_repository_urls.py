#!/usr/bin/env python3
"""Strip prose appended to a layer's repository URL (2026-09-20).

`layer.schema.json` types `metadata.repository` as `format: uri`. Ten
layers carry a valid URL with a parenthetical note glued on:

    https://github.com/red-hat-storage/odr-operator (downstream of RamenDR/ramen)
    https://github.com/openshift/image-based-install-operator (stolostron/... → 404, mirrored at openshift org)

Those layers fail validation outright, so storage/v1 never sees them or
their events. The note is real provenance but there is nowhere typed to
put it: metadata is `additionalProperties: false`, and `external_refs` is
a per-FINDING map to CVE/Bugzilla/Jira, not repo-level lineage. The URL
must be a URL, so the annotation comes out; both original strings are
recorded verbatim in the commit that applies this.

Distinct from `unknown://<name>`, which 245 layers use when the repo URL
was not known. Those are URI-valid, ingest fine, and are NOT touched --
they honestly say "unknown" rather than asserting a wrong URL.

    python3 -m traust.migrations.repair_annotated_repository_urls <root>
    python3 -m traust.migrations.repair_annotated_repository_urls <root> --write
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

#: A URL followed by a parenthetical note. Anchored on both ends so a URL
#: that legitimately contains parentheses is not truncated.
ANNOTATED = re.compile(r"^(https?://\S+?)\s+\((.*)\)\s*$")


def repair(document: dict) -> tuple[str, str, str] | None:
    """Strip the annotation. Returns (before, after, note), or None."""
    metadata = document.get("metadata") or {}
    value = metadata.get("repository")
    if not isinstance(value, str):
        return None
    match = ANNOTATED.match(value)
    if match is None:
        return None
    metadata["repository"] = match.group(1)
    return value, match.group(1), match.group(2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--write", action="store_true", help="persist the repairs")
    args = parser.parse_args(argv)

    touched: list[tuple[Path, dict]] = []
    notes: dict[str, str] = {}
    for path in sorted(args.root.rglob("*-findings-layer.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            print(f"skip {path}: {error}", file=sys.stderr)
            continue
        result = repair(document)
        if result is None:
            continue
        before, after, note = result
        notes[before] = note
        touched.append((path, document))

    print(f"annotated repository URLs: {len(touched)} layer(s)")
    for before, note in notes.items():
        print(f"  {before}")
        print(f"    -> {ANNOTATED.match(before).group(1)}")
        print(f"    note dropped: {note}")

    if not args.write:
        print("\ndry run: nothing written. Re-run with --write.")
        return 0
    for path, document in touched:
        path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nwrote {len(touched)} layer(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
