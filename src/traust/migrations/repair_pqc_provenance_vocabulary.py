#!/usr/bin/env python3
"""Map leaked governance-chain provenance terms onto the summary vocabulary
(2026-09-19).

`pqc-readiness.schema.json` `provenance_summary.dominant` is a SUMMARY
vocabulary. The per-fact hints that feed it come from the governance-chain
table, which uses an overlapping but different one:

    governance-chain flat_provenance   vendored, inherited-constrained,
                                       delegated-dependency, provider-census,
                                       adoption-signal, native-candidate,
                                       externalized
    readiness dominant                 inherited-platform,
                                       inherited-constrained,
                                       delegated-dependency,
                                       native-first-party, vendored,
                                       externalized,
                                       not-assessable-from-source, none

`dominant` is model-authored, and in 12 of 3,159 assessments (0.4%, all
dated 2026-07-21) the raw per-fact hint `native-candidate` was carried
through instead of being rolled up. Those 12 fail contract validation and
cannot be ingested at all, which showed up as a -12 delta against the
published dashboard's `not-applicable` bucket.

`native-candidate` and `native-first-party` denote the same thing at the two
levels -- crypto in the application's own code -- so this is a 1:1
vocabulary mapping, not a re-assessment. No score, bucket or flag is
touched.

Only terms with an unambiguous counterpart are mapped. `provider-census`
and `adoption-signal` have none and are reported rather than guessed.

    python3 -m traust.migrations.repair_pqc_provenance_vocabulary <root>
    python3 -m traust.migrations.repair_pqc_provenance_vocabulary <root> --write
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

#: Governance-chain term -> readiness summary term. Deliberately partial:
#: a term with no unambiguous counterpart must be adjudicated, not guessed.
VOCABULARY = {"native-candidate": "native-first-party"}

DECLARED = {
    "inherited-platform",
    "inherited-constrained",
    "delegated-dependency",
    "native-first-party",
    "vendored",
    "externalized",
    "not-assessable-from-source",
    "none",
}


def repair(document: dict) -> str | None:
    """Map one document's dominant term. Returns the change, or None."""
    summary = document.get("provenance_summary")
    if not isinstance(summary, dict):
        return None
    current = summary.get("dominant")
    if current in DECLARED or current is None:
        return None
    mapped = VOCABULARY.get(current)
    if mapped is None:
        return f"UNMAPPED:{current}"
    summary["dominant"] = mapped
    return f"{current}->{mapped}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--write", action="store_true", help="persist the repairs")
    args = parser.parse_args(argv)

    tally: Counter[str] = Counter()
    touched: list[tuple[Path, dict]] = []
    unmapped: Counter[str] = Counter()

    for path in sorted(args.root.rglob("*-pqc-readiness.json")):
        if "_manifest" in path.parts:
            continue  # retired duplicates are not live assessments
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            print(f"skip {path}: {error}", file=sys.stderr)
            continue
        change = repair(document)
        if change is None:
            continue
        if change.startswith("UNMAPPED:"):
            unmapped[change.removeprefix("UNMAPPED:")] += 1
            continue
        tally[change] += 1
        touched.append((path, document))

    print(f"provenance vocabulary: {len(touched)} assessment(s) to map")
    for change, count in tally.most_common():
        print(f"  {count:5}  {change}")
    if unmapped:
        print(
            f"\nNO UNAMBIGUOUS MAPPING for {dict(unmapped)} -- these need a "
            "decision, not a rename",
            file=sys.stderr,
        )

    if not args.write:
        print("\ndry run: nothing written. Re-run with --write.")
        return 0
    for path, document in touched:
        path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nwrote {len(touched)} assessment(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
