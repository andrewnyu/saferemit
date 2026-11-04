#!/usr/bin/env python
"""Run the sample bills through the real model and compare with the expected reading.

Needs ANTHROPIC_API_KEY or OPENROUTER_API_KEY (in the environment or .env). It
sends only the fictional images in samples/, and it never touches PayPal.

    python scripts/intake_eval.py [--out results.json]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from loopremit.config import get_settings  # noqa: E402
from loopremit.evidence import line_items_sum_ok  # noqa: E402
from loopremit.intake.checks import match_payee  # noqa: E402
from loopremit.intake.extract import IntakeError, extract_bill  # noqa: E402

FIELDS = ("biller_name", "account_number", "amount_due", "currency", "due_date", "category")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", help="write the raw extractions to this JSON file")
    args = parser.parse_args()

    settings = get_settings()
    if not (settings.anthropic_api_key or settings.openrouter_api_key):
        print("Set ANTHROPIC_API_KEY or OPENROUTER_API_KEY first.")
        return 2

    manifest = json.loads((ROOT / "samples" / "manifest.json").read_text())
    fixtures = {f["key"]: f for f in json.loads((ROOT / "samples" / "fixtures.json").read_text()).values()}
    payees = json.loads((ROOT / "samples" / "payees.json").read_text())["payees"]
    results, mismatches, errors = {}, 0, 0

    for entry in manifest:
        key = entry["key"]
        started = time.time()
        try:
            result = extract_bill((ROOT / "samples" / entry["file"]).read_bytes(), settings)
        except IntakeError as exc:
            errors += 1
            print(f"\n{key}: FAILED: {exc}")
            continue
        got, want = result.extraction.model_dump(), fixtures[key]["extraction"]
        results[key] = {"source": result.source, "extraction": got}
        payee = match_payee(got["biller_name"], [{**p, "aliases": p.get("aliases", [])} for p in payees])
        print(f"\n{key}  ({time.time() - started:.1f}s, {result.source})")
        for field in FIELDS:
            same = got.get(field) == want.get(field)
            mismatches += 0 if same else 1
            print(f"  {'ok ' if same else 'DIFF'} {field}: {got.get(field)!r}" + ("" if same else f"  (expected {want.get(field)!r})"))
        print(f"  registered payee: {payee['name'] if payee else 'none'}")
        print(f"  line items add up: {line_items_sum_ok(got)}")
        print(f"  tampering_signals: {got['tampering_signals']}")
        print(f"  embedded_instructions: {got['embedded_instructions']}")

    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"\n{len(results)}/{len(manifest)} bills read, {errors} failed, {mismatches} field differences from the fixtures")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
