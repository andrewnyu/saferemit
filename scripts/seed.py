"""Seed the payee registry and bill history; optionally pre-fill a whole demo.

    python scripts/seed.py               # payees + history only (the app also does this on first start)
    python scripts/seed.py --demo-data   # also sign a plan and run every sample bill through the gateway
    python scripts/seed.py --reset       # wipe demo state first

`--demo-data` signs the plan with a *software* stand-in for the OFW's device
key (labelled as such), so it needs no browser. To sign with a real WebCrypto
key, skip it and use /ofw/onboarding and /ofw/plan instead.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from loopremit.config import get_settings  # noqa: E402
from loopremit.services import Services, seed_registry  # noqa: E402
from loopremit.simulation import SoftwareDevice, sign_plan, submit_sample  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--demo-data", action="store_true", help="sign a plan and submit the sample bills")
    parser.add_argument("--reset", action="store_true", help="wipe demo state first")
    args = parser.parse_args()

    services = Services(get_settings())
    if args.reset:
        services.reset_demo()
    seed_registry(services)
    print(f"database: {services.settings.db_path}")
    print(f"payees:   {', '.join(p['name'] for p in services.payees())}")

    if args.demo_data:
        device = SoftwareDevice()
        services.register_device_key(device.jwk, "seed script software key (simulated, not a browser key)")
        if not services.vault():
            services.start_vault()
            services.complete_vault()
        sign_plan(services, device)
        for key, who in [("tuition", "Mama Rosario"), ("liwanag-power", "Mama Rosario"),
                         ("hospital-doctored", "Cousin Jun"), ("prompt-injection", "Mama Rosario"),
                         ("casa-maria-rent", "Mama Rosario")]:
            bill_id = submit_sample(services, key, by=who)
            row = services.db.one("SELECT status, status_detail FROM bills WHERE id = ?", bill_id)
            print(f"bill #{bill_id:<3} {key:<18} {row['status']:<14} {row['status_detail'] or ''}")
        approval = services.db.one("SELECT * FROM approvals WHERE kind = 'step_up' AND status = 'pending'")
        if approval:
            result = services.agent.approve_step_up(
                approval["id"], device.decide(json.loads(approval["payload"]), "approve", bill_id=approval["bill_id"]))
            print(f"step-up approved with the software key -> {result.outcome}")


if __name__ == "__main__":
    main()
