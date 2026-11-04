import importlib.util
import sys
from pathlib import Path


def test_every_redteam_attack_is_blocked_at_the_expected_step():
    path = Path(__file__).resolve().parent.parent / "scripts" / "redteam.py"
    spec = importlib.util.spec_from_file_location("redteam", path)
    redteam = importlib.util.module_from_spec(spec)
    sys.modules["redteam"] = redteam  # dataclasses need the module registered
    spec.loader.exec_module(redteam)
    rows = redteam.run_all(verbose=False)
    assert rows and all(r["ok"] for r in rows), [r for r in rows if not r["ok"]]
