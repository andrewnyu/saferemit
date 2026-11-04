import time

import pytest

from loopremit.simulation import build_world, sign_plan

# A fixed "now" inside the sample bills' window: 2026-11-03 10:00 Asia/Manila.
DEMO_NOW = 1_793_671_200


@pytest.fixture
def clock():
    state = {"t": DEMO_NOW}

    def now():
        return state["t"]

    now.state = state
    return now


@pytest.fixture
def world(tmp_path, clock, monkeypatch):
    monkeypatch.setattr(time, "time", clock)  # db.now() and nonce TTLs follow the fake clock
    services, device = build_world(tmp_path, clock=clock)
    return services, device


@pytest.fixture
def planned(world):
    services, device = world
    sign_plan(services, device)
    return services, device
