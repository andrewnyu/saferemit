"""Settings, read once from the environment (and an optional .env file)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Minimal .env reader: KEY=VALUE lines, # comments. Real env vars win."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    base_url: str
    paypal_mode: str  # "mock" | "sandbox"
    paypal_client_id: str
    paypal_client_secret: str
    intake_mode: str  # "auto" | "ai" | "offline"
    anthropic_api_key: str
    fx_offline: bool
    fx_fallback_rate: float
    gateway_audience: str = "loopremit-gateway"
    openrouter_api_key: str = ""
    openrouter_model: str = "anthropic/claude-opus-5.5"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "loopremit.db"

    @property
    def uploads_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def keys_dir(self) -> Path:
        return self.data_dir / "keys"

    @property
    def use_ai(self) -> bool:
        if self.intake_mode == "ai":
            return True
        if self.intake_mode == "offline":
            return False
        return bool(self.anthropic_api_key or self.openrouter_api_key)


@lru_cache
def get_settings() -> Settings:
    _load_dotenv(ROOT / ".env")
    data_dir = Path(os.environ.get("LOOPREMIT_DATA_DIR", "var"))
    if not data_dir.is_absolute():
        data_dir = ROOT / data_dir
    mode = os.environ.get("PAYPAL_MODE", "mock").lower()
    if mode not in ("mock", "sandbox"):
        raise ValueError("PAYPAL_MODE must be 'mock' or 'sandbox'")
    intake = os.environ.get("LOOPREMIT_INTAKE_MODE", "auto").lower()
    if intake not in ("auto", "ai", "offline"):
        raise ValueError("LOOPREMIT_INTAKE_MODE must be auto, ai or offline")
    return Settings(
        data_dir=data_dir,
        base_url=os.environ.get("LOOPREMIT_BASE_URL", "http://localhost:8000").rstrip("/"),
        paypal_mode=mode,
        paypal_client_id=os.environ.get("PAYPAL_CLIENT_ID", ""),
        paypal_client_secret=os.environ.get("PAYPAL_CLIENT_SECRET", ""),
        intake_mode=intake,
        anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
        fx_offline=os.environ.get("LOOPREMIT_FX_OFFLINE", "0") == "1",
        fx_fallback_rate=float(os.environ.get("LOOPREMIT_FX_FALLBACK_RATE", "58.50")),
        openrouter_api_key=os.environ.get("OPENROUTER_API_KEY", ""),
        openrouter_model=os.environ.get("LOOPREMIT_OPENROUTER_MODEL", "anthropic/claude-opus-5.5"),
    )
