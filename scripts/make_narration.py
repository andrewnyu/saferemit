#!/usr/bin/env python
"""Turn the narration in docs/VIDEO_SCRIPT.md into audio with ElevenLabs via OpenRouter.

Needs OPENROUTER_API_KEY (in the environment or .env). Output goes to var/video/,
which is gitignored.

    python scripts/make_narration.py --voice george
    python scripts/make_narration.py --voices    # list the voices this model accepts
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from padala.config import get_settings  # noqa: E402

SPEECH_URL = "https://openrouter.ai/api/v1/audio/speech"
MODELS_URL = "https://openrouter.ai/api/v1/models?output_modalities=speech"
MODEL = "elevenlabs/eleven-v4"


def narration_text() -> str:
    section = (ROOT / "docs" / "VIDEO_SCRIPT.md").read_text().split("## Narration", 1)[1]
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", section)]
    return "\n\n".join(p for p in paragraphs if p and not p.startswith(">"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--voice", default="george")
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--voices", action="store_true")
    parser.add_argument("--out", default=str(ROOT / "var" / "video" / "narration.mp3"))
    args = parser.parse_args()

    if args.voices:
        models = httpx.get(MODELS_URL, timeout=30).json()["data"]
        print(next(m for m in models if m["id"] == args.model).get("supported_voices"))
        return 0

    key = (get_settings().openrouter_api_key or "").strip()
    if not key:
        print("Set OPENROUTER_API_KEY first.")
        return 2
    text = narration_text()
    print(f"{len(text)} characters, {len(text.split())} words, voice {args.voice}, model {args.model}")
    response = httpx.post(SPEECH_URL, headers={"Authorization": f"Bearer {key}"}, timeout=300,
                          json={"model": args.model, "input": text, "voice": args.voice, "response_format": "mp3"})
    if response.status_code != 200:
        print(f"OpenRouter error {response.status_code}: {response.text[:400]}")
        return 1
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(response.content)
    print(f"wrote {out} ({len(response.content):,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
