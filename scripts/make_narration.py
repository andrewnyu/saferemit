#!/usr/bin/env python
"""Turn the narration in docs/VIDEO_SCRIPT.md into audio with ElevenLabs via OpenRouter.

Each paragraph is voiced separately and joined with a short pause, so
narration.json records exactly when each one starts. Needs OPENROUTER_API_KEY (in
the environment or .env) and ffmpeg. Output goes to var/video/, which is gitignored.

    python scripts/make_narration.py
    python scripts/make_narration.py --voice sarah
    python scripts/make_narration.py --voices    # list the voices this model accepts
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from loopremit.config import get_settings  # noqa: E402

SPEECH_URL = "https://openrouter.ai/api/v1/audio/speech"
MODELS_URL = "https://openrouter.ai/api/v1/models?output_modalities=speech"
MODEL = "elevenlabs/eleven-v3"
STYLE = "[strong Filipino accent]"
PAUSE_SECONDS = 0.6


def narration_paragraphs() -> list[str]:
    section = (ROOT / "docs" / "VIDEO_SCRIPT.md").read_text().split("## Narration", 1)[1]
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", section)]
    return [p for p in paragraphs if p and not p.startswith(">")]


def duration(path: Path) -> float:
    out = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(path)],
                         capture_output=True, text=True, check=True).stdout
    return float(out)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--voice", default="matilda")
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--style", default=STYLE, help="direction placed before each paragraph; not spoken")
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

    paragraphs = narration_paragraphs()
    print(f"{sum(map(len, paragraphs))} characters, {len(paragraphs)} paragraphs, voice {args.voice}, model {args.model}")
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        silence = work / "pause.wav"
        subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "anullsrc=r=44100:cl=mono",
                        "-t", str(PAUSE_SECONDS), str(silence)], check=True)
        parts, timings, clock = [], [], 0.0
        for i, paragraph in enumerate(paragraphs):
            text = f"{args.style} {paragraph}".strip()
            response = httpx.post(SPEECH_URL, headers={"Authorization": f"Bearer {key}"}, timeout=300,
                                  json={"model": args.model, "input": text, "voice": args.voice, "response_format": "mp3"})
            if response.status_code != 200:
                print(f"OpenRouter error {response.status_code}: {response.text[:400]}")
                return 1
            mp3 = work / f"{i:02d}.mp3"
            mp3.write_bytes(response.content)
            wav = work / f"{i:02d}.wav"
            subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(mp3), "-ar", "44100", "-ac", "1", str(wav)], check=True)
            seconds = duration(wav)
            timings.append({"start": round(clock, 3), "seconds": round(seconds, 3), "text": paragraph})
            print(f"  {clock:7.2f}  {seconds:6.2f}s  {paragraph[:50]}", flush=True)
            clock += seconds + PAUSE_SECONDS
            parts += [wav, silence]
        listing = work / "list.txt"
        listing.write_text("".join(f"file '{p}'\n" for p in parts[:-1]))
        subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "concat", "-safe", "0", "-i", str(listing),
                        "-c:a", "libmp3lame", "-b:a", "160k", str(out)], check=True)
    out.with_suffix(".json").write_text(json.dumps(
        {"voice": args.voice, "model": args.model, "style": args.style, "pause": PAUSE_SECONDS, "paragraphs": timings},
        indent=1, ensure_ascii=False))
    print(f"wrote {out} ({duration(out):.2f}s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
