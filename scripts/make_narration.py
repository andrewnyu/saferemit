#!/usr/bin/env python
"""Turn the narration in docs/VIDEO_SCRIPT.md into audio with ElevenLabs via OpenRouter.

The whole script is voiced as one take, because separate takes can sound like
different people. The audio is then transcribed with word timestamps and aligned
to the script, so narration.json records when each paragraph starts. Needs
OPENROUTER_API_KEY (in the environment or .env) and ffmpeg. Output goes to
var/video/, which is gitignored.

    python scripts/make_narration.py
    python scripts/make_narration.py --voice OPouXJLzlYeaXfgM6Q7O --model elevenlabs/eleven-v3-conversational
    python scripts/make_narration.py --retime    # keep the take, redo the speed and timings
    python scripts/make_narration.py --voices    # list the stock voices this model accepts
"""

from __future__ import annotations

import argparse
import base64
import difflib
import json
import re
import subprocess
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from loopremit.config import get_settings  # noqa: E402

SPEECH_URL = "https://openrouter.ai/api/v1/audio/speech"
TRANSCRIBE_URL = "https://openrouter.ai/api/v1/audio/transcriptions"
MODELS_URL = "https://openrouter.ai/api/v1/models?output_modalities=speech"
MODEL = "elevenlabs/eleven-multilingual-v2"
VOICE = "uB4mdw2feSGsIhOhlVRR"  # Carmela, a young Filipino voice from the ElevenLabs Voice Library
SEED = 42
TEMPO = 1.02  # keeps the video safely under three minutes without changing the pitch
MAX_CHARS = 5000
TAIL_SECONDS = 0.3  # how long the picture holds after the last word


def narration_paragraphs() -> list[str]:
    section = (ROOT / "docs" / "VIDEO_SCRIPT.md").read_text().split("## Narration", 1)[1]
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", section)]
    return [p for p in paragraphs if p and not p.startswith(">")]


def duration(path: Path) -> float:
    out = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(path)],
                         capture_output=True, text=True, check=True).stdout
    return float(out)


def transcribe_words(path: Path, key: str) -> list[dict]:
    response = httpx.post(TRANSCRIBE_URL, headers={"Authorization": f"Bearer {key}"}, timeout=600, json={
        "model": "openai/whisper-1", "response_format": "verbose_json", "timestamp_granularities": ["word"],
        "input_audio": {"data": base64.b64encode(path.read_bytes()).decode(), "format": "mp3"},
    })
    response.raise_for_status()
    return response.json()["words"]


def normalized(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower().replace("-", " "))


def timings(paragraphs: list[str], words: list[dict], total: float) -> list[dict]:
    """Find where each paragraph's first words fall in the transcript."""
    script = [(i, w) for i, paragraph in enumerate(paragraphs) for w in normalized(paragraph)]
    heard = [(j, n) for j, word in enumerate(words) for n in normalized(word["word"])]
    blocks = difflib.SequenceMatcher(None, [w for _, w in script], [n for _, n in heard], autojunk=False).get_matching_blocks()
    starts = [0.0]
    for i in range(1, len(paragraphs)):
        first = next(k for k, (p, _) in enumerate(script) if p == i)
        block = next(b for b in blocks if b.a + b.size > first and b.size >= 2)
        at = block.b + max(0, first - block.a)
        starts.append(float(words[heard[at][0]]["start"]))
    assert starts == sorted(starts), f"paragraphs out of order: {starts}"
    ends = [*starts[1:], total]
    return [{"start": round(s, 3), "seconds": round(e - s, 3), "text": paragraph}
            for s, e, paragraph in zip(starts, ends, paragraphs)]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--voice", default=VOICE)
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--voices", action="store_true")
    parser.add_argument("--retime", action="store_true", help="reuse the take already saved next to --out")
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
    text = "\n\n".join(paragraphs)
    print(f"{len(text)} characters, {len(paragraphs)} paragraphs, voice {args.voice}, model {args.model}")
    if len(text) > MAX_CHARS:
        print(f"The script is over the {MAX_CHARS}-character limit for one take.")
        return 2

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    take = out.with_suffix(".take.mp3")
    if not args.retime:
        response = httpx.post(SPEECH_URL, headers={"Authorization": f"Bearer {key}"}, timeout=600, json={
            "model": args.model, "input": text, "voice": args.voice, "response_format": "mp3",
            "provider": {"options": {"elevenlabs": {"seed": args.seed}}},
        })
        if response.status_code != 200:
            print(f"OpenRouter error {response.status_code}: {response.text[:400]}")
            return 1
        take.write_bytes(response.content)
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(take), "-af", f"atempo={TEMPO}",
                    "-c:a", "libmp3lame", "-b:a", "160k", str(out)], check=True)

    rows = timings(paragraphs, transcribe_words(out, key), duration(out))
    for row in rows:
        print(f"  {row['start']:7.2f}  {row['seconds']:6.2f}s  {row['text'][:50]}")
    out.with_suffix(".json").write_text(json.dumps(
        {"voice": args.voice, "model": args.model, "seed": args.seed, "tempo": TEMPO, "pause": TAIL_SECONDS, "paragraphs": rows},
        indent=1, ensure_ascii=False))
    print(f"wrote {out} ({duration(out):.2f}s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
