"""Asks an AI model to explain the rule engine's findings in plain language.
Provider is chosen in .env, so switching Gemini <-> Groq needs no code change.
If one provider fails, the next one with a key is tried automatically."""
import json
import os
import time

import httpx

VERDICTS = {"likely_scam", "suspicious", "looks_ok"}

SYSTEM = """You are a scam-analysis assistant for everyday people, including mobile-money and banking users.
You receive a suspicious message plus signals found by an automated rule engine.
Reply with ONLY a JSON object, no markdown, in exactly this shape:
{"verdict": "likely_scam" | "suspicious" | "looks_ok",
 "summary": "at most 2 plain sentences",
 "red_flags": ["short, specific flags, max 5"],
 "next_steps": ["concrete actions, max 4"]}
Rules: never tell the user to click links. Do not claim certainty you lack. If the message looks
legitimate, say so, and still advise checking through the official app or phone number.
Reply in the same language as the message."""


def _prompt(text: str, h: dict) -> str:
    return (
        f"MESSAGE:\n{text[:4000]}\n\n"
        f"RULE ENGINE SIGNALS:\n{json.dumps(h['signals'])}\n"
        f"Rule score: {h['score']}/100"
    )


def _call_gemini(prompt: str) -> str:
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    resp = client.models.generate_content(
        model=os.getenv("GEMINI_MODEL", "gemini-3.8-flash"),
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM,
            response_mime_type="application/json",
        ),
    )
    return resp.text


def _call_groq(prompt: str) -> str:
    r = httpx.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {os.environ['GROQ_API_KEY']}"},
        json={
            "model": os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"),
            "messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
        },
        timeout=30,
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


# provider name -> (env variable holding its key, function that calls it)
PROVIDERS = {
    "gemini": ("GEMINI_API_KEY", _call_gemini),
    "groq": ("GROQ_API_KEY", _call_groq),
}


def _clean(raw: str, h: dict) -> dict:
    """Parse the model's JSON and make sure every field is safe to use."""
    data = json.loads(raw.replace("```json", "").replace("```", "").strip())
    if data.get("verdict") not in VERDICTS:
        data["verdict"] = h["verdict"]
    data["summary"] = str(data.get("summary", ""))
    data["red_flags"] = list(data.get("red_flags", []))[:5]
    data["next_steps"] = list(data.get("next_steps", []))[:4]
    return data


def explain(text: str, h: dict) -> dict | None:
    """Try the chosen provider (with one retry), then any other provider that has a key.
    Returns None only if every option fails."""
    first = os.getenv("LLM_PROVIDER", "gemini").lower()
    order = [first] + [p for p in PROVIDERS if p != first]
    prompt = _prompt(text, h)

    for provider in order:
        key_name, call = PROVIDERS.get(provider, (None, None))
        if not call or not os.getenv(key_name):
            continue  # no key for this provider, skip it
        for attempt in (1, 2):
            try:
                return _clean(call(prompt), h)
            except Exception as e:
                print(f"[llm] {provider} attempt {attempt} failed: {e}")
                if attempt == 1:
                    time.sleep(1.5)  # demand spikes are usually brief
    return None


def fallback(h: dict) -> dict:
    """Plain rule-based explanation, used when the AI is unavailable."""
    summaries = {
        "likely_scam": "This message has several strong scam signs.",
        "suspicious": "This message has some warning signs. Treat it with caution.",
        "looks_ok": "No strong scam signs found, but always verify through official channels.",
    }
    return {
        "verdict": h["verdict"],
        "summary": summaries[h["verdict"]],
        "red_flags": [s["label"] for s in h["signals"][:5]],
        "next_steps": [
            "Do not click any links or reply.",
            "Check directly in the official app or by calling the number on your card.",
            "Report and delete the message.",
        ],
    }