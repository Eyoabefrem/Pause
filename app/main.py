import os
import time
from collections import defaultdict, deque
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()  # reads your .env file

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import heuristics, llm

app = FastAPI(title="Pause", version="1.0.0")
STATIC = Path(__file__).resolve().parent.parent / "static"
_hits: dict[str, deque] = defaultdict(deque)


class CheckIn(BaseModel):
    text: str = Field(min_length=5, max_length=4000)


def rate_limit(ip: str) -> None:
    """Simple per-IP limit so nobody can drain your free AI quota."""
    cap = int(os.getenv("RATE_LIMIT_PER_MIN", "10"))
    now = time.time()
    q = _hits[ip]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= cap:
        raise HTTPException(429, "Too many checks. Try again in a minute.")
    q.append(now)


@app.get("/health")
def health():
    provider = os.getenv("LLM_PROVIDER", "gemini")
    key_name = llm.PROVIDERS.get(provider, ("", None))[0]
    return {"ok": True, "provider": provider, "ai_key_found": bool(key_name and os.getenv(key_name))}


@app.post("/api/check")
def check(body: CheckIn, request: Request):
    rate_limit(request.client.host if request.client else "unknown")
    h = heuristics.analyze(body.text)
    ai = llm.explain(body.text, h)
    result = ai or llm.fallback(h)
    # Rules set a floor: the AI may escalate a verdict but never downgrade a high-risk one.
    if h["verdict"] == "likely_scam":
        result["verdict"] = "likely_scam"
    return {**result, "score": h["score"], "signals": h["signals"], "ai_used": ai is not None}


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")