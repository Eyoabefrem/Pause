# Pause

**Check before you tap.** Paste a suspicious SMS, email or chat message and get a verdict, the warning signs, and what to do next. Built with mobile-money and banking scams in mind.

<!-- Add a screenshot or demo GIF here: ![Pause demo](docs/demo.gif) -->

## How it works

```
message --> rule engine --> risk score (0-100) + labeled signals
                |
                +--> AI explains the signals in plain language
                          |
        rules set a floor: the AI can raise a verdict, never lower a high-risk one
```

- **Explainable:** every point of the score maps to a visible signal (look-alike domains, shortened links, fake urgency, requests for money or codes).
- **Resilient:** if the AI provider fails, the app retries, switches to a backup provider, and finally falls back to a rule-based answer.
- **Provider-agnostic:** Gemini and Groq are supported. Switching is one line in `.env`, which avoids vendor lock-in.
- **Safe defaults:** input length limit, per-IP rate limiting, no message storage, escaped output.

## Tech stack

Python, FastAPI, vanilla JavaScript, Gemini / Groq APIs (free tiers), pytest, Docker.

## Run locally

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1        # Windows (PowerShell)
# source .venv/bin/activate       # Mac/Linux
pip install -r requirements.txt
copy .env.example .env            # Mac/Linux: cp .env.example .env
# edit .env and add your API key
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000. Run the tests with `python -m pytest -v`.

## Configuration

| Variable | Purpose |
|---|---|
| `LLM_PROVIDER` | `gemini` or `groq` (tried first) |
| `GEMINI_API_KEY`, `GROQ_API_KEY` | Free keys from Google AI Studio and Groq |
| `GEMINI_MODEL`, `GROQ_MODEL` | Override model names if a provider retires one |
| `RATE_LIMIT_PER_MIN` | Checks allowed per IP per minute (default 10) |

## Run with Docker

```bash
docker build -t pause .
docker run -p 8000:8000 --env-file .env pause
```

## API

`POST /api/check` with `{"text": "..."}` returns `verdict`, `summary`, `red_flags`, `next_steps`, `score`, `signals`, `ai_used`.

## Roadmap

- Screenshot input using a vision model
- Telegram bot front-end
- Community-reported scam number list
- Local-language keyword and brand packs (Amharic, Swahili)

## Disclaimer

Pause gives guidance, not proof. Always confirm through your bank or provider's official app or phone number.