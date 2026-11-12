# Linkforge

A URL shortener with real analytics, built with **FastAPI, Redis, MongoDB** and a hand-written HTML/CSS/JS front end.

## Run it

**Zero setup** (uses in-memory Redis and MongoDB stand-ins; data resets on restart):
```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```
Open http://localhost:8000. API docs are at /api/docs. Run tests with `pytest`.

**Real Redis + MongoDB** (persistent data): `docker compose up --build`

## What makes it different
| Feature | How it works |
|---|---|
| Unguessable codes, zero collisions | A Redis counter is passed through a bijective permutation (`n * prime mod 62^7`) and base62-encoded, so codes are not sequential and need no uniqueness check |
| Instant "is this name free?" | A Bloom filter answers most alias checks and rejects unknown short codes without touching Redis or MongoDB |
| Three-tier lookup | In-process LRU cache, then Redis, then MongoDB |
| Rate limiting | Sliding-window log on a Redis sorted set: 10 creations/min, 120 redirects/min per IP, 5 password tries/min |
| Unique visitors | Redis HyperLogLog (`PFADD` / `PFCOUNT`), about 12 KB per link regardless of traffic |
| Atomic click limits | Redis `INCR` decides if a visit is allowed, so concurrent clicks can't exceed the limit |
| Link controls | Custom alias, expiry, click limit, password (PBKDF2-hashed) |
| Ownership | Creator gets a secret token (stored as a SHA-256 hash). Only the token holder can view stats or delete |
| Safety | Rejects localhost and private IPs, non-http schemes and redirect loops |
| Analytics | Browser, OS, device, referrer, 24-hour and 7-day charts, live click feed, QR codes |

## Design decisions to talk about in interviews
- **302, not 301**, so browsers don't cache the redirect and every click is counted.
- **Analytics are written in a background task**, so the redirect itself stays fast.
- **Why Redis + MongoDB**: Redis for hot, atomic, expiring data (counters, cache, rate limits); MongoDB for durable documents and click events.
- **Known limits and next steps**: the in-process LRU is per worker (use Redis pub/sub to invalidate across workers), a Bloom filter can't delete entries (a false positive only costs one DB lookup), and per-click aggregation could move to MongoDB's aggregation pipeline or pre-aggregated counters at larger scale.

## Structure
```
app/core.py   base62, Bloom filter, LRU, rate limiter, storage setup
app/main.py   API routes, redirect logic, analytics
static/       single-page UI
tests/        pytest suite
```
