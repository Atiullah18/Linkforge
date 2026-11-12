import hashlib, hmac, io, ipaddress, json, os, re, secrets, time
from collections import Counter
from html import escape
from urllib.parse import urlparse

import segno
from fastapi import BackgroundTasks, FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from pymongo.errors import DuplicateKeyError

from .core import LRU, Bloom, allow, b62, check_pw, connect, hash_pw, parse_ua, scramble

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app = FastAPI(title="Linkforge", docs_url="/api/docs", openapi_url="/api/openapi.json")
app.mount("/static", StaticFiles(directory=os.path.join(ROOT, "static")), name="static")

r, db = connect()
links, clicks = db.links, db.clicks
links.create_index("code", unique=True)
clicks.create_index("code")
bloom, L1 = Bloom(), LRU()
for d in links.find({}, {"code": 1}):
    bloom.add(d["code"])

RESERVED = {"api", "static", "docs", "unlock", "favicon.ico", "robots.txt"}


# ---------- helpers ----------
def ip_of(req: Request) -> str:
    return (req.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (req.client.host if req.client else "0.0.0.0"))


def base(req: Request) -> str:
    return os.getenv("BASE_URL", str(req.base_url)).rstrip("/")


def clean_url(raw: str, own_host: str | None) -> str:
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    u = urlparse(raw)
    host = (u.hostname or "").lower()
    if u.scheme not in ("http", "https") or not host or len(raw) > 2048:
        raise HTTPException(422, "Enter a valid http or https link.")
    if host == own_host:
        raise HTTPException(422, "That link already points to Linkforge.")
    try:
        ip = ipaddress.ip_address(host)
        bad = ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        bad = host == "localhost" or host.endswith(".local") or "." not in host
    if bad:
        raise HTTPException(422, "Private or local addresses can't be shortened.")
    return raw


def page(status: int, title: str, msg: str, body: str = "") -> HTMLResponse:
    html = f"""<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>{escape(title)}</title><body style="margin:0;min-height:100vh;display:grid;place-items:center;background:#EEEAFF;
font:16px/1.5 system-ui,sans-serif;color:#15123B"><main style="background:#fff;padding:36px;border-radius:22px;max-width:420px;margin:20px">
<h1 style="margin:0 0 8px;font-size:28px">{escape(title)}</h1><p style="color:#6B678F;margin:0 0 20px">{escape(msg)}</p>{body}
<p><a href="/" style="color:#FF5A87;font-weight:600">Make your own short link</a></p></main>"""
    return HTMLResponse(html, status_code=status)


def resolve(code: str):
    """3-tier lookup: in-process LRU -> Redis -> MongoDB."""
    d = L1.get(code)
    if d:
        return d
    raw = r.get("link:" + code)
    if raw:
        d = json.loads(raw)
    else:
        d = links.find_one({"code": code}, {"_id": 0})
        if not d:
            return None
        r.setnx("hits:" + code, d.get("clicks", 0))
        r.set("link:" + code, json.dumps(d), ex=3600)
    L1.put(code, d)
    return d


def summary(d, req=None):
    hits = int(r.get("hits:" + d["code"]) or d.get("clicks", 0))
    return {"code": d["code"], "url": d["url"], "created": d["created"], "clicks": hits,
            "expires_at": d.get("expires_at"), "max_clicks": d.get("max_clicks"),
            "protected": bool(d.get("pw")), "short": f"{base(req)}/{d['code']}" if req else None}


def owned(d, token):
    if not d or not token or not hmac.compare_digest(
            hashlib.sha256(token.encode()).hexdigest(), d["owner"]):
        raise HTTPException(404, "Link not found.")


def record(code, ua, ref, ip):
    br, os_, dev = parse_ua(ua)
    host = urlparse(ref).hostname if ref else None
    ev = {"code": code, "ts": time.time(), "browser": br, "os": os_, "device": dev,
          "referrer": host or "Direct"}
    clicks.insert_one(dict(ev))
    links.update_one({"code": code}, {"$inc": {"clicks": 1}})
    r.pfadd("uv:" + code, hashlib.sha256(f"{ip}{ua}".encode()).hexdigest())  # HyperLogLog
    r.incr("total_clicks")
    r.lpush("feed", json.dumps({"c": code[:2] + "•••", "d": dev, "b": br, "t": ev["ts"]}))
    r.ltrim("feed", 0, 19)


def visit(d, req, bg):
    code = d["code"]
    n = r.incr("hits:" + code)
    if d.get("max_clicks") and n > d["max_clicks"]:
        r.decr("hits:" + code)
        return page(410, "This link has reached its limit", "It was set to stop after a fixed number of visits.")
    bg.add_task(record, code, req.headers.get("user-agent", ""), req.headers.get("referer"), ip_of(req))
    return RedirectResponse(d["url"], 302, headers={"Cache-Control": "no-store"})


# ---------- API ----------
class NewLink(BaseModel):
    url: str
    alias: str | None = None
    expires_in: int | None = Field(None, ge=1, le=525_600, description="minutes")
    max_clicks: int | None = Field(None, ge=1, le=10_000_000)
    password: str | None = Field(None, max_length=64)


@app.post("/api/links")
def create(body: NewLink, req: Request):
    ok, _ = allow(r, "c:" + ip_of(req), 10, 60)
    if not ok:
        raise HTTPException(429, "Too many links created. Wait a minute and try again.")
    url = clean_url(body.url, req.url.hostname)
    token = secrets.token_urlsafe(18)
    doc = {"url": url, "created": time.time(), "clicks": 0, "max_clicks": body.max_clicks,
           "expires_at": time.time() + body.expires_in * 60 if body.expires_in else None,
           "pw": hash_pw(body.password) if body.password else None,
           "owner": hashlib.sha256(token.encode()).hexdigest()}
    if body.alias:
        a = body.alias.strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{3,32}", a) or a.lower() in RESERVED:
            raise HTTPException(422, "Aliases use 3 to 32 letters, numbers, - or _.")
        doc["code"] = a
        try:
            links.insert_one(dict(doc))
        except DuplicateKeyError:
            raise HTTPException(409, "That alias is taken. Try another.")
    else:
        while True:  # scrambled counter is collision-free; loop only guards custom-alias clashes
            doc["code"] = b62(scramble(r.incr("seq") + 10 ** 9))
            try:
                links.insert_one(dict(doc))
                break
            except DuplicateKeyError:
                continue
    bloom.add(doc["code"])
    return {**summary(doc, req), "token": token}


@app.get("/api/available/{alias}")
def available(alias: str):
    if alias.lower() in RESERVED:
        return {"available": False, "via": "reserved"}
    if alias not in bloom:   # certain: never seen
        return {"available": True, "via": "bloom"}
    return {"available": links.find_one({"code": alias}) is None, "via": "db"}


class Item(BaseModel):
    code: str
    token: str


@app.post("/api/links/batch")
def batch(items: list[Item], req: Request):
    out = []
    for it in items[:50]:
        d = resolve(it.code) if it.code in bloom else None
        try:
            owned(d, it.token)
            out.append(summary(d, req))
        except HTTPException:
            out.append({"code": it.code, "gone": True})
    return out


@app.get("/api/links/{code}/stats")
def stats(code: str, req: Request, x_owner_token: str | None = Header(None)):
    d = resolve(code) if code in bloom else None
    owned(d, x_owner_token)
    rows = list(clicks.find({"code": code}, {"_id": 0}))
    now = time.time()
    hourly, daily = [0] * 24, [0] * 7
    for c in rows:
        age = now - c["ts"]
        if age < 86400:
            hourly[23 - int(age // 3600)] += 1
        if age < 7 * 86400:
            daily[6 - int(age // 86400)] += 1
    top = lambda k: Counter(c[k] for c in rows).most_common(5)
    return {**summary(d, req), "unique": r.pfcount("uv:" + code), "hourly": hourly, "daily": daily,
            "browsers": top("browser"), "os": top("os"), "devices": top("device"),
            "referrers": top("referrer")}


@app.delete("/api/links/{code}")
def delete(code: str, x_owner_token: str | None = Header(None)):
    owned(resolve(code) if code in bloom else None, x_owner_token)
    links.delete_one({"code": code})
    clicks.delete_many({"code": code})
    r.delete("link:" + code, "hits:" + code, "uv:" + code)
    L1.drop(code)
    return {"deleted": code}


@app.get("/api/qr/{code}.svg")
def qr(code: str, req: Request):
    if code not in bloom:
        raise HTTPException(404, "Link not found.")
    buf = io.BytesIO()
    segno.make(f"{base(req)}/{code}", error="m").save(buf, kind="svg", scale=8, border=1, dark="#15123B")
    return Response(buf.getvalue(), media_type="image/svg+xml")


@app.get("/api/feed")
def feed():
    return {"events": [json.loads(x) for x in r.lrange("feed", 0, 7)],
            "links": int(r.get("seq") or 0), "clicks": int(r.get("total_clicks") or 0)}


@app.get("/api/health")
def health():
    return {"ok": r.ping(), "bloom_bits": bloom.m, "bloom_hashes": bloom.k, "lru_size": len(L1.d)}


# ---------- pages & redirects ----------
@app.get("/")
def index():
    return FileResponse(os.path.join(ROOT, "static", "index.html"))


@app.get("/{code}")
def go(code: str, req: Request, bg: BackgroundTasks):
    if code not in bloom:
        return page(404, "Link not found", "Check the address for typos.")
    ok, _ = allow(r, "g:" + ip_of(req), 120, 60)
    if not ok:
        return page(429, "Slow down", "Too many requests from your network. Try again in a minute.")
    d = resolve(code)
    if not d:
        return page(404, "Link not found", "This link was deleted.")
    if d.get("expires_at") and time.time() > d["expires_at"]:
        return page(410, "This link has expired", "Ask the sender for a fresh one.")
    if d.get("pw"):
        form = (f'<form method=post action="/unlock/{escape(code)}"><input name=password type=password required '
                'placeholder="Password" style="width:100%;padding:12px;border:1px solid #DAD4F5;border-radius:10px;'
                'font:inherit;margin-bottom:10px;box-sizing:border-box"><button style="width:100%;padding:12px;border:0;'
                'border-radius:10px;background:#FF5A87;color:#fff;font:inherit;font-weight:600">Open link</button></form>')
        return page(200, "This link is protected", "Enter the password to continue.", form)
    return visit(d, req, bg)


@app.post("/unlock/{code}")
def unlock(code: str, req: Request, bg: BackgroundTasks, password: str = Form(...)):
    ok, _ = allow(r, f"u:{ip_of(req)}:{code}", 5, 60)   # brute-force guard
    if not ok:
        return page(429, "Too many attempts", "Wait a minute before trying again.")
    d = resolve(code) if code in bloom else None
    if not d or not d.get("pw"):
        return page(404, "Link not found", "Check the address for typos.")
    if not check_pw(password, d["pw"]):
        return page(401, "Wrong password", "Go back and try again.")
    return visit(d, req, bg)
