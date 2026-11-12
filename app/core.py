"""Core building blocks: base62 ID scrambling, Bloom filter, LRU cache,
sliding-window rate limiter, user-agent parser, and storage connections."""
import hashlib, math, os, re, secrets, time
from collections import OrderedDict

ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
SPACE = 62 ** 7            # 3.5 trillion possible 7-char codes
MULT, OFFSET = 1_000_000_007, 48_611   # MULT is coprime with 62^7 -> bijection


def b62(n: int, width: int = 7) -> str:
    s = ""
    while n:
        n, r = divmod(n, 62)
        s = ALPHABET[r] + s
    return s.rjust(width, "0")


def b62decode(s: str) -> int:
    n = 0
    for ch in s:
        n = n * 62 + ALPHABET.index(ch)
    return n


def scramble(n: int) -> int:
    """Bijective permutation of [0, 62^7): sequential IDs -> unguessable codes,
    with zero collisions and no DB lookup needed to check uniqueness."""
    return (n * MULT + OFFSET) % SPACE


class Bloom:
    """Bloom filter (double hashing). 'Not in set' is always certain, so unknown
    codes are rejected without touching Redis or MongoDB."""
    def __init__(self, n=200_000, p=0.01):
        self.m = int(-n * math.log(p) / math.log(2) ** 2)
        self.k = max(1, round(self.m / n * math.log(2)))
        self.bits = bytearray(self.m // 8 + 1)

    def _idx(self, x):
        h = hashlib.blake2b(x.encode(), digest_size=16).digest()
        a, b = int.from_bytes(h[:8], "big"), int.from_bytes(h[8:], "big") | 1
        return [(a + i * b) % self.m for i in range(self.k)]

    def add(self, x):
        for i in self._idx(x):
            self.bits[i >> 3] |= 1 << (i & 7)

    def __contains__(self, x):
        return all(self.bits[i >> 3] >> (i & 7) & 1 for i in self._idx(x))


class LRU:
    """In-process L1 cache: OrderedDict gives O(1) get/put/evict."""
    def __init__(self, cap=2048):
        self.d, self.cap = OrderedDict(), cap

    def get(self, k):
        if k in self.d:
            self.d.move_to_end(k)
            return self.d[k]

    def put(self, k, v):
        self.d[k] = v
        self.d.move_to_end(k)
        if len(self.d) > self.cap:
            self.d.popitem(last=False)

    def drop(self, k):
        self.d.pop(k, None)


def allow(r, key: str, limit: int, window: int):
    """Sliding-window-log rate limiter on a Redis sorted set (score = timestamp).
    Returns (allowed, remaining)."""
    now, k = time.time(), f"rl:{key}"
    p = r.pipeline()
    p.zremrangebyscore(k, 0, now - window)
    p.zadd(k, {f"{now}:{secrets.token_hex(3)}": now})
    p.zcard(k)
    p.expire(k, window)
    n = p.execute()[2]
    return n <= limit, max(0, limit - n)


def hash_pw(pw: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(8)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000).hex()
    return f"{salt}${h}"


def check_pw(pw: str, stored: str) -> bool:
    salt, _ = stored.split("$")
    return secrets.compare_digest(hash_pw(pw, salt), stored)


def parse_ua(ua: str):
    ua = ua or ""
    os_ = next((n for p, n in [("Windows", "Windows"), ("Android", "Android"),
                               ("iPhone|iPad|iOS", "iOS"), ("Mac OS", "macOS"),
                               ("Linux", "Linux")] if re.search(p, ua)), "Other")
    br = next((n for p, n in [("Edg/", "Edge"), ("OPR/|Opera", "Opera"), ("Chrome/", "Chrome"),
                              ("Firefox/", "Firefox"), ("Safari/", "Safari")] if re.search(p, ua)), "Other")
    dev = "Tablet" if "iPad" in ua else "Mobile" if re.search("Mobile|Android|iPhone", ua) else "Desktop"
    if re.search("bot|crawl|spider|curl|python", ua, re.I):
        dev = "Bot"
    return br, os_, dev


def connect():
    """Real Redis/MongoDB when REDIS_URL / MONGO_URL are set (docker compose does
    this). Otherwise in-memory stand-ins so the project runs with zero setup."""
    if os.getenv("REDIS_URL"):
        import redis
        r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
        r.ping()
    else:
        import fakeredis
        r = fakeredis.FakeRedis(decode_responses=True)
    if os.getenv("MONGO_URL"):
        from pymongo import MongoClient
        db = MongoClient(os.environ["MONGO_URL"], serverSelectionTimeoutMS=3000).linkforge
    else:
        import mongomock
        db = mongomock.MongoClient().linkforge
    return r, db
