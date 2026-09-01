"""
Just Osint - single-file Telegram Mini App starter
Public-source OSINT only.

Secrets are read from environment variables:
  ABUSEIPDB_API_KEY
  OTX_API_KEY
  THREATFOX_API_KEY
  TELEGRAM_BOT_TOKEN
  JWT_SECRET
  ADMIN_EMAIL

Run:
  pip install fastapi uvicorn[standard] sqlalchemy argon2-cffi python-jose[cryptography] httpx email-validator
  python just_osint.py
"""
import os, re, hmac, json, time, hashlib
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, quote_plus

import httpx
from argon2 import PasswordHasher
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr, Field
from jose import jwt, JWTError
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# ---------- configuration ----------
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME_IN_PRODUCTION")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY", "")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").lower().strip()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./just_osint.db")
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()
ph = PasswordHasher()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(500), nullable=False)
    nickname = Column(String(80), nullable=False)
    avatar_url = Column(String(1000), default="")
    telegram_id = Column(String(64), unique=True, nullable=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=True)
    action = Column(String(120), nullable=False)
    target = Column(String(500), default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

Base.metadata.create_all(engine)

app = FastAPI(title="Just Osint", version="2.0-single-file")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if CORS_ORIGINS == "*" else [x.strip() for x in CORS_ORIGINS.split(",")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def db():
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()

def public_user(u):
    return {
        "id": u.id, "email": u.email, "nickname": u.nickname,
        "avatar_url": u.avatar_url or "",
        "telegram_linked": bool(u.telegram_id),
        "is_admin": bool(u.is_admin),
    }

def make_token(u):
    payload = {
        "sub": str(u.id),
        "exp": datetime.now(timezone.utc) + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def current_user(auth: str | None, s: Session):
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(401, "Oturum gerekli.")
    try:
        payload = jwt.decode(auth[7:], JWT_SECRET, algorithms=["HS256"])
        uid = int(payload["sub"])
    except (JWTError, ValueError, KeyError):
        raise HTTPException(401, "GeÃ§ersiz oturum.")
    u = s.get(User, uid)
    if not u:
        raise HTTPException(401, "KullanÄ±cÄ± bulunamadÄ±.")
    return u

def audit(s, uid, action, target=""):
    s.add(AuditLog(user_id=uid, action=action, target=str(target)[:500]))
    s.commit()

class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    nickname: str = Field(min_length=2, max_length=80)

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class ProfileIn(BaseModel):
    nickname: str | None = Field(default=None, min_length=2, max_length=80)
    avatar_url: str | None = Field(default=None, max_length=1000)
    email: EmailStr | None = None
    password: str | None = Field(default=None, min_length=8, max_length=128)

class TelegramLinkIn(BaseModel):
    init_data: str

# ---------- auth ----------
@app.post("/api/auth/register")
def register(x: RegisterIn, s: Session = Depends(db)):
    email = str(x.email).lower().strip()
    if s.query(User).filter(User.email == email).first():
        raise HTTPException(409, "Bu e-posta zaten kayÄ±tlÄ±.")
    admin = bool(ADMIN_EMAIL and email == ADMIN_EMAIL)
    u = User(email=email, password_hash=ph.hash(x.password),
             nickname=x.nickname.strip(), is_admin=admin)
    s.add(u); s.commit(); s.refresh(u)
    audit(s, u.id, "register")
    return {"token": make_token(u), "user": public_user(u)}

@app.post("/api/auth/login")
def login(x: LoginIn, s: Session = Depends(db)):
    u = s.query(User).filter(User.email == str(x.email).lower().strip()).first()
    if not u:
        raise HTTPException(401, "E-posta veya Åifre hatalÄ±.")
    try:
        ph.verify(u.password_hash, x.password)
    except Exception:
        raise HTTPException(401, "E-posta veya Åifre hatalÄ±.")
    audit(s, u.id, "login")
    return {"token": make_token(u), "user": public_user(u)}

@app.get("/api/me")
def me(authorization: str | None = Header(None), s: Session = Depends(db)):
    return public_user(current_user(authorization, s))

@app.patch("/api/me")
def update_me(x: ProfileIn, authorization: str | None = Header(None), s: Session = Depends(db)):
    u = current_user(authorization, s)
    if x.nickname is not None: u.nickname = x.nickname.strip()
    if x.avatar_url is not None: u.avatar_url = x.avatar_url.strip()
    if x.email is not None:
        email = str(x.email).lower().strip()
        if s.query(User).filter(User.email == email, User.id != u.id).first():
            raise HTTPException(409, "Bu e-posta kullanÄ±mda.")
        u.email = email
    if x.password:
        u.password_hash = ph.hash(x.password)
    s.commit(); audit(s, u.id, "profile_update")
    return public_user(u)

# ---------- Telegram Mini App linking ----------
def validate_telegram_init_data(init_data: str):
    if not TELEGRAM_BOT_TOKEN:
        raise HTTPException(503, "TELEGRAM_BOT_TOKEN ayarlÄ± deÄil.")
    pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    received = pairs.pop("hash", None)
    if not received:
        raise HTTPException(400, "Telegram hash eksik.")
    try:
        auth_date = int(pairs.get("auth_date", "0"))
    except ValueError:
        raise HTTPException(400, "GeÃ§ersiz auth_date.")
    if time.time() - auth_date > 86400:
        raise HTTPException(400, "Telegram oturumu sÃ¼resi dolmuÅ.")
    check = "\n".join(f"{k}={pairs[k]}" for k in sorted(pairs))
    secret = hmac.new(b"WebAppData", TELEGRAM_BOT_TOKEN.encode(), hashlib.sha256).digest()
    calc = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calc, received):
        raise HTTPException(403, "Telegram doÄrulamasÄ± baÅarÄ±sÄ±z.")
    tg_user = json.loads(pairs.get("user", "{}"))
    if not tg_user.get("id"):
        raise HTTPException(400, "Telegram kullanÄ±cÄ± bilgisi yok.")
    return str(tg_user["id"]), tg_user

@app.post("/api/telegram/link")
def link_telegram(x: TelegramLinkIn, authorization: str | None = Header(None), s: Session = Depends(db)):
    u = current_user(authorization, s)
    tid, tg = validate_telegram_init_data(x.init_data)
    if s.query(User).filter(User.telegram_id == tid, User.id != u.id).first():
        raise HTTPException(409, "Bu Telegram hesabÄ± baÅka hesaba baÄlÄ±.")
    u.telegram_id = tid
    if not u.nickname or u.nickname == "Yeni KullanÄ±cÄ±":
        u.nickname = tg.get("username") or tg.get("first_name") or u.nickname
    s.commit(); audit(s, u.id, "telegram_link", tid)
    return public_user(u)

# ---------- OSINT helpers ----------
def clean_host(v: str):
    v = v.strip().lower()
    v = re.sub(r"^https?://", "", v).split("/")[0].split(":")[0]
    if not re.fullmatch(r"[a-z0-9.-]{1,253}", v):
        raise HTTPException(400, "GeÃ§ersiz domain/IP.")
    return v

async def get_json(url, params=None, headers=None):
    h = {"User-Agent": "JustOsint/2.0"}
    if headers: h.update(headers)
    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as c:
        r = await c.get(url, params=params, headers=h)
        r.raise_for_status()
        return r.json()

async def abuse_check(ip):
    if not ABUSEIPDB_API_KEY:
        return {"configured": False}
    try:
        d = await get_json(
            "https://api.abuseipdb.com/api/v2/check",
            {"ipAddress": ip, "maxAgeInDays": 90},
            {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
        )
        x = d.get("data", {})
        return {"configured": True, "data": {
            "ipAddress": x.get("ipAddress"),
            "abuseConfidenceScore": x.get("abuseConfidenceScore"),
            "countryCode": x.get("countryCode"),
            "usageType": x.get("usageType"),
            "isp": x.get("isp"),
            "domain": x.get("domain"),
            "hostnames": x.get("hostnames", []),
            "totalReports": x.get("totalReports"),
            "numDistinctUsers": x.get("numDistinctUsers"),
            "lastReportedAt": x.get("lastReportedAt"),
            "isWhitelisted": x.get("isWhitelisted"),
        }}
    except Exception as e:
        return {"configured": True, "error": str(e)}

async def otx_indicator(indicator_type, indicator):
    if not OTX_API_KEY:
        return {"configured": False}
    # OTX AlienVault pulse endpoint. Only public threat-intel metadata is returned.
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general"
        return {"configured": True, "data": await get_json(url, headers={"X-OTX-API-KEY": OTX_API_KEY})}
    except Exception as e:
        return {"configured": True, "error": str(e)}

async def threatfox_search(indicator):
    if not THREATFOX_API_KEY:
        return {"configured": False}
    try:
        payload = {"query": "search_ioc", "search_term": indicator}
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json=payload,
                headers={"Auth-Key": THREATFOX_API_KEY, "Content-Type": "application/json"},
            )
            if r.status_code >= 400:
                return {"configured": True, "error": f"HTTP {r.status_code}"}
            return {"configured": True, "data": r.json()}
    except Exception as e:
        return {"configured": True, "error": str(e)}

# ---------- OSINT ----------
@app.get("/api/osint/ip")
async def ip_osint(q: str):
    ip = clean_host(q)
    result = {"query": ip}
    try: result["rdap"] = await get_json(f"https://rdap.org/ip/{ip}")
    except Exception as e: result["rdap_error"] = str(e)
    result["abuseipdb"] = await abuse_check(ip)
    result["otx"] = await otx_indicator("IPv4" if "." in ip else "IPv6", ip)
    result["threatfox"] = await threatfox_search(ip)
    return result

@app.get("/api/osint/domain")
async def domain_osint(q: str):
    domain = clean_host(q)
    result = {"query": domain}
    try: result["rdap"] = await get_json(f"https://rdap.org/domain/{domain}")
    except Exception as e: result["rdap_error"] = str(e)
    try: result["dns"] = await get_json("https://cloudflare-dns.com/dns-query",
                                         {"name": domain, "type": "A"})
    except Exception as e: result["dns_error"] = str(e)
    result["otx"] = await otx_indicator("domain", domain)
    result["threatfox"] = await threatfox_search(domain)
    return result

@app.get("/api/osint/dns")
async def dns_osint(q: str):
    domain = clean_host(q)
    records = {}
    for typ in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        try:
            records[typ] = await get_json("https://cloudflare-dns.com/dns-query",
                                          {"name": domain, "type": typ})
        except Exception as e:
            records[typ] = {"error": str(e)}
    return {"query": domain, "records": records}

@app.get("/api/osint/certificates")
async def certificates(q: str):
    domain = clean_host(q)
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
                        headers={"User-Agent": "JustOsint/2.0"})
    if r.status_code >= 400:
        raise HTTPException(502, "crt.sh sorgusu baÅarÄ±sÄ±z.")
    names = sorted({n.strip().lower() for row in r.json()
                    for n in row.get("name_value", "").splitlines() if n.strip()})
    return {"query": domain, "count": len(names), "subdomains": names[:1000]}

@app.get("/api/osint/ioc")
async def ioc_osint(q: str):
    value = q.strip()
    if not value or len(value) > 300:
        raise HTTPException(400, "GeÃ§ersiz IOC.")
    return {
        "query": value,
        "otx": await otx_indicator("file" if re.fullmatch(r"[a-fA-F0-9]{32,64}", value) else "domain", value),
        "threatfox": await threatfox_search(value),
    }

@app.get("/api/osint/search-links")
def search_links(q: str, kind: str = "username"):
    value = q.strip()
    if not value or len(value) > 200:
        raise HTTPException(400, "GeÃ§ersiz sorgu.")
    e = quote_plus(value.lstrip("@"))
    if kind == "username":
        links = [
            ["Google", f'https://www.google.com/search?q="%s"' % e],
            ["Bing", f'https://www.bing.com/search?q="%s"' % e],
            ["GitHub", f"https://github.com/search?q={e}&type=users"],
            ["Reddit", f"https://www.reddit.com/search/?q={e}"],
            ["X", f"https://x.com/search?q={e}"],
        ]
    else:
        links = [
            ["Google", f'https://www.google.com/search?q="%s"' % e],
            ["Bing", f'https://www.bing.com/search?q="%s"' % e],
        ]
    return {"query": value, "links": links}

# ---------- admin ----------
def admin_required(auth, s):
    u = current_user(auth, s)
    if not u.is_admin:
        raise HTTPException(403, "Admin yetkisi gerekli.")
    return u

@app.get("/api/admin/users")
def admin_users(authorization: str | None = Header(None), s: Session = Depends(db)):
    admin_required(authorization, s)
    return [{
        "id": u.id, "email": u.email, "nickname": u.nickname,
        "is_admin": bool(u.is_admin), "telegram_linked": bool(u.telegram_id),
        "created_at": u.created_at.isoformat()
    } for u in s.query(User).order_by(User.id.desc()).all()]

@app.get("/api/admin/logs")
def admin_logs(authorization: str | None = Header(None), s: Session = Depends(db)):
    admin_required(authorization, s)
    return [{
        "id": x.id, "user_id": x.user_id, "action": x.action,
        "target": x.target, "created_at": x.created_at.isoformat()
    } for x in s.query(AuditLog).order_by(AuditLog.id.desc()).limit(300).all()]

# ---------- tiny built-in Mini App ----------
HTML = r"""<!doctype html>
<html lang="tr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#080b12"><title>Just Osint</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#080b12;color:#f5f7fb;font-family:system-ui,-apple-system,sans-serif}
.wrap{max-width:720px;margin:auto;padding:20px}.top{display:flex;align-items:center;justify-content:space-between;padding:10px 0 24px}
.logo{font-weight:900;letter-spacing:.08em}.logo span{color:#7b7fff}.card{background:#101621;border:1px solid #222d3e;border-radius:18px;padding:16px;margin:10px 0}
input,button{width:100%;padding:13px;border-radius:12px;border:1px solid #29354a;background:#0b111b;color:#fff;margin:5px 0}
button{background:#6d78ff;border:0;font-weight:800}.grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
pre{white-space:pre-wrap;word-break:break-word;max-height:55vh;overflow:auto;color:#c6d0e2}
small{color:#8995aa}h1{font-size:30px}
@media(max-width:500px){.grid{grid-template-columns:1fr}}
</style></head>
<body><div class="wrap">
<div class="top"><b class="logo">JUST <span>OSINT</span></b><small>PUBLIC SOURCE</small></div>
<div class="card"><h1>Just Osint</h1><small>Single-file Mini App API + UI. Public-source intelligence only.</small></div>
<div class="card"><input id="q" placeholder="IP / domain / IOC / username"><div class="grid">
<button onclick="run('ip')">IP OSINT</button><button onclick="run('domain')">DOMAIN</button>
<button onclick="run('dns')">DNS</button><button onclick="run('certificates')">CERTIFICATES</button>
<button onclick="run('ioc')">IOC</button><button onclick="run('search-links')">USERNAME</button>
</div><pre id="out">SonuÃ§lar burada gÃ¶rÃ¼necek.</pre></div>
</div>
<script>
async function run(kind){
 const q=document.getElementById('q').value.trim(), out=document.getElementById('out');
 if(!q){out.textContent='Bir sorgu gir.';return}
 out.textContent='SorgulanÄ±yor...';
 try{const r=await fetch('/api/osint/'+kind+'?q='+encodeURIComponent(q)+(kind==='search-links'?'&kind=username':''));const d=await r.json();out.textContent=JSON.stringify(d,null,2)}
 catch(e){out.textContent=e.toString()}
}
</script></body></html>"""

@app.get("/", response_class=HTMLResponse)
def home():
    return HTML

@app.get("/api/health")
def health():
    return {
        "ok": True,
        "service": "Just Osint",
        "integrations": {
            "abuseipdb": bool(ABUSEIPDB_API_KEY),
            "otx": bool(OTX_API_KEY),
            "threatfox": bool(THREATFOX_API_KEY),
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
