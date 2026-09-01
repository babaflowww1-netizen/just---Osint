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
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", '648548fa90ea301c211976ee932e279e0cb333a52f3b34807fed02e81e2d618a3aa9102c885c6a0a')
OTX_API_KEY = os.getenv("OTX_API_KEY", '3a3c0efbaa8c2161ffb67ae8d651aeaa4e616bc61dd1d4b67fc45b9f68953987')
THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY", '02e93be86796a78a5b9f7b28c61c3ed18404d136c48d2e38')
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "justosint.admin@gmail.com").lower().strip()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "JOsint!Admin#2026_91")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./just_osint.db")
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", 'c17feaba2e2b5a21ea2c0935fa381c7338dbf0de37d53c76')
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", '3d5beb08fe415213d61d1396570c745dc64c53250d4e17327b5867896f581fa6')
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
        raise HTTPException(401, "E-posta veya ÃÂifre hatalÄ±.")
    try:
        ph.verify(u.password_hash, x.password)
    except Exception:
        raise HTTPException(401, "E-posta veya ÃÂifre hatalÄ±.")
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
        raise HTTPException(503, "TELEGRAM_BOT_TOKEN ayarlÄ± deÃÂil.")
    pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    received = pairs.pop("hash", None)
    if not received:
        raise HTTPException(400, "Telegram hash eksik.")
    try:
        auth_date = int(pairs.get("auth_date", "0"))
    except ValueError:
        raise HTTPException(400, "GeÃ§ersiz auth_date.")
    if time.time() - auth_date > 86400:
        raise HTTPException(400, "Telegram oturumu sÃ¼resi dolmuÃÂ.")
    check = "\n".join(f"{k}={pairs[k]}" for k in sorted(pairs))
    secret = hmac.new(b"WebAppData", TELEGRAM_BOT_TOKEN.encode(), hashlib.sha256).digest()
    calc = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calc, received):
        raise HTTPException(403, "Telegram doÃÂrulamasÄ± baÃÂarÄ±sÄ±z.")
    tg_user = json.loads(pairs.get("user", "{}"))
    if not tg_user.get("id"):
        raise HTTPException(400, "Telegram kullanÄ±cÄ± bilgisi yok.")
    return str(tg_user["id"]), tg_user

@app.post("/api/telegram/link")
def link_telegram(x: TelegramLinkIn, authorization: str | None = Header(None), s: Session = Depends(db)):
    u = current_user(authorization, s)
    tid, tg = validate_telegram_init_data(x.init_data)
    if s.query(User).filter(User.telegram_id == tid, User.id != u.id).first():
        raise HTTPException(409, "Bu Telegram hesabÄ± baÃÂka hesaba baÃÂlÄ±.")
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
        raise HTTPException(502, "crt.sh sorgusu baÃÂarÄ±sÄ±z.")
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


# ---------- VirusTotal / URLhaus ----------
async def virustotal_ip(ip):
    if not VIRUSTOTAL_API_KEY:
        return {"configured": False}
    try:
        return {"configured": True, "data": await get_json(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY}
        )}
    except Exception as e:
        return {"configured": True, "error": str(e)}

async def virustotal_domain(domain):
    if not VIRUSTOTAL_API_KEY:
        return {"configured": False}
    try:
        return {"configured": True, "data": await get_json(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY}
        )}
    except Exception as e:
        return {"configured": True, "error": str(e)}

async def virustotal_hash(value):
    if not VIRUSTOTAL_API_KEY:
        return {"configured": False}
    try:
        return {"configured": True, "data": await get_json(
            f"https://www.virustotal.com/api/v3/files/{value}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY}
        )}
    except Exception as e:
        return {"configured": True, "error": str(e)}

async def urlhaus_lookup(value):
    if not URLHAUS_AUTH_KEY:
        return {"configured": False}
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": value},
                headers={"Auth-Key": URLHAUS_AUTH_KEY}
            )
            if r.status_code >= 400:
                return {"configured": True, "error": f"HTTP {r.status_code}"}
            return {"configured": True, "data": r.json()}
    except Exception as e:
        return {"configured": True, "error": str(e)}

@app.get("/api/osint/virustotal/ip")
async def vt_ip(q: str, authorization: str | None = Header(None), s: Session = Depends(db)):
    u = current_user(authorization, s); consume_credit(s, u)
    return {"query": q.strip(), "virustotal": await virustotal_ip(q.strip())}

@app.get("/api/osint/virustotal/domain")
async def vt_domain(q: str, authorization: str | None = Header(None), s: Session = Depends(db)):
    u = current_user(authorization, s); consume_credit(s, u)
    return {"query": clean_host(q), "virustotal": await virustotal_domain(clean_host(q))}

@app.get("/api/osint/virustotal/hash")
async def vt_hash(q: str, authorization: str | None = Header(None), s: Session = Depends(db)):
    u = current_user(authorization, s); consume_credit(s, u)
    return {"query": q.strip(), "virustotal": await virustotal_hash(q.strip())}

@app.get("/api/osint/urlhaus")
async def urlhaus(q: str, authorization: str | None = Header(None), s: Session = Depends(db)):
    u = current_user(authorization, s); consume_credit(s, u)
    return {"query": q.strip(), "urlhaus": await urlhaus_lookup(q.strip())}

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
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#080b12">
<title>Just Osint</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#080b12;color:#f5f7fb;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{max-width:760px;margin:auto;padding:18px}
.top{display:flex;align-items:center;justify-content:space-between;padding:8px 0 20px}
.logo{font-size:21px;font-weight:900;letter-spacing:.08em}.logo span{color:#7b7fff}
.card{background:#101621;border:1px solid #26334a;border-radius:20px;padding:18px;margin:12px 0}
h1{font-size:30px;margin:0 0 8px}h2{margin-top:0}
.muted{color:#94a3b8;line-height:1.5}
input{width:100%;padding:14px;margin:6px 0 10px;border-radius:13px;border:1px solid #2b3952;background:#0b111c;color:#fff;font-size:16px}
button{padding:14px;border-radius:13px;border:0;background:#6975ff;color:#fff;font-weight:800;font-size:15px;cursor:pointer}
.row{display:grid;grid-template-columns:1fr 1fr;gap:9px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:9px}
.secondary{background:#172033;border:1px solid #2b3952}
.danger{background:#c93c48}
.badge{display:inline-block;background:#e33434;border-radius:7px;padding:3px 7px;font-size:11px;font-weight:900}
.hidden{display:none!important}
pre{white-space:pre-wrap;word-break:break-word;background:#080d17;border:1px solid #202c40;padding:13px;border-radius:13px;max-height:50vh;overflow:auto}
@media(max-width:520px){.grid,.row{grid-template-columns:1fr}}
</style>
</head>
<body>
<main>
<div class="top">
<button class="secondary" style="width:auto" onclick="openPage('profile')">ð¤ Profil</button>
<b class="logo">JUST <span>OSINT</span></b>
<button class="secondary" style="width:auto" onclick="openPage('admin')">â°</button>
</div>

<!-- FIRST SCREEN -->
<section id="welcome" class="card">
<h1>Just Osint'e HoÅ Geldin</h1>
<p class="muted">AÃ§Ä±k kaynak OSINT araÃ§larÄ±na eriÅmek iÃ§in hesabÄ±na giriÅ yap veya yeni hesap oluÅtur.</p>
<div class="row">
<button onclick="openPage('login')">ð GiriÅ Yap</button>
<button onclick="openPage('register')">ð KayÄ±t Ol</button>
</div>
</section>

<!-- LOGIN -->
<section id="login" class="card hidden">
<h2>ð GiriÅ Yap</h2>
<p class="muted">HesabÄ±na Gmail ve Åifrenle giriÅ yap.</p>
<input id="loginEmail" type="email" autocomplete="email" placeholder="Gmail">
<input id="loginPassword" type="password" autocomplete="current-password" placeholder="Åifre">
<button onclick="login()">GiriÅ Yap</button>
<button class="secondary" onclick="openPage('welcome')">Geri</button>
<p id="loginMsg" class="muted"></p>
</section>

<!-- REGISTER -->
<section id="register" class="card hidden">
<h2>ð KayÄ±t Ol</h2>
<p class="muted">Yeni Just Osint hesabÄ±nÄ± oluÅtur.</p>
<input id="regNick" autocomplete="nickname" placeholder="Takma ad">
<input id="regEmail" type="email" autocomplete="email" placeholder="Gmail">
<input id="regPassword" type="password" autocomplete="new-password" placeholder="Åifre (en az 8 karakter)">
<input id="regPassword2" type="password" autocomplete="new-password" placeholder="Åifre tekrar">
<button onclick="register()">Hesap OluÅtur</button>
<button class="secondary" onclick="openPage('welcome')">Geri</button>
<p id="registerMsg" class="muted"></p>
</section>

<!-- DASHBOARD -->
<section id="dashboard" class="hidden">
<div class="card">
<h1>Just Osint</h1>
<p id="account" class="muted">Hesap bilgileri yÃ¼kleniyor...</p>
<input id="query" placeholder="IP / Domain / IOC / Username">
<div class="grid">
<button onclick="runTool('ip')">ð IP OSINT</button>
<button onclick="runTool('domain')">ð DOMAIN</button>
<button onclick="runTool('dns')">ð§­ DNS</button>
<button onclick="runTool('certificates')">ð SSL / CERT</button>
<button onclick="runTool('ioc')">ð¡ï¸ IOC</button><button onclick="runTool('virustotal/domain')">ð¦  VirusTotal</button><button onclick="runTool('urlhaus')">ð¨ URLhaus</button>
<button onclick="runTool('search-links')">ð¤ USERNAME</button>
</div>
<pre id="result">Sorgu sonuÃ§larÄ± burada gÃ¶rÃ¼necek.</pre>
</div>
<div class="grid">
<button onclick="openPage('vip')">ð VIP & Kredi</button>
<button onclick="openPage('history')">ð GeÃ§miÅ</button>
<button onclick="openPage('favorites')">â­ Favoriler</button>
<button onclick="openPage('reports')">ð Raporlar</button>
</div>
</section>

<section id="profile" class="card hidden">
<h2>ð¤ Profil</h2>
<input id="profileNick" placeholder="Takma ad">
<input id="profileAvatar" placeholder="Profil resmi URL">
<input id="profileEmail" type="email" placeholder="Gmail">
<input id="profilePassword" type="password" placeholder="Yeni Åifre (boÅ bÄ±rakÄ±labilir)">
<button onclick="saveProfile()">DeÄiÅiklikleri Kaydet</button>
<button class="secondary" onclick="openPage('dashboard')">Geri</button>
</section>

<section id="vip" class="card hidden">
<h2>ð VIP & Kredi</h2>
<p id="vipInfo" class="muted"></p>
<button class="secondary" onclick="openPage('dashboard')">Geri</button>
</section>

<section id="history" class="card hidden">
<h2>ð Sorgu GeÃ§miÅi</h2><pre id="historyOut">YÃ¼kleniyor...</pre>
<button class="secondary" onclick="openPage('dashboard')">Geri</button>
</section>

<section id="favorites" class="card hidden">
<h2>â­ Favoriler</h2><pre id="favoritesOut">YÃ¼kleniyor...</pre>
<button class="secondary" onclick="openPage('dashboard')">Geri</button>
</section>

<section id="reports" class="card hidden">
<h2>ð Raporlar</h2><p class="muted">KaydettiÄin raporlarÄ± burada gÃ¶rebilirsin.</p>
<pre id="reportsOut">YÃ¼kleniyor...</pre>
<button class="secondary" onclick="openPage('dashboard')">Geri</button>
</section>

<section id="admin" class="card hidden">
<h2>ð® Admin Paneli <span class="badge">ADMIN</span></h2>
<p class="muted">YalnÄ±zca admin hesabÄ± eriÅebilir.</p>
<pre id="adminOut">Dashboard verileri burada.</pre>
<button onclick="loadAdmin()">ð Dashboard</button>
<button class="secondary" onclick="openPage('dashboard')">Geri</button>
</section>

<script>
let token=localStorage.getItem('justosint_token')||'';
const $=id=>document.getElementById(id);

function openPage(id){
  document.querySelectorAll('section').forEach(x=>x.classList.add('hidden'));
  $(id).classList.remove('hidden');
  if(id==='dashboard') loadAccount();
  if(id==='profile') loadProfile();
  if(id==='vip') loadAccount();
  if(id==='history') loadHistory();
  if(id==='favorites') loadFavorites();
  if(id==='reports') loadReports();
}

function headers(){
  return {'Content-Type':'application/json','Authorization':'Bearer '+token};
}

async function api(url, options={}){
  options.headers=Object.assign(headers(),options.headers||{});
  const r=await fetch(url,options);
  let d={}; try{d=await r.json()}catch(_){}
  if(!r.ok) throw new Error(d.detail||'Ä°Ålem baÅarÄ±sÄ±z.');
  return d;
}

async function login(){
  $('loginMsg').textContent='GiriÅ yapÄ±lÄ±yor...';
  try{
    const d=await api('/api/auth/login',{
      method:'POST',
      body:JSON.stringify({email:$('loginEmail').value,password:$('loginPassword').value})
    });
    token=d.token; localStorage.setItem('justosint_token',token);
    $('loginMsg').textContent='';
    openPage('dashboard');
  }catch(e){$('loginMsg').textContent=e.message}
}

async function register(){
  const p1=$('regPassword').value,p2=$('regPassword2').value;
  if(p1!==p2){$('registerMsg').textContent='Åifreler eÅleÅmiyor.';return}
  $('registerMsg').textContent='Hesap oluÅturuluyor...';
  try{
    const d=await api('/api/auth/register',{
      method:'POST',
      body:JSON.stringify({
        email:$('regEmail').value,
        password:p1,
        nickname:$('regNick').value
      })
    });
    token=d.token; localStorage.setItem('justosint_token',token);
    $('registerMsg').textContent='';
    openPage('dashboard');
  }catch(e){$('registerMsg').textContent=e.message}
}

async function loadAccount(){
  try{
    const d=await api('/api/account/status');
    $('account').textContent=
      'Kredi: '+d.credits+' â¢ GÃ¼nlÃ¼k kullanÄ±m: '+d.daily_used+'/'+d.daily_free_limit+
      (d.vip?' â¢ ð VIP':'');
    $('vipInfo').textContent=JSON.stringify(d,null,2);
  }catch(e){$('account').textContent=e.message}
}

async function loadProfile(){
  try{
    const d=await api('/api/me');
    $('profileNick').value=d.nickname||'';
    $('profileAvatar').value=d.avatar_url||'';
    $('profileEmail').value=d.email||'';
  }catch(e){alert(e.message)}
}

async function saveProfile(){
  try{
    await api('/api/me',{
      method:'PATCH',
      body:JSON.stringify({
        nickname:$('profileNick').value||null,
        avatar_url:$('profileAvatar').value||null,
        email:$('profileEmail').value||null,
        password:$('profilePassword').value||null
      })
    });
    $('profilePassword').value='';
    alert('Profil gÃ¼ncellendi.');
  }catch(e){alert(e.message)}
}

async function runTool(kind){
  const q=$('query').value.trim();
  if(!q){$('result').textContent='Ãnce bir sorgu gir.';return}
  $('result').textContent='SorgulanÄ±yor...';
  try{
    const suffix=kind==='search-links'?'&kind=username':'';
    const d=await api('/api/osint/'+kind+'?q='+encodeURIComponent(q)+suffix);
    $('result').textContent=JSON.stringify(d,null,2);
    loadAccount();
  }catch(e){$('result').textContent=e.message}
}

async function loadHistory(){
  try{$('historyOut').textContent=JSON.stringify(await api('/api/history'),null,2)}
  catch(e){$('historyOut').textContent=e.message}
}
async function loadFavorites(){
  try{$('favoritesOut').textContent=JSON.stringify(await api('/api/favorites'),null,2)}
  catch(e){$('favoritesOut').textContent=e.message}
}
async function loadReports(){
  try{$('reportsOut').textContent=JSON.stringify(await api('/api/reports'),null,2)}
  catch(e){$('reportsOut').textContent=e.message}
}
async function loadAdmin(){
  try{$('adminOut').textContent=JSON.stringify(await api('/api/admin/dashboard'),null,2)}
  catch(e){$('adminOut').textContent=e.message}
}

if(token) openPage('dashboard'); else openPage('welcome');
</script>
</main></body></html>"""


@app.get("/", response_class=HTMLResponse)
async def home():
    return HTMLResponse("""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Just Osint</title>
<style>
:root{--bg:#070a12;--card:#111827;--line:#27344d;--accent:#6d73ff;--text:#f5f7ff;--muted:#9aa7bf;--danger:#ef4444}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
header{display:flex;justify-content:space-between;align-items:center;padding:18px 18px 12px;position:sticky;top:0;background:rgba(7,10,18,.94);backdrop-filter:blur(12px);z-index:5}
.logo{font-weight:900;font-size:21px;letter-spacing:.5px}.logo span{color:var(--accent)}
button{border:0;border-radius:14px;padding:14px 16px;font-weight:800;color:white;background:var(--accent);font-size:15px}
.icon{background:#172033;border:1px solid var(--line);padding:10px 13px;border-radius:12px}
main{max-width:760px;margin:auto;padding:12px 16px 40px}.hero,.panel{background:var(--card);border:1px solid var(--line);border-radius:22px;padding:22px;margin:14px 0}
.hero h1{font-size:34px;margin:0 0 8px}.muted{color:var(--muted);line-height:1.55}
input,select{width:100%;background:#0c1220;color:white;border:1px solid var(--line);border-radius:14px;padding:15px;margin:7px 0 12px;font-size:16px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:11px}.tool{background:#151e31;border:1px solid var(--line);text-align:left}
.tool b{display:block}.tool small{display:block;color:var(--muted);margin-top:4px}
.row{display:flex;gap:10px;align-items:center}.row>*{flex:1}.hidden{display:none}
.badge{display:inline-block;background:var(--danger);border-radius:8px;padding:3px 7px;font-size:11px;font-weight:900}
.result{white-space:pre-wrap;background:#080d18;border-radius:14px;padding:14px;border:1px solid var(--line);margin-top:12px}
.nav{display:flex;gap:8px;overflow:auto;margin:10px 0}.nav button{white-space:nowrap;background:#151e31}
@media(max-width:520px){.grid{grid-template-columns:1fr}.hero h1{font-size:29px}}
</style>
</head>
<body>
<header>
<button class="icon" onclick="show('profile')">ð¤</button>
<div class="logo">JUST <span>OSINT</span></div>
<button class="icon" onclick="show('admin')">â°</button>
</header>
<main>
<section id="login" class="panel">
<h1>Just Osint'e HoÅ Geldin</h1><p class="muted">OSINT araÃ§larÄ±na eriÅmek iÃ§in giriÅ yap veya yeni hesap oluÅtur.</p>
<input id="email" type="email" placeholder="Gmail">
<input id="password" type="password" placeholder="Åifre">
<div class="row"><button onclick="fakeLogin()">GiriÅ Yap</button><button onclick="fakeRegister()">KayÄ±t Ol</button></div>
<p id="authmsg" class="muted"></p>
</section>

<section id="dashboard" class="hidden">
<div class="hero"><h1>Just Osint</h1><p class="muted">AÃ§Ä±k kaynaklardan teknik istihbarat. SonuÃ§lar burada gÃ¶rÃ¼necek.</p></div>
<div class="panel"><input id="target" placeholder="IP / Domain / IOC / Username">
<div class="grid">
<button class="tool" onclick="runTool('ip')"><b>ð IP OSINT</b><small>IP itibar ve tehdit bilgileri</small></button>
<button class="tool" onclick="runTool('domain')"><b>ð DOMAIN</b><small>Alan adÄ± bilgileri</small></button>
<button class="tool" onclick="runTool('dns')"><b>ð§­ DNS</b><small>DNS kayÄ±tlarÄ±</small></button>
<button class="tool" onclick="runTool('ssl')"><b>ð SSL / TLS</b><small>Sertifika bilgileri</small></button>
<button class="tool" onclick="runTool('ioc')"><b>ð¡ï¸ IOC</b><small>Tehdit gÃ¶stergesi analizi</small></button>
<button class="tool" onclick="runTool('username')"><b>ð¤ USERNAME</b><small>AÃ§Ä±k kaynak kullanÄ±cÄ± adÄ± araÅtÄ±rmasÄ±</small></button>
</div><div id="result" class="result">Bir araÃ§ seÃ§ip sorgu gÃ¶nder.</div></div>

<div class="panel"><h2>ð VIP & Krediler</h2><p class="muted">VIP durumun ve sorgu kredilerin burada gÃ¶rÃ¼ntÃ¼lenir.</p>
<div class="row"><button onclick="show('vip')">VIP Merkezi</button><button onclick="show('history')">Sorgu GeÃ§miÅi</button></div></div>

<div class="panel"><h2>ð Raporlar</h2><div class="row"><button onclick="show('reports')">KayÄ±tlÄ± SonuÃ§lar</button><button onclick="show('sslInfo')">SSL Bilgilendirme</button></div></div>
</section>

<section id="profile" class="panel hidden"><h1>Profil</h1><p class="muted">Profil ayarlarÄ±nÄ± buradan yÃ¶net.</p>
<input placeholder="Takma ad"><input type="email" placeholder="Gmail"><input type="password" placeholder="Yeni Åifre">
<button onclick="alert('Profil ayarlarÄ± kaydedildi.')">Kaydet</button></section>

<section id="vip" class="panel hidden"><h1>ð VIP Merkezi</h1><p class="muted">VIP Ã¼yelik, rozet ve sÃ¼reli eriÅim seÃ§enekleri bu bÃ¶lÃ¼mde yÃ¶netilir.</p><span class="badge">VIP</span></section>

<section id="history" class="panel hidden"><h1>ð Sorgu GeÃ§miÅi</h1><p class="muted">HesabÄ±na ait sorgular burada listelenir.</p></section>

<section id="reports" class="panel hidden"><h1>ð Raporlar</h1><p class="muted">SonuÃ§larÄ± kaydetme, JSON dÄ±Åa aktarma ve PDF raporu oluÅturma seÃ§enekleri.</p>
<div class="row"><button onclick="alert('JSON dÄ±Åa aktarma hazÄ±rlanÄ±yor.')">JSON</button><button onclick="alert('PDF raporu hazÄ±rlanÄ±yor.')">PDF</button></div></section>

<section id="sslInfo" class="panel hidden"><h1>ð SSL / TLS</h1><p class="muted">SSL/TLS, HTTPS baÄlantÄ±larÄ±nda kullanÄ±lan Åifreleme ve kimlik doÄrulama teknolojileridir. Bu bÃ¶lÃ¼m herkese aÃ§Ä±k teknik sertifika bilgilerini incelemek iÃ§indir. Ãzel anahtarlar veya kiÅisel bilgiler toplanmaz.</p><button onclick="show('dashboard')">Geri DÃ¶n</button></section>

<section id="admin" class="panel hidden"><h1>ð® Admin Paneli <span class="badge">ADMIN</span></h1><p class="muted">KullanÄ±cÄ± yÃ¶netimi, ban/unban, kredi iÅlemleri, API istatistikleri ve dashboard.</p>
<div class="grid"><button class="tool">ð¥ KullanÄ±cÄ±lar</button><button class="tool">ð« Ban / Unban</button><button class="tool">ð³ Kredi YÃ¶netimi</button><button class="tool">ð API Ä°statistikleri</button></div></section>
</main>
<script>
function show(id){document.querySelectorAll('section').forEach(x=>x.classList.add('hidden'));document.getElementById(id).classList.remove('hidden')}
function fakeLogin(){const e=document.getElementById('email').value,p=document.getElementById('password').value;if(!e||!p){document.getElementById('authmsg').textContent='Gmail ve Åifre gerekli.';return}show('dashboard')}
function fakeRegister(){fakeLogin()}
function runTool(kind){const t=document.getElementById('target').value.trim();if(!t){document.getElementById('result').textContent='Ãnce bir hedef gir.';return}document.getElementById('result').textContent='Sorgu hazÄ±rlanÄ±yor: '+kind.toUpperCase()+'\\nHedef: '+t+'\\n\\nBackend API baÄlantÄ±sÄ± Ã¼zerinden sonuÃ§ alÄ±nacak.'}
show('login')
</script>
</body></html>""")

@app.get("/api/health")
def health():
    return {
        "ok": True,
        "service": "Just Osint",
        "integrations": {
            "virustotal": bool(VIRUSTOTAL_API_KEY),
            "urlhaus": bool(URLHAUS_AUTH_KEY),
            "abuseipdb": bool(ABUSEIPDB_API_KEY),
            "otx": bool(OTX_API_KEY),
            "threatfox": bool(THREATFOX_API_KEY),
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
