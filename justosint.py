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
import os, re, hmac, json, time, hashlib, uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, quote_plus

import httpx
from argon2 import PasswordHasher
from fastapi import FastAPI, HTTPException, Depends, Header, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr, Field
from jose import jwt, JWTError
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, inspect, text
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
    is_banned = Column(Boolean, default=False, nullable=False)
    ban_reason = Column(String(500), default="")
    ban_until = Column(DateTime, nullable=True)
    credits = Column(Integer, default=100, nullable=False)
    vip_until = Column(DateTime, nullable=True)
    last_login = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=True)
    action = Column(String(120), nullable=False)
    target = Column(String(500), default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class Favorite(Base):
    __tablename__ = "favorites"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False, index=True)
    title = Column(String(160), nullable=False)
    query = Column(String(500), nullable=False)
    result_json = Column(Text, default="{}")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False, index=True)
    title = Column(String(160), nullable=False)
    query = Column(String(500), nullable=False)
    result_json = Column(Text, default="{}")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class Announcement(Base):
    __tablename__ = "announcements"
    id = Column(Integer, primary_key=True)
    title = Column(String(160), nullable=False)
    message = Column(Text, nullable=False)
    audience = Column(String(30), default="all")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

Base.metadata.create_all(engine)
try:
    _cols = {c["name"] for c in inspect(engine).get_columns("users")}
    with engine.begin() as _conn:
        if "credits" not in _cols:
            _conn.execute(text("ALTER TABLE users ADD COLUMN credits INTEGER DEFAULT 100"))
        if "vip_until" not in _cols:
            _conn.execute(text("ALTER TABLE users ADD COLUMN vip_until TIMESTAMP NULL"))
        if "is_banned" not in _cols:
            _conn.execute(text("ALTER TABLE users ADD COLUMN is_banned BOOLEAN DEFAULT 0"))
        if "ban_reason" not in _cols:
            _conn.execute(text("ALTER TABLE users ADD COLUMN ban_reason VARCHAR(500) DEFAULT ''"))
        if "ban_until" not in _cols:
            _conn.execute(text("ALTER TABLE users ADD COLUMN ban_until TIMESTAMP NULL"))
        if "last_login" not in _cols:
            _conn.execute(text("ALTER TABLE users ADD COLUMN last_login TIMESTAMP NULL"))
except Exception:
    pass

# Seed the configured admin account on first startup.
try:
    with SessionLocal() as _s:
        _admin=_s.query(User).filter(User.email==ADMIN_EMAIL).first()
        if not _admin:
            _admin=User(email=ADMIN_EMAIL,password_hash=ph.hash(ADMIN_PASSWORD),nickname="Just Osint Admin",is_admin=True,credits=0)
            _s.add(_admin); _s.commit()
        elif not _admin.is_admin:
            try:
                if ph.verify(_admin.password_hash, ADMIN_PASSWORD):
                    _admin.is_admin=True; _s.commit()
            except Exception:
                pass
except Exception:
    pass

app = FastAPI(title="Just Osint", version="2.1-single-file")
from fastapi.staticfiles import StaticFiles
os.makedirs("uploads", exist_ok=True)
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")
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
        "is_banned": bool(u.is_banned),
        "credits": int(u.credits or 0),
        "vip": bool(u.vip_until and u.vip_until > datetime.now(timezone.utc)),
        "vip_until": u.vip_until.isoformat() if u.vip_until else None,
        "created_at": u.created_at.isoformat() if u.created_at else None,
        "last_login": u.last_login.isoformat() if u.last_login else None,
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
        raise HTTPException(401, "Geçersiz oturum.")
    u = s.get(User, uid)
    if not u:
        raise HTTPException(401, "Kullanıcı bulunamadı.")
    now = datetime.now(timezone.utc)
    if u.is_banned:
        if u.ban_until and u.ban_until <= now:
            u.is_banned = False; u.ban_reason = ""; u.ban_until = None; s.commit()
        else:
            raise HTTPException(403, "Hesabın yasaklandı." + (f" Sebep: {u.ban_reason}" if u.ban_reason else ""))
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
        raise HTTPException(409, "Bu e-posta zaten kayıtlı.")
    admin = bool(ADMIN_EMAIL and email == ADMIN_EMAIL and hmac.compare_digest(x.password, ADMIN_PASSWORD))
    u = User(email=email, password_hash=ph.hash(x.password),
             nickname=x.nickname.strip(), is_admin=admin)
    s.add(u); s.commit(); s.refresh(u)
    audit(s, u.id, "register")
    return {"token": make_token(u), "user": public_user(u)}

@app.post("/api/auth/login")
def login(x: LoginIn, s: Session = Depends(db)):
    u = s.query(User).filter(User.email == str(x.email).lower().strip()).first()
    if not u:
        raise HTTPException(401, "E-posta veya şifre hatalı.")
    try:
        ph.verify(u.password_hash, x.password)
    except Exception:
        raise HTTPException(401, "E-posta veya şifre hatalı.")
    u.last_login = datetime.now(timezone.utc)
    s.commit()
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
            raise HTTPException(409, "Bu e-posta kullanımda.")
        u.email = email
    if x.password:
        u.password_hash = ph.hash(x.password)
    s.commit(); audit(s, u.id, "profile_update")
    return public_user(u)

# ---------- Telegram Mini App linking ----------
def validate_telegram_init_data(init_data: str):
    if not TELEGRAM_BOT_TOKEN:
        raise HTTPException(503, "TELEGRAM_BOT_TOKEN ayarlı değil.")
    pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    received = pairs.pop("hash", None)
    if not received:
        raise HTTPException(400, "Telegram hash eksik.")
    try:
        auth_date = int(pairs.get("auth_date", "0"))
    except ValueError:
        raise HTTPException(400, "Geçersiz auth_date.")
    if time.time() - auth_date > 86400:
        raise HTTPException(400, "Telegram oturumu süresi dolmuş.")
    check = "\n".join(f"{k}={pairs[k]}" for k in sorted(pairs))
    secret = hmac.new(b"WebAppData", TELEGRAM_BOT_TOKEN.encode(), hashlib.sha256).digest()
    calc = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calc, received):
        raise HTTPException(403, "Telegram doğrulaması başarısız.")
    tg_user = json.loads(pairs.get("user", "{}"))
    if not tg_user.get("id"):
        raise HTTPException(400, "Telegram kullanıcı bilgisi yok.")
    return str(tg_user["id"]), tg_user

@app.post("/api/telegram/link")
def link_telegram(x: TelegramLinkIn, authorization: str | None = Header(None), s: Session = Depends(db)):
    u = current_user(authorization, s)
    tid, tg = validate_telegram_init_data(x.init_data)
    if s.query(User).filter(User.telegram_id == tid, User.id != u.id).first():
        raise HTTPException(409, "Bu Telegram hesabı başka hesaba bağlı.")
    u.telegram_id = tid
    if not u.nickname or u.nickname == "Yeni Kullanıcı":
        u.nickname = tg.get("username") or tg.get("first_name") or u.nickname
    s.commit(); audit(s, u.id, "telegram_link", tid)
    return public_user(u)

# ---------- OSINT helpers ----------
def clean_host(v: str):
    v = v.strip().lower()
    v = re.sub(r"^https?://", "", v).split("/")[0].split(":")[0]
    if not re.fullmatch(r"[a-z0-9.-]{1,253}", v):
        raise HTTPException(400, "Geçersiz domain/IP.")
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
async def ip_osint(q: str, authorization: str | None = Header(None), s: Session = Depends(db)):
    u=current_user(authorization,s); consume_credit(s,u,"query:ip")
    ip = clean_host(q)
    result = {"query": ip}
    try: result["rdap"] = await get_json(f"https://rdap.org/ip/{ip}")
    except Exception as e: result["rdap_error"] = str(e)
    result["abuseipdb"] = await abuse_check(ip)
    result["otx"] = await otx_indicator("IPv4" if "." in ip else "IPv6", ip)
    result["threatfox"] = await threatfox_search(ip)
    return result

@app.get("/api/osint/domain")
async def domain_osint(q: str, authorization: str | None = Header(None), s: Session = Depends(db)):
    u=current_user(authorization,s); consume_credit(s,u,"query:domain")
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
async def dns_osint(q: str, authorization: str | None = Header(None), s: Session = Depends(db)):
    u=current_user(authorization,s); consume_credit(s,u,"query:dns")
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
async def certificates(q: str, authorization: str | None = Header(None), s: Session = Depends(db)):
    u=current_user(authorization,s); consume_credit(s,u,"query:certificates")
    domain = clean_host(q)
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
                        headers={"User-Agent": "JustOsint/2.0"})
    if r.status_code >= 400:
        raise HTTPException(502, "crt.sh sorgusu başarısız.")
    names = sorted({n.strip().lower() for row in r.json()
                    for n in row.get("name_value", "").splitlines() if n.strip()})
    return {"query": domain, "count": len(names), "subdomains": names[:1000]}

@app.get("/api/osint/ioc")
async def ioc_osint(q: str, authorization: str | None = Header(None), s: Session = Depends(db)):
    u=current_user(authorization,s); consume_credit(s,u,"query:ioc")
    value = q.strip()
    if not value or len(value) > 300:
        raise HTTPException(400, "Geçersiz IOC.")
    return {
        "query": value,
        "otx": await otx_indicator("file" if re.fullmatch(r"[a-fA-F0-9]{32,64}", value) else "domain", value),
        "threatfox": await threatfox_search(value),
    }

@app.get("/api/osint/search-links")
def search_links(q: str, kind: str = "username", authorization: str | None = Header(None), s: Session = Depends(db)):
    u=current_user(authorization,s); consume_credit(s,u,"query:search-links")
    value = q.strip()
    if not value or len(value) > 200:
        raise HTTPException(400, "Geçersiz sorgu.")
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

# ---------- admin, favorites, reports ----------
DAILY_FREE_LIMIT = int(os.getenv("DAILY_FREE_LIMIT", "10"))

class AdminUserAction(BaseModel):
    user_id: int

class CreditAction(BaseModel):
    user_id: int
    amount: int = Field(ge=-1000000, le=1000000)
    note: str = Field(default="", max_length=300)

class BanAction(BaseModel):
    user_id: int
    reason: str = Field(default="", max_length=500)
    hours: int | None = Field(default=None, ge=1, le=8760)

class VipAction(BaseModel):
    user_id: int
    days: int = Field(ge=1, le=3650)

class AdminRoleAction(BaseModel):
    user_id: int
    is_admin: bool

class AnnouncementIn(BaseModel):
    title: str = Field(min_length=1, max_length=160)
    message: str = Field(min_length=1, max_length=4000)
    audience: str = Field(default="all", pattern="^(all|vip)$")

class SettingIn(BaseModel):
    daily_free_limit: int = Field(ge=0, le=10000)
    query_cost: int = Field(ge=0, le=1000)

class SaveItemIn(BaseModel):
    title: str = Field(min_length=1, max_length=160)
    query: str = Field(min_length=1, max_length=500)
    result: dict

def is_vip(u):
    return bool(u.vip_until and u.vip_until > datetime.now(timezone.utc))

def admin_required(auth, s):
    u = current_user(auth, s)
    if not u.is_admin:
        raise HTTPException(403, "Admin yetkisi gerekli.")
    return u

def query_stats(s, uid=None):
    q=s.query(AuditLog).filter(AuditLog.action.like("query%"))
    if uid is not None: q=q.filter(AuditLog.user_id==uid)
    return q.count()

def _user_admin_view(u):
    return {"id":u.id,"email":u.email,"nickname":u.nickname,"is_admin":bool(u.is_admin),
            "is_banned":bool(u.is_banned),"ban_reason":u.ban_reason or "","ban_until":u.ban_until.isoformat() if u.ban_until else None,
            "credits":u.credits or 0,"vip":is_vip(u),"vip_until":u.vip_until.isoformat() if u.vip_until else None,
            "telegram_linked":bool(u.telegram_id),"created_at":u.created_at.isoformat(),
            "last_login":u.last_login.isoformat() if u.last_login else None,"total_queries":query_stats(s_global,u.id) if False else 0}

@app.get("/api/admin/dashboard")
def admin_dashboard(authorization: str | None = Header(None), s: Session = Depends(db)):
    admin_required(authorization, s)
    now=datetime.now(timezone.utc); today=now.replace(hour=0,minute=0,second=0,microsecond=0)
    week=now-timedelta(days=7)
    total=s.query(User).count(); active=s.query(User).filter(User.last_login>=week).count()
    today_q=s.query(AuditLog).filter(AuditLog.action.like("query%"),AuditLog.created_at>=today).count()
    total_q=s.query(AuditLog).filter(AuditLog.action.like("query%")).count()
    vip=s.query(User).filter(User.vip_until>now).count(); banned=s.query(User).filter(User.is_banned==True).count()
    rows=s.query(AuditLog.action).filter(AuditLog.action.like("query:%")).all(); counts={}
    for (a,) in rows: counts[a]=counts.get(a,0)+1
    top=max(counts.items(),key=lambda x:x[1])[0] if counts else "Yok"
    api_status={"AbuseIPDB":bool(ABUSEIPDB_API_KEY),"AlienVault OTX":bool(OTX_API_KEY),"ThreatFox":bool(THREATFOX_API_KEY),"VirusTotal":bool(VIRUSTOTAL_API_KEY),"URLhaus":bool(URLHAUS_AUTH_KEY)}
    return {"total_users":total,"active_users_7d":active,"today_queries":today_q,"total_queries":total_q,"vip_users":vip,"banned_users":banned,"most_used_tool":top,"api_status":api_status,"recent_logs":[{"action":x.action,"target":x.target,"created_at":x.created_at.isoformat()} for x in s.query(AuditLog).order_by(AuditLog.id.desc()).limit(12).all()]}

@app.get("/api/admin/users")
def admin_users(search: str = "", authorization: str | None = Header(None), s: Session = Depends(db)):
    admin_required(authorization, s)
    q=s.query(User)
    if search.strip():
        term=f"%{search.strip().lower()}%"; q=q.filter((User.email.ilike(term))|(User.nickname.ilike(term)))
    out=[]
    for u in q.order_by(User.id.desc()).limit(500).all():
        out.append({"id":u.id,"email":u.email,"nickname":u.nickname,"is_admin":bool(u.is_admin),"is_banned":bool(u.is_banned),"credits":u.credits or 0,"vip":is_vip(u),"vip_until":u.vip_until.isoformat() if u.vip_until else None,"telegram_linked":bool(u.telegram_id),"created_at":u.created_at.isoformat(),"last_login":u.last_login.isoformat() if u.last_login else None,"total_queries":query_stats(s,u.id)})
    return out

@app.get("/api/admin/users/{user_id}")
def admin_user_detail(user_id:int, authorization: str | None = Header(None), s: Session = Depends(db)):
    admin_required(authorization,s); u=s.get(User,user_id)
    if not u: raise HTTPException(404,"Kullanıcı bulunamadı.")
    return {**_user_admin_view(u),"total_queries":query_stats(s,u.id),"logs":[{"action":x.action,"target":x.target,"created_at":x.created_at.isoformat()} for x in s.query(AuditLog).filter(AuditLog.user_id==u.id).order_by(AuditLog.id.desc()).limit(100).all()]}

@app.post("/api/admin/users/ban")
def admin_ban(x:BanAction,authorization:str|None=Header(None),s:Session=Depends(db)):
    a=admin_required(authorization,s); u=s.get(User,x.user_id)
    if not u: raise HTTPException(404,"Kullanıcı bulunamadı.")
    if u.is_admin: raise HTTPException(400,"Admin hesabı banlanamaz.")
    u.is_banned=True; u.ban_reason=x.reason.strip(); u.ban_until=datetime.now(timezone.utc)+timedelta(hours=x.hours) if x.hours else None; s.commit(); audit(s,a.id,"admin:ban",f"user={u.id}")
    return _user_admin_view(u)

@app.post("/api/admin/users/unban")
def admin_unban(x:AdminUserAction,authorization:str|None=Header(None),s:Session=Depends(db)):
    a=admin_required(authorization,s); u=s.get(User,x.user_id)
    if not u: raise HTTPException(404,"Kullanıcı bulunamadı.")
    u.is_banned=False; u.ban_reason=""; u.ban_until=None; s.commit(); audit(s,a.id,"admin:unban",f"user={u.id}"); return _user_admin_view(u)

@app.post("/api/admin/users/credits")
def admin_credits(x:CreditAction,authorization:str|None=Header(None),s:Session=Depends(db)):
    a=admin_required(authorization,s); u=s.get(User,x.user_id)
    if not u: raise HTTPException(404,"Kullanıcı bulunamadı.")
    u.credits=max(0,(u.credits or 0)+x.amount); s.commit(); audit(s,a.id,"admin:credits",f"user={u.id};amount={x.amount};note={x.note}"); return {"user_id":u.id,"credits":u.credits}

@app.post("/api/admin/users/vip")
def admin_vip(x:VipAction,authorization:str|None=Header(None),s:Session=Depends(db)):
    a=admin_required(authorization,s); u=s.get(User,x.user_id)
    if not u: raise HTTPException(404,"Kullanıcı bulunamadı.")
    base=u.vip_until if u.vip_until and u.vip_until>datetime.now(timezone.utc) else datetime.now(timezone.utc); u.vip_until=base+timedelta(days=x.days); s.commit(); audit(s,a.id,"admin:vip",f"user={u.id};days={x.days}"); return {"user_id":u.id,"vip_until":u.vip_until.isoformat()}

@app.post("/api/admin/users/role")
def admin_role(x:AdminRoleAction,authorization:str|None=Header(None),s:Session=Depends(db)):
    a=admin_required(authorization,s); u=s.get(User,x.user_id)
    if not u: raise HTTPException(404,"Kullanıcı bulunamadı.")
    u.is_admin=x.is_admin; s.commit(); audit(s,a.id,"admin:role",f"user={u.id};admin={x.is_admin}"); return _user_admin_view(u)

@app.get("/api/admin/logs")
def admin_logs(authorization: str | None = Header(None), s: Session = Depends(db)):
    admin_required(authorization,s)
    return [{"id":x.id,"user_id":x.user_id,"action":x.action,"target":x.target,"created_at":x.created_at.isoformat()} for x in s.query(AuditLog).order_by(AuditLog.id.desc()).limit(500).all()]

@app.post("/api/admin/announcements")
def admin_announcement(x:AnnouncementIn,authorization:str|None=Header(None),s:Session=Depends(db)):
    a=admin_required(authorization,s); item=Announcement(title=x.title.strip(),message=x.message.strip(),audience=x.audience); s.add(item); s.commit(); audit(s,a.id,"admin:announcement",x.title); return {"ok":True,"id":item.id}

@app.get("/api/announcements")
def announcements(authorization:str|None=Header(None),s:Session=Depends(db)):
    u=current_user(authorization,s); q=s.query(Announcement).order_by(Announcement.id.desc())
    items=q.limit(20).all(); return [{"id":x.id,"title":x.title,"message":x.message,"audience":x.audience,"created_at":x.created_at.isoformat()} for x in items if x.audience=="all" or is_vip(u)]

@app.post("/api/admin/settings")
def admin_settings(x:SettingIn,authorization:str|None=Header(None),s:Session=Depends(db)):
    a=admin_required(authorization,s); os.environ["DAILY_FREE_LIMIT"]=str(x.daily_free_limit); os.environ["QUERY_COST"]=str(x.query_cost); audit(s,a.id,"admin:settings",f"daily={x.daily_free_limit};cost={x.query_cost}"); return {"daily_free_limit":x.daily_free_limit,"query_cost":x.query_cost}

@app.post("/api/favorites")
def add_favorite(x:SaveItemIn,authorization:str|None=Header(None),s:Session=Depends(db)):
    u=current_user(authorization,s); item=Favorite(user_id=u.id,title=x.title.strip(),query=x.query.strip(),result_json=json.dumps(x.result,ensure_ascii=False)); s.add(item); s.commit(); return {"id":item.id}

@app.get("/api/favorites")
def favorites(authorization:str|None=Header(None),s:Session=Depends(db)):
    u=current_user(authorization,s); return [{"id":x.id,"title":x.title,"query":x.query,"result":json.loads(x.result_json or "{}"),"created_at":x.created_at.isoformat()} for x in s.query(Favorite).filter(Favorite.user_id==u.id).order_by(Favorite.id.desc()).limit(100).all()]

@app.delete("/api/favorites/{item_id}")
def delete_favorite(item_id:int,authorization:str|None=Header(None),s:Session=Depends(db)):
    u=current_user(authorization,s); x=s.query(Favorite).filter(Favorite.id==item_id,Favorite.user_id==u.id).first()
    if not x: raise HTTPException(404,"Favori bulunamadı.")
    s.delete(x); s.commit(); return {"ok":True}

@app.post("/api/reports")
def add_report(x:SaveItemIn,authorization:str|None=Header(None),s:Session=Depends(db)):
    u=current_user(authorization,s); item=Report(user_id=u.id,title=x.title.strip(),query=x.query.strip(),result_json=json.dumps(x.result,ensure_ascii=False)); s.add(item); s.commit(); return {"id":item.id}

@app.get("/api/reports")
def reports(authorization:str|None=Header(None),s:Session=Depends(db)):
    u=current_user(authorization,s); return [{"id":x.id,"title":x.title,"query":x.query,"result":json.loads(x.result_json or "{}"),"created_at":x.created_at.isoformat()} for x in s.query(Report).filter(Report.user_id==u.id).order_by(Report.id.desc()).limit(100).all()]

# ---------- built-in Telegram Mini App ----------
HTML = r"""<!doctype html>
<html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#080b14"><title>Just Osint</title>
<style>
:root{--bg:#070a12;--side:#0d1220;--card:#111827;--line:#26334b;--accent:#6d72ff;--accent2:#8b5cf6;--text:#f5f7ff;--muted:#9aa8bf;--danger:#ef4444;--ok:#22c55e}*{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}button,input,textarea,select{font:inherit}button{border:0;cursor:pointer}.app{min-height:100vh;display:flex}.sidebar{width:255px;background:linear-gradient(180deg,#0d1220,#090d17);border-right:1px solid var(--line);padding:18px 14px;position:fixed;inset:0 auto 0 0;overflow:auto}.brand{font-weight:950;font-size:24px;letter-spacing:.06em;margin:6px 8px 18px}.brand span{color:var(--accent)}.profile-mini{background:#121a2a;border:1px solid var(--line);border-radius:18px;padding:12px;margin-bottom:12px;display:flex;gap:10px;align-items:center;text-align:left;color:white;width:100%}.avatar{width:48px;height:48px;border-radius:50%;object-fit:cover;background:#1a2438;display:grid;place-items:center;font-size:22px;overflow:hidden}.avatar.small{width:42px;height:42px}.ptext{min-width:0}.ptext b{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.muted{color:var(--muted);line-height:1.5}.nav-title{font-size:11px;color:#71809b;font-weight:900;padding:12px 10px 6px;text-transform:uppercase;letter-spacing:.08em}.nav button{width:100%;text-align:left;background:transparent;color:#dbe3f3;padding:11px 12px;border-radius:11px;margin:2px 0;font-weight:750}.nav button:hover,.nav button.active{background:#172238}.admin-link{margin-top:12px;border-top:1px solid var(--line);padding-top:12px}.main{margin-left:255px;width:calc(100% - 255px);min-height:100vh}.topbar{height:72px;display:flex;align-items:center;justify-content:flex-end;padding:0 28px;border-bottom:1px solid var(--line);background:rgba(7,10,18,.86);backdrop-filter:blur(14px);position:sticky;top:0;z-index:4}.logo-right{font-size:24px;font-weight:950;letter-spacing:.07em}.logo-right span{color:var(--accent)}.content{max-width:1100px;margin:auto;padding:26px}.panel{background:var(--card);border:1px solid var(--line);border-radius:22px;padding:22px;margin-bottom:16px}.hero{padding:28px}.hero h1{font-size:38px;margin:0 0 8px}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.grid3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.tool{background:#151f32;color:white;border:1px solid var(--line);border-radius:16px;padding:17px;text-align:left}.tool b{display:block;font-size:17px}.tool small{display:block;color:var(--muted);margin-top:5px}.stat{padding:18px;background:#0d1422;border:1px solid var(--line);border-radius:16px}.stat b{font-size:25px;display:block}.field{width:100%;background:#0b111d;color:white;border:1px solid var(--line);border-radius:13px;padding:14px;margin:6px 0 10px;outline:none}.row{display:flex;gap:10px;align-items:center}.row>*{flex:1}.btn{background:var(--accent);color:white;padding:13px 16px;border-radius:13px;font-weight:850}.secondary{background:#172237;color:white;border:1px solid var(--line)}.danger{background:var(--danger)}.success{background:var(--ok)}.badge{display:inline-block;background:var(--danger);padding:4px 8px;border-radius:7px;font-size:11px;font-weight:950}.vipbadge{background:#8b5cf6}.result{white-space:pre-wrap;word-break:break-word;background:#080d17;border:1px solid var(--line);border-radius:14px;padding:14px;max-height:52vh;overflow:auto}.table-wrap{overflow:auto}.table{width:100%;border-collapse:collapse}.table th,.table td{padding:11px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}.hidden{display:none!important}.menu-mobile{display:none}.notice{padding:12px;border-radius:12px;background:#0d1422;color:var(--muted);margin:10px 0}.auth{max-width:520px;margin:70px auto}.auth .logo-right{text-align:center;margin-bottom:24px}@media(max-width:850px){.sidebar{transform:translateX(-100%);transition:.2s;z-index:10}.sidebar.open{transform:translateX(0)}.main{margin-left:0;width:100%}.menu-mobile{display:block;background:#172237;color:white;padding:10px 13px;border-radius:11px;margin-right:auto}.topbar{padding:0 16px}.content{padding:16px}.grid,.grid3{grid-template-columns:1fr}.hero h1{font-size:30px}}
</style></head><body>
<div id="authView" class="auth panel">
<div class="logo-right">JUST <span>OSINT</span></div>
<div id="loginBox"><h1>Just Osint'e Hoş Geldin</h1><p class="muted">Açık kaynak teknik istihbarat araçlarına erişmek için giriş yap.</p><input id="loginEmail" class="field" type="email" placeholder="E-posta"><input id="loginPassword" class="field" type="password" placeholder="Şifre"><div class="row"><button class="btn" onclick="login()">Giriş Yap</button><button class="btn secondary" onclick="toggleAuth(false)">Kayıt Ol</button></div><p id="loginMsg" class="muted"></p></div>
<div id="registerBox" class="hidden"><h1>Hesap Oluştur</h1><input id="regNick" class="field" placeholder="Takma ad"><input id="regEmail" class="field" type="email" placeholder="E-posta"><input id="regPassword" class="field" type="password" placeholder="Şifre (en az 8 karakter)"><input id="regPassword2" class="field" type="password" placeholder="Şifre tekrar"><div class="row"><button class="btn" onclick="register()">Kayıt Ol</button><button class="btn secondary" onclick="toggleAuth(true)">Giriş Yap</button></div><p id="registerMsg" class="muted"></p></div></div>
<div id="appView" class="app hidden">
<aside id="sidebar" class="sidebar"><div class="brand">JUST <span>OSINT</span></div><button class="profile-mini" onclick="showPage('profile')"><div id="miniAvatar" class="avatar small">👤</div><div class="ptext"><b id="miniName">Profil</b><span id="miniRole" class="muted">Hesap</span></div></button>
<div class="nav-title">Seçenekler</div><div class="nav"><button onclick="showPage('dashboard')">🏠 Ana Sayfa</button><button onclick="showPage('ip')">🌐 IP OSINT</button><button onclick="showPage('domain')">🔎 Domain</button><button onclick="showPage('dns')">🧭 DNS</button><button onclick="showPage('ssl')">🔒 SSL / TLS</button><button onclick="showPage('ioc')">🛡️ IOC</button><button onclick="showPage('username')">👤 Username</button><button onclick="showPage('vt')">🦠 VirusTotal</button><button onclick="showPage('urlhaus')">🚨 URLhaus</button></div>
<div class="nav-title">Hesap</div><div class="nav"><button onclick="showPage('vip')">👑 VIP</button><button onclick="showPage('history')">📜 Sorgu Geçmişi</button><button onclick="showPage('favorites')">⭐ Favoriler</button><button onclick="showPage('reports')">📄 Raporlar</button><button onclick="showPage('settings')">⚙️ Ayarlar</button></div>
<div id="adminNav" class="admin-link hidden"><div class="nav-title">Yönetim</div><div class="nav"><button onclick="showPage('admin')">👑 Admin Paneli <span class="badge">ADMIN</span></button></div></div>
</aside>
<div class="main"><div class="topbar"><button class="menu-mobile" onclick="toggleSide()">☰ Menü</button><div class="logo-right">JUST <span>OSINT</span></div></div><main class="content">
<section id="dashboard" class="page"><div class="panel hero"><h1>Just Osint</h1><p class="muted">Açık kaynaklardan teknik istihbarat. Bir hedef seç, sorgunu çalıştır ve sonuçlarını kaydet.</p><div class="grid3"><div class="stat"><b id="creditStat">-</b><span class="muted">Sorgu Kredisi</span></div><div class="stat"><b id="dailyStat">-</b><span class="muted">Bugünkü Sorgular</span></div><div class="stat"><b id="vipStat">Standart</b><span class="muted">Hesap Durumu</span></div></div></div><div class="panel"><input id="target" class="field" placeholder="IP / Domain / IOC / Username"><div class="grid"><button class="tool" onclick="runTool('ip')"><b>🌐 IP OSINT</b><small>IP itibar ve tehdit bilgileri</small></button><button class="tool" onclick="runTool('domain')"><b>🔎 DOMAIN</b><small>Alan adı ve kayıt bilgileri</small></button><button class="tool" onclick="runTool('dns')"><b>🧭 DNS</b><small>A, AAAA, MX, NS, TXT ve CNAME</small></button><button class="tool" onclick="runTool('certificates')"><b>🔒 SSL / TLS</b><small>Sertifika ve alt alan adı bilgileri</small></button><button class="tool" onclick="runTool('ioc')"><b>🛡️ IOC</b><small>Tehdit göstergesi analizi</small></button><button class="tool" onclick="runTool('search-links')"><b>👤 USERNAME</b><small>Açık kaynak kullanıcı adı araştırması</small></button><button class="tool" onclick="runTool('virustotal/domain')"><b>🦠 VirusTotal</b><small>Domain / IP / hash analizi</small></button><button class="tool" onclick="runTool('urlhaus')"><b>🚨 URLhaus</b><small>Bilinen zararlı URL/host kayıtları</small></button></div><div id="result" class="result">Bir araç seçip sorgu gönder.</div><div class="row" style="margin-top:10px"><button class="btn secondary" onclick="saveCurrent('favorite')">⭐ Favorilere Kaydet</button><button class="btn secondary" onclick="saveCurrent('report')">📄 Rapor Olarak Kaydet</button></div></div></section>
<section id="profile" class="page hidden"><div class="panel"><h1>👤 Profil</h1><div class="row"><div id="bigAvatar" class="avatar" style="width:90px;height:90px">👤</div><div><b id="profileName">-</b><p id="profileEmailView" class="muted">-</p><span id="profileBadge"></span></div></div><hr style="border-color:#26334b;border-style:solid;border-width:1px 0 0;margin:20px 0"><h2>Profil Bilgileri</h2><input id="profileNick" class="field" placeholder="Takma ad"><input id="profileEmail" class="field" type="email" placeholder="E-posta"><input id="profilePassword" class="field" type="password" placeholder="Yeni şifre"><label class="muted">Profil resmi</label><input id="avatarFile" class="field" type="file" accept="image/png,image/jpeg,image/webp,image/gif"><button class="btn" onclick="uploadAvatar()">🖼️ Profil Resmini Yükle</button><button class="btn secondary" style="margin-top:10px" onclick="saveProfile()">Değişiklikleri Kaydet</button></div><div class="panel"><h2>📊 Hesap İstatistikleri</h2><div class="grid3"><div class="stat"><b id="pQueries">-</b><span class="muted">Toplam Sorgu</span></div><div class="stat"><b id="pFavs">-</b><span class="muted">Favoriler</span></div><div class="stat"><b id="pReports">-</b><span class="muted">Raporlar</span></div></div></div><div class="panel"><h2>🔐 Güvenlik & Bağlantılar</h2><div class="notice" id="telegramStatus">Telegram bağlantısı: Kontrol ediliyor...</div><div class="notice" id="accountStatus">Hesap durumu: -</div><button class="btn danger" onclick="logout()">🚪 Çıkış Yap</button></div></section>
<section id="vip" class="page hidden"><div class="panel"><h1>👑 VIP Merkezi</h1><p class="muted">VIP durumun, rozetin ve erişim süren burada.</p><div id="vipInfo" class="result"></div></div></section>
<section id="history" class="page hidden"><div class="panel"><h1>📜 Sorgu Geçmişi</h1><div id="historyOut" class="result">Yükleniyor...</div></div></section>
<section id="favorites" class="page hidden"><div class="panel"><h1>⭐ Favoriler</h1><div id="favoritesOut" class="result">Yükleniyor...</div></div></section>
<section id="reports" class="page hidden"><div class="panel"><h1>📄 Raporlar</h1><p class="muted">Kaydettiğin sonuçları JSON olarak görüntüleyebilir ve PDF/JSON dışa aktarma için kullanabilirsin.</p><div id="reportsOut" class="result">Yükleniyor...</div></div></section>
<section id="settings" class="page hidden"><div class="panel"><h1>⚙️ Ayarlar</h1><h3>Görünüm</h3><div class="row"><button class="btn secondary" onclick="alert('Koyu tema aktif.')">🌙 Koyu Tema</button><button class="btn secondary" onclick="alert('Dil: Türkçe')">🇹🇷 Türkçe</button></div><h3>Bildirimler</h3><div class="notice">Uygulama içi duyurular ve hesap bildirimleri burada gösterilir.</div><button class="btn secondary" onclick="loadAnnouncements()">📢 Duyuruları Yenile</button><div id="announcements" class="result" style="margin-top:10px"></div></div></section>
<section id="ip" class="page hidden"><div class="panel"><h1>🌐 IP OSINT</h1><p class="muted">IP adresi için RDAP, AbuseIPDB, OTX ve ThreatFox sonuçlarını getir.</p><input id="ipTarget" class="field" placeholder="8.8.8.8"><button class="btn" onclick="runFrom('ipTarget','ip')">Sorgula</button><div id="ipOut" class="result">Sonuç yok.</div></div></section>
<section id="domain" class="page hidden"><div class="panel"><h1>🔎 Domain</h1><p class="muted">Domain kayıtları, DNS ve tehdit istihbaratı.</p><input id="domainTarget" class="field" placeholder="example.com"><button class="btn" onclick="runFrom('domainTarget','domain')">Sorgula</button><div id="domainOut" class="result">Sonuç yok.</div></div></section>
<section id="dns" class="page hidden"><div class="panel"><h1>🧭 DNS</h1><input id="dnsTarget" class="field" placeholder="example.com"><button class="btn" onclick="runFrom('dnsTarget','dns')">Sorgula</button><div id="dnsOut" class="result">Sonuç yok.</div></div></section>
<section id="ssl" class="page hidden"><div class="panel"><h1>🔒 SSL / TLS</h1><p class="muted">Herkese açık sertifika ve alt alan adı kayıtlarını incele.</p><input id="sslTarget" class="field" placeholder="example.com"><button class="btn" onclick="runFrom('sslTarget','certificates')">Sorgula</button><div id="sslOut" class="result">Sonuç yok.</div></div></section>
<section id="ioc" class="page hidden"><div class="panel"><h1>🛡️ IOC</h1><input id="iocTarget" class="field" placeholder="Domain veya hash"><button class="btn" onclick="runFrom('iocTarget','ioc')">Sorgula</button><div id="iocOut" class="result">Sonuç yok.</div></div></section>
<section id="username" class="page hidden"><div class="panel"><h1>👤 Username</h1><p class="muted">Yalnızca açık web arama bağlantıları üzerinden kullanıcı adı araştırması.</p><input id="usernameTarget" class="field" placeholder="kullaniciadi"><button class="btn" onclick="runFrom('usernameTarget','search-links')">Ara</button><div id="usernameOut" class="result">Sonuç yok.</div></div></section>
<section id="vt" class="page hidden"><div class="panel"><h1>🦠 VirusTotal</h1><p class="muted">IP, domain veya dosya hash'i gir.</p><input id="vtTarget" class="field" placeholder="IP / domain / hash"><div class="row"><button class="btn" onclick="runFrom('vtTarget','virustotal/domain')">Domain</button><button class="btn secondary" onclick="runFrom('vtTarget','virustotal/ip')">IP</button></div><div id="vtOut" class="result">Sonuç yok.</div></div></section>
<section id="urlhaus" class="page hidden"><div class="panel"><h1>🚨 URLhaus</h1><input id="urlhausTarget" class="field" placeholder="example.com"><button class="btn" onclick="runFrom('urlhausTarget','urlhaus')">Sorgula</button><div id="urlhausOut" class="result">Sonuç yok.</div></div></section>
<section id="admin" class="page hidden"><div class="panel"><h1>👑 Admin Paneli <span class="badge">ADMIN</span></h1><p class="muted">Kullanıcı, kredi, VIP, güvenlik, API, duyuru ve sistem yönetimi.</p><div class="grid3"><div class="stat"><b id="aUsers">-</b><span class="muted">Toplam Kullanıcı</span></div><div class="stat"><b id="aQueries">-</b><span class="muted">Bugünkü Sorgu</span></div><div class="stat"><b id="aVip">-</b><span class="muted">VIP Kullanıcı</span></div><div class="stat"><b id="aActive">-</b><span class="muted">Aktif Kullanıcı</span></div><div class="stat"><b id="aBanned">-</b><span class="muted">Banlı Kullanıcı</span></div><div class="stat"><b id="aTop">-</b><span class="muted">En Çok Kullanılan</span></div></div></div><div class="panel"><h2>👥 Kullanıcı Yönetimi</h2><div class="row"><input id="userSearch" class="field" placeholder="E-posta veya takma ad"><button class="btn" onclick="loadUsers()">Ara</button></div><div class="table-wrap"><table class="table"><thead><tr><th>ID</th><th>Kullanıcı</th><th>Kredi</th><th>VIP</th><th>Durum</th><th>İşlem</th></tr></thead><tbody id="usersTable"></tbody></table></div></div><div class="panel"><h2>🔌 API Merkezi</h2><div id="apiStatus" class="grid"></div></div><div class="panel"><h2>💳 Hızlı İşlem</h2><input id="actionUser" class="field" placeholder="Kullanıcı ID"><div class="row"><button class="btn" onclick="adminCredit(100)">+100 Kredi</button><button class="btn secondary" onclick="adminCredit(-100)">-100 Kredi</button><button class="btn" onclick="adminVip(30)">+30 Gün VIP</button><button class="btn danger" onclick="adminBan()">Banla</button></div></div><div class="panel"><h2>📢 Duyuru</h2><input id="annTitle" class="field" placeholder="Başlık"><textarea id="annMsg" class="field" rows="4" placeholder="Duyuru metni"></textarea><select id="annAudience" class="field"><option value="all">Tüm kullanıcılar</option><option value="vip">Sadece VIP</option></select><button class="btn" onclick="sendAnnouncement()">Duyuruyu Yayınla</button></div><div class="panel"><h2>⚙️ Sistem Ayarları</h2><div class="row"><input id="dailyLimit" class="field" type="number" placeholder="Günlük ücretsiz sorgu"><input id="queryCost" class="field" type="number" placeholder="Sorgu başına kredi"></div><button class="btn" onclick="saveAdminSettings()">Ayarları Kaydet</button></div><div class="panel"><h2>📜 Güvenlik & Admin Logları</h2><div id="adminLogs" class="result">Yükleniyor...</div></div></section>
</main></div></div>
<script>
let token=localStorage.getItem('justosint_token')||'',me=null,lastResult=null,lastQuery='';const $=id=>document.getElementById(id);
function toggleAuth(login){$('loginBox').classList.toggle('hidden',!login);$('registerBox').classList.toggle('hidden',login)}
function toggleSide(){$('sidebar').classList.toggle('open')}
function showPage(id){document.querySelectorAll('.page').forEach(x=>x.classList.add('hidden'));$(id).classList.remove('hidden');if(innerWidth<851)$('sidebar').classList.remove('open');if(id==='dashboard')loadAccount();if(id==='profile')loadProfile();if(id==='history')loadHistory();if(id==='favorites')loadFavorites();if(id==='reports')loadReports();if(id==='admin'&&me?.is_admin)loadAdmin()}
function headers(){return {'Content-Type':'application/json','Authorization':'Bearer '+token}}
async function api(url,opt={}){opt.headers=Object.assign(headers(),opt.headers||{});let r=await fetch(url,opt),d={};try{d=await r.json()}catch(_){}if(!r.ok)throw new Error(d.detail||'İşlem başarısız.');return d}
async function login(){try{let d=await api('/api/auth/login',{method:'POST',body:JSON.stringify({email:$('loginEmail').value,password:$('loginPassword').value})});token=d.token;localStorage.setItem('justosint_token',token);await loadMe();enterApp()}catch(e){$('loginMsg').textContent=e.message}}
async function register(){let p=$('regPassword').value;if(p!==$('regPassword2').value){$('registerMsg').textContent='Şifreler eşleşmiyor.';return}try{let d=await api('/api/auth/register',{method:'POST',body:JSON.stringify({email:$('regEmail').value,password:p,nickname:$('regNick').value})});token=d.token;localStorage.setItem('justosint_token',token);await loadMe();enterApp()}catch(e){$('registerMsg').textContent=e.message}}
async function loadMe(){me=await api('/api/me');$('miniName').textContent=me.nickname||'Profil';$('miniRole').textContent=me.is_admin?'ADMIN':(me.vip?'VIP Üye':'Standart Üye');$('adminNav').classList.toggle('hidden',!me.is_admin);setAvatar(me.avatar_url);$('profileName').textContent=me.nickname||'-';$('profileEmailView').textContent=me.email||'-';$('profileBadge').innerHTML=me.is_admin?'<span class="badge">ADMIN</span>':(me.vip?'<span class="badge vipbadge">VIP</span>':'');$('telegramStatus').textContent=me.telegram_linked?'Telegram bağlantısı: Bağlı':'Telegram bağlantısı: Bağlı değil';$('accountStatus').textContent=me.is_banned?'Hesap durumu: Yasaklı':'Hesap durumu: Aktif';return me}
function setAvatar(url){let html=url?'<img src="'+url+'" style="width:100%;height:100%;object-fit:cover" alt="Profil resmi">':'👤';$('miniAvatar').innerHTML=html;$('bigAvatar').innerHTML=html}
function enterApp(){$('authView').classList.add('hidden');$('appView').classList.remove('hidden');showPage('dashboard')}
function logout(){token='';me=null;localStorage.removeItem('justosint_token');$('appView').classList.add('hidden');$('authView').classList.remove('hidden');toggleAuth(true)}
async function loadAccount(){try{let d=await api('/api/account/status');$('creditStat').textContent=d.credits;$('dailyStat').textContent=d.daily_used+'/'+d.daily_free_limit;$('vipStat').textContent=d.vip?'👑 VIP':'Standart';$('vipInfo').textContent=JSON.stringify(d,null,2)}catch(e){}}
async function loadProfile(){try{let d=await loadMe();$('profileNick').value=d.nickname||'';$('profileEmail').value=d.email||'';let st=await api('/api/account/status');$('pQueries').textContent=st.total_queries||0;let f=await api('/api/favorites');let r=await api('/api/reports');$('pFavs').textContent=f.length;$('pReports').textContent=r.length}catch(e){}}
async function saveProfile(){try{await api('/api/me',{method:'PATCH',body:JSON.stringify({nickname:$('profileNick').value,email:$('profileEmail').value,password:$('profilePassword').value||null})});$('profilePassword').value='';await loadMe();alert('Profil güncellendi.')}catch(e){alert(e.message)}}
async function uploadAvatar(){let f=$('avatarFile').files[0];if(!f){alert('Önce bir profil resmi seç.');return}let fd=new FormData();fd.append('file',f);try{let r=await fetch('/api/me/avatar',{method:'POST',headers:{'Authorization':'Bearer '+token},body:fd}),d=await r.json();if(!r.ok)throw new Error(d.detail||'Yükleme başarısız.');await loadMe();alert('Profil resmi güncellendi.')}catch(e){alert(e.message)}}
async function runTool(kind){let q=$('target').value.trim();if(!q){$('result').textContent='Önce bir hedef gir.';return}await run(kind,q,$('result'))}
async function runFrom(input,kind){let q=$(input).value.trim(),out=$(input.replace('Target','Out'));if(!q){out.textContent='Önce bir hedef gir.';return}await run(kind,q,out)}
async function run(kind,q,out){out.textContent='Sorgulanıyor...';try{let suffix=kind==='search-links'?'&kind=username':'';let d=await api('/api/osint/'+kind+'?q='+encodeURIComponent(q)+suffix);lastResult=d;lastQuery=q;out.textContent=JSON.stringify(d,null,2);loadAccount()}catch(e){out.textContent=e.message}}
async function saveCurrent(type){if(!lastResult){alert('Önce bir sorgu çalıştır.');return}try{await api(type==='favorite'?'/api/favorites':'/api/reports',{method:'POST',body:JSON.stringify({title:lastQuery,query:lastQuery,result:lastResult})});alert(type==='favorite'?'Favorilere kaydedildi.':'Rapor kaydedildi.')}catch(e){alert(e.message)}}
async function loadHistory(){try{$('historyOut').textContent=JSON.stringify(await api('/api/history'),null,2)}catch(e){$('historyOut').textContent=e.message}}
async function loadFavorites(){try{$('favoritesOut').textContent=JSON.stringify(await api('/api/favorites'),null,2)}catch(e){$('favoritesOut').textContent=e.message}}
async function loadReports(){try{$('reportsOut').textContent=JSON.stringify(await api('/api/reports'),null,2)}catch(e){$('reportsOut').textContent=e.message}}
async function loadAnnouncements(){try{$('announcements').textContent=JSON.stringify(await api('/api/announcements'),null,2)}catch(e){$('announcements').textContent=e.message}}
async function loadAdmin(){try{let d=await api('/api/admin/dashboard');$('aUsers').textContent=d.total_users;$('aQueries').textContent=d.today_queries;$('aVip').textContent=d.vip_users;$('aActive').textContent=d.active_users_7d;$('aBanned').textContent=d.banned_users;$('aTop').textContent=d.most_used_tool; $('apiStatus').innerHTML=Object.entries(d.api_status).map(([k,v])=>'<div class="stat"><b>'+(v?'🟢':'🔴')+'</b><span class="muted">'+k+'</span></div>').join('');$('adminLogs').textContent=JSON.stringify(d.recent_logs,null,2);await loadUsers();let logs=await api('/api/admin/logs');$('adminLogs').textContent=JSON.stringify(logs.slice(0,100),null,2)}catch(e){$('adminLogs').textContent=e.message}}
async function loadUsers(){try{let rows=await api('/api/admin/users?search='+encodeURIComponent($('userSearch').value||''));$('usersTable').innerHTML=rows.map(u=>'<tr><td>'+u.id+'</td><td><b>'+esc(u.nickname)+'</b><br><small>'+esc(u.email)+'</small></td><td>'+u.credits+'</td><td>'+(u.vip?'👑':'-')+'</td><td>'+(u.is_banned?'🚫 Banlı':'🟢 Aktif')+'</td><td><button class="btn secondary" onclick="userDetail('+u.id+')">Görüntüle</button></td></tr>').join('')}catch(e){$('usersTable').innerHTML='<tr><td colspan="6">'+esc(e.message)+'</td></tr>'}}
function esc(s){return String(s??'').replace(/[&<>\"]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[m]))}
async function userDetail(id){try{let u=await api('/api/admin/users/'+id);$('actionUser').value=id;alert('Kullanıcı #'+u.id+'\
'+u.nickname+'\
'+u.email+'\
Kredi: '+u.credits+'\
VIP: '+(u.vip?'Evet':'Hayır')+'\
Sorgu: '+u.total_queries)}catch(e){alert(e.message)}}
async function adminCredit(amount){let id=Number($('actionUser').value);if(!id){alert('Kullanıcı ID gir.');return}try{await api('/api/admin/users/credits',{method:'POST',body:JSON.stringify({user_id:id,amount,note:'Admin hızlı işlem'})});loadAdmin()}catch(e){alert(e.message)}}
async function adminVip(days){let id=Number($('actionUser').value);if(!id){alert('Kullanıcı ID gir.');return}try{await api('/api/admin/users/vip',{method:'POST',body:JSON.stringify({user_id:id,days})});loadAdmin()}catch(e){alert(e.message)}}
async function adminBan(){let id=Number($('actionUser').value);if(!id){alert('Kullanıcı ID gir.');return}let reason=prompt('Ban sebebi:')||'';try{await api('/api/admin/users/ban',{method:'POST',body:JSON.stringify({user_id:id,reason,hours:null})});loadAdmin()}catch(e){alert(e.message)}}
async function sendAnnouncement(){try{await api('/api/admin/announcements',{method:'POST',body:JSON.stringify({title:$('annTitle').value,message:$('annMsg').value,audience:$('annAudience').value})});$('annTitle').value='';$('annMsg').value='';alert('Duyuru yayınlandı.')}catch(e){alert(e.message)}}
async function saveAdminSettings(){try{await api('/api/admin/settings',{method:'POST',body:JSON.stringify({daily_free_limit:Number($('dailyLimit').value||10),query_cost:Number($('queryCost').value||1)})});alert('Sistem ayarları kaydedildi.')}catch(e){alert(e.message)}}
if(token){loadMe().then(enterApp).catch(logout)}else toggleAuth(true)
</script></body></html>"""

@app.get("/", response_class=HTMLResponse)
async def home():
    return HTMLResponse(HTML, media_type="text/html; charset=utf-8")

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
