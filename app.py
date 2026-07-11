#!/usr/bin/env python3
"""
Config Collector Bot v6.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
نسخه تولیدی ربات جمع‌آوری و توزیع کانفیگ‌های V2Ray/VPN — Railway.com
تمام پارامترها از طریق متغیرهای محیطی قابل تنظیم در Railway هستند.

[v6.0] ویژگی‌های جدید:
  • سیستم VIP کاربران (bypass محدودیت روزانه)
  • جستجوی پیشرفته کانفیگ برای کاربران (cooldown 30s)
  • پنل ادمین شیشه‌ای با ۳۰+ دستور حرفه‌ای
  • Dedup پیشرفته بر اساس fingerprint (UUID/host/port)
  • Blacklist IP برای کانفیگ‌های مخرب
  • سیستم Abuse Detection با امتیازدهی ریسک
  • Smart Notification (کش کم، RAM بالا، خطای زیاد)
  • Broadcast حرفه‌ای (فعال، غیرفعال، VIP، همه)
  • سیستم Feedback کانفیگ توسط کاربران
  • Analytics کاربران فعال/غیرفعال
  • پروفایل کاربر (محبوب‌ترین کشور، پروتکل، آمار)
  • Version Compare هنگام Reload
  • Rule Engine ساده (شرط ← عمل)
  • DataCenter Detection مبتنی بر کلیدواژه
  • Auto Cleanup خودکار (قابل تنظیم)
  • GitHub Source Finder (هر ۵ ساعت)
  • Benchmark فشرده
  • دو زبان فارسی/انگلیسی
  • Memory Optimizer خودکار
  • Anomaly Detection (هشدار انحراف ناگهانی)
"""

# ── Standard library ──────────────────────────────────────────────────────────
import io, os, re, json, base64, random, hashlib, hmac, logging
import asyncio, time, math, sys, platform, socket, ipaddress, threading
from collections import defaultdict, OrderedDict
from datetime import datetime, timezone, timedelta
from functools import wraps
from urllib.parse import urlparse, unquote
from zoneinfo import ZoneInfo

# ── Third-party ───────────────────────────────────────────────────────────────
import aiohttp
import aiosqlite
try:
    from aiohttp_socks import ProxyConnector
    _AIOHTTP_SOCKS_AVAILABLE = True
except ImportError:
    ProxyConnector = None
    _AIOHTTP_SOCKS_AVAILABLE = False
from tenacity import retry, stop_after_attempt, wait_exponential

# ── Telegram ──────────────────────────────────────────────────────────────────
from telegram import BotCommand, InlineKeyboardButton, InlineKeyboardMarkup, Update, ForceReply
from telegram.error import BadRequest, TelegramError
from telegram.ext import (
    Application, ApplicationHandlerStop, CallbackQueryHandler,
    CommandHandler, ContextTypes, MessageHandler, filters,
)

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════════════════════
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)
# httpx/httpcore هر request موفق getUpdates را با سطح INFO لاگ می‌کنند که برخی
# پلتفرم‌های میزبانی (از جمله بعضی حالت‌های Railway) آن را اشتباهاً "error" نشان
# می‌دهند. سطح این لاگرها را بالاتر می‌بریم تا فقط لاگ‌های واقعی ما دیده شوند.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("telegram").setLevel(logging.WARNING)

# ═══════════════════════════════════════════════════════════════════════════════
# ENV HELPERS — خواندن امن متغیرهای محیطی (رفع کرش روی مقدار نامعتبر)
# ═══════════════════════════════════════════════════════════════════════════════
# قبلاً int(os.environ.get(...)) / float(os.environ.get(...)) مستقیم صدا زده
# می‌شد. اگر یک متغیر در Railway با مقدار خالی، فاصله، یا رشته‌ی غیرعددی ست
# می‌شد (مثلاً MAX_DAILY_REQUESTS="" یا "5 ")، کل پروسه همان لحظه‌ی import شدن
# ماژول با ValueError کرش می‌کرد — قبل از اینکه Config.validate() حتی فرصت
# گزارش‌دهی داشته باشد. این توابع چنین مقادیری را با لاگ هشدار به مقدار
# پیش‌فرض برمی‌گردانند تا بات فقط به‌خاطر یک متغیر محیطی خراب از کار نیفتد.
_ENV_WARNINGS: list = []

def _env_str(name: str, default: str) -> str:
    v = os.environ.get(name)
    return v if v is not None else default

def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw.strip())
    except (ValueError, TypeError):
        _ENV_WARNINGS.append(f"{name}='{raw}' عدد صحیح معتبر نیست — مقدار پیش‌فرض ({default}) استفاده شد.")
        return default

def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw.strip())
    except (ValueError, TypeError):
        _ENV_WARNINGS.append(f"{name}='{raw}' عدد اعشاری معتبر نیست — مقدار پیش‌فرض ({default}) استفاده شد.")
        return default

def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    v = raw.strip().lower()
    if v in ("true", "1", "yes", "on"):   return True
    if v in ("false", "0", "no", "off"):  return False
    _ENV_WARNINGS.append(f"{name}='{raw}' مقدار بولی معتبر نیست (true/false) — مقدار پیش‌فرض ({default}) استفاده شد.")
    return default


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIG  —  تمام متغیرها قابل تنظیم از Railway Environment Variables
# ═══════════════════════════════════════════════════════════════════════════════
class Config:
    # ── اجباری ─────────────────────────────────────────────────────────────────
    BOT_TOKEN:  str  = _env_str("BOT_TOKEN", "").strip()
    ADMIN_ID:   int  = _env_int("ADMIN_ID", 0)

    # ── کانال‌ها ────────────────────────────────────────────────────────────────
    CHANNEL_ID:       str = _env_str("CHANNEL_ID", "").strip()
    REQUIRED_CHANNEL: str = _env_str("REQUIRED_CHANNEL", "").strip()   # اگر خالی → بدون Force-Join

    # ── محدودیت کاربر ──────────────────────────────────────────────────────────
    MAX_DAILY_REQUESTS:      int = _env_int("MAX_DAILY_REQUESTS",      5)
    MAX_DAILY_CONFIGS:       int = _env_int("MAX_DAILY_CONFIGS",       50)
    MAX_CONFIGS_PER_REQUEST: int = _env_int("MAX_CONFIGS_PER_REQUEST", 500)
    VIP_MAX_DAILY_REQUESTS:  int = _env_int("VIP_MAX_DAILY_REQUESTS",  20)
    VIP_MAX_DAILY_CONFIGS:   int = _env_int("VIP_MAX_DAILY_CONFIGS",   200)

    # ── پست کانال ──────────────────────────────────────────────────────────────
    CHANNEL_POST_COUNT:          int = _env_int("CHANNEL_POST_COUNT",          10)
    CHANNEL_POST_INTERVAL:       int = _env_int("CHANNEL_POST_INTERVAL",       300)
    CHANNEL_FILTER_PROTOCOL:     str = _env_str("CHANNEL_FILTER_PROTOCOL",     "VLESS").strip().upper()
    CHANNEL_FILTER_COUNTRIES:   list = [
        c.strip().lower()
        for c in _env_str("CHANNEL_FILTER_COUNTRIES", "de,nl,fi,se,fr,gb,us,ca").split(",")
        if c.strip()
    ]

    # ── تایمینگ ─────────────────────────────────────────────────────────────────
    CACHE_REFRESH_INTERVAL: int = _env_int("CACHE_REFRESH_INTERVAL", 1200)
    AUTO_CLEANUP_INTERVAL:  int = _env_int("AUTO_CLEANUP_INTERVAL",  86400)
    GITHUB_SEARCH_INTERVAL: int = _env_int("GITHUB_SEARCH_INTERVAL", 18000)
    SEARCH_COOLDOWN:        int = _env_int("SEARCH_COOLDOWN",         30)

    # ── HTTP ─────────────────────────────────────────────────────────────────────
    FETCH_TIMEOUT:          int  = _env_int("FETCH_TIMEOUT",          15)
    MAX_CONCURRENT_FETCHES: int  = _env_int("MAX_CONCURRENT_FETCHES", 10)
    DISABLE_SSL_VERIFY:     bool = _env_bool("DISABLE_SSL_VERIFY", False)
    GITHUB_TOKEN:           str  = _env_str("GITHUB_TOKEN", "").strip()   # اختیاری، rate-limit بیشتر

    # ── کیفیت و فیلتر ───────────────────────────────────────────────────────────
    FILTER_QUALITY:  bool = _env_bool("FILTER_QUALITY",  True)
    MAX_CACHE_SIZE:  int  = _env_int("MAX_CACHE_SIZE", 50000)
    CONFIG_BRAND:    str  = _env_str("CONFIG_BRAND", "@ConfigggCollectorBot").strip()

    # ── هشدارهای هوشمند ─────────────────────────────────────────────────────────
    MIN_CACHE_NOTIFY:    int   = _env_int("MIN_CACHE_NOTIFY",    1000)
    CPU_ALERT_THRESHOLD: float = _env_float("CPU_ALERT_THRESHOLD", 85.0)
    MEM_ALERT_THRESHOLD: float = _env_float("MEM_ALERT_THRESHOLD", 80.0)
    MEM_OPTIMIZER_MB:    int   = _env_int("MEM_OPTIMIZER_MB",    350)

    # ── Abuse Detection ─────────────────────────────────────────────────────────
    ABUSE_WARN_THRESHOLD: int = _env_int("ABUSE_WARN_THRESHOLD", 10)
    ABUSE_MUTE_THRESHOLD: int = _env_int("ABUSE_MUTE_THRESHOLD", 25)
    ABUSE_BAN_THRESHOLD:  int = _env_int("ABUSE_BAN_THRESHOLD",  50)
    ABUSE_MUTE_MINUTES:   int = _env_int("ABUSE_MUTE_MINUTES",   60)

    # ── دیتابیس ──────────────────────────────────────────────────────────────────
    DB_PATH: str = _env_str("DB_PATH", "bot_database.db").strip()

    # ── زبان پیش‌فرض (fa / en) ───────────────────────────────────────────────────
    DEFAULT_LANGUAGE: str = _env_str("DEFAULT_LANGUAGE", "fa").strip().lower()

    # ── Real Ping Tester (Xray-core) ─────────────────────────────────────────────
    # هشدار منابع: روی پلن Railway با 0.5GB RAM، همزمانی بالا ریسک OOM دارد.
    # رفع باگ «تست‌شده همیشه فقط کسر کوچکی از کل کش است»: با مقادیر قبلی
    # (batch=100 هر ۵ دقیقه، concurrency=3) یک دور کامل روی استخر ~۲۰,۰۰۰
    # تایی حدود ۱۶-۱۷ ساعت طول می‌کشید — یعنی بات هرگز فرصت نمی‌کرد کل کش
    # را حتی یک‌بار تست کند، پیش از آنکه دوباره reload کش (هر ۲۰ دقیقه)
    # صورت‌مسئله را عوض کند. این باعث می‌شد وضعیت «فقط تعداد کمی زنده» دائمی
    # به‌نظر برسد، درحالی‌که مشکل واقعی «کندی چرخه‌ی تست» بود نه خرابی
    # منطق تست. مقادیر جدید محافظه‌کارانه‌تر از حداکثر ممکن ولی به‌اندازه‌ی
    # کافی سریع‌تر انتخاب شده‌اند تا یک دور کامل در حدود ۳-۴ ساعت تمام شود؛
    # هر دو مقدار هم‌چنان از طریق env قابل تنظیم‌اند اگر رم سرور اجازه نداد.
    PING_TEST_ENABLED:       bool  = _env_bool("PING_TEST_ENABLED", True)
    PING_TEST_BATCH_SIZE:    int   = _env_int("PING_TEST_BATCH_SIZE",    250)   # هر دور چند کانفیگ از کش اصلی تست شود
    PING_TEST_CONCURRENCY:   int   = _env_int("PING_TEST_CONCURRENCY",   6)     # حداکثر پروسه Xray همزمان
    PING_TEST_MEM_SAFETY_MB: int   = _env_int("PING_TEST_MEM_SAFETY_MB", 400)    # بالاتر از این RAM، دور تست رد می‌شود (محافظت OOM)
    PING_TEST_INTERVAL_SEC:  int   = _env_int("PING_TEST_INTERVAL_SEC",  180)   # هر ۳ دقیقه: دسته جدید از کش اصلی
    PING_RETEST_INTERVAL_SEC:int   = _env_int("PING_RETEST_INTERVAL_SEC",7200)  # هر ۲ ساعت: بازتست موجودی‌های قبلی
    # نکته مهم: عمداً از IP خام گوگل استفاده می‌شود (نه دامنه) با هدر Host دستی.
    # اگر از دامنه استفاده شود، در برخی شرایط ممکن است resolve/اتصال به‌جای عبور
    # از تونل SOCKS پروکسی، از مسیر دیگری (leak) انجام شود و نتیجه فالس‌پازیتیو
    # بدهد. با IP خام + هدر Host، مسیر اتصال همیشه از outbound پروکسی اجباری است.
    PING_TEST_URL:           str   = _env_str("PING_TEST_URL",   "http://142.250.72.174/generate_204").strip()
    PING_TEST_HOST_HEADER:   str   = _env_str("PING_TEST_HOST_HEADER", "www.google.com").strip()
    PING_TEST_TIMEOUT:       float = _env_float("PING_TEST_TIMEOUT", 6.0)       # ثانیه، شامل بالا آمدن xray
    PING_XRAY_STARTUP_WAIT:  float = _env_float("PING_XRAY_STARTUP_WAIT", 2.5)  # ثانیه، سقف انتظار (polling فعال) تا SOCKS آماده شود
    # سقف زمان اتصال TCP/هندشیک به سرور پروکسی (نه کل تست HTTP) — قابل تنظیم
    # از Railway. قبلاً این مقدار به‌صورت هاردکد 1.5 ثانیه بود؛ روی سرورهای
    # دوردست یا با لینک ضعیف باعث رد شدن کانفیگ‌های سالم اما کمی کند می‌شد.
    _CONNECT_TIMEOUT:        float = _env_float("CONNECT_TIMEOUT", 1.5)

    PING_GOOD_MS:            int   = _env_int("PING_GOOD_MS",  300)    # زیر این → 🟢
    PING_OK_MS:              int   = _env_int("PING_OK_MS",    800)    # زیر این → 🟡، بالاتر → 🔴
    PING_MAX_TESTED_STORE:   int   = _env_int("PING_MAX_TESTED_STORE", 2000)    # سقف نگهداری کانفیگ‌های تست‌شده
    MAX_ARCHIVED_CONFIGS:    int   = _env_int("MAX_ARCHIVED_CONFIGS", 20000)    # سقف نگهداری آرشیو کانفیگ‌های حذف‌شده
    # آدرس عمومی پنل تحت وب (dashboard.py) روی Railway — برای ساخت لینک‌های
    # «ساب من» و «پنل ادمین تحت وب» مستقیماً از داخل خودِ بات. باید دقیقاً
    # همان دامنه‌ای باشد که از Generate Domain در Railway گرفته‌اید، بدون
    # اسلش انتهایی (مثال: https://your-app.up.railway.app).
    WEBDASH_PUBLIC_URL:      str   = _env_str("WEBDASH_PUBLIC_URL", "").strip().rstrip("/")
    # باید دقیقاً همان مقداری باشد که در dashboard.py برای SUB_LINK_SECRET
    # ست کرده‌اید — چون بات و پنل وب باید یک کلید امضای مشترک داشته باشند
    # تا لینکی که بات می‌سازد، توسط پنل وب هم معتبر تشخیص داده شود.
    SUB_LINK_SECRET:         str   = _env_str("SUB_LINK_SECRET", "change-me-in-railway-env").strip()
    ADMIN_PANEL_TOKEN:       str   = _env_str("ADMIN_PANEL_TOKEN", "").strip()
    XRAY_BIN_PATH:           str   = _env_str("XRAY_BIN_PATH", "/tmp/xray_bin/xray").strip()
    XRAY_DOWNLOAD_VERSION:   str   = _env_str("XRAY_DOWNLOAD_VERSION", "v26.6.27").strip()
    # رفع باگ «حذف فوری بعد از یک بار تست ناموفق»: قبلاً purge_dead_tested_configs
    # با max_fail_streak=1 صدا زده می‌شد، یعنی همان اولین شکست (که می‌تواند
    # صرفاً نوسان لحظه‌ای شبکه یا تأخیر بالای موقت باشد، نه خرابی واقعی کانفیگ)
    # باعث حذف دائمی از جدول tested_configs می‌شد. حالا یک کانفیگ باید
    # PING_FAIL_TOLERANCE بار پیاپی شکست بخورد تا از استخر تست‌شده حذف شود؛
    # مهم‌تر از آن، این حذف فقط از جدول tested_configs است — کانفیگ همچنان در
    # کش خام منابع (CacheManager._cache) باقی می‌ماند و در دور بعدی
    # cron_ping_test_batch دوباره شانس تست شدن دارد.
    PING_FAIL_TOLERANCE:     int   = _env_int("PING_FAIL_TOLERANCE", 3)

    # ── ConfigReputation — سقف حافظه (رفع رشد بی‌نهایت دیکشنری کش) ──────────────
    REPUTATION_MAX_ENTRIES:  int   = _env_int("REPUTATION_MAX_ENTRIES", 20000)

    @classmethod
    def validate(cls) -> None:
        missing = [k for k, v in [("BOT_TOKEN", cls.BOT_TOKEN), ("ADMIN_ID", str(cls.ADMIN_ID))]
                   if not v or v == "0"]
        if missing:
            raise ValueError(f"❌ متغیرهای اجباری: {', '.join(missing)}")
        logger.info("✅ تنظیمات تأیید شد.")
        if cls.DISABLE_SSL_VERIFY:
            logger.warning(
                "⚠️  DISABLE_SSL_VERIFY=true — تأیید گواهی SSL برای دریافت منابع "
                "غیرفعال است؛ بات در برابر حملات Man-in-the-Middle روی این اتصالات "
                "آسیب‌پذیر می‌شود. فقط در صورت نیاز واقعی (مثلاً منبع داخلی با "
                "گواهی self-signed) فعال نگه دارید.")
        # هر متغیر محیطی که مقدار نامعتبر داشته (و به پیش‌فرض بازگردانده شده) را
        # اینجا با صدای بلند (WARNING، نه فقط silent fallback) گزارش می‌دهیم تا
        # ادمین در لاگ‌های Railway متوجه‌ی خرابی مقدار شود.
        for w in _ENV_WARNINGS:
            logger.warning(f"⚠️  متغیر محیطی نامعتبر: {w}")
        if not _ENV_WARNINGS:
            logger.info("✅ همه‌ی متغیرهای محیطی عددی/بولی معتبر بودند.")


# ═══════════════════════════════════════════════════════════════════════════════
# منابع پیش‌فرض
# ═══════════════════════════════════════════════════════════════════════════════
DEFAULT_SOURCES: list = [
    "https://sub.whitedns.shop/sub/base64.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/FRAGMENT",
    "https://raw.githubusercontent.com/ShadowException/VPN/refs/heads/main/configs/VPN-cat",
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub3.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha.txt",
    "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/subscriptions/all.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://mifa.world/ss", "https://mifa.world/trojan", "https://mifa.world/hysteria",
    "https://mifa.world/other", "https://mifa.world/vmess", "https://mifa.world/vless",
    "https://raw.githubusercontent.com/pytimusprime/FreeV2ray/refs/heads/main/all_servers.txt",
    "https://raw.githubusercontent.com/ThomasJasperthecat/sub/main/sublist1.txt",
    "https://raw.githubusercontent.com/masir-sefid/Sub/main/@Masir_Sefid.txt",
    "https://raw.githubusercontent.com/AmyraxVPN-Main/AmyraxVPN/refs/heads/main/AmyraxVPN.txt",
    "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html",
    "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt",
    "https://raw.githubusercontent.com/DukeMehdi/FreeList-V2ray-Configs/refs/heads/main/Configs/VLESS-DukeMehdi-Configs.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix.txt",
    "https://raw.githubusercontent.com/YawStar/Proxy-Hunter/refs/heads/main/configs/proxy_configs_tested.txt",
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/countries/us/mixed",
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/countries/jp/mixed",
    # ── درخواست‌شده توسط ادمین (اضافه شد) ──────────────────────────────────
    "https://raw.githubusercontent.com/flaafix/AetrisVPN/refs/heads/main/AetrisVPN.txt",
    "https://raw.githubusercontent.com/sinavm/SVM/main/subscriptions/xray/normal/mix",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/vless.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha-All-Type.txt",
]

# منابعی که ادمین صریحاً درخواست حذف داده — چه در DEFAULT_SOURCES بالا نباشند
# (نسخه‌های تازه) چه در جدول sources یک نصب قدیمی‌تر از قبل موجود باشند، این
# لیست هم برای فیلتر seed اولیه و هم برای حذف واقعی رکوردهای موجود در دیتابیس
# (در init_db، هر بار در استارتاپ) استفاده می‌شود تا نصب‌های در حال اجرا هم
# این منابع را واقعاً از دست بدهند، نه فقط نصب‌های تازه.
REMOVED_SOURCES: list = [
    "https://raw.githubusercontent.com/10ium/HiN-VPN/main/subscription/normal/trojan",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
]

# کلید تنظیم روشن/خاموش دکمه‌ی «کانفیگ‌های پینگ گرفته‌شده» در منوی اصلی —
# طبق درخواست ادمین، این دکمه باید هر وقت خواست بتواند از پنل خاموش/روشن شود.
SETTING_TESTED_BTN = "show_tested_configs_button"

async def _tested_btn_enabled() -> bool:
    return (await DatabaseManager.get_setting(SETTING_TESTED_BTN, "1")) == "1"

def sign_user_id(user_id: int) -> str:
    """
    امضای HMAC یک user_id — باید دقیقاً همان الگوریتم dashboard.py را دنبال
    کند (همان کلید SUB_LINK_SECRET، همان هش SHA-256، همان برش ۱۶ کاراکتری)
    تا لینکی که خودِ بات می‌سازد، توسط پنل وب هم معتبر تشخیص داده شود.
    """
    mac = hmac.new(Config.SUB_LINK_SECRET.encode(), str(user_id).encode(), hashlib.sha256)
    return mac.hexdigest()[:16]

def webdash_configured() -> bool:
    return bool(Config.WEBDASH_PUBLIC_URL)

def user_sub_url(user_id: int) -> str:
    return f"{Config.WEBDASH_PUBLIC_URL}/sub/{user_id}/{sign_user_id(user_id)}"

def admin_panel_url() -> str:
    return f"{Config.WEBDASH_PUBLIC_URL}/admin?token={Config.ADMIN_PANEL_TOKEN}"

# ═══════════════════════════════════════════════════════════════════════════════
# نقشه کشورها
# ═══════════════════════════════════════════════════════════════════════════════
COUNTRY_MAP: dict = {
    "de": ("🇩🇪","آلمان"),      "nl": ("🇳🇱","هلند"),       "fi": ("🇫🇮","فنلاند"),
    "se": ("🇸🇪","سوئد"),      "fr": ("🇫🇷","فرانسه"),     "gb": ("🇬🇧","انگلستان"),
    "us": ("🇺🇸","آمریکا"),    "ca": ("🇨🇦","کانادا"),     "jp": ("🇯🇵","ژاپن"),
    "sg": ("🇸🇬","سنگاپور"),   "ru": ("🇷🇺","روسیه"),      "ua": ("🇺🇦","اوکراین"),
    "br": ("🇧🇷","برزیل"),     "au": ("🇦🇺","استرالیا"),   "in": ("🇮🇳","هند"),
    "kr": ("🇰🇷","کره جنوبی"), "tr": ("🇹🇷","ترکیه"),      "at": ("🇦🇹","اتریش"),
    "ch": ("🇨🇭","سوئیس"),     "pl": ("🇵🇱","لهستان"),     "cz": ("🇨🇿","چک"),
    "ro": ("🇷🇴","رومانی"),    "hu": ("🇭🇺","مجارستان"),   "lt": ("🇱🇹","لیتوانی"),
    "lv": ("🇱🇻","لتونی"),     "ee": ("🇪🇪","استونی"),     "no": ("🇳🇴","نروژ"),
    "dk": ("🇩🇰","دانمارک"),   "es": ("🇪🇸","اسپانیا"),    "it": ("🇮🇹","ایتالیا"),
}
_UNKNOWN_COUNTRY = ("🏳️","نامشخص")

def country_display(code: str, lang: str = "fa") -> str:
    if code == "ALL":
        return "🌍 همه لوکیشن‌ها" if lang == "fa" else "🌍 All Locations"
    flag, name_fa = COUNTRY_MAP.get(code, _UNKNOWN_COUNTRY)
    return f"{flag} {name_fa}"

# ═══════════════════════════════════════════════════════════════════════════════
# I18N — دو زبان فارسی و انگلیسی
# ═══════════════════════════════════════════════════════════════════════════════
_T: dict = {
    "fa": {
        "welcome":           "🤖 *ربات مدیریت کانفیگ V2Ray*",
        "loading":           "🔄 در حال بارگذاری کش...",
        "get_configs":       "📦 دریافت کانفیگ",
        "random_cfg":        "🎲 کانفیگ تصادفی",
        "filter_proto":      "🔧 فیلتر پروتکل",
        "filter_country":    "🌍 فیلتر کشور",
        "search_cfg":        "🔍 جستجوی کانفیگ",
        "my_profile":        "👤 پروفایل من",
        "admin_panel":       "👑 پنل ادمین",
        "back":              "🔙 بازگشت",
        "cancel":            "❌ انصراف",
        "join_channel":      "📢 عضویت در کانال",
        "force_join_msg":    "🔒 برای دسترسی باید در کانال ما عضو باشید 👇",
        "daily_limit":       "⚠️ سقف روزانه تمام شده. فردا مجدداً تلاش کنید.",
        "no_configs":        "❌ کانفیگی با این فیلترها یافت نشد.",
        "enter_count":       "🔢 چند کانفیگ می‌خواهید؟",
        "enter_search":      "🔍 عبارت جستجو را وارد کنید:\n\nمثال: `germany vless` یا `us reality`",
        "search_cooldown":   "⏳ تا {sec} ثانیه دیگر صبر کنید.",
        "search_results":    "🔍 {count} کانفیگ یافت شد. چند تا می‌خواهید؟",
        "search_none":       "❌ کانفیگی با این عبارت یافت نشد.",
        "feedback_prompt":   "❗ گزارش مشکل",
        "feedback_sent":     "✅ گزارش شما ثبت شد. ممنون!",
        "feedback_not_work": "❌ کار نمی‌کند",
        "feedback_slow":     "🐌 پینگ بالا",
        "feedback_weak":     "📶 اتصال ضعیف",
        "vip_badge":         "⭐ VIP",
        "lang_toggle":       "🌐 English",
        "proto_select":      "🔧 پروتکل مورد نظر:",
        "country_select":    "🌍 کشور مقصد:",
        "sent_file":         "📦 {n} کانفیگ",
        "abuse_warned":      "⚠️ هشدار: رفتار غیرعادی شناسایی شد.",
        "muted":             "🔇 دسترسی شما موقتاً محدود شده است.",
        "invalid_number":    "❌ عدد صحیح مثبت وارد کنید.",
        "search_empty":      "❌ عبارت جستجو نمی‌تواند خالی باشد.",
        "tested_disabled":   "این قابلیت موقتاً غیرفعال است.",
    },
    "en": {
        "welcome":           "🤖 *V2Ray Config Manager Bot*",
        "loading":           "🔄 Loading cache...",
        "get_configs":       "📦 Get Configs",
        "random_cfg":        "🎲 Random Config",
        "filter_proto":      "🔧 Filter Protocol",
        "filter_country":    "🌍 Filter Country",
        "search_cfg":        "🔍 Search Config",
        "my_profile":        "👤 My Profile",
        "admin_panel":       "👑 Admin Panel",
        "back":              "🔙 Back",
        "cancel":            "❌ Cancel",
        "join_channel":      "📢 Join Channel",
        "force_join_msg":    "🔒 Please join our channel to get access 👇",
        "daily_limit":       "⚠️ Daily limit reached. Try again tomorrow.",
        "no_configs":        "❌ No configs found with these filters.",
        "enter_count":       "🔢 How many configs do you want?",
        "enter_search":      "🔍 Enter your search query:\n\nExample: `germany vless` or `us reality`",
        "search_cooldown":   "⏳ Wait {sec} more seconds.",
        "search_results":    "🔍 Found {count} configs. How many do you want?",
        "search_none":       "❌ No configs found for this query.",
        "feedback_prompt":   "❗ Report Issue",
        "feedback_sent":     "✅ Feedback recorded. Thank you!",
        "feedback_not_work": "❌ Not Working",
        "feedback_slow":     "🐌 High Ping",
        "feedback_weak":     "📶 Weak Connection",
        "vip_badge":         "⭐ VIP",
        "lang_toggle":       "🌐 فارسی",
        "proto_select":      "🔧 Select protocol:",
        "country_select":    "🌍 Select country:",
        "sent_file":         "📦 {n} Configs",
        "abuse_warned":      "⚠️ Warning: abnormal behavior detected.",
        "muted":             "🔇 Your access has been temporarily restricted.",
        "invalid_number":    "❌ Please enter a positive whole number.",
        "search_empty":      "❌ Search query cannot be empty.",
        "tested_disabled":   "This feature is currently disabled.",
    },
}

def T(key: str, lang: str = "fa", **kw) -> str:
    s = _T.get(lang, _T["fa"]).get(key, _T["fa"].get(key, key))
    return s.format(**kw) if kw else s

# ═══════════════════════════════════════════════════════════════════════════════
# DataCenter Detection — شناسایی ارائه‌دهنده هاستینگ از روی hostname
# ═══════════════════════════════════════════════════════════════════════════════
_DC_MAP = {
    "hetzner": "Hetzner", "hetzner.cloud": "Hetzner",
    "ovh": "OVH", "ovhcloud": "OVH",
    "contabo": "Contabo",
    "digitalocean": "DigitalOcean", "droplet": "DigitalOcean",
    "vultr": "Vultr",
    "amazonaws": "AWS", "aws": "AWS",
    "azure": "Azure",
    "cloud.google": "GCP", "gce": "GCP", "gcp": "GCP",
    "alibaba": "Alibaba", "aliyun": "Alibaba",
    "oracle": "Oracle Cloud",
    "linode": "Akamai/Linode", "akamai": "Akamai/Linode",
    "cloudflare": "Cloudflare",
    "fastly": "Fastly",
    "upcloud": "UpCloud",
    "ionos": "IONOS",
    "scaleway": "Scaleway",
}

def detect_datacenter(host: str) -> str:
    h = host.lower()
    for kw, dc in _DC_MAP.items():
        if kw in h:
            return dc
    return "Unknown"


# ═══════════════════════════════════════════════════════════════════════════════
# BrandingEngine — پاک‌سازی رمارک و اعمال برند
# ═══════════════════════════════════════════════════════════════════════════════
class BrandingEngine:
    @classmethod
    def apply(cls, cfg: str) -> str:
        brand = Config.CONFIG_BRAND
        cfg   = cfg.strip()
        try:
            if cfg.lower().startswith("vmess://"):
                return cls._brand_vmess(cfg, brand)
            return cls._brand_uri(cfg, brand)
        except Exception:
            return cls._brand_uri(cfg, brand)

    @classmethod
    def _brand_vmess(cls, cfg: str, brand: str) -> str:
        b64 = cfg[8:].strip() + "=" * ((4 - len(cfg[8:].strip()) % 4) % 4)
        try:
            data = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
        except Exception as exc:
            # رفع باگ «از دست رفتن برند در کانفیگ‌های Vmess معیوب»: قبلاً این
            # fallback کاملاً بی‌صدا بود. توجه: fallback به _brand_uri فقط
            # کاراکتر '#brand' را بعد از رشته‌ی base64 خام اضافه می‌کند — این
            # فیلد "ps" واقعی داخل JSON (که کلاینت‌های vmess معمولاً برای
            # نمایش نام کانفیگ استفاده می‌کنند) را تغییر نمی‌دهد، پس برندسازی
            # عملاً از دست می‌رود، هرچند اتصال همچنان کار می‌کند. حالا این
            # اتفاق لاگ می‌شود تا مشخص شود چند درصد کانفیگ‌های vmess برند
            # نمی‌گیرند و چرا (معمولاً یعنی منبع، JSON بدفرمت تولید کرده).
            logger.warning(f"BrandingEngine: پارس JSON کانفیگ vmess ناموفق — برند به fragment منتقل شد (نه فیلد ps): {exc}")
            return cls._brand_uri(cfg, brand)
        data["ps"] = brand
        new_b64 = base64.b64encode(
            json.dumps(data, ensure_ascii=False, separators=(",",":")).encode()
        ).decode()
        return f"vmess://{new_b64}"

    @classmethod
    def _brand_uri(cls, cfg: str, brand: str) -> str:
        if "#" in cfg:
            cfg = cfg[:cfg.index("#")]
        return f"{cfg}#{brand}"

# ═══════════════════════════════════════════════════════════════════════════════
# CountryDetector — تشخیص کشور صرفاً regex-based
# ═══════════════════════════════════════════════════════════════════════════════
class CountryDetector:
    """
    رفع درخواست «فیلتر کشور بسیار حرفه‌ای‌تر شود» + رفع باگ ضمنی «کانفیگ‌های
    منابع با ریمارک استیکری/ایموجی انگار حذف می‌شوند»: نسخه‌ی قبلی فقط به
    نام فارسی کشور در COUNTRY_MAP و یک regex ساده‌ی دو-حرفی وابسته بود. یک
    ریمارک مثل «🇩🇪 Germany #1 🔥» یا «DE-Premium-01» یا شهرهایی مثل
    Frankfurt/Amsterdam اصلاً تشخیص داده نمی‌شد و کانفیگ به‌عنوان «ALL»
    (نامشخص) ثبت می‌شد — این یعنی از دید فیلتر کشور کاربر، انگار کانفیگ
    اصلاً وجود نداشت (نه اینکه واقعاً حذف شده باشد، ولی حسِ «حذف‌شدن» را
    القا می‌کند). نسخه‌ی جدید این منابع را هم بررسی می‌کند:
      • ایموجی پرچم کشور (خیلی از منابع دقیقاً همین را در ریمارک می‌گذارند)
      • نام انگلیسی کامل کشور (نه فقط فارسی)
      • کد ISO-3166 آلفا-۲ با مرزبندی صحیح کلمه (نه یک substring خام)
      • نام شهرهای پرکاربرد هاستینگ/VPN (فرانکفورت، آمستردام، سنگاپور، ...)
    ترتیب اولویت: پرچم ایموجی > نام کامل کشور (fa/en) > نام شهر > کد دو-حرفی.
    """
    _HOST_RE   = re.compile(r"@([^:/@\s?#\[\]]+)", re.IGNORECASE)
    _CODE_SEP  = re.compile(r"(?:^|[-_./ |,])([a-zA-Z]{2})(?:[-_./ |,]|$)")

    # پرچم‌های ایموجی → کد کشور (تولید خودکار از COUNTRY_MAP + چند مورد رایج
    # اضافه که ممکن است در COUNTRY_MAP نباشند اما در ریمارک منابع دیده شوند).
    _FLAG_TO_CODE: dict = {}

    # نام انگلیسی کشورها — برای کشورهایی که فقط نام فارسی در COUNTRY_MAP دارند.
    _EN_NAMES: dict = {
        "de":"germany", "nl":"netherlands", "fi":"finland", "se":"sweden",
        "fr":"france", "gb":"united kingdom", "us":"united states", "ca":"canada",
        "jp":"japan", "sg":"singapore", "ru":"russia", "ua":"ukraine",
        "br":"brazil", "au":"australia", "in":"india", "kr":"south korea",
        "tr":"turkey", "at":"austria", "ch":"switzerland", "pl":"poland",
        "cz":"czech", "ro":"romania", "hu":"hungary", "lt":"lithuania",
        "lv":"latvia", "ee":"estonia", "no":"norway", "dk":"denmark",
        "es":"spain", "it":"italy",
    }
    # اسم‌های رایج شهرهای هاستینگ/دیتاسنتر که در ریمارک‌ها به‌جای اسم کشور
    # استفاده می‌شوند.
    _CITY_TO_CODE: dict = {
        "frankfurt":"de", "berlin":"de", "munich":"de", "nuremberg":"de", "falkenstein":"de",
        "amsterdam":"nl",
        "helsinki":"fi",
        "stockholm":"se",
        "paris":"fr", "marseille":"fr", "strasbourg":"fr", "gravelines":"fr", "roubaix":"fr",
        "london":"gb", "manchester":"gb",
        "newyork":"us", "new york":"us", "losangeles":"us", "los angeles":"us",
        "dallas":"us", "chicago":"us", "seattle":"us", "miami":"us", "ashburn":"us",
        "sanjose":"us", "san jose":"us", "sunnyvale":"us", "portland":"us", "vint hill":"us",
        "toronto":"ca", "montreal":"ca",
        "tokyo":"jp", "osaka":"jp",
        "singapore":"sg",
        "moscow":"ru", "petersburg":"ru", "moskva":"ru",
        "kyiv":"ua", "kiev":"ua",
        "saopaulo":"br", "sao paulo":"br",
        "sydney":"au", "melbourne":"au",
        "mumbai":"in", "bangalore":"in", "delhi":"in", "chennai":"in",
        "seoul":"kr",
        "istanbul":"tr", "ankara":"tr",
        "vienna":"at",
        "zurich":"ch", "geneva":"ch",
        "warsaw":"pl",
        "prague":"cz",
        "bucharest":"ro",
        "budapest":"hu",
        "vilnius":"lt",
        "riga":"lv",
        "tallinn":"ee",
        "oslo":"no",
        "copenhagen":"dk",
        "madrid":"es", "barcelona":"es",
        "milan":"it", "rome":"it",
    }

    @classmethod
    def _build_flag_map(cls) -> dict:
        if cls._FLAG_TO_CODE:
            return cls._FLAG_TO_CODE
        for code, (flag, _name) in COUNTRY_MAP.items():
            cls._FLAG_TO_CODE[flag] = code
        return cls._FLAG_TO_CODE

    @classmethod
    def detect(cls, cfg: str) -> str:
        cfg_lower = cfg.lower()
        hostname = remark = ""
        if cfg_lower.startswith("vmess://"):
            try:
                b64  = cfg[8:].strip()
                b64 += "=" * ((4 - len(b64) % 4) % 4)
                data     = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
                hostname = str(data.get("add","")).lower()
                remark   = str(data.get("ps",""))   # پرچم ایموجی حساس به کوچک/بزرگی نیست ولی case اصلی متن حفظ شود
            except Exception:
                pass
        else:
            m = cls._HOST_RE.search(cfg)
            if m: hostname = m.group(1).lower()
            if "#" in cfg: remark = unquote(cfg[cfg.index("#")+1:])

        remark_lower = remark.lower()
        blob = f"{cfg_lower} {hostname} {remark_lower}"

        # ۱) پرچم ایموجی — قوی‌ترین سیگنال، چون تقریباً هرگز اشتباه نیست.
        flag_map = cls._build_flag_map()
        for flag, code in flag_map.items():
            if flag in remark:
                return code

        # ۲) نام کامل کشور — فارسی (از COUNTRY_MAP) یا انگلیسی.
        for code, (_, name_fa) in COUNTRY_MAP.items():
            if name_fa in blob:
                return code
        for code, name_en in cls._EN_NAMES.items():
            if name_en in blob:
                return code

        # ۳) نام شهرهای پرکاربرد هاستینگ/VPN.
        blob_compact = re.sub(r"[-_.]", "", blob)
        for city, code in cls._CITY_TO_CODE.items():
            city_compact = city.replace(" ", "")
            if city in blob or city_compact in blob_compact:
                return code

        # ۴) کد دو-حرفی با مرزبندی صحیح کلمه (نه substring خام — رفع باگ
        # false-positive قدیمی مثل «us» داخل کلمه‌ی «house» یا «trust»).
        for src in (remark_lower, hostname):
            if not src: continue
            for m in cls._CODE_SEP.finditer(src):
                c = m.group(1).lower()
                if c in COUNTRY_MAP: return c
            for part in re.split(r"[-_./|, ]", src):
                if len(part) == 2 and part in COUNTRY_MAP: return part

        return "ALL"


# ═══════════════════════════════════════════════════════════════════════════════
# AdvancedDeduplicator — dedup بر اساس fingerprint (نه فقط رشته مساوی)
# ═══════════════════════════════════════════════════════════════════════════════
class AdvancedDeduplicator:
    """
    fingerprint = sha256(normalized_key)
    کلید نرمال‌سازی‌شده:
      vmess  → add:port:id
      others → host:port:uuid_or_first64chars_of_path
    """
    _HOST_PORT_RE = re.compile(r"@([^:/@\s?#\[\]]+):(\d{1,5})")
    _UUID_RE      = re.compile(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
    )

    @classmethod
    def fingerprint(cls, cfg: str) -> str:
        cfg = cfg.strip()
        lower = cfg.lower()
        try:
            if lower.startswith("vmess://"):
                b64  = cfg[8:].strip()
                b64 += "=" * ((4 - len(b64) % 4) % 4)
                d    = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
                key  = f"{d.get('add','')}:{d.get('port','')}:{d.get('id','')}"
                return hashlib.sha256(key.lower().encode()).hexdigest()[:16]

            m_hp = cls._HOST_PORT_RE.search(cfg)
            host = m_hp.group(1).lower() if m_hp else ""
            port = m_hp.group(2)         if m_hp else "0"
            m_uuid = cls._UUID_RE.search(cfg)
            uid  = m_uuid.group(0).lower() if m_uuid else cfg[10:74]
            key  = f"{host}:{port}:{uid}"
            return hashlib.sha256(key.encode()).hexdigest()[:16]
        except Exception:
            return hashlib.sha256(cfg[:128].encode()).hexdigest()[:16]

# ═══════════════════════════════════════════════════════════════════════════════
# IPBlacklist — بلاک IP های مخرب
# ═══════════════════════════════════════════════════════════════════════════════
class IPBlacklist:
    _set: set = set()   # in-memory fast lookup

    @classmethod
    def load(cls, ips: list) -> None:
        cls._set = set(ips)

    @classmethod
    def add(cls, ip: str) -> None:
        cls._set.add(ip.strip())

    @classmethod
    def is_blocked(cls, ip_or_host: str) -> bool:
        return ip_or_host.strip() in cls._set

    @classmethod
    def extract_host(cls, cfg: str) -> str:
        m = re.search(r"@([^:/@\s?#\[\]]+)", cfg)
        return m.group(1) if m else ""

    @classmethod
    def config_is_blocked(cls, cfg: str) -> bool:
        host = cls.extract_host(cfg)
        return bool(host) and cls.is_blocked(host)

# ═══════════════════════════════════════════════════════════════════════════════
# SSRFGuard — جلوگیری از افزودن منبع داخلی/مخرب از طریق /addsource
# ═══════════════════════════════════════════════════════════════════════════════
# رفع باگ «امکان SSRF»: قبلاً /addsource فقط scheme و netloc را چک می‌کرد و
# هیچ اعتبارسنجی روی خودِ آدرس IP انجام نمی‌داد. یک ادمین (یا هر کسی که به
# این دستور دسترسی پیدا کند) می‌توانست یک URL داخلی مثل
# http://169.254.169.254/latest/meta-data (سرویس متادیتای AWS/GCP/Railway
# داخلی) یا http://localhost:PORT اضافه کند و بات (که خودش fetch را انجام
# می‌دهد) را وادار به درخواست به شبکه‌ی داخلی کانتینر کند. این کلاس هاست را
# resolve کرده و هر IP بازگشتی را در برابر بازه‌های خصوصی/loopback/link-local
# چک می‌کند — نه فقط ظاهر رشته‌ی URL را.
class SSRFGuard:
    @staticmethod
    def _is_dangerous_ip(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return True   # اگر حتی parse نشد، برای احتیاط مسدود می‌کنیم
        return (
            ip.is_private or ip.is_loopback or ip.is_link_local or
            ip.is_multicast or ip.is_reserved or ip.is_unspecified or
            ip.is_site_local
        )

    @classmethod
    async def is_safe_url(cls, url: str) -> "tuple[bool, str]":
        """
        برمی‌گرداند (safe, reason_if_unsafe).

        رفع باگ «بلاک‌شدن event loop روی /addsource»: قبلاً socket.getaddrinfo
        (که یک فراخوانی synchronous و کند شبکه است) مستقیم داخل یک تابع async
        صدا زده می‌شد. چون این تابع خودش await نمی‌کرد، در عمل کل event loop
        بات (یعنی رسیدگی به تمام کاربران دیگر هم‌زمان) تا تمام‌شدن resolve
        دامنه فریز می‌شد. حالا resolve با loop.run_in_executor در یک ترد
        جداگانه اجرا می‌شود تا event loop اصلی هرگز بلاک نشود.
        """
        try:
            parsed = urlparse(url)
        except Exception:
            return False, "URL قابل‌پارس نیست."
        if parsed.scheme not in ("http", "https"):
            return False, "فقط http/https مجاز است."
        host = parsed.hostname
        if not host:
            return False, "میزبان (host) در URL یافت نشد."
        host_lower = host.lower()
        if host_lower in ("localhost", "metadata", "metadata.google.internal"):
            return False, f"میزبان '{host}' مسدود است (آدرس داخلی/متادیتا)."
        # اگر خودِ host یک IP لیترال باشد
        try:
            ipaddress.ip_address(host)
            if cls._is_dangerous_ip(host):
                return False, f"آدرس IP '{host}' در بازه‌ی خصوصی/داخلی/متادیتا است."
            return True, ""
        except ValueError:
            pass   # host یک دامنه است، نه IP خام — باید resolve شود
        # Resolve دامنه و چک همه‌ی IP های بازگشتی (defense-in-depth در برابر
        # DNS rebinding: اگر حتی یکی از IP ها خطرناک باشد، کل URL رد می‌شود).
        try:
            loop = asyncio.get_running_loop()
            infos = await loop.run_in_executor(None, socket.getaddrinfo, host, None)
        except Exception as exc:
            return False, f"resolve نام دامنه ناموفق بود: {exc}"
        resolved_ips = {info[4][0] for info in infos}
        if not resolved_ips:
            return False, "هیچ IP ای برای این دامنه resolve نشد."
        for ip_str in resolved_ips:
            if cls._is_dangerous_ip(ip_str):
                return False, f"دامنه به آدرس داخلی/خصوصی ({ip_str}) resolve می‌شود."
        return True, ""

# ═══════════════════════════════════════════════════════════════════════════════
# HoneyPotDetector — تشخیص سرورهای مشکوک بر اساس heuristics
# ═══════════════════════════════════════════════════════════════════════════════
class HoneyPotDetector:
    # پورت‌های بسیار کم که ممکن است honeypot باشند
    _SUSPICIOUS_PORTS = {22, 23, 25, 80, 110, 143, 443, 8080, 8443}  # پورت‌های خیلی رایج
    _HONEYPOT_HOSTS   = re.compile(
        r"(honeypot|canary|trap|decoy|sinker|tarpit)", re.IGNORECASE
    )

    @classmethod
    def is_suspicious(cls, cfg: str) -> bool:
        if cls._HONEYPOT_HOSTS.search(cfg):
            return True
        m = re.search(r":(\d{1,5})[?#/]", cfg)
        if m:
            port = int(m.group(1))
            # پورت‌های خیلی کم (زیر 1024) برای VPN مشکوک هستند
            if 0 < port < 1024:
                return True
        return False

# ═══════════════════════════════════════════════════════════════════════════════
# QualityFilter — فیلتر کیفیت پیشرفته
# ═══════════════════════════════════════════════════════════════════════════════
class QualityFilter:
    _PRIVATE_RE = re.compile(
        r"@(127\.\d+\.\d+\.\d+|0\.0\.0\.0"
        r"|10\.\d+\.\d+\.\d+"
        r"|192\.168\.\d+\.\d+"
        r"|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)"
    )
    _LOCALHOST_RE = re.compile(r"@(localhost|local|127\.0\.0\.1)", re.IGNORECASE)

    @classmethod
    def is_quality(cls, cfg: str) -> bool:
        if len(cfg) < 20 or len(cfg) > 2048:        return False
        if cls._PRIVATE_RE.search(cfg):              return False
        if cls._LOCALHOST_RE.search(cfg):            return False
        if IPBlacklist.config_is_blocked(cfg):       return False
        if HoneyPotDetector.is_suspicious(cfg):      return False
        # رفع باگ «حذف کانفیگ‌های معتبر VLESS»: قبلاً اینجا هر کانفیگ
        # VLESS/Trojan با security=none و type=tcp (یا بدون این پارامترها)
        # به‌عنوان «غیرکیفی» رد می‌شد. این ترکیب کاملاً استاندارد و رایج است
        # (اتصال TCP ساده بدون TLS، مثلاً پشت CDN یا در تنظیمات Reality) و
        # هیچ نشانه‌ی واقعی از بی‌کیفیت بودن کانفیگ نیست — این قانون صرفاً
        # کانفیگ‌های سالم زیادی را بی‌دلیل حذف می‌کرد. قانون حذف شده است.
        return True

# ═══════════════════════════════════════════════════════════════════════════════
# ConfigStructureValidator — اعتبارسنجی فرمت URI
# ═══════════════════════════════════════════════════════════════════════════════
class ConfigStructureValidator:
    @staticmethod
    def is_valid(cfg: str) -> bool:
        s, lower = cfg.strip(), cfg.strip().lower()
        try:
            if lower.startswith(("vless://","trojan://","tuic://")):
                return "@" in s and ":" in s
            if lower.startswith("vmess://"):
                b64  = s[8:].strip()
                b64 += "=" * ((4 - len(b64) % 4) % 4)
                d    = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
                return bool(d.get("add") and d.get("port"))
            if lower.startswith("ss://"):
                return "@" in s or ":" in s
            if lower.startswith(("hysteria2://","hy2://")):
                return "@" in s
            if lower.startswith(("wireguard://","wg://")):
                return "@" in s or ":" in s
        except Exception:
            return False
        return False

# ═══════════════════════════════════════════════════════════════════════════════
# XrayManager — دانلود و مدیریت باینری Xray-core
# ═══════════════════════════════════════════════════════════════════════════════
class XrayManager:
    """
    مدیریت باینری Xray-core: دانلود در اولین اجرا (اگر موجود نباشد) و نگهداری
    مسیر آن. باینری از GitHub Releases گرفته می‌شود (فقط linux amd64).
    """
    _ready:  bool = False
    _lock:   "asyncio.Lock|None" = None
    _download_failed: bool = False

    @classmethod
    def _get_lock(cls) -> asyncio.Lock:
        if cls._lock is None:
            cls._lock = asyncio.Lock()
        return cls._lock

    @classmethod
    def is_ready(cls) -> bool:
        return cls._ready and os.path.isfile(Config.XRAY_BIN_PATH) and os.access(Config.XRAY_BIN_PATH, os.X_OK)

    @classmethod
    async def ensure_ready(cls) -> bool:
        """اگر باینری موجود نیست، دانلودش می‌کند. Idempotent و safe برای فراخوانی مکرر."""
        if cls.is_ready():
            return True
        if cls._download_failed:
            return False

        async with cls._get_lock():
            if cls.is_ready():
                return True
            try:
                bin_dir = os.path.dirname(Config.XRAY_BIN_PATH)
                os.makedirs(bin_dir, exist_ok=True)

                arch = platform.machine().lower()
                asset = "Xray-linux-64.zip" if arch in ("x86_64", "amd64") else \
                         "Xray-linux-arm64-v8a.zip" if arch in ("aarch64", "arm64") else None
                if asset is None:
                    logger.error(f"❌ XrayManager: معماری ناشناخته '{arch}' — Real Ping Test غیرفعال شد.")
                    cls._download_failed = True
                    return False

                url = f"https://github.com/XTLS/Xray-core/releases/download/{Config.XRAY_DOWNLOAD_VERSION}/{asset}"
                logger.info(f"⬇️  در حال دانلود Xray-core از {url} ...")

                zip_path = os.path.join(bin_dir, "xray.zip")
                timeout  = aiohttp.ClientTimeout(total=90)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url) as resp:
                        if resp.status != 200:
                            raise RuntimeError(f"HTTP {resp.status} هنگام دانلود Xray")
                        data = await resp.read()
                with open(zip_path, "wb") as f:
                    f.write(data)

                import zipfile
                with zipfile.ZipFile(zip_path, "r") as zf:
                    zf.extract("xray", bin_dir)
                os.chmod(Config.XRAY_BIN_PATH, 0o755)
                try:
                    os.remove(zip_path)
                except OSError:
                    pass

                cls._ready = True
                logger.info(f"✅ Xray-core آماده شد در {Config.XRAY_BIN_PATH}")
                return True

            except Exception as exc:
                logger.error(f"❌ خطا در دانلود/آماده‌سازی Xray-core: {exc}", exc_info=True)
                cls._download_failed = True
                return False


# ═══════════════════════════════════════════════════════════════════════════════
# XrayConfigBuilder — تبدیل URI کانفیگ به فایل JSON قابل‌اجرا برای Xray
# ═══════════════════════════════════════════════════════════════════════════════
class XrayConfigBuilder:
    """
    یک URI کانفیگ (vless/vmess/trojan/ss/hysteria2) را به یک دیکشنری JSON
    قابل مصرف برای `xray run -config` تبدیل می‌کند، با یک SOCKS inbound
    محلی روی پورت داده‌شده تا بشود از طریقش تست HTTP انجام داد.

    توجه: hysteria2/tuic/wireguard از پروتکل‌های UDP-native هستند و ساخت
    outbound برایشان در Xray خالص پشتیبانی محدودی دارد؛ برای این پروتکل‌ها
    build() مقدار None برمی‌گرداند و تست به‌جای Real Ping، به TCP-check
    برمی‌گردد (در RealPingTester مدیریت می‌شود).
    """

    @staticmethod
    def _parse_vless_trojan(cfg: str, scheme: str) -> "dict|None":
        try:
            rest = cfg[len(scheme)+3:]
            rest, _, frag = rest.partition("#")
            userinfo, _, hostpart = rest.partition("@")
            userinfo = unquote(userinfo)
            hostport, _, query = hostpart.partition("?")
            if ":" in hostport:
                host, port_s = hostport.rsplit(":", 1)
                port = int(port_s)
            else:
                host, port = hostport, 443
            params = {}
            for kv in query.split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    params[unquote(k)] = unquote(v)

            security   = params.get("security", "none")
            sni        = params.get("sni") or params.get("peer") or host
            fp         = params.get("fp", "chrome")
            net_type   = params.get("type", "tcp")
            pbk        = params.get("pbk", "")
            sid        = params.get("sid", "")
            flow       = params.get("flow", "")

            stream_settings = {"network": net_type}
            if security == "tls":
                stream_settings["security"] = "tls"
                stream_settings["tlsSettings"] = {"serverName": sni, "allowInsecure": True, "fingerprint": fp}
            elif security == "reality":
                stream_settings["security"] = "reality"
                stream_settings["realitySettings"] = {
                    "serverName": sni, "fingerprint": fp, "publicKey": pbk, "shortId": sid, "spiderX": "",
                }
            if net_type == "ws":
                stream_settings["wsSettings"] = {"path": params.get("path", "/"), "headers": {"Host": params.get("host", sni)}}
            elif net_type == "grpc":
                stream_settings["grpcSettings"] = {"serviceName": params.get("serviceName", "")}

            if scheme == "vless":
                outbound = {
                    "protocol": "vless",
                    "settings": {"vnext": [{
                        "address": host, "port": port,
                        "users": [{"id": userinfo, "encryption": "none", "flow": flow}],
                    }]},
                    "streamSettings": stream_settings,
                }
            else:  # trojan
                outbound = {
                    "protocol": "trojan",
                    "settings": {"servers": [{"address": host, "port": port, "password": userinfo}]},
                    "streamSettings": stream_settings,
                }
            return outbound
        except Exception:
            return None

    @staticmethod
    def _parse_vmess(cfg: str) -> "dict|None":
        try:
            b64 = cfg[8:].strip()
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            d = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
            host = d.get("add", "")
            port = int(d.get("port", 0) or 0)
            uid  = d.get("id", "")
            if not (host and port and uid):
                return None
            net  = d.get("net", "tcp")
            tls  = d.get("tls", "")

            stream_settings = {"network": net}
            if tls == "tls":
                stream_settings["security"] = "tls"
                stream_settings["tlsSettings"] = {"serverName": d.get("sni") or d.get("host") or host, "allowInsecure": True}
            if net == "ws":
                stream_settings["wsSettings"] = {"path": d.get("path", "/"), "headers": {"Host": d.get("host", host)}}
            elif net == "grpc":
                stream_settings["grpcSettings"] = {"serviceName": d.get("path", "")}

            return {
                "protocol": "vmess",
                "settings": {"vnext": [{
                    "address": host, "port": port,
                    "users": [{"id": uid, "alterId": int(d.get("aid", 0) or 0), "security": "auto"}],
                }]},
                "streamSettings": stream_settings,
            }
        except Exception:
            return None

    @staticmethod
    def _parse_ss(cfg: str) -> "dict|None":
        try:
            rest = cfg[5:]
            rest, _, _frag  = rest.partition("#")
            rest, _, _query = rest.partition("?")

            if "@" in rest:
                # فرمت: ss://BASE64(method:password)@host:port
                userinfo, _, hostport = rest.partition("@")
                pad = "=" * ((4 - len(userinfo) % 4) % 4)
                try:
                    userinfo = base64.urlsafe_b64decode(userinfo + pad).decode("utf-8", errors="ignore")
                except Exception:
                    pass  # ممکن است از قبل رمزگشایی‌نشده (method:password@) باشد
            else:
                # فرمت قدیمی: ss://BASE64(method:password@host:port)
                pad = "=" * ((4 - len(rest) % 4) % 4)
                decoded = base64.urlsafe_b64decode(rest + pad).decode("utf-8", errors="ignore")
                userinfo, _, hostport = decoded.rpartition("@")

            method, _, password = userinfo.partition(":")
            host, _, port_s = hostport.rpartition(":")
            port = int(port_s)
            if not (host and port and method and password):
                return None
            return {
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": host, "port": port, "method": method, "password": password}]},
            }
        except Exception:
            return None

    @classmethod
    def build(cls, cfg: str, socks_port: int) -> "dict|None":
        lower = cfg.strip().lower()
        if lower.startswith("vless://"):
            outbound = cls._parse_vless_trojan(cfg, "vless")
        elif lower.startswith("trojan://"):
            outbound = cls._parse_vless_trojan(cfg, "trojan")
        elif lower.startswith("vmess://"):
            outbound = cls._parse_vmess(cfg)
        elif lower.startswith("ss://"):
            outbound = cls._parse_ss(cfg)
        else:
            return None  # hysteria2/tuic/wireguard/غیره — پشتیبانی نمی‌شود

        if outbound is None:
            return None

        outbound["tag"] = "proxy"
        xray_log_level = "warning" if logger.isEnabledFor(logging.DEBUG) else "none"
        return {
            "log": {"loglevel": xray_log_level},
            "inbounds": [{
                "listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
                "settings": {"udp": False}, "tag": "socks-in",
            }],
            # "blackhole" به‌جای یک outbound "freedom" دوم برای مسیر پیش‌فرض:
            # قبلاً یک outbound "direct" (freedom) هم وجود داشت بدون هیچ routing
            # صریحی. طبق رفتار Xray، بدون routing rule، ترافیک به اولین outbound
            # می‌رود که "proxy" است — اما این تضمین قوی‌ای نیست؛ اگر outbound
            # "proxy" به هر دلیلی کنار گذاشته می‌شد، ترافیک از "direct" (یعنی
            # مستقیماً از روی سرور Railway، بدون عبور از کانفیگ تست‌شونده) خارج
            # می‌شد و نتیجه HTTP 204 واقعی می‌گرفت — یعنی یک کانفیگ کاملاً مرده
            # هم "زنده" ثبت می‌شد. با این routing rule صریح + blackhole به‌جای
            # freedom برای مسیر پیش‌فرض، هر ترافیکی که از outbound "proxy" رد
            # نشود اصلاً به اینترنت نمی‌رسد و درخواست HTTP با خطا مواجه می‌شود.
            "outbounds": [
                outbound,
                {"protocol": "blackhole", "tag": "block"},
            ],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [
                    {"type": "field", "inboundTag": ["socks-in"], "outboundTag": "proxy"},
                    {"type": "field", "network": "tcp,udp", "outboundTag": "block"},
                ],
            },
        }


# ═══════════════════════════════════════════════════════════════════════════════
# RealPingTester — تست پینگ واقعی از طریق اجرای واقعی Xray و درخواست HTTP
# ═══════════════════════════════════════════════════════════════════════════════
class RealPingTester:
    """
    برای هر کانفیگ: یک نمونه Xray با یک SOCKS inbound محلی بالا می‌آورد،
    از طریق آن یک GET به Config.PING_TEST_URL می‌زند و کد پاسخ + زمان را
    می‌سنجد (تست generate_204 شبیه رفتار v2rayNG/Nekobox).

    محدودیت‌های ایمنی حیاتی برای منابع محدود (0.5GB RAM):
      • Semaphore با سقف Config.PING_TEST_CONCURRENCY (پیش‌فرض ۳) — هیچ‌وقت
        بیش از این تعداد پروسه Xray هم‌زمان اجرا نمی‌شود.
      • هر پروسه حداکثر Config.PING_TEST_TIMEOUT ثانیه فرصت دارد، بعد kill می‌شود.
      • پورت‌های SOCKS به‌صورت چرخشی از یک بازه گرفته می‌شوند تا تصادفی باز نمانند.
    """
    _semaphore: "asyncio.Semaphore|None" = None
    _port_counter = 20000  # بازه پورت‌های SOCKS محلی موقت
    # رفع باگ «race condition احتمالی در پورت‌های SOCKS»: قبلاً _port_counter
    # بدون قفل افزایش می‌یافت. زیر asyncio تک‌رشته‌ای فعلی (بدون await بین
    # خواندن و نوشتن) این خودش مشکلی ایجاد نمی‌کرد، اما اگر بات در آینده به
    # حالت چندنخی (multi-thread/multi-process) برود، تصادم پورت واقعی
    # می‌شد. یک threading.Lock سبک اضافه شده که هم زیر asyncio هم زیر thread
    # واقعی درست کار می‌کند (چون بخش بحرانی synchronous و بسیار کوتاه است).
    _port_lock = threading.Lock()

    @classmethod
    def _get_sem(cls) -> asyncio.Semaphore:
        if cls._semaphore is None:
            cls._semaphore = asyncio.Semaphore(max(1, Config.PING_TEST_CONCURRENCY))
        return cls._semaphore

    @classmethod
    def _next_port(cls) -> int:
        with cls._port_lock:
            cls._port_counter += 1
            if cls._port_counter > 20999:
                cls._port_counter = 20000
            return cls._port_counter

    @classmethod
    async def _wait_socks_ready(cls, port: int, deadline: float) -> bool:
        """
        به‌جای یک sleep ثابت، واقعاً چک می‌کند که پورت SOCKS محلی باز شده
        (یعنی Xray واقعاً آماده‌ی پذیرش اتصال است) — قابل‌اتکاتر از حدس زدن
        یک عدد ثابت برای زمان بالا آمدن، چون سرعت بالا آمدن Xray روی
        سرورهای کم‌منبع (مثل Railway free tier) متغیر است.
        """
        while time.monotonic() < deadline:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", port), timeout=0.3)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return True
            except Exception:
                await asyncio.sleep(0.1)
        return False

    @classmethod
    async def test_one(cls, cfg: str) -> "tuple[bool, int, str]":
        """
        برمی‌گرداند (is_alive, ping_ms, reason). اگر تست ناموفق باشد یا پروتکل
        پشتیبانی‌نشده باشد، (False, -1, <علت کوتاه>) برمی‌گردد. علت برای
        تجمیع در test_batch استفاده می‌شود تا الگوهای شکست حتی وقتی سطح لاگ
        debug نیست هم قابل مشاهده باشند (رفع باگ «عدم لاگ‌گیری کافی»).
        """
        if not await XrayManager.ensure_ready():
            # این یک خطای سیستمی است (نه یک کانفیگ خاص) — یعنی هیچ تستی در
            # این دور اصلاً انجام نمی‌شود. سطح debug باعث می‌شد در محیط تولید
            # (که معمولاً debug غیرفعال است) کاملاً نامرئی بماند و عیب‌یابی
            # اینکه «چرا هیچ کانفیگی تست نمی‌شود» را غیرممکن می‌کرد.
            logger.warning("Ping test: Xray آماده نیست — همه‌ی تست‌های این دور رد می‌شوند.")
            return False, -1, "xray_not_ready"
        if not _AIOHTTP_SOCKS_AVAILABLE:
            logger.warning("Ping test: کتابخانه‌ی aiohttp-socks نصب نیست — همه‌ی تست‌ها رد می‌شوند "
                            "(به requirements.txt مراجعه کنید).")
            return False, -1, "socks_lib_missing"

        socks_port  = cls._next_port()
        xray_config = XrayConfigBuilder.build(cfg, socks_port)
        if xray_config is None:
            logger.debug(f"Ping test: پروتکل پشتیبانی‌نشده یا پارس ناموفق: {cfg[:40]}...")
            return False, -1, "unsupported_protocol_or_parse"

        async with cls._get_sem():
            # محافظت لحظه‌ای OOM: حتی داخل همان ۳ اسلات Semaphore، اگر مموری
            # کانتینر همین الان به سقف نزدیک شده (مثلاً به‌خاطر پروسه‌های
            # قبلی که هنوز کاملاً آزاد نشده‌اند)، از اجرای پروسه‌ی جدید Xray
            # صرف‌نظر می‌کنیم — این محافظت دقیق‌تر از فقط شمارش پروسه‌هاست.
            mem_now = _read_mem_mb()
            if mem_now > Config.PING_TEST_MEM_SAFETY_MB:
                logger.debug(f"Ping test: RAM={mem_now:.0f}MB نزدیک سقف — از اجرای Xray صرف‌نظر شد.")
                return False, -1, "mem_safety_skip"

            proc = None
            cfg_path = None
            try:
                cfg_path = f"/tmp/xray_cfg_{socks_port}_{int(time.time()*1000)}.json"
                with open(cfg_path, "w") as f:
                    json.dump(xray_config, f)

                proc = await asyncio.create_subprocess_exec(
                    Config.XRAY_BIN_PATH, "run", "-config", cfg_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                startup_deadline = time.monotonic() + max(Config.PING_XRAY_STARTUP_WAIT, 2.0)
                ready = await cls._wait_socks_ready(socks_port, startup_deadline)

                if proc.returncode is not None:
                    stderr_data = b""
                    try:
                        stderr_data = await asyncio.wait_for(proc.stderr.read(500), timeout=0.5)
                    except Exception:
                        pass
                    logger.debug(
                        f"Ping test: xray فوراً با کد {proc.returncode} خارج شد — "
                        f"{stderr_data.decode(errors='ignore')[:200]}")
                    return False, -1, f"xray_exit_{proc.returncode}"

                if not ready:
                    logger.debug(f"Ping test: پورت SOCKS {socks_port} در {Config.PING_XRAY_STARTUP_WAIT}s+ باز نشد.")
                    return False, -1, "socks_port_not_ready"

                t0 = time.monotonic()
                # connect: سقف زمان اتصال TCP/هندشیک به سرور پروکسی (قابل تنظیم
                # با CONNECT_TIMEOUT در Railway). total: سقف کل تست شامل هندشیک.
                timeout = aiohttp.ClientTimeout(
                    total=max(2.0, Config.PING_TEST_TIMEOUT - 2.0),
                    connect=Config._CONNECT_TIMEOUT,
                    sock_connect=Config._CONNECT_TIMEOUT,
                )
                reason = "ok"
                try:
                    connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{socks_port}")
                    # هدر Host را دستی می‌فرستیم چون PING_TEST_URL از IP خام
                    # استفاده می‌کند (نه دامنه) — دقیقاً همان رفتار v2rayNG که
                    # کانکتیویتی واقعی از طریق تونل پروکسی را می‌سنجد، نه یک
                    # DNS/route جایگزین که ممکن است از پروکسی عبور نکرده باشد.
                    headers = {"Host": Config.PING_TEST_HOST_HEADER}
                    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                        async with session.get(Config.PING_TEST_URL, headers=headers,
                                                allow_redirects=False) as resp:
                            ok = resp.status == 204
                            if not ok:
                                reason = f"http_status_{resp.status}"
                                logger.debug(f"Ping test: پاسخ HTTP {resp.status} (انتظار 204) برای {cfg[:40]}...")
                except Exception as exc:
                    logger.debug(f"Ping test: خطای HTTP از طریق SOCKS: {type(exc).__name__}: {exc}")
                    ok = False
                    reason = f"http_exc_{type(exc).__name__}"

                ping_ms = int((time.monotonic() - t0) * 1000) if ok else -1
                return ok, ping_ms, reason

            except Exception as exc:
                logger.debug(f"Ping test: خطای عمومی برای {cfg[:40]}...: {type(exc).__name__}: {exc}")
                return False, -1, f"general_exc_{type(exc).__name__}"

            finally:
                if proc is not None and proc.returncode is None:
                    try:
                        proc.terminate()
                        await asyncio.wait_for(proc.wait(), timeout=3)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass
                if cfg_path:
                    try:
                        os.remove(cfg_path)
                    except OSError:

                        pass

    @classmethod
    async def test_batch(cls, configs: list) -> list:
        """
        `configs`: لیست رشته کانفیگ. خروجی: لیست دیکشنری
        {"config", "alive", "ping_ms"} به همان ترتیب ورودی.

        رفع باگ «عدم لاگ‌گیری کافی»: علت‌های شکست تک‌تک کانفیگ‌ها همچنان در
        سطح debug است (برای جلوگیری از سیل لاگ روی صدها کانفیگ در هر دسته)،
        ولی اینجا یک خلاصه‌ی آماری از علل شکست در سطح INFO/WARNING لاگ می‌شود
        تا بدون فعال‌کردن debug هم بتوان فهمید چرا مثلاً ۹۰٪ یک دسته شکست
        خورده‌اند (مثلاً همه xray_not_ready یا همه socks_port_not_ready).
        """
        results = await asyncio.gather(
            *[cls.test_one(c) for c in configs], return_exceptions=True
        )
        out = []
        reason_counts: dict = defaultdict(int)
        for cfg, r in zip(configs, results):
            if isinstance(r, BaseException):
                out.append({"config": cfg, "alive": False, "ping_ms": -1})
                reason_counts[f"gather_exc_{type(r).__name__}"] += 1
            else:
                ok, ms, reason = r
                out.append({"config": cfg, "alive": ok, "ping_ms": ms})
                reason_counts[reason] += 1

        total = len(configs)
        fail_reasons = {k: v for k, v in reason_counts.items() if k != "ok"}
        if fail_reasons and total:
            fail_total = sum(fail_reasons.values())
            top = sorted(fail_reasons.items(), key=lambda kv: -kv[1])[:5]
            summary = ", ".join(f"{k}={v}" for k, v in top)
            level = logger.warning if fail_total / total > 0.5 else logger.info
            level(f"Ping batch: {fail_total}/{total} ناموفق — علل عمده: {summary}")
        return out


# ═══════════════════════════════════════════════════════════════════════════════
# نکته: کلاس AbuseTracker (کانتر in-memory) در این‌جا قبلاً وجود داشت و حذف
# شد — رفع باگ «کانتر Abuse در حافظه بی‌استفاده». امتیاز in-memory آن هیچ‌گاه
# در تصمیم‌گیری process_abuse استفاده نمی‌شد؛ تصمیم‌گیری همیشه صرفاً بر پایه‌ی
# امتیاز پایدار در دیتابیس (DatabaseManager.get_abuse/update_abuse) بوده و
# هست، که بر خلاف یک کانتر حافظه، بعد از ری‌استارت بات هم از دست نمی‌رود.
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# ConfigReputation — سیستم اعتبار کانفیگ
# ═══════════════════════════════════════════════════════════════════════════════
class ConfigReputation:
    """
    ذخیره success/fail برای هر config_hash.
    کاربران می‌توانند کانفیگ معیوب گزارش دهند.

    رفع باگ «رشد بی‌نهایت حافظه»: قبلاً _cache یک dict معمولی بود که هیچ‌گاه
    پاک‌سازی نمی‌شد — با هر گزارش کاربر یک رکورد جدید اضافه می‌شد و با گذشت
    زمان کل حافظه‌ی بات را پر می‌کرد (OOM). حالا از OrderedDict به‌عنوان یک
    LRU cache با سقف Config.REPUTATION_MAX_ENTRIES استفاده می‌شود: هر بار که
    یک ورودی خوانده یا نوشته می‌شود به انتهای صف منتقل می‌شود (most-recently
    used)، و اگر تعداد از سقف رد شود، قدیمی‌ترین/کم‌استفاده‌ترین ورودی‌ها حذف
    می‌شوند.
    """
    _cache: "OrderedDict" = OrderedDict()   # config_hash → {success, fail, reports}

    @classmethod
    def _touch(cls, config_hash: str) -> dict:
        if config_hash in cls._cache:
            cls._cache.move_to_end(config_hash)
            return cls._cache[config_hash]
        entry = {"success": 0, "fail": 0, "reports": 0}
        cls._cache[config_hash] = entry
        while len(cls._cache) > Config.REPUTATION_MAX_ENTRIES:
            cls._cache.popitem(last=False)   # حذف قدیمی‌ترین ورودی
        return entry

    @classmethod
    def record_report(cls, config_hash: str) -> None:
        e = cls._touch(config_hash)
        e["reports"] += 1
        e["fail"]    += 1

    @classmethod
    def record_success(cls, config_hash: str) -> None:
        e = cls._touch(config_hash)
        e["success"] += 1

    @classmethod
    def get(cls, config_hash: str) -> dict:
        if config_hash in cls._cache:
            cls._cache.move_to_end(config_hash)
            return cls._cache[config_hash]
        return {"success": 0, "fail": 0, "reports": 0}

    @classmethod
    def reliability(cls, config_hash: str) -> float:
        e     = cls.get(config_hash)
        total = e["success"] + e["fail"]
        return round(e["success"] / total * 100, 1) if total else 100.0


# ═══════════════════════════════════════════════════════════════════════════════
# System Metrics — CPU / RAM / disk
# ═══════════════════════════════════════════════════════════════════════════════
_START_TIME   = time.time()
_prev_cpu     = {"idle": 0, "total": 0, "ts": 0.0}

def _read_mem_mb() -> float:
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024
    except Exception:
        pass
    return 0.0

def _read_container_cpu_ns() -> "tuple[float, float]|None":
    """
    زمان CPU مصرف‌شده توسط خودِ کانتینر (نه کل سرور میزبان) را از cgroups
    می‌خواند. cgroup v2 (فایل واحد cpu.stat) و cgroup v1 (cpuacct.usage) هر دو
    پشتیبانی می‌شوند. اگر هیچ‌کدام در دسترس نبود، None برمی‌گرداند تا کد فراخوان
    به /proc/stat (سراسر سرور) بازگردد.
    برمی‌گرداند: (usage_seconds, wall_clock_seconds) یا None.
    """
    # cgroup v2
    try:
        with open("/sys/fs/cgroup/cpu.stat") as f:
            for line in f:
                if line.startswith("usage_usec"):
                    usage_usec = int(line.split()[1])
                    return usage_usec / 1_000_000, time.monotonic()
    except Exception:
        pass
    # cgroup v1
    try:
        with open("/sys/fs/cgroup/cpu/cpuacct.usage") as f:
            usage_ns = int(f.read().strip())
            return usage_ns / 1_000_000_000, time.monotonic()
    except Exception:
        pass
    return None


def _read_cgroup_cpu_quota() -> "float|None":
    """تعداد هسته‌های تخصیص‌یافته به کانتینر (cpu.max یا cfs_quota/period)."""
    try:
        with open("/sys/fs/cgroup/cpu.max") as f:
            quota_s, period_s = f.read().split()
            if quota_s == "max":
                return None
            return int(quota_s) / int(period_s)
    except Exception:
        pass
    try:
        with open("/sys/fs/cgroup/cpu/cpu.cfs_quota_us") as f:
            quota = int(f.read().strip())
        with open("/sys/fs/cgroup/cpu/cpu.cfs_period_us") as f:
            period = int(f.read().strip())
        if quota <= 0:
            return None
        return quota / period
    except Exception:
        return None


def _read_cpu_percent() -> float:
    """
    درصد CPU مصرفی — ابتدا تلاش می‌کند از cgroup (مخصوص خودِ کانتینر) بخواند
    که روی پلتفرم‌هایی مثل Railway دقیق‌تر از /proc/stat (که کل سرور میزبان را
    نشان می‌دهد) است. اگر cgroup در دسترس نبود (مثلاً محیط غیرکانتینری)، به
    /proc/stat سراسری بازمی‌گردد.
    """
    cg = _read_container_cpu_ns()
    if cg is not None:
        usage_sec, now_mono = cg
        prev = _prev_cpu.get("cgroup")
        _prev_cpu["cgroup"] = {"usage": usage_sec, "ts": now_mono}
        if prev is None:
            return 0.0
        d_usage = usage_sec - prev["usage"]
        d_wall  = now_mono - prev["ts"]
        if d_wall <= 0:
            return 0.0
        quota_cores = _read_cgroup_cpu_quota() or 1.0
        pct = (d_usage / d_wall) / max(quota_cores, 0.01) * 100
        return round(min(pct, 100.0), 1)

    # Fallback: /proc/stat سراسری (فقط اگر cgroup اصلاً در دسترس نبود)
    try:
        with open("/proc/stat") as f:
            parts = f.readline().split()
        vals  = [int(x) for x in parts[1:]]
        total = sum(vals)
        idle  = vals[3] + (vals[4] if len(vals) > 4 else 0)
        prev  = _prev_cpu
        prev_total = prev.get("total", 0)
        prev_idle  = prev.get("idle", 0)
        dt    = total - prev_total
        di    = idle  - prev_idle
        prev["total"] = total; prev["idle"] = idle; prev["ts"] = time.time()
        if dt <= 0: return 0.0
        return round((1 - di / dt) * 100, 1)
    except Exception:
        return 0.0

def _format_uptime(sec: float) -> str:
    sec = int(sec)
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m, _   = divmod(rem, 60)
    return " ".join(filter(None, [f"{d}روز" if d else "", f"{h}ساعت" if h else "", f"{m}دقیقه"]))

def safe_truncate(text: str, max_len: int = 4000) -> str:
    if len(text) <= max_len: return text
    t = text[:max_len]
    if t.count("`") % 2: t += "`"
    return t + "\n\n`... (بریده شد)`"

# ═══════════════════════════════════════════════════════════════════════════════
# SmartNotifier — هشدارهای هوشمند به ادمین
# ═══════════════════════════════════════════════════════════════════════════════
class SmartNotifier:
    _last_notify: dict = {}
    _COOLDOWN = 1800   # 30 دقیقه بین هشدارهای مشابه

    @classmethod
    async def notify(cls, bot, key: str, msg: str) -> None:
        now = time.time()
        if now - cls._last_notify.get(key, 0) < cls._COOLDOWN:
            return
        cls._last_notify[key] = now
        try:
            await bot.send_message(Config.ADMIN_ID, msg, parse_mode="Markdown")
        except Exception:
            pass

    @classmethod
    async def check_all(cls, bot) -> None:
        # رفع باگ «وابستگی دایره‌ای»: قبلاً از __main__ ایمپورت می‌شد که فقط
        # وقتی این فایل مستقیماً به‌عنوان اسکریپت اصلی اجرا می‌شد کار می‌کرد و
        # نوشتن تست یا استفاده‌ی این کلاس‌ها به‌عنوان یک ماژول قابل import را
        # غیرممکن می‌کرد. چون CacheManager در همین فایل (پایین‌تر) تعریف شده،
        # و این متد فقط زمان فراخوانی واقعی اجرا می‌شود (نه در زمان تعریف
        # کلاس)، پایتون نام CacheManager را در scope سراسری همین ماژول به‌طور
        # طبیعی resolve می‌کند — نیازی به import صریح نیست.
        cache_size = len(CacheManager._cache)
        mem_mb     = _read_mem_mb()
        cpu_pct    = _read_cpu_percent()

        if cache_size < Config.MIN_CACHE_NOTIFY and cache_size > 0:
            await cls.notify(bot, "low_cache",
                f"⚠️ *هشدار کش*\n\nتعداد کانفیگ‌ها به `{cache_size:,}` رسید (کمتر از {Config.MIN_CACHE_NOTIFY:,})")
        if mem_mb > Config.MEM_ALERT_THRESHOLD / 100 * 1024:
            await cls.notify(bot, "high_mem",
                f"⚠️ *هشدار RAM*\n\nمصرف حافظه: `{mem_mb:.1f} MB`")
        if cpu_pct > Config.CPU_ALERT_THRESHOLD:
            await cls.notify(bot, "high_cpu",
                f"⚠️ *هشدار CPU*\n\nمصرف پردازنده: `{cpu_pct:.1f}%`")

# ═══════════════════════════════════════════════════════════════════════════════
# RuleEngine — موتور قوانین ساده  IF condition THEN action
# ═══════════════════════════════════════════════════════════════════════════════
class RuleEngine:
    """
    قوانین از DB لود می‌شوند. فرمت شرط:
      cache_size < N   →  reload
      mem_mb > N       →  clear_cache
      error_rate > N   →  notify_admin
    """
    @classmethod
    async def evaluate_all(cls, bot) -> None:
        # رفع باگ وابستگی دایره‌ای — توضیح کامل در SmartNotifier.check_all.
        try:
            rules = await DatabaseManager.get_rules()
        except Exception:
            return
        mem   = _read_mem_mb()
        cache = len(CacheManager._cache)
        for rule in rules:
            if not rule["enabled"]: continue
            try:
                cond   = rule["condition"].strip()
                action = rule["action"].strip()
                if not cls._eval(cond, cache_size=cache, mem_mb=mem):
                    continue
                await cls._act(action, bot, cache, mem)
                await DatabaseManager.touch_rule(rule["id"])
            except Exception:
                pass

    @classmethod
    def _eval(cls, cond: str, **ctx) -> bool:
        # هر شرط فقط از مقایسه‌های ساده پشتیبانی می‌کند: var op value
        m = re.match(r"(\w+)\s*([<>=!]+)\s*([0-9.]+)", cond)
        if not m: return False
        var, op, val = m.group(1), m.group(2), float(m.group(3))
        lv = float(ctx.get(var, 0))
        return {"<": lv<val, ">": lv>val, "<=": lv<=val, ">=": lv>=val,
                "==": lv==val, "!=": lv!=val}.get(op, False)

    @classmethod
    async def _act(cls, action: str, bot, cache, mem) -> None:
        # رفع باگ وابستگی دایره‌ای — توضیح کامل در SmartNotifier.check_all.
        a = action.strip().lower()
        if a == "reload":
            asyncio.create_task(CacheManager.reload())
        elif a == "clear_cache":
            async with CacheManager._get_lock():
                half = len(CacheManager._cache) // 2
                CacheManager._cache = CacheManager._cache[:half]
        elif a == "notify_admin":
            await SmartNotifier.notify(bot, f"rule_{action}",
                f"⚙️ *Rule Engine*\n`{action}` اجرا شد — کش: {cache:,} | RAM: {mem:.0f}MB")

# ═══════════════════════════════════════════════════════════════════════════════
# AnomalyDetector — تشخیص انحراف ناگهانی
# ═══════════════════════════════════════════════════════════════════════════════
class AnomalyDetector:
    _prev_cache = 0
    _prev_source_fail = 0

    @classmethod
    async def check(cls, bot, new_cache: int, source_fail_count: int) -> None:
        # افت ناگهانی بیش از ۵۰٪ کانفیگ
        if cls._prev_cache > 0 and new_cache < cls._prev_cache * 0.5:
            await SmartNotifier.notify(bot, "anomaly_cache",
                f"🚨 *Anomaly: افت شدید کانفیگ*\n{cls._prev_cache:,} → {new_cache:,}")
        # بیش از ۷۰٪ منابع ناموفق
        if source_fail_count > 5 and cls._prev_source_fail == 0:
            await SmartNotifier.notify(bot, "anomaly_sources",
                f"🚨 *Anomaly: {source_fail_count} منبع ناموفق*")
        cls._prev_cache       = new_cache
        cls._prev_source_fail = source_fail_count


# ═══════════════════════════════════════════════════════════════════════════════
# DatabaseManager — مدیریت SQLite با صف نوشتن
# ═══════════════════════════════════════════════════════════════════════════════
class DatabaseManager:
    _conn:        "aiosqlite.Connection | None" = None
    _write_queue: "asyncio.Queue | None"        = None
    _worker_task: "asyncio.Task | None"         = None

    # ── اتصال ──────────────────────────────────────────────────────────────────
    @classmethod
    async def get_conn(cls) -> "aiosqlite.Connection":
        if cls._conn is None:
            cls._conn = await aiosqlite.connect(Config.DB_PATH)
            for pragma in ["PRAGMA journal_mode=WAL", "PRAGMA synchronous=NORMAL",
                           "PRAGMA cache_size=-8000", "PRAGMA busy_timeout=5000"]:
                await cls._conn.execute(pragma)
            cls._conn.row_factory = aiosqlite.Row
        return cls._conn

    # ── صف نوشتن ────────────────────────────────────────────────────────────────
    # نکته دربارهٔ رفع باگ «از دست رفتن داده در صف نوشتن»: قبلاً وقتی صف اصلی
    # (ظرفیت ۴۰۹۶) پر می‌شد، put_nowait با QueueFull مواجه می‌شد و آیتم فقط با
    # یک لاگ هشدار به‌کلی دور ریخته می‌شد — یعنی آمار مصرف، فیدبک و رویدادهای
    # مهم در پیک بار برای همیشه گم می‌شدند. حالا یک بافر overflow محدود (deque)
    # اضافه شده: اگر صف اصلی پر باشد، آیتم به‌جای دور ریختن در این بافر می‌ماند
    # و worker همیشه قبل از گرفتن آیتم جدید از صف، ابتدا overflow را خالی
    # می‌کند. فقط اگر خودِ overflow هم پر شود (فشار پایدار و غیرعادی، نه یک
    # پیک لحظه‌ای) آیتم دور ریخته می‌شود و شمارنده‌ی dropped برای دیده‌شدن در
    # /health افزایش می‌یابد.
    _overflow:      "list|None" = None
    _dropped_count: int = 0
    _OVERFLOW_MAX:  int = 20000

    @classmethod
    def _get_queue(cls) -> "asyncio.Queue":
        if cls._write_queue is None:
            cls._write_queue = asyncio.Queue(maxsize=4096)
        return cls._write_queue

    @classmethod
    def _get_overflow(cls) -> list:
        if cls._overflow is None:
            cls._overflow = []
        return cls._overflow

    @classmethod
    async def start_write_worker(cls) -> None:
        cls._worker_task = asyncio.create_task(cls._write_worker(), name="db-write-worker")
        logger.info("⚙️  DB write-worker آماده.")

    @classmethod
    async def _write_worker(cls) -> None:
        q = cls._get_queue()
        while True:
            # ابتدا هر آیتمی که به‌خاطر پر بودن صف در overflow جا مانده را
            # به صف اصلی برمی‌گردانیم (اگر جا باز شده باشد) تا هیچ نوشتنی
            # جا نماند.
            overflow = cls._get_overflow()
            while overflow and not q.full():
                q.put_nowait(overflow.pop(0))

            first = await q.get()
            batch = [first]
            for _ in range(49):
                try:    batch.append(q.get_nowait())
                except asyncio.QueueEmpty: break
            db = await cls.get_conn()
            try:
                for sql, params in batch: await db.execute(sql, params)
                await db.commit()
            except Exception as exc:
                logger.error(f"DB write-worker: خطای دسته‌ای، تلاش مجدد تک‌به‌تک: {exc}")
                try: await db.rollback()
                except Exception: pass
                # Fallback فردی: تراکنش‌های سالم را از دست ندهیم — فقط چون یک
                # آیتم خراب (مثلاً نقض UNIQUE) کل batch را fail کرده، بقیه‌ی
                # ۴۹ نوشتن سالم دیگر نباید قربانی شوند.
                ok_count, fail_count = 0, 0
                for sql, params in batch:
                    try:
                        await db.execute(sql, params)
                        await db.commit()
                        ok_count += 1
                    except Exception as item_exc:
                        fail_count += 1
                        try: await db.rollback()
                        except Exception: pass
                        logger.warning(f"DB write (individual) ناموفق: {sql[:60]}... — {item_exc}")
                logger.info(f"DB write-worker fallback: {ok_count} موفق، {fail_count} ناموفق از {len(batch)}")
            finally:
                for _ in batch: q.task_done()

    @classmethod
    def _enqueue(cls, sql: str, params: tuple) -> None:
        try:
            cls._get_queue().put_nowait((sql, params))
        except asyncio.QueueFull:
            overflow = cls._get_overflow()
            if len(overflow) < cls._OVERFLOW_MAX:
                overflow.append((sql, params))
                logger.warning(
                    f"صف اصلی DB پر — به overflow منتقل شد ({len(overflow)}/{cls._OVERFLOW_MAX}): {sql[:50]}")
            else:
                # فقط وقتی هم صف اصلی و هم overflow (جمعاً ~۲۴٬۰۰۰ نوشتن در
                # صف انتظار) پر باشند به این نقطه می‌رسیم — یعنی فشار پایدار
                # غیرعادی، نه یک پیک معمولی. اینجا واقعاً باید دور بریزیم تا
                # از مصرف بی‌نهایت حافظه جلوگیری شود، ولی این رویداد را
                # می‌شمریم تا در /health دیده شود.
                cls._dropped_count += 1
                logger.error(
                    f"⚠️ صف DB و overflow هر دو پر — نوشتن دور ریخته شد "
                    f"(مجموع دورریز: {cls._dropped_count}): {sql[:50]}")

    @classmethod
    def get_write_queue_health(cls) -> dict:
        """برای نمایش در /health — وضعیت صف نوشتن دیتابیس."""
        q = cls._write_queue
        return {
            "queue_size":    q.qsize() if q else 0,
            "overflow_size": len(cls._get_overflow()),
            "dropped_total": cls._dropped_count,
        }

    # ── init_db ─────────────────────────────────────────────────────────────────
    @staticmethod
    async def init_db() -> None:
        db = await DatabaseManager.get_conn()
        stmts = [
            """CREATE TABLE IF NOT EXISTS prefs (
                user_id        INTEGER PRIMARY KEY,
                protocol       TEXT    NOT NULL DEFAULT 'ALL',
                country        TEXT    NOT NULL DEFAULT 'ALL',
                language       TEXT    NOT NULL DEFAULT 'fa',
                is_vip         INTEGER NOT NULL DEFAULT 0,
                user_state     TEXT,
                username       TEXT, first_name TEXT,
                first_seen     TEXT, last_seen  TEXT,
                total_downloads INTEGER NOT NULL DEFAULT 0,
                fav_country    TEXT    NOT NULL DEFAULT 'ALL',
                fav_protocol   TEXT    NOT NULL DEFAULT 'ALL'
            )""",
            """CREATE TABLE IF NOT EXISTS sources (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                url            TEXT    UNIQUE NOT NULL,
                enabled        INTEGER NOT NULL DEFAULT 1,
                fail_count     INTEGER NOT NULL DEFAULT 0,
                last_fail_time REAL    NOT NULL DEFAULT 0,
                datacenter     TEXT    DEFAULT 'Unknown',
                found_via      TEXT    DEFAULT 'manual'
            )""",
            """CREATE TABLE IF NOT EXISTS daily_usage (
                user_id          INTEGER NOT NULL,
                date             TEXT    NOT NULL,
                requests_count   INTEGER NOT NULL DEFAULT 0,
                configs_received INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (user_id, date)
            )""",
            """CREATE TABLE IF NOT EXISTS banned_users (
                user_id   INTEGER PRIMARY KEY,
                banned_at TEXT NOT NULL, reason TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS ip_blacklist (
                ip        TEXT PRIMARY KEY,
                reason    TEXT, added_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS user_feedback (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,
                config_hash TEXT    NOT NULL,
                reason      TEXT,
                timestamp   TEXT    NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS abuse_scores (
                user_id      INTEGER PRIMARY KEY,
                score        INTEGER NOT NULL DEFAULT 0,
                warn_count   INTEGER NOT NULL DEFAULT 0,
                mute_until   TEXT,
                last_updated TEXT    NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS system_logs (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                level     TEXT NOT NULL,
                source    TEXT,
                message   TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS rules (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                name         TEXT NOT NULL,
                condition    TEXT NOT NULL,
                action       TEXT NOT NULL,
                enabled      INTEGER NOT NULL DEFAULT 1,
                last_triggered TEXT,
                created_at   TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS github_sources (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                url        TEXT UNIQUE NOT NULL,
                repo       TEXT NOT NULL,
                stars      INTEGER DEFAULT 0,
                found_at   TEXT NOT NULL,
                notified   INTEGER DEFAULT 0
            )""",
            """CREATE TABLE IF NOT EXISTS search_cooldown (
                user_id    INTEGER PRIMARY KEY,
                last_search REAL NOT NULL DEFAULT 0
            )""",
            """CREATE TABLE IF NOT EXISTS tested_configs (
                fp          TEXT PRIMARY KEY,
                config      TEXT NOT NULL,
                protocol    TEXT NOT NULL DEFAULT 'unknown',
                country     TEXT NOT NULL DEFAULT 'ALL',
                ping_ms     INTEGER NOT NULL DEFAULT -1,
                last_tested REAL NOT NULL,
                fail_streak INTEGER NOT NULL DEFAULT 0,
                posted_to_channel INTEGER NOT NULL DEFAULT 0
            )""",
            # جدول تنظیمات عمومی key-value — برای سوییچ‌های روشن/خاموش قابل‌تغییر
            # توسط ادمین از داخل پنل (مثلاً نمایش/عدم‌نمایش دکمه‌ی کانفیگ‌های
            # تست‌شده) بدون نیاز به تغییر متغیر محیطی و ری‌استارت بات.
            """CREATE TABLE IF NOT EXISTS bot_settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )""",
            # آرشیو کانفیگ‌های حذف‌شده (خراب یا تکراری تشخیص داده‌شده توسط بات)
            # — طبق درخواست ادمین، این کانفیگ‌ها به‌جای نابودی کامل، اینجا
            # نگه داشته می‌شوند تا از پنل ادمین قابل مرور/دریافت باشند.
            """CREATE TABLE IF NOT EXISTS archived_configs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                config     TEXT    NOT NULL,
                protocol   TEXT    DEFAULT 'unknown',
                reason     TEXT    NOT NULL,
                archived_at REAL   NOT NULL
            )""",
            "CREATE INDEX IF NOT EXISTS idx_daily     ON daily_usage(user_id, date)",
            "CREATE INDEX IF NOT EXISTS idx_logs_ts   ON system_logs(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_feedback  ON user_feedback(config_hash)",
            "CREATE INDEX IF NOT EXISTS idx_tested_ping ON tested_configs(ping_ms)",
            "CREATE INDEX IF NOT EXISTS idx_archived_at ON archived_configs(archived_at)",
        ]
        for stmt in stmts:
            await db.execute(stmt)
        # migrate existing prefs if needed
        for col, decl in [
            ("language","TEXT NOT NULL DEFAULT 'fa'"),("is_vip","INTEGER NOT NULL DEFAULT 0"),
            ("user_state","TEXT"),("first_name","TEXT"),("total_downloads","INTEGER NOT NULL DEFAULT 0"),
            ("fav_country","TEXT NOT NULL DEFAULT 'ALL'"),("fav_protocol","TEXT NOT NULL DEFAULT 'ALL'"),
        ]:
            try: await db.execute(f"ALTER TABLE prefs ADD COLUMN {col} {decl}")
            except Exception: pass
        # migrate existing tested_configs if needed (برای دیتابیس‌های قدیمی‌تر
        # که این ستون را ندارند — جلوگیری از پست تکراری کانفیگ در کانال)
        for col, decl in [("posted_to_channel", "INTEGER NOT NULL DEFAULT 0")]:
            try: await db.execute(f"ALTER TABLE tested_configs ADD COLUMN {col} {decl}")
            except Exception: pass
        await db.commit()
        logger.info("⚙️  دیتابیس آماده.")

    @staticmethod
    async def populate_default_sources() -> None:
        """
        رفع باگ «منابع درخواستی حذف/اضافه فقط روی نصب‌های تازه اعمال می‌شد»:
        قبلاً seed فقط وقتی جدول sources کاملاً خالی بود اجرا می‌شد — یعنی
        روی یک بات که از قبل در حال اجراست (که دقیقاً همان چیزی است که
        ادمین دارد)، تغییر DEFAULT_SOURCES/REMOVED_SOURCES در کد هیچ اثری
        روی دیتابیس واقعی نداشت. حالا این تابع همیشه (در هر استارتاپ) دو کار
        را انجام می‌دهد، مستقل از خالی یا پر بودن جدول:
          ۱) هر URL در REMOVED_SOURCES را به‌صورت قطعی از جدول حذف می‌کند.
          ۲) هر URL در DEFAULT_SOURCES که هنوز در جدول نیست را INSERT OR
             IGNORE می‌کند (بدون دست زدن به منابعی که ادمین بعداً دستی
             اضافه/حذف کرده).
        """
        db = await DatabaseManager.get_conn()

        if REMOVED_SOURCES:
            placeholders = ",".join("?" for _ in REMOVED_SOURCES)
            cur = await db.execute(
                f"DELETE FROM sources WHERE url IN ({placeholders})", REMOVED_SOURCES)
            if cur.rowcount:
                logger.info(f"🗑 {cur.rowcount} منبع منسوخ (REMOVED_SOURCES) از دیتابیس حذف شد.")

        await db.executemany(
            "INSERT OR IGNORE INTO sources (url,enabled) VALUES (?,1)",
            [(u,) for u in DEFAULT_SOURCES])
        await db.commit()
        logger.info(f"✅ بررسی منابع پیش‌فرض کامل شد ({len(DEFAULT_SOURCES)} URL بررسی شد).")

    # ── تنظیمات عمومی (key-value) — سوییچ‌های روشن/خاموش قابل‌تغییر از پنل ──────
    @staticmethod
    async def get_setting(key: str, default: str = "") -> str:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT value FROM bot_settings WHERE key=?", (key,)) as cur:
            row = await cur.fetchone()
            return row[0] if row else default

    @staticmethod
    async def set_setting(key: str, value: str) -> None:
        db = await DatabaseManager.get_conn()
        await db.execute(
            "INSERT INTO bot_settings (key,value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
        await db.commit()

    # ── آرشیو کانفیگ‌های حذف‌شده ────────────────────────────────────────────────
    @staticmethod
    async def archive_config(config: str, protocol: str, reason: str) -> None:
        """
        طبق درخواست ادمین: هر کانفیگی که بات به‌عنوان خراب یا تکراری کنار
        می‌گذارد، به‌جای نابودی کامل، اینجا با دلیل حذف نگه داشته می‌شود تا
        از پنل ادمین قابل مرور و دریافت باشد. برای جلوگیری از رشد بی‌نهایت
        دیتابیس، این جدول توسط trim_archived_configs به یک سقف محدود می‌شود.
        """
        db = await DatabaseManager.get_conn()
        await db.execute(
            "INSERT INTO archived_configs (config,protocol,reason,archived_at) VALUES (?,?,?,?)",
            (config, protocol, reason, time.time()))
        await db.commit()

    @staticmethod
    async def archive_configs_batch(items: list) -> None:
        """نسخه‌ی دسته‌ای archive_config — items: لیست (config, protocol, reason)."""
        if not items: return
        db  = await DatabaseManager.get_conn()
        now = time.time()
        await db.executemany(
            "INSERT INTO archived_configs (config,protocol,reason,archived_at) VALUES (?,?,?,?)",
            [(cfg, proto, reason, now) for cfg, proto, reason in items])
        await db.commit()

    @staticmethod
    async def trim_archived_configs(max_rows: int = 20000) -> None:
        db = await DatabaseManager.get_conn()
        await db.execute(
            "DELETE FROM archived_configs WHERE id NOT IN "
            "(SELECT id FROM archived_configs ORDER BY archived_at DESC LIMIT ?)", (max_rows,))
        await db.commit()

    @staticmethod
    async def get_archived_configs(page: int = 1, per_page: int = 20) -> "tuple[list, int]":
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT COUNT(*) FROM archived_configs") as cur:
            total = (await cur.fetchone())[0]
        offset = max(0, (page - 1) * per_page)
        async with db.execute(
            "SELECT config,protocol,reason,archived_at FROM archived_configs "
            "ORDER BY archived_at DESC LIMIT ? OFFSET ?", (per_page, offset)
        ) as cur:
            rows = await cur.fetchall()
        return rows, total

    @staticmethod
    async def export_archived_configs() -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT config FROM archived_configs ORDER BY archived_at DESC") as cur:
            rows = await cur.fetchall()
        return [r[0] for r in rows]

    @staticmethod
    async def export_archived_configs_n(limit: int) -> list:
        """طبق درخواست ادمین: دریافت تعداد دلخواه (نه فقط کل آرشیو) از کانفیگ‌های بایگانی‌شده."""
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT config FROM archived_configs ORDER BY archived_at DESC LIMIT ?", (limit,)
        ) as cur:
            rows = await cur.fetchall()
        return [r[0] for r in rows]

    # ── prefs ──────────────────────────────────────────────────────────────────
    @staticmethod
    async def get_user_prefs(user_id: int) -> dict:
        db = await DatabaseManager.get_conn()
        await db.execute("INSERT OR IGNORE INTO prefs (user_id) VALUES (?)",(user_id,))
        await db.commit()
        async with db.execute(
            "SELECT protocol,country,language,is_vip,user_state,total_downloads,"
            "fav_country,fav_protocol FROM prefs WHERE user_id=?", (user_id,)
        ) as cur:
            r = await cur.fetchone()

        if r is None:
            # رفع باگ «احتمال خطای NoneType»: قبلاً اگر به هر دلیلی (مثلاً
            # race condition بین چند درخواست همزمان، یا یک خطای گذرای DB)
            # INSERT OR IGNORE سطر را واقعاً ننوشته بود، SELECT بعدی None
            # برمی‌گرداند و r[0] بلافاصله با TypeError کرش می‌کرد. حالا یک
            # بار دیگر INSERT+SELECT تلاش می‌شود (برای رفع race condition
            # لحظه‌ای)؛ اگر باز هم ناموفق بود، به‌جای کرش، مقادیر پیش‌فرض
            # امن (همان مقادیر DEFAULT جدول prefs) برگردانده می‌شود تا کاربر
            # حداقل بتواند با بات کار کند.
            logger.warning(f"get_user_prefs: ردیف prefs برای user_id={user_id} یافت نشد — تلاش مجدد.")
            await db.execute("INSERT OR IGNORE INTO prefs (user_id) VALUES (?)",(user_id,))
            await db.commit()
            async with db.execute(
                "SELECT protocol,country,language,is_vip,user_state,total_downloads,"
                "fav_country,fav_protocol FROM prefs WHERE user_id=?", (user_id,)
            ) as cur:
                r = await cur.fetchone()

        if r is None:
            logger.error(f"get_user_prefs: تلاش مجدد هم ناموفق بود برای user_id={user_id} — پیش‌فرض امن استفاده شد.")
            return {
                "protocol": "ALL", "country": "ALL", "language": "fa",
                "is_vip": False, "user_state": None,
                "total_downloads": 0,
                "fav_country": "ALL", "fav_protocol": "ALL",
            }

        return {
            "protocol": r[0], "country": r[1], "language": r[2] or "fa",
            "is_vip": bool(r[3]), "user_state": r[4],
            "total_downloads": r[5] or 0,
            "fav_country": r[6] or "ALL", "fav_protocol": r[7] or "ALL",
        }

    @staticmethod
    async def set_user_pref(user_id: int, key: str, value) -> None:
        _SQL = {
            "protocol":       "UPDATE prefs SET protocol=?       WHERE user_id=?",
            "country":        "UPDATE prefs SET country=?        WHERE user_id=?",
            "language":       "UPDATE prefs SET language=?       WHERE user_id=?",
            "is_vip":         "UPDATE prefs SET is_vip=?         WHERE user_id=?",
            "user_state":     "UPDATE prefs SET user_state=?     WHERE user_id=?",
            "fav_country":    "UPDATE prefs SET fav_country=?    WHERE user_id=?",
            "fav_protocol":   "UPDATE prefs SET fav_protocol=?   WHERE user_id=?",
        }
        if key not in _SQL: raise ValueError(f"کلید نامعتبر: {key!r}")
        db = await DatabaseManager.get_conn()
        await db.execute("INSERT OR IGNORE INTO prefs (user_id) VALUES (?)",(user_id,))
        await db.execute(_SQL[key],(int(value) if isinstance(value,bool) else value, user_id))
        await db.commit()

    # ── usage ──────────────────────────────────────────────────────────────────
    @staticmethod
    async def check_rate_limit(user_id: int) -> tuple:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        db    = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT requests_count,configs_received FROM daily_usage WHERE user_id=? AND date=?",
            (user_id,today)
        ) as cur:
            r = await cur.fetchone()
            return (r[0],r[1]) if r else (0,0)

    @staticmethod
    async def increment_usage(user_id: int, count: int) -> None:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        DatabaseManager._enqueue(
            """INSERT INTO daily_usage (user_id,date,requests_count,configs_received)
               VALUES (?,?,1,?) ON CONFLICT(user_id,date) DO UPDATE SET
               requests_count=requests_count+1,configs_received=configs_received+?""",
            (user_id,today,count,count))
        DatabaseManager._enqueue(
            "UPDATE prefs SET total_downloads=total_downloads+? WHERE user_id=?",(count,user_id))

    @staticmethod
    async def touch_user(user_id: int, username: "str|None", first_name: "str|None" = None) -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        DatabaseManager._enqueue(
            "INSERT OR IGNORE INTO prefs (user_id,first_seen) VALUES (?,?)",(user_id,now))
        DatabaseManager._enqueue(
            "UPDATE prefs SET username=?,first_name=?,last_seen=?,first_seen=COALESCE(first_seen,?) WHERE user_id=?",
            (username,first_name,now,now,user_id))

    # ── کاربران ────────────────────────────────────────────────────────────────
    @staticmethod
    async def count_total_users() -> int:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT COUNT(*) FROM prefs") as cur:
            return (await cur.fetchone())[0]

    @staticmethod
    async def get_all_user_ids() -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT user_id FROM prefs") as cur:
            return [r[0] for r in await cur.fetchall()]

    @staticmethod
    async def get_active_users(days: int = 7) -> list:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
        db     = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT user_id,username,first_name,last_seen FROM prefs WHERE last_seen>=? ORDER BY last_seen DESC",
            (cutoff,)
        ) as cur:
            return await cur.fetchall()

    @staticmethod
    async def get_inactive_users(days: int = 30) -> list:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
        db     = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT user_id,username,first_name,last_seen FROM prefs WHERE last_seen<? OR last_seen IS NULL ORDER BY last_seen",
            (cutoff,)
        ) as cur:
            return await cur.fetchall()

    @staticmethod
    async def get_top_users(limit: int = 10) -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT p.user_id,p.username,p.first_name,p.total_downloads "
            "FROM prefs p ORDER BY p.total_downloads DESC LIMIT ?", (limit,)
        ) as cur:
            return await cur.fetchall()

    @staticmethod
    async def get_user_full(user_id: int) -> "dict|None":
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT user_id,username,first_name,protocol,country,language,is_vip,"
            "first_seen,last_seen,total_downloads,fav_country,fav_protocol FROM prefs WHERE user_id=?",
            (user_id,)
        ) as cur:
            r = await cur.fetchone()
            if not r: return None
            return dict(zip([c[0] for c in cur.description], r))

    @staticmethod
    async def find_user(query: str) -> list:
        db = await DatabaseManager.get_conn()
        q  = f"%{query}%"
        async with db.execute(
            "SELECT user_id,username,first_name,last_seen FROM prefs WHERE username LIKE ? OR first_name LIKE ? OR CAST(user_id AS TEXT) LIKE ?",
            (q,q,q)
        ) as cur:
            return await cur.fetchall()

    # ── ban / VIP ───────────────────────────────────────────────────────────────
    @staticmethod
    async def ban_user(user_id: int, reason: str = "") -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        db  = await DatabaseManager.get_conn()
        await db.execute("INSERT OR REPLACE INTO banned_users (user_id,banned_at,reason) VALUES (?,?,?)",(user_id,now,reason))
        await db.commit()

    @staticmethod
    async def unban_user(user_id: int) -> bool:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT 1 FROM banned_users WHERE user_id=?",(user_id,)) as cur:
            if not await cur.fetchone(): return False
        await db.execute("DELETE FROM banned_users WHERE user_id=?",(user_id,))
        await db.commit()
        return True

    @staticmethod
    async def is_banned(user_id: int) -> bool:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT 1 FROM banned_users WHERE user_id=?",(user_id,)) as cur:
            return bool(await cur.fetchone())

    @staticmethod
    async def get_banned_users() -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT user_id,banned_at,reason FROM banned_users ORDER BY banned_at DESC") as cur:
            return await cur.fetchall()

    @staticmethod
    async def set_vip(user_id: int, status: bool) -> None:
        db = await DatabaseManager.get_conn()
        await db.execute("INSERT OR IGNORE INTO prefs (user_id) VALUES (?)",(user_id,))
        await db.execute("UPDATE prefs SET is_vip=? WHERE user_id=?",(1 if status else 0, user_id))
        await db.commit()

    @staticmethod
    async def get_vip_users() -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT user_id,username,first_name,last_seen FROM prefs WHERE is_vip=1 ORDER BY last_seen DESC"
        ) as cur:
            return await cur.fetchall()

    # ── abuse ───────────────────────────────────────────────────────────────────
    @staticmethod
    async def get_abuse(user_id: int) -> dict:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT score,warn_count,mute_until FROM abuse_scores WHERE user_id=?",(user_id,)) as cur:
            r = await cur.fetchone()
            return {"score": r[0], "warn_count": r[1], "mute_until": r[2]} if r else {"score":0,"warn_count":0,"mute_until":None}

    @staticmethod
    async def update_abuse(user_id: int, score: int, warn_count: int, mute_until: "str|None") -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        DatabaseManager._enqueue(
            """INSERT INTO abuse_scores (user_id,score,warn_count,mute_until,last_updated) VALUES (?,?,?,?,?)
               ON CONFLICT(user_id) DO UPDATE SET score=?,warn_count=?,mute_until=?,last_updated=?""",
            (user_id,score,warn_count,mute_until,now, score,warn_count,mute_until,now))

    @staticmethod
    async def is_muted(user_id: int) -> bool:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT mute_until FROM abuse_scores WHERE user_id=?",(user_id,)) as cur:
            r = await cur.fetchone()
            if not r or not r[0]: return False
        try:
            mu = datetime.fromisoformat(r[0]).replace(tzinfo=timezone.utc)
            return datetime.now(timezone.utc) < mu
        except Exception:
            return False

    # ── IP blacklist ─────────────────────────────────────────────────────────────
    @staticmethod
    async def load_ip_blacklist() -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT ip FROM ip_blacklist") as cur:
            return [r[0] for r in await cur.fetchall()]

    @staticmethod
    async def add_ip_blacklist(ip: str, reason: str = "") -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        db  = await DatabaseManager.get_conn()
        await db.execute("INSERT OR IGNORE INTO ip_blacklist (ip,reason,added_at) VALUES (?,?,?)",(ip,reason,now))
        await db.commit()
        IPBlacklist.add(ip)

    @staticmethod
    async def get_ip_blacklist() -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT ip,reason,added_at FROM ip_blacklist ORDER BY added_at DESC") as cur:
            return await cur.fetchall()

    # ── feedback ────────────────────────────────────────────────────────────────
    @staticmethod
    async def add_feedback(user_id: int, config_hash: str, reason: str) -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        DatabaseManager._enqueue(
            "INSERT INTO user_feedback (user_id,config_hash,reason,timestamp) VALUES (?,?,?,?)",
            (user_id,config_hash,reason,now))
        ConfigReputation.record_report(config_hash)

    @staticmethod
    async def get_feedback(limit: int = 20) -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT uf.user_id,p.username,uf.config_hash,uf.reason,uf.timestamp "
            "FROM user_feedback uf LEFT JOIN prefs p ON uf.user_id=p.user_id ORDER BY uf.timestamp DESC LIMIT ?",
            (limit,)
        ) as cur:
            return await cur.fetchall()

    # ── منابع ───────────────────────────────────────────────────────────────────
    @staticmethod
    async def add_source(url: str, found_via: str = "manual") -> "tuple[bool, str]":
        """
        برمی‌گرداند (ok, reason). رفع باگ «لاگ‌نکردن موفقیت‌آمیز بودن افزودن
        منبع»: قبلاً هر خطایی (چه تکراری‌بودن URL چه خطای واقعی DB) با یک
        except Exception یکسان نادیده گرفته می‌شد و فقط True/False برمی‌گشت؛
        ادمین نمی‌فهمید مشکل واقعی چه بوده. حالا علت دقیق هم برگردانده و هم
        لاگ می‌شود.
        """
        try:
            dc = detect_datacenter(urlparse(url).netloc)
            db = await DatabaseManager.get_conn()
            await db.execute("INSERT INTO sources (url,enabled,datacenter,found_via) VALUES (?,1,?,?)",(url,dc,found_via))
            await db.commit()
            return True, "added"
        except aiosqlite.IntegrityError:
            logger.info(f"addsource: URL تکراری رد شد: {url}")
            return False, "duplicate"
        except Exception as exc:
            logger.error(f"addsource: خطای DB هنگام افزودن منبع {url}: {exc}", exc_info=True)
            return False, f"db_error: {exc}"

    @staticmethod
    async def remove_source(source_id: int) -> bool:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT id FROM sources WHERE id=?",(source_id,)) as cur:
            if not await cur.fetchone(): return False
        await db.execute("DELETE FROM sources WHERE id=?",(source_id,))
        await db.commit()
        return True

    @staticmethod
    async def set_source_enabled(source_id: int, enabled: bool) -> bool:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT id FROM sources WHERE id=?",(source_id,)) as cur:
            if not await cur.fetchone(): return False
        await db.execute("UPDATE sources SET enabled=? WHERE id=?",(1 if enabled else 0, source_id))
        await db.commit()
        return True

    @staticmethod
    async def get_all_sources() -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT id,url,enabled,fail_count,last_fail_time,datacenter,found_via FROM sources ORDER BY id"
        ) as cur:
            return await cur.fetchall()

    @staticmethod
    async def update_source_status(url: str, failed: bool) -> None:
        db = await DatabaseManager.get_conn()
        if failed:
            await db.execute("UPDATE sources SET fail_count=fail_count+1,last_fail_time=? WHERE url=?",(time.time(),url))
            await db.execute("UPDATE sources SET enabled=0 WHERE url=? AND fail_count>=3",(url,))
        else:
            await db.execute("UPDATE sources SET fail_count=0,last_fail_time=0,enabled=1 WHERE url=?",(url,))
        await db.commit()

    @staticmethod
    async def reenable_cooled_sources(cooldown: int = 1800) -> None:
        db = await DatabaseManager.get_conn()
        await db.execute("UPDATE sources SET enabled=1,fail_count=0 WHERE enabled=0 AND last_fail_time<?",(time.time()-cooldown,))
        await db.commit()

    @staticmethod
    async def get_top_sources(limit: int = 5) -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT id,url,fail_count,enabled,last_fail_time FROM sources ORDER BY fail_count ASC, enabled DESC LIMIT ?",
            (limit,)
        ) as cur:
            return await cur.fetchall()

    @staticmethod
    async def get_slow_sources(limit: int = 5) -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT id,url,fail_count,enabled FROM sources ORDER BY fail_count DESC LIMIT ?", (limit,)
        ) as cur:
            return await cur.fetchall()

    # ── search cooldown ──────────────────────────────────────────────────────────
    @staticmethod
    async def check_search_cooldown(user_id: int) -> float:
        """برمی‌گرداند چند ثانیه باید صبر کند (0 = آزاد)."""
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT last_search FROM search_cooldown WHERE user_id=?",(user_id,)) as cur:
            r = await cur.fetchone()
            if not r: return 0.0
        elapsed = time.time() - r[0]
        wait    = Config.SEARCH_COOLDOWN - elapsed
        return max(0.0, wait)

    @staticmethod
    async def update_search_time(user_id: int) -> None:
        now = time.time()
        db  = await DatabaseManager.get_conn()
        await db.execute(
            "INSERT INTO search_cooldown (user_id,last_search) VALUES (?,?) ON CONFLICT(user_id) DO UPDATE SET last_search=?",
            (user_id,now,now))
        await db.commit()

    # ── rules ────────────────────────────────────────────────────────────────────
    @staticmethod
    async def get_rules() -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT id,name,condition,action,enabled,last_triggered FROM rules ORDER BY id") as cur:
            return [dict(zip([c[0] for c in cur.description], r)) for r in await cur.fetchall()]

    @staticmethod
    async def add_rule(name: str, condition: str, action: str) -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        db  = await DatabaseManager.get_conn()
        await db.execute("INSERT INTO rules (name,condition,action,created_at) VALUES (?,?,?,?)",(name,condition,action,now))
        await db.commit()

    @staticmethod
    async def delete_rule(rule_id: int) -> bool:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT id FROM rules WHERE id=?",(rule_id,)) as cur:
            if not await cur.fetchone(): return False
        await db.execute("DELETE FROM rules WHERE id=?",(rule_id,))
        await db.commit()
        return True

    @staticmethod
    async def touch_rule(rule_id: int) -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        DatabaseManager._enqueue("UPDATE rules SET last_triggered=? WHERE id=?",(now,rule_id))

    # ── system logs ──────────────────────────────────────────────────────────────
    @staticmethod
    async def add_log(level: str, message: str, source: str = "") -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        DatabaseManager._enqueue(
            "INSERT INTO system_logs (level,source,message,timestamp) VALUES (?,?,?,?)",
            (level,source,message,now))

    @staticmethod
    async def get_logs(limit: int = 30, level: str = "") -> list:
        db = await DatabaseManager.get_conn()
        if level:
            async with db.execute(
                "SELECT level,source,message,timestamp FROM system_logs WHERE level=? ORDER BY timestamp DESC LIMIT ?",
                (level,limit)
            ) as cur:
                return await cur.fetchall()
        else:
            async with db.execute(
                "SELECT level,source,message,timestamp FROM system_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
            ) as cur:
                return await cur.fetchall()

    @staticmethod
    async def cleanup_logs(days: int = 7) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
        db     = await DatabaseManager.get_conn()
        async with db.execute("SELECT COUNT(*) FROM system_logs WHERE timestamp<?",(cutoff,)) as cur:
            n = (await cur.fetchone())[0]
        await db.execute("DELETE FROM system_logs WHERE timestamp<?",(cutoff,))
        await db.commit()
        return n

    # ── GitHub sources ───────────────────────────────────────────────────────────
    @staticmethod
    async def save_github_source(url: str, repo: str, stars: int) -> bool:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            db = await DatabaseManager.get_conn()
            await db.execute(
                "INSERT OR IGNORE INTO github_sources (url,repo,stars,found_at) VALUES (?,?,?,?)",
                (url,repo,stars,now))
            await db.commit()
            return True
        except Exception:
            return False

    @staticmethod
    async def get_unnotified_github_sources() -> list:
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT id,url,repo,stars,found_at FROM github_sources WHERE notified=0 ORDER BY stars DESC"
        ) as cur:
            return await cur.fetchall()

    @staticmethod
    async def mark_github_notified(ids: list) -> None:
        if not ids: return
        db = await DatabaseManager.get_conn()
        await db.executemany("UPDATE github_sources SET notified=1 WHERE id=?",[(i,) for i in ids])
        await db.commit()

    # ── backup ───────────────────────────────────────────────────────────────────
    @staticmethod
    async def backup_db() -> bytes:
        import shutil, tempfile
        tmp = tempfile.mktemp(suffix=".db")
        db  = await DatabaseManager.get_conn()
        async with aiosqlite.connect(tmp) as dst:
            await db.backup(dst)
        with open(tmp, "rb") as f:
            data = f.read()
        os.unlink(tmp)
        return data

    # ── Real Ping Tester: مدیریت جدول tested_configs ────────────────────────────
    @staticmethod
    async def upsert_tested_configs(results: list) -> None:
        """
        `results`: لیست دیکشنری {config, protocol, country, alive, ping_ms}.
        اگر alive=False باشد، fail_streak افزایش می‌یابد (روی conflict) یا
        روی ۱ ست می‌شود (اولین شکست). بعد از این تابع، purge_dead_tested_configs
        با Config.PING_FAIL_TOLERANCE صدا زده می‌شود — یعنی یک کانفیگ باید چند
        بار پیاپی شکست بخورد (نه فقط یک‌بار) تا از جدول تست‌شده حذف شود؛ این
        از حذف نادرست کانفیگ‌های سالمی که فقط دچار نوسان لحظه‌ای شبکه شده‌اند
        جلوگیری می‌کند. توجه: این حذف فقط از tested_configs است، نه از کش خام
        منابع (CacheManager._cache) — کانفیگ در دور بعدی دوباره شانس تست دارد.
        """
        if not results:
            return
        now = time.time()
        db  = await DatabaseManager.get_conn()
        for r in results:
            fp = AdvancedDeduplicator.fingerprint(r["config"])
            # نکته مهم دربارهٔ رفع باگ فیلتر کیس‌حساس: CountryDetector.detect()
            # مقدار "ALL" (حروف بزرگ) را برای کشور نامشخص برمی‌گرداند، در حالی
            # که کدهای کشور واقعی (مثلاً "de") حروف کوچک هستند. اگر این مقدار
            # بدون نرمال‌سازی در دیتابیس ذخیره شود، ستون country ترکیبی از
            # حروف بزرگ/کوچک می‌شود و مقایسه‌های دقیق (=?) در جاهای دیگر (مثل
            # get_live_configs_for_delivery که ورودی کاربر را lower() می‌کند)
            # با آن مطابقت پیدا نمی‌کنند. اینجا هر دو مقدار را قبل از ذخیره
            # lower() می‌کنیم تا کل دیتابیس همیشه یک‌دست (case-consistent) باشد.
            protocol = str(r.get("protocol", "unknown") or "unknown").lower()
            country  = str(r.get("country", "ALL") or "ALL").lower()
            if r["alive"]:
                await db.execute(
                    """INSERT INTO tested_configs (fp,config,protocol,country,ping_ms,last_tested,fail_streak)
                       VALUES (?,?,?,?,?,?,0)
                       ON CONFLICT(fp) DO UPDATE SET
                         ping_ms=excluded.ping_ms, last_tested=excluded.last_tested, fail_streak=0""",
                    (fp, r["config"], protocol, country, r["ping_ms"], now))
            else:
                await db.execute(
                    """INSERT INTO tested_configs (fp,config,protocol,country,ping_ms,last_tested,fail_streak)
                       VALUES (?,?,?,?,-1,?,1)
                       ON CONFLICT(fp) DO UPDATE SET
                         ping_ms=-1, last_tested=excluded.last_tested, fail_streak=fail_streak+1""",
                    (fp, r["config"], protocol, country, now))
        await db.commit()

    @staticmethod
    async def purge_dead_tested_configs(max_fail_streak: int = 1) -> int:
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT COUNT(*) FROM tested_configs WHERE fail_streak>=?", (max_fail_streak,)
        ) as cur:
            n = (await cur.fetchone())[0]
        await db.execute("DELETE FROM tested_configs WHERE fail_streak>=?", (max_fail_streak,))
        await db.commit()
        return n

    @staticmethod
    async def trim_tested_configs(max_store: int) -> None:
        """اگر تعداد از سقف رد شد، قدیمی‌ترین‌ها (بر اساس last_tested) حذف می‌شوند."""
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT COUNT(*) FROM tested_configs") as cur:
            total = (await cur.fetchone())[0]
        if total > max_store:
            excess = total - max_store
            await db.execute(
                "DELETE FROM tested_configs WHERE fp IN "
                "(SELECT fp FROM tested_configs ORDER BY last_tested ASC LIMIT ?)", (excess,))
            await db.commit()

    @staticmethod
    async def purge_all_tested_configs() -> int:
        """
        پاک‌سازی کامل جدول tested_configs (حتی 🟢 و 🟡) — هر ۲۴ ساعت طبق
        درخواست، تا بات همیشه با تازه‌ترین دسته‌ی ممکن از کانفیگ‌های زنده کار
        کند و کانفیگ‌های قدیمی که ممکن است دیگر معتبر نباشند انباشته نشوند.
        """
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT COUNT(*) FROM tested_configs") as cur:
            n = (await cur.fetchone())[0]
        await db.execute("DELETE FROM tested_configs")
        await db.commit()
        return n

    @staticmethod
    async def admin_add_tested_config(cfg: str, protocol: str, country: str = "ALL",
                                       ping_ms: int = 1) -> None:
        """
        افزودن دستی یک کانفیگ به لیست تست‌شده‌ها توسط ادمین (بدون تست واقعی Xray).
        ping_ms=1 پیش‌فرض می‌شود تا در دسته‌ی 🟢 قرار گیرد و بلافاصله قابل تحویل
        به کاربران باشد؛ در دور بعدی بازتست (cron_ping_retest)، مقدار واقعی
        جایگزین می‌شود چون این کانفیگ هم مثل بقیه در چرخه‌ی بازتست قرار می‌گیرد.
        """
        db = await DatabaseManager.get_conn()
        fp = AdvancedDeduplicator.fingerprint(cfg)
        await db.execute(
            """INSERT INTO tested_configs (fp,config,protocol,country,ping_ms,last_tested,fail_streak)
               VALUES (?,?,?,?,?,?,0)
               ON CONFLICT(fp) DO UPDATE SET
                 config=excluded.config, protocol=excluded.protocol, country=excluded.country,
                 ping_ms=excluded.ping_ms, last_tested=excluded.last_tested, fail_streak=0""",
            (fp, cfg, protocol.lower(), country.lower(), ping_ms, time.time()))
        await db.commit()

    @staticmethod
    async def admin_remove_tested_config(identifier: str) -> int:
        """
        حذف دستی یک یا چند کانفیگ تست‌شده. identifier می‌تواند fingerprint دقیق
        یا یک زیررشته از خود کانفیگ (مثلاً بخشی از هاست/پورت) باشد.
        خروجی: تعداد ردیف‌های حذف‌شده.
        """
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT COUNT(*) FROM tested_configs WHERE fp=? OR config LIKE ?",
            (identifier, f"%{identifier}%")
        ) as cur:
            n = (await cur.fetchone())[0]
        await db.execute(
            "DELETE FROM tested_configs WHERE fp=? OR config LIKE ?",
            (identifier, f"%{identifier}%"))
        await db.commit()
        return n

    @staticmethod
    async def get_tested_configs(page: int = 1, per_page: int = 10) -> "tuple[list, int, int]":
        # WHERE ping_ms>=0: فقط کانفیگ‌های زنده نمایش داده شوند. purge_dead_tested_configs
        # معمولاً بلافاصله بعد از هر دور تست، ردیف‌های مرده را حذف می‌کند، اما این
        # شرط یک لایه محافظتی اضافه است تا در فاصله‌ی کوتاه بین insert و purge،
        # یا در صورت هر خطای دیگر، هیچ‌وقت کانفیگ -1ms به کاربر نشان داده نشود.
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT COUNT(*) FROM tested_configs WHERE ping_ms>=0") as cur:
            total = (await cur.fetchone())[0]
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = max(1, min(page, total_pages))
        async with db.execute(
            "SELECT config,protocol,country,ping_ms,last_tested FROM tested_configs "
            "WHERE ping_ms>=0 ORDER BY ping_ms ASC LIMIT ? OFFSET ?", (per_page, (page-1)*per_page)
        ) as cur:
            rows = await cur.fetchall()
        return rows, page, total_pages

    @staticmethod
    async def get_unposted_tested_configs_raw() -> list:
        """کانفیگ‌های زنده‌ی تست‌شده که هنوز در کانال پست نشده‌اند — برای جلوگیری از پست تکراری."""
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT fp,config,protocol,country,ping_ms FROM tested_configs "
            "WHERE ping_ms>=0 AND posted_to_channel=0 ORDER BY ping_ms ASC"
        ) as cur:
            return await cur.fetchall()

    @staticmethod
    async def mark_posted_to_channel(fps: list) -> None:
        if not fps:
            return
        db = await DatabaseManager.get_conn()
        await db.executemany(
            "UPDATE tested_configs SET posted_to_channel=1 WHERE fp=?",
            [(fp,) for fp in fps])
        await db.commit()

    @staticmethod
    async def reset_channel_post_flags() -> None:
        """وقتی همه‌ی استخر زنده قبلاً پست شده، فلگ‌ها را ریست می‌کند تا کانال
        بدون پست نماند و چرخه‌ی پست از نو (روی همان کانفیگ‌های همچنان زنده) آغاز شود."""
        db = await DatabaseManager.get_conn()
        await db.execute("UPDATE tested_configs SET posted_to_channel=0 WHERE ping_ms>=0")
        await db.commit()

    @staticmethod
    async def get_all_tested_configs_raw() -> list:
        """برای CacheManager: همه کانفیگ‌های تست‌شده و زنده (بدون صفحه‌بندی) — برای پست کانال."""
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT config,protocol,country,ping_ms FROM tested_configs WHERE ping_ms>=0 ORDER BY ping_ms ASC"
        ) as cur:
            return await cur.fetchall()

    @staticmethod
    async def count_live_tested_configs() -> int:
        db = await DatabaseManager.get_conn()
        async with db.execute("SELECT COUNT(*) FROM tested_configs WHERE ping_ms>=0") as cur:
            return (await cur.fetchone())[0]

    @staticmethod
    async def get_live_configs_for_delivery(proto: str = "ALL", country: str = "ALL",
                                             limit: "int|None" = None) -> list:
        """
        استخر واقعی برای تحویل به کاربر: فقط کانفیگ‌هایی که با Real Ping Tester
        (Xray واقعی) تست شده و زنده تشخیص داده شده‌اند (ping_ms>=0). قبلاً تحویل
        کاربر از کش خام منابع (تست‌نشده) انجام می‌شد که باعث می‌شد کاربر کانفیگ‌های
        مرده/فیلترشده هم دریافت کند.

        رفع باگ «عدم رعایت محدودیت تعداد»: قبلاً اگر limit پاس داده نمی‌شد یا
        صفر/None بود، هیچ سقفی روی SQL اعمال نمی‌شد و کل جدول tested_configs
        (که می‌تواند تا PING_MAX_TESTED_STORE=۲۰۰۰+ ردیف باشد) در حافظه لود
        می‌شد. حالا حتی بدون limit صریح، یک سقف سخت (MAX_CONFIGS_PER_REQUEST×5)
        همیشه در سطح SQL اعمال می‌شود — مستقل از اینکه فراخوان چه چیزی پاس داده.
        """
        db = await DatabaseManager.get_conn()
        q = "SELECT config FROM tested_configs WHERE ping_ms>=0"
        params: list = []
        if proto != "ALL":
            q += " AND protocol=?"
            params.append(proto.lower())
        if country != "ALL":
            q += " AND country=?"
            params.append(country.lower())
        q += " ORDER BY ping_ms ASC"
        # سقف سخت مستقل از ورودی — همیشه اعمال می‌شود، حتی اگر limit فراموش شود.
        hard_cap = Config.MAX_CONFIGS_PER_REQUEST * 5
        effective_limit = min(limit * 5, hard_cap) if limit else hard_cap
        q += " LIMIT ?"
        params.append(effective_limit)
        async with db.execute(q, tuple(params)) as cur:
            rows = await cur.fetchall()
        configs = [r[0] for r in rows]
        random.shuffle(configs)
        return configs

    @staticmethod
    async def get_stale_tested_configs(older_than_sec: int, limit: int) -> list:
        """کانفیگ‌هایی که آخرین بار قبل از N ثانیه تست شده‌اند — برای بازتست دوره‌ای."""
        cutoff = time.time() - older_than_sec
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT config FROM tested_configs WHERE last_tested<? ORDER BY last_tested ASC LIMIT ?",
            (cutoff, limit)
        ) as cur:
            rows = await cur.fetchall()
        return [r[0] for r in rows]

    @staticmethod
    async def get_stale_tested_configs_with_meta(older_than_sec: int, limit: int) -> list:
        """
        مثل get_stale_tested_configs ولی protocol/country موجود را هم برمی‌گرداند
        تا در بازتست، این متادیتا حفظ شود و بعد از هر بازتست به "unknown"/"ALL"
        بازنویسی نشود (رفع باگ گم‌شدن فیلتر پروتکل/کشور بعد از بازتست).
        """
        cutoff = time.time() - older_than_sec
        db = await DatabaseManager.get_conn()
        async with db.execute(
            "SELECT config,protocol,country FROM tested_configs WHERE last_tested<? "
            "ORDER BY last_tested ASC LIMIT ?",
            (cutoff, limit)
        ) as cur:
            rows = await cur.fetchall()
        return [{"config": r[0], "protocol": r[1], "country": r[2]} for r in rows]


# ═══════════════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════════════
# SourceManager — دریافت و پردازش منابع
# ═══════════════════════════════════════════════════════════════════════════════
class SourceManager:
    _CONFIG_RE = re.compile(
        r"(?:vless|vmess|trojan|ss|hysteria2|hy2|tuic|wireguard|wg)"
        r"://[^\s\n\r,\"'\]\[<>{}|\\^`]+", re.IGNORECASE)
    _ALIASES   = {"hy2":"hysteria2","wg":"wireguard"}
    _semaphore: "asyncio.Semaphore|None" = None
    _MAX_B64   = 70 * 1024 * 1024
    _WS_TABLE  = str.maketrans("","","  \t\n\r\x0b\x0c")

    @classmethod
    def _get_sem(cls) -> asyncio.Semaphore:
        if cls._semaphore is None:
            cls._semaphore = asyncio.Semaphore(Config.MAX_CONCURRENT_FETCHES)
        return cls._semaphore

    @staticmethod
    def extract_configs(text: str) -> list:
        return SourceManager._CONFIG_RE.findall(text)

    @staticmethod
    def try_decode_base64(raw: str) -> str:
        if len(raw) > SourceManager._MAX_B64: return ""
        cleaned = raw.translate(SourceManager._WS_TABLE)
        if len(cleaned) < 20 or not re.match(r"^[A-Za-z0-9+/=_-]+$", cleaned): return ""
        cleaned += "=" * ((4 - len(cleaned) % 4) % 4)
        last_err = None
        for fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                return fn(cleaned.encode()).decode("utf-8", errors="ignore")
            except Exception as exc:
                last_err = exc
                continue
        # رفع باگ «مدیریت ناقص خطا در دیکود Base64»: قبلاً خطا کاملاً نادیده
        # گرفته می‌شد و فقط رشته‌ی خالی برمی‌گشت — هیچ ردی از علت شکست باقی
        # نمی‌ماند. حالا حداقل در سطح debug لاگ می‌شود (نه warning، چون این
        # تابع مرتب روی متن‌های غیر-base64 هم صدا زده می‌شود و لاگ سطح بالاتر
        # فقط نویز تولید می‌کند؛ برای دیباگ عمیق‌تر سطح لاگ را DEBUG کنید).
        logger.debug(f"try_decode_base64: دیکود ناموفق ({len(cleaned)} کاراکتر): {last_err}")
        return ""

    @staticmethod
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10), reraise=True)
    async def _fetch(session: aiohttp.ClientSession, url: str) -> str:
        ssl_ctx = False if Config.DISABLE_SSL_VERIFY else None
        if ssl_ctx is False:
            # رفع باگ SSL/MitM: قبلاً فقط یک بار در startup (Config.validate)
            # هشدار داده می‌شد. حالا هر بار که یک fetch واقعی بدون تأیید
            # گواهی انجام می‌شود جداگانه لاگ می‌شود تا در محیط تولید مشخص
            # باشد دقیقاً کدام درخواست‌ها بدون SSL verification رفته‌اند.
            logger.warning(f"⚠️ SSL verification غیرفعال — fetch بدون تأیید گواهی: {url}")
        timeout = aiohttp.ClientTimeout(total=Config.FETCH_TIMEOUT)
        async with session.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ConfigBot/6.0)"},
            timeout=timeout, ssl=ssl_ctx,
        ) as resp:
            if resp.status != 200: raise RuntimeError(f"HTTP {resp.status}")
            return await resp.text()

    @classmethod
    async def process_source(cls, session: aiohttp.ClientSession, url: str) -> "tuple[list,bool]":
        """
        برمی‌گرداند (items, failed).

        رفع درخواست ادمین «کانفیگ‌های خراب/تکراری بایگانی شوند، نه نابود»:
        هر کانفیگی که رد می‌شود (ساختار نامعتبر، کیفیت پایین، یا تکراری در
        همین دسته) حالا با دلیل دقیق در archived_configs ثبت می‌شود تا از
        پنل ادمین قابل مرور/دریافت باشد — به‌جای گم‌شدن کامل و بی‌ردپا.
        نوشتن‌های آرشیو دسته‌ای (executemany یک‌باره در پایان تابع) انجام
        می‌شود، نه یک INSERT به‌ازای هر کانفیگ رد‌شده، تا فشار روی SQLite
        در حجم بالا زیاد نشود.
        """
        async with cls._get_sem():
            try:
                text     = await cls._fetch(session, url)
                raw_cfgs = cls.extract_configs(text)
                decoded  = cls.try_decode_base64(text)
                if decoded: raw_cfgs.extend(cls.extract_configs(decoded))

                results: list = []
                seen: set     = set()
                fps:  set     = set()   # fingerprint dedup
                to_archive: list = []   # (config, protocol, reason) — batched

                for raw in raw_cfgs:
                    if raw in seen: continue
                    seen.add(raw)
                    proto_guess = raw.split("://")[0].lower()
                    if not ConfigStructureValidator.is_valid(raw):
                        to_archive.append((raw, proto_guess, "invalid_structure"))
                        continue
                    if Config.FILTER_QUALITY and not QualityFilter.is_quality(raw):
                        to_archive.append((raw, proto_guess, "low_quality"))
                        continue
                    fp = AdvancedDeduplicator.fingerprint(raw)
                    if fp in fps:
                        to_archive.append((raw, proto_guess, "duplicate_in_batch"))
                        continue
                    fps.add(fp)
                    branded = BrandingEngine.apply(raw)
                    proto   = cls._ALIASES.get(proto_guess, proto_guess)
                    country = CountryDetector.detect(raw)
                    hp_match = AdvancedDeduplicator._HOST_PORT_RE.search(raw)
                    dc       = detect_datacenter(hp_match.group(1) if hp_match else url)
                    results.append({"config": branded, "protocol": proto,
                                    "country": country, "dc": dc, "fp": fp})

                if to_archive:
                    await DatabaseManager.archive_configs_batch(to_archive)

                await DatabaseManager.update_source_status(url, failed=False)
                return results, False

            except Exception as exc:
                logger.warning(f"❌ منبع ناموفق [{url}]: {type(exc).__name__}: {exc}")
                await DatabaseManager.update_source_status(url, failed=True)
                return [], True

# ═══════════════════════════════════════════════════════════════════════════════
# CacheManager — مدیریت کش کانفیگ‌ها
# ═══════════════════════════════════════════════════════════════════════════════
class CacheManager:
    _cache:       list = []
    _last_update: str  = "هنوز بروزرسانی نشده"
    _prev_count:  int  = 0
    _prev_delta:  str  = ""
    is_loading:   bool = True
    _lock: "asyncio.Lock|None" = None
    _global_fps:  set = set()   # fingerprints of all cached configs
    _last_reload_mono: float = 0.0   # monotonic ts — برای جلوگیری از reload تکراری همزمان

    @classmethod
    def _get_lock(cls) -> asyncio.Lock:
        if cls._lock is None: cls._lock = asyncio.Lock()
        return cls._lock

    @classmethod
    async def reload(cls, bot=None) -> int:
        cls.is_loading = True
        prev_cnt = len(cls._cache)
        async with cls._get_lock():
            # محافظت در برابر Race Condition: اگر یک reload دیگر همین الان
            # (کمتر از ۱۰ ثانیه پیش) کارش تمام شده، این یکی صرفاً از آن نتیجه استفاده می‌کند
            # به‌جای تکرار فرآیند سنگین fetch از صدها منبع.
            now_mono = time.monotonic()
            if cls._cache and (now_mono - cls._last_reload_mono) < 10:
                cls.is_loading = False
                return len(cls._cache)

            logger.info("🔄 reload کش...")
            fail_count = 0
            try:
                await DatabaseManager.reenable_cooled_sources()
                sources     = await DatabaseManager.get_all_sources()
                active_urls = [r[1] for r in sources if r[2] == 1]
                logger.info(f"📡 {len(active_urls)} منبع فعال...")

                new_cache: list = []
                new_fps:   set  = set()
                connector = aiohttp.TCPConnector(limit=Config.MAX_CONCURRENT_FETCHES)
                async with aiohttp.ClientSession(connector=connector) as session:
                    results = await asyncio.gather(
                        *[SourceManager.process_source(session, u) for u in active_urls],
                        return_exceptions=True)

                for result in results:
                    if isinstance(result, BaseException): fail_count += 1; continue
                    items, failed = result
                    if failed: fail_count += 1
                    for item in items:
                        if item["fp"] not in new_fps:
                            new_fps.add(item["fp"])
                            new_cache.append(item)

                # Memory Optimizer — اگر از سقف گذشت، برش بزن
                if len(new_cache) > Config.MAX_CACHE_SIZE:
                    new_cache = new_cache[:Config.MAX_CACHE_SIZE]

                if new_cache:
                    delta = len(new_cache) - prev_cnt
                    cls._prev_delta  = f"{'+'if delta>=0 else ''}{delta:,} کانفیگ"
                    cls._cache       = new_cache
                    cls._global_fps  = new_fps
                    cls._last_update = datetime.now(ZoneInfo("Asia/Tehran")).strftime("%H:%M:%S")
                    logger.info(f"✅ کش آماده — {len(cls._cache):,} کانفیگ (delta: {cls._prev_delta})")
                else:
                    logger.warning("⚠️  هیچ کانفیگی یافت نشد.")

                await DatabaseManager.add_log("INFO", f"Reload: {len(new_cache):,} configs, {fail_count} source failures")
                cls._last_reload_mono = now_mono

            except Exception as exc:
                logger.error(f"❌ خطای reload: {exc}", exc_info=True)
                await DatabaseManager.add_log("ERROR", str(exc), "CacheManager.reload")
            finally:
                cls.is_loading = False

        # Anomaly check بعد از unlock — فقط وقتی bot واقعی در دسترس باشد
        # (در post_init اولین reload بدون bot صدا زده می‌شود، پس چک را نادیده می‌گیریم)
        if bot is not None:
            try:
                asyncio.create_task(AnomalyDetector.check(bot, len(cls._cache), fail_count))
            except Exception:
                pass

        return len(cls._cache)

    @classmethod
    def get_filtered(cls, proto: str, country: str, limit: "int|None" = None) -> list:
        """
        رفع باگ «بارگذاری تمام کانفیگ‌ها در حافظه»: قبلاً این تابع همیشه کل
        نتایج منطبق را به‌صورت یک لیست کامل در حافظه می‌ساخت (result = [...])
        و شافل می‌کرد، حتی وقتی فراخوان فقط چند کانفیگ لازم داشت. حالا اگر
        limit داده شود، از الگوریتم reservoir sampling استفاده می‌شود که با
        یک پاس روی کش، بدون نگه‌داشتن کل نتایج منطبق در حافظه، دقیقاً `limit`
        آیتم تصادفی انتخاب می‌کند. اگر limit داده نشود (برای سازگاری با
        فراخوان‌های قدیمی)، رفتار قبلی حفظ می‌شود.
        """
        proto_l   = proto.lower()   if proto   != "ALL" else None
        country_l = country.lower() if country != "ALL" else None

        def _matches(c: dict) -> bool:
            if proto_l   is not None and c["protocol"] != proto_l:   return False
            if country_l is not None and c["country"]  != country_l: return False
            return True

        if limit is None:
            result  = [c for c in cls._cache if _matches(c)]
            configs = [i["config"] for i in result]
            random.shuffle(configs)
            return configs

        # --- Reservoir sampling: یک پاس، حافظه ثابت به‌اندازه‌ی limit ---
        reservoir: list = []
        seen = 0
        for c in cls._cache:
            if not _matches(c):
                continue
            seen += 1
            if len(reservoir) < limit:
                reservoir.append(c["config"])
            else:
                j = random.randint(0, seen - 1)
                if j < limit:
                    reservoir[j] = c["config"]
        return reservoir

    @classmethod
    def count_filtered(cls, proto: str, country: str) -> int:
        """فقط تعداد نتایج منطبق را می‌شمارد — بدون ساخت لیست کامل در حافظه."""
        proto_l   = proto.lower()   if proto   != "ALL" else None
        country_l = country.lower() if country != "ALL" else None
        n = 0
        for c in cls._cache:
            if proto_l   is not None and c["protocol"] != proto_l:   continue
            if country_l is not None and c["country"]  != country_l: continue
            n += 1
        return n

    @classmethod
    def search_configs(cls, query: str, limit: "int|None" = None) -> list:
        """
        جستجو در کانفیگ‌های کش. رفع باگ «جستجوی چندکلمه‌ای هرگز نتیجه‌ای
        برنمی‌گرداند»: قبلاً کل عبارت جستجو (مثلاً دقیقاً همان مثال راهنمای
        بات: "germany vless") به‌عنوان یک substring واحد چک می‌شد — و چون
        هیچ کانفیگی واقعاً رشته‌ی «germany vless» را کلمه‌به‌کلمه ندارد،
        چنین جستجویی همیشه صفر نتیجه می‌داد، دقیقاً برخلاف راهنمای خودِ بات.
        حالا هر جستجو به کلمات جدا (whitespace) شکسته می‌شود و یک کانفیگ
        فقط وقتی match می‌شود که همه‌ی کلمات (AND) هرکدام در حداقل یکی از
        فیلدهای config/پروتکل/کد کشور/نام کشور دیده شوند — حالا «germany
        vless» هر کانفیگ VLESS آلمانی را پیدا می‌کند، نه هیچ‌کدام را.
        رفع باگ «بازگشت تعداد بیشتر از درخواست»: اگر limit داده شود، به‌جای
        جمع‌آوری کل نتایج و برش بعدی با random.sample، از reservoir sampling
        با حافظه ثابت استفاده می‌شود.
        """
        terms = query.strip().lower().split()
        if not terms: return []

        def _matches(item: dict) -> bool:
            cfg_lower    = item["config"].lower()
            protocol     = item.get("protocol", "").lower()
            country      = item.get("country", "").lower()
            country_name = COUNTRY_MAP.get(item.get("country",""), _UNKNOWN_COUNTRY)[1].lower()
            blob = f"{cfg_lower} {protocol} {country} {country_name}"
            return all(term in blob for term in terms)

        if limit is None:
            results = [item["config"] for item in cls._cache if _matches(item)]
            random.shuffle(results)
            return results

        reservoir: list = []
        seen = 0
        for item in cls._cache:
            if not _matches(item):
                continue
            seen += 1
            if len(reservoir) < limit:
                reservoir.append(item["config"])
            else:
                j = random.randint(0, seen - 1)
                if j < limit:
                    reservoir[j] = item["config"]
        return reservoir

    @classmethod
    def count_search(cls, query: str) -> int:
        """فقط تعداد نتایج جستجو را می‌شمارد — بدون ساخت لیست کامل در حافظه."""
        terms = query.strip().lower().split()
        if not terms: return 0
        n = 0
        for item in cls._cache:
            cfg_lower    = item["config"].lower()
            protocol     = item.get("protocol", "").lower()
            country      = item.get("country", "").lower()
            country_name = COUNTRY_MAP.get(item.get("country",""), _UNKNOWN_COUNTRY)[1].lower()
            blob = f"{cfg_lower} {protocol} {country} {country_name}"
            if all(term in blob for term in terms):
                n += 1
        return n


    @classmethod
    def get_channel_configs(cls) -> list:
        proto     = Config.CHANNEL_FILTER_PROTOCOL.lower()
        countries = Config.CHANNEL_FILTER_COUNTRIES
        return [
            i["config"] for i in cls._cache
            if (proto == "all" or i["protocol"] == proto)
            and (not countries or i["country"] in countries)
        ]

    @classmethod
    def stats(cls) -> dict:
        protos:    dict = {}
        countries: dict = {}
        dcs:       dict = {}
        for item in cls._cache:
            protos[item["protocol"]]   = protos.get(item["protocol"],   0) + 1
            countries[item["country"]] = countries.get(item["country"], 0) + 1
            dcs[item.get("dc","?")]    = dcs.get(item.get("dc","?"),    0) + 1
        return {
            "total":       len(cls._cache),
            "last_update": cls._last_update,
            "delta":       cls._prev_delta,
            "protocols":   protos,
            "countries":   countries,
            "datacenters": dcs,
        }

# ═══════════════════════════════════════════════════════════════════════════════
# GitHubSourceFinder — جستجوی خودکار منابع جدید در GitHub
# ═══════════════════════════════════════════════════════════════════════════════
class GitHubSourceFinder:
    _QUERIES = [
        "v2ray vless config subscription",
        "vless vmess trojan free subscription",
        "free vpn config vless reality",
    ]
    _RAW_PATTERNS = [
        r"https://raw\.githubusercontent\.com/[^/]+/[^/]+/[^/]+/[^\s\"'<>]+\.txt",
        r"https://raw\.githubusercontent\.com/[^/]+/[^/]+/[^/]+/[^\s\"'<>]+sub",
    ]

    @classmethod
    async def search(cls, bot=None) -> int:
        headers = {"Accept": "application/vnd.github.v3+json"}
        if Config.GITHUB_TOKEN:
            headers["Authorization"] = f"token {Config.GITHUB_TOKEN}"
        timeout = aiohttp.ClientTimeout(total=15)
        found   = 0
        try:
            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                for q in cls._QUERIES:
                    url = f"https://api.github.com/search/repositories?q={aiohttp.helpers.quote(q)}&sort=stars&order=desc&per_page=10"
                    async with session.get(url) as resp:
                        if resp.status != 200: continue
                        data = await resp.json()
                    for item in data.get("items",[]):
                        html_url = item.get("html_url","")
                        repo     = item.get("full_name","")
                        stars    = item.get("stargazers_count",0)
                        # تبدیل به raw URL ممکن — فقط repo URL ذخیره می‌شود
                        saved = await DatabaseManager.save_github_source(
                            html_url, repo, stars)
                        if saved: found += 1
                    await asyncio.sleep(1)

            # گزارش به ادمین
            if bot:
                unnotified = await DatabaseManager.get_unnotified_github_sources()
                if unnotified:
                    lines = [f"🔍 *منابع GitHub جدید یافت شد ({len(unnotified)}):*\n"]
                    for row in unnotified[:10]:
                        lines.append(f"⭐ `{row[3]}` — [{row[2]}]({row[1]})")
                    await SmartNotifier.notify(bot, "github_found", "\n".join(lines))
                    await DatabaseManager.mark_github_notified([r[0] for r in unnotified])

        except Exception as exc:
            logger.warning(f"GitHubSourceFinder: {exc}")
        return found


# ═══════════════════════════════════════════════════════════════════════════════
# Force-Join Middleware
# ═══════════════════════════════════════════════════════════════════════════════
async def check_channel_membership(bot, user_id: int) -> bool:
    if not Config.REQUIRED_CHANNEL: return True
    try:
        m = await bot.get_chat_member(chat_id=Config.REQUIRED_CHANNEL, user_id=user_id)
        return m.status in ("member","creator","administrator")
    except TelegramError:
        return False

def make_join_keyboard(lang: str = "fa") -> InlineKeyboardMarkup:
    ch   = Config.REQUIRED_CHANNEL
    link = f"https://t.me/{ch.lstrip('@')}"
    return InlineKeyboardMarkup([[InlineKeyboardButton(T("join_channel",lang), url=link)]])

# ═══════════════════════════════════════════════════════════════════════════════
# کمک‌کننده‌های گروه
# ═══════════════════════════════════════════════════════════════════════════════
def _is_group(update: Update) -> bool:
    return update.effective_chat is not None and \
           update.effective_chat.type in ("group","supergroup","channel")

def _bot_is_addressed(update: Update, bot_username: "str|None") -> bool:
    """
    رفع باگ حیاتی «هیچ دستور/دکمه‌ای در گروه کار نمی‌کند»: قبلاً این تابع
    فقط دو حالت را «خطاب به بات» می‌شناخت: ریپلای مستقیم به پیام بات، یا
    وجود متنِ کامل `@usernameبات` هرجایی در پیام. اما تلگرام دستورهای گروهی
    را معمولاً به‌صورت `/addsource@YourBot` می‌فرستد (نه با @mention جدا)،
    و اگر ادمین صرفاً `/addsource https://...` را بدون منشن بات در گروه
    بفرستد (که رایج‌ترین حالت استفاده‌ی واقعی است)، هیچ‌کدام از دو شرط بالا
    برقرار نمی‌شد. در نتیجه global_guard در group=-1 بلافاصله
    ApplicationHandlerStop می‌زد و پیام هرگز به CommandHandler نمی‌رسید —
    بات کاملاً بی‌پاسخ می‌ماند، دقیقاً همان گزارش «/addsource هیچ پاسخی
    نمی‌دهد». حالا هر پیامی که با یک دستور شروع شود (`/cmd` یا
    `/cmd@BotUsername`) هم «خطاب به بات» محسوب می‌شود — چون تلگرام خودش
    فقط دستورهایی را که واقعاً برای این بات هستند تحویل می‌دهد (دستورهای
    `/cmd@AnotherBot` اصلاً به این هندلر نمی‌رسند)، پس نیازی به بررسی
    دستی username نیست. کال‌بک‌های دکمه‌های شیشه‌ای (اینلاین) هم چون از
    طریق تعامل مستقیم با پیام‌های خودِ بات صادر می‌شوند، همیشه «خطاب به
    بات» محسوب می‌شوند.
    """
    msg = update.effective_message
    if update.callback_query is not None:
        return True
    if not msg: return False
    if msg.text and msg.text.startswith("/"): return True
    if (msg.reply_to_message and msg.reply_to_message.from_user and bot_username
            and msg.reply_to_message.from_user.username == bot_username): return True
    if bot_username and f"@{bot_username}" in (msg.text or msg.caption or ""): return True
    return False

def _rk(update: Update) -> dict:
    if _is_group(update) and update.effective_message:
        return {"reply_to_message_id": update.effective_message.message_id}
    return {}

# ═══════════════════════════════════════════════════════════════════════════════
# Abuse Processing — پردازش هوشمند Abuse
# ═══════════════════════════════════════════════════════════════════════════════
async def process_abuse(update: Update, context: ContextTypes.DEFAULT_TYPE, weight: int = 1) -> bool:
    """True = کاربر باید متوقف شود."""
    user = update.effective_user
    if not user or user.id == Config.ADMIN_ID: return False
    # رفع باگ «کانتر Abuse در حافظه بی‌استفاده»: قبلاً AbuseTracker.record()
    # اینجا صدا زده می‌شد و یک امتیاز in-memory برمی‌گرداند که هیچ‌گاه در
    # تصمیم‌گیری استفاده نمی‌شد (فقط new_score بر پایه‌ی دیتابیس تصمیم‌گیر
    # بود) — این کانتر صرفاً سردرگمی ایجاد می‌کرد و حذف شد. تصمیم‌گیری همیشه
    # بر اساس امتیاز پایدار در دیتابیس است (که برخلاف کانتر حافظه، بعد از
    # ری‌استارت بات هم از دست نمی‌رود).
    abuse = await DatabaseManager.get_abuse(user.id)
    new_score = abuse["score"] + weight

    mute_until = None
    warned     = False

    if new_score >= Config.ABUSE_BAN_THRESHOLD:
        await DatabaseManager.ban_user(user.id, "Auto-ban: abuse score")
        await SmartNotifier.notify(context.bot, f"autoban_{user.id}",
            f"🚫 *Auto-Ban*\nکاربر `{user.id}` به دلیل Abuse مسدود شد.")
        return True

    if new_score >= Config.ABUSE_MUTE_THRESHOLD and not await DatabaseManager.is_muted(user.id):
        mute_until = (datetime.now(timezone.utc) + timedelta(minutes=Config.ABUSE_MUTE_MINUTES)).isoformat(timespec="seconds")
        try:
            lang = (await DatabaseManager.get_user_prefs(user.id))["language"]
            await context.bot.send_message(user.id, T("muted", lang))
        except Exception: pass

    if new_score >= Config.ABUSE_WARN_THRESHOLD and abuse["warn_count"] == 0:
        warned = True
        try:
            lang = (await DatabaseManager.get_user_prefs(user.id))["language"]
            await context.bot.send_message(user.id, T("abuse_warned", lang))
        except Exception: pass

    await DatabaseManager.update_abuse(
        user.id, new_score,
        abuse["warn_count"] + (1 if warned else 0),
        mute_until or abuse["mute_until"])
    return False

# ═══════════════════════════════════════════════════════════════════════════════
# Decorators
# ═══════════════════════════════════════════════════════════════════════════════
def admin_only(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *a, **kw):
        if not update.effective_user or update.effective_user.id != Config.ADMIN_ID: return
        return await func(update, context, *a, **kw)
    return wrapper

def is_allowed(user_id: int, prefs: dict, reqs: int, cfgs: int) -> "tuple[bool,str]":
    """بررسی محدودیت روزانه — True = مجاز، str = پیام خطا."""
    if user_id == Config.ADMIN_ID: return True, ""
    is_vip = prefs.get("is_vip", False)
    max_r  = Config.VIP_MAX_DAILY_REQUESTS if is_vip else Config.MAX_DAILY_REQUESTS
    max_c  = Config.VIP_MAX_DAILY_CONFIGS  if is_vip else Config.MAX_DAILY_CONFIGS
    if reqs >= max_r: return False, f"⚠️ سقف درخواست روزانه ({max_r}) تمام شد."
    if cfgs >= max_c: return False, f"⚠️ سقف کانفیگ روزانه ({max_c}) تمام شد."
    return True, ""

# ═══════════════════════════════════════════════════════════════════════════════
# Global Guard
# ═══════════════════════════════════════════════════════════════════════════════
async def global_guard(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if not user: return
    # ادمین همیشه معاف از گیت «خطاب به بات در گروه» است — یک ادمینی که در
    # گروه مدیریتی خودش دستور می‌زند نباید هرگز به‌خاطر این گیت بی‌پاسخ بماند.
    if user.id != Config.ADMIN_ID and _is_group(update):
        if not _bot_is_addressed(update, context.bot.username if context.bot else None):
            raise ApplicationHandlerStop
    if await DatabaseManager.is_banned(user.id): raise ApplicationHandlerStop
    if await DatabaseManager.is_muted(user.id):  raise ApplicationHandlerStop
    await DatabaseManager.touch_user(user.id, user.username,
                                     getattr(user,"first_name",None))
    # Abuse: هر پیام = weight 1
    if update.message:
        await process_abuse(update, context, weight=1)

# ═══════════════════════════════════════════════════════════════════════════════
# UI Keyboards
# ═══════════════════════════════════════════════════════════════════════════════
def make_main_keyboard(user_id: int, lang: str = "fa", tested_btn_on: bool = True) -> InlineKeyboardMarkup:
    is_adm = (user_id == Config.ADMIN_ID)
    rows   = [
        [InlineKeyboardButton(T("get_configs",lang),    callback_data="get_configs"),
         InlineKeyboardButton(T("random_cfg",lang),     callback_data="random_cfg")],
        [InlineKeyboardButton(T("filter_proto",lang),   callback_data="menu_proto"),
         InlineKeyboardButton(T("filter_country",lang), callback_data="menu_country")],
        [InlineKeyboardButton(T("search_cfg",lang),     callback_data="search_configs"),
         InlineKeyboardButton(T("my_profile",lang),     callback_data="my_profile")],
    ]
    # طبق درخواست ادمین: این دکمه از پنل ادمین قابل روشن/خاموش‌کردن است.
    if tested_btn_on:
        rows.append([InlineKeyboardButton(
            "🛰 کانفیگ‌های پینگ گرفته شده" if lang=="fa" else "🛰 Ping-Tested Configs",
            callback_data="tested_configs_1")])
    # دکمه‌ی «لینک ساب من» — فقط وقتی WEBDASH_PUBLIC_URL تنظیم شده باشد نشان
    # داده می‌شود، تا اگر ادمین هنوز پنل وب را دیپلوی نکرده، کاربر با یک
    # دکمه‌ی از کار افتاده روبه‌رو نشود.
    if webdash_configured():
        rows.append([InlineKeyboardButton(
            "🔗 لینک ساب من" if lang=="fa" else "🔗 My Subscription Link",
            callback_data="my_sub_link")])
    rows.append([InlineKeyboardButton(T("lang_toggle",lang), callback_data="toggle_lang")])
    if is_adm:
        rows.append([InlineKeyboardButton(T("admin_panel",lang), callback_data="admin_panel")])
        if webdash_configured():
            rows.append([InlineKeyboardButton(
                "🌐 پنل ادمین تحت وب" if lang=="fa" else "🌐 Web Admin Panel",
                url=admin_panel_url())])
    return InlineKeyboardMarkup(rows)


def make_back_keyboard(lang: str = "fa") -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton(T("back",lang), callback_data="main_menu")]])

def make_admin_keyboard(page: int = 1, lang: str = "fa", tested_btn_on: bool = True) -> InlineKeyboardMarkup:
    """پنل ادمین شیشه‌ای — ۲ صفحه."""
    if page == 1:
        rows = [
            [InlineKeyboardButton("📊 آمار سیستم",         callback_data="adm_stats"),
             InlineKeyboardButton("🏥 Health",              callback_data="adm_health")],
            [InlineKeyboardButton("💾 Cache Info",          callback_data="adm_cache"),
             InlineKeyboardButton("🔄 Reload کش",           callback_data="adm_reload")],
            [InlineKeyboardButton("📡 منابع",               callback_data="adm_sources"),
             InlineKeyboardButton("📈 بهترین منابع",        callback_data="adm_top_sources")],
            [InlineKeyboardButton("🐌 منابع کند",           callback_data="adm_slow_sources"),
             InlineKeyboardButton("🔬 Benchmark",           callback_data="adm_benchmark")],
            [InlineKeyboardButton("👥 کاربران",             callback_data="adm_users"),
             InlineKeyboardButton("🏆 Top کاربران",         callback_data="adm_top_users")],
            [InlineKeyboardButton("📤 Broadcast",           callback_data="adm_broadcast_menu"),
             InlineKeyboardButton("🚫 Ban/Unban",           callback_data="adm_ban_menu")],
            [InlineKeyboardButton("⭐ VIP",                 callback_data="adm_vip_menu"),
             InlineKeyboardButton("🛡 IP Blacklist",        callback_data="adm_blacklist")],
            [InlineKeyboardButton("📋 Logs",                callback_data="adm_logs"),
             InlineKeyboardButton("❌ Errors",              callback_data="adm_errors")],
            [InlineKeyboardButton("⚙️ Rules",               callback_data="adm_rules"),
             InlineKeyboardButton("💬 Feedback",            callback_data="adm_feedback")],
            [InlineKeyboardButton("💾 Backup DB",           callback_data="adm_backup"),
             InlineKeyboardButton("📤 Export کانفیگ",       callback_data="adm_export")],
            [InlineKeyboardButton("📦 آرشیو کانفیگ‌ها",     callback_data="adm_archive_1")],
            [InlineKeyboardButton("▶ صفحه ۲ »",            callback_data="admin_panel_2"),
             InlineKeyboardButton("🔙 منوی اصلی",           callback_data="main_menu")],
        ]
    else:
        toggle_label = ("🔘 دکمه «کانفیگ تست‌شده»: روشن ✅" if tested_btn_on
                         else "⚪️ دکمه «کانفیگ تست‌شده»: خاموش ❌")
        rows = [
            [InlineKeyboardButton("🖥 CPU",                callback_data="adm_cpu"),
             InlineKeyboardButton("🧠 Memory",             callback_data="adm_memory")],
            [InlineKeyboardButton("🌐 GitHub Sources",     callback_data="adm_github"),
             InlineKeyboardButton("📊 Version Compare",    callback_data="adm_version")],
            [InlineKeyboardButton("👤 User Info",          callback_data="adm_userinfo_prompt"),
             InlineKeyboardButton("🔍 Find User",          callback_data="adm_finduser_prompt")],
            [InlineKeyboardButton("🔍 Find Config",        callback_data="adm_findconfig_prompt"),
             InlineKeyboardButton("📊 Analytics",          callback_data="adm_analytics")],
            [InlineKeyboardButton("🗑 Cleanup",             callback_data="adm_cleanup"),
             InlineKeyboardButton("📦 Tasks",              callback_data="adm_tasks")],
            [InlineKeyboardButton("🛰 Ping Test Status",    callback_data="adm_pingstatus")],
            [InlineKeyboardButton("➕ افزودن کانفیگ تست‌شده", callback_data="adm_addtested_prompt"),
             InlineKeyboardButton("➖ حذف کانفیگ تست‌شده",   callback_data="adm_deltested_prompt")],
            [InlineKeyboardButton(toggle_label,            callback_data="adm_toggle_tested_btn")],
            [InlineKeyboardButton("« صفحه ۱",              callback_data="admin_panel"),
             InlineKeyboardButton("🔙 منوی اصلی",          callback_data="main_menu")],
        ]
    return InlineKeyboardMarkup(rows)


def make_broadcast_menu(lang: str = "fa") -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📢 همه کاربران",           callback_data="bc_all")],
        [InlineKeyboardButton("✅ فعالان (۷ روز)",        callback_data="bc_active")],
        [InlineKeyboardButton("😴 غیرفعالان (۳۰+ روز)",  callback_data="bc_inactive")],
        [InlineKeyboardButton("⭐ کاربران VIP",           callback_data="bc_vip")],
        [InlineKeyboardButton("📦 ارسال کانفیگ",          callback_data="bc_configs")],
        [InlineKeyboardButton(T("back",lang),             callback_data="admin_panel")],
    ])

def make_proto_keyboard(current: str, lang: str = "fa") -> InlineKeyboardMarkup:
    PROTOS = ["ALL","VLESS","VMESS","TROJAN","SS","HYSTERIA2","WIREGUARD","TUIC"]
    kb = []
    for i in range(0, len(PROTOS), 2):
        row = []
        for p in PROTOS[i:i+2]:
            mark = " ✅" if current == p else ""
            row.append(InlineKeyboardButton(f"{p}{mark}", callback_data=f"set_proto_{p}"))
        kb.append(row)
    kb.append([InlineKeyboardButton(T("back",lang), callback_data="main_menu")])
    return InlineKeyboardMarkup(kb)

def make_country_keyboard(current: str, lang: str = "fa") -> InlineKeyboardMarkup:
    all_m = " ✅" if current == "ALL" else ""
    kb    = [[InlineKeyboardButton(f"🌍 همه کشورها{all_m}", callback_data="set_cty_ALL")]]
    codes = list(COUNTRY_MAP.keys())
    for i in range(0, len(codes), 3):
        row = []
        for code in codes[i:i+3]:
            flag, name = COUNTRY_MAP[code]
            mark = " ✅" if current == code else ""
            row.append(InlineKeyboardButton(f"{flag} {name}{mark}", callback_data=f"set_cty_{code}"))
        kb.append(row)
    kb.append([InlineKeyboardButton(T("back",lang), callback_data="main_menu")])
    return InlineKeyboardMarkup(kb)

def make_feedback_keyboard(config_hash: str, lang: str = "fa") -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(T("feedback_not_work",lang), callback_data=f"fb_not_work_{config_hash}")],
        [InlineKeyboardButton(T("feedback_slow",lang),     callback_data=f"fb_slow_{config_hash}")],
        [InlineKeyboardButton(T("feedback_weak",lang),     callback_data=f"fb_weak_{config_hash}")],
        [InlineKeyboardButton(T("cancel",lang),            callback_data="main_menu")],
    ])

# ═══════════════════════════════════════════════════════════════════════════════
# send_main_menu
# ═══════════════════════════════════════════════════════════════════════════════
async def send_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE,
                          edit: bool = False) -> None:
    user_id = update.effective_user.id
    prefs   = await DatabaseManager.get_user_prefs(user_id)
    lang    = prefs["language"]
    rk      = _rk(update)

    if CacheManager.is_loading and not CacheManager._cache:
        text = T("loading", lang)
        if edit and update.callback_query:
            try: await update.callback_query.edit_message_text(text); return
            except BadRequest: pass
        await context.bot.send_message(update.effective_chat.id, text, **rk)
        return

    reqs, cfgs = await DatabaseManager.check_rate_limit(user_id)
    is_adm     = (user_id == Config.ADMIN_ID)
    is_vip     = prefs.get("is_vip", False)
    vip_badge  = f" {T('vip_badge',lang)}" if is_vip else ""
    cdisplay   = country_display(prefs["country"], lang)

    if is_adm:
        text = (
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"{T('welcome',lang)}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🕐 آخرین بروزرسانی: `{CacheManager._last_update}`\n"
            f"📦 کانفیگ‌های فعال: `{len(CacheManager._cache):,}`\n"
            f"🔄 تغییر آخر: `{CacheManager._prev_delta or '---'}`\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"⚙️ پروتکل: `{prefs['protocol']}`  |  🌍 کشور: `{cdisplay}`\n"
            f"👑 *ادمین — بدون محدودیت*\n"
        )
    else:
        max_r    = Config.VIP_MAX_DAILY_REQUESTS if is_vip else Config.MAX_DAILY_REQUESTS
        max_c    = Config.VIP_MAX_DAILY_CONFIGS  if is_vip else Config.MAX_DAILY_CONFIGS
        rem_c    = max(0, max_c - cfgs)
        text = (
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"{T('welcome',lang)}{vip_badge}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🕐 بروزرسانی: `{CacheManager._last_update}`\n"
            f"📦 کانفیگ‌های موجود: `{len(CacheManager._cache):,}`\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"⚙️ پروتکل: `{prefs['protocol']}`  |  🌍 `{cdisplay}`\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📈 مصرف امروز:\n"
            f"  🔢 درخواست: `{reqs}/{max_r}`\n"
            f"  📥 کانفیگ:  `{cfgs}/{max_c}` — باقی: `{rem_c}`\n"
        )

    tested_on = await _tested_btn_enabled()
    kb = make_main_keyboard(user_id, lang, tested_btn_on=tested_on)
    if edit and update.callback_query:
        try:
            await update.callback_query.edit_message_text(text, reply_markup=kb, parse_mode="Markdown")
            return
        except BadRequest: pass
    await context.bot.send_message(update.effective_chat.id, text,
                                   reply_markup=kb, parse_mode="Markdown", **rk)


# ═══════════════════════════════════════════════════════════════════════════════
# دستورات کاربر
# ═══════════════════════════════════════════════════════════════════════════════
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await DatabaseManager.set_user_pref(update.effective_user.id, "user_state", None)
    await send_main_menu(update, context, edit=False)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    prefs  = await DatabaseManager.get_user_prefs(update.effective_user.id)
    lang   = prefs["language"]
    is_adm = update.effective_user.id == Config.ADMIN_ID
    # رفع باگ «/help همیشه فارسی است»: قبلاً lang از prefs خوانده می‌شد ولی
    # هرگز واقعاً برای انتخاب متن استفاده نمی‌شد — کاربرانی که زبان انگلیسی
    # را انتخاب کرده بودند هم همیشه همین متن فارسی هاردکدشده را می‌دیدند.
    if lang == "en":
        text = (
            "❓ *Bot Guide*\n\n"
            "📦 *Get Configs:* enter how many you want\n"
            "🎲 *Random:* one config with your current filters\n"
            "🔍 *Search:* a search term, e.g. `germany vless`\n"
            "🔧 *Protocol Filter:* config type\n"
            "🌍 *Country Filter:* destination country\n"
            "👤 *Profile:* your personal stats\n"
            "🌐 *Language:* switch between Persian/English\n\n"
            "📌 /start — main menu\n"
            "📌 /profile — your profile\n"
            "📌 /lang — change language\n"
        )
        if is_adm:
            text += (
                "\n━━━━━━━━━━━━━━━━━━\n"
                "👑 *Admin commands:*\n"
                "/admin — admin panel\n"
                "/stats — full stats\n"
                "/health — system health\n"
                "/reload — reload cache\n"
                "/benchmark — run benchmark\n"
                "/vip add/remove ID — manage VIP\n"
                "/ban ID — ban user\n"
                "/unban ID — unban user\n"
                "/broadcast MSG — broadcast message\n"
                "/addsource URL — add source\n"
                "/removesource ID — remove source\n"
                "/backup — DB backup\n"
                "/export — export all configs\n"
            )
    else:
        text = (
            "❓ *راهنمای ربات*\n\n"
            "📦 *دریافت کانفیگ:* عدد دلخواه را وارد کنید\n"
            "🎲 *تصادفی:* یک کانفیگ با فیلتر فعلی\n"
            "🔍 *جستجو:* عبارت مورد نظر مثل `germany vless`\n"
            "🔧 *فیلتر پروتکل:* نوع کانفیگ\n"
            "🌍 *فیلتر کشور:* کشور مقصد\n"
            "👤 *پروفایل:* آمار شخصی شما\n"
            "🌐 *زبان:* تغییر بین فارسی/انگلیسی\n\n"
            "📌 /start — منوی اصلی\n"
            "📌 /profile — پروفایل شما\n"
            "📌 /lang — تغییر زبان\n"
        )
        if is_adm:
            text += (
                "\n━━━━━━━━━━━━━━━━━━\n"
                "👑 *دستورات ادمین:*\n"
                "/admin — پنل ادمین\n"
                "/stats — آمار کامل\n"
                "/health — وضعیت سیستم\n"
                "/reload — بروزرسانی کش\n"
                "/benchmark — بنچمارک\n"
                "/vip add/remove ID — مدیریت VIP\n"
                "/ban ID — مسدودسازی\n"
                "/unban ID — رفع مسدودیت\n"
                "/broadcast MSG — پیام همگانی\n"
                "/addsource URL — افزودن منبع\n"
                "/removesource ID — حذف منبع\n"
                "/backup — پشتیبان DB\n"
                "/export — خروجی همه کانفیگ‌ها\n"
            )
    await update.message.reply_text(text, parse_mode="Markdown", **_rk(update))

async def lang_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    prefs   = await DatabaseManager.get_user_prefs(update.effective_user.id)
    new_lng = "en" if prefs["language"] == "fa" else "fa"
    await DatabaseManager.set_user_pref(update.effective_user.id, "language", new_lng)
    label   = "🇮🇷 زبان به فارسی تغییر یافت." if new_lng == "fa" else "🇬🇧 Language changed to English."
    await update.message.reply_text(label, **_rk(update))

async def profile_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    uid   = update.effective_user.id
    prefs = await DatabaseManager.get_user_prefs(uid)
    lang  = prefs["language"]
    full  = await DatabaseManager.get_user_full(uid)
    reqs, cfgs = await DatabaseManager.check_rate_limit(uid)
    # رفع باگ «/profile همیشه فارسی است»: مشابه /help، قبلاً lang خوانده
    # می‌شد ولی هرگز در انتخاب متن استفاده نمی‌شد.
    if lang == "en":
        text = (
            "👤 *Your Profile*\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"🆔 ID: `{uid}`\n"
            f"📛 Name: `{full.get('first_name','—')}`\n"
            f"🔗 Username: `{'@'+full['username'] if full.get('username') else '—'}`\n"
            f"⭐ VIP: `{'Yes' if prefs['is_vip'] else 'No'}`\n"
            f"🌍 Language: `{lang.upper()}`\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"📦 Total downloaded: `{prefs['total_downloads']:,}` configs\n"
            f"⚙️ Current protocol: `{prefs['protocol']}`\n"
            f"🌍 Current country: `{country_display(prefs['country'], lang)}`\n"
            f"📅 First seen: `{(full.get('first_seen') or '—')[:10]}`\n"
            f"🕐 Last active: `{(full.get('last_seen') or '—')[:16].replace('T',' ')}`\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"📈 Today: requests `{reqs}` | configs `{cfgs}`\n"
        )
    else:
        text = (
            "👤 *پروفایل شما*\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"🆔 آیدی: `{uid}`\n"
            f"📛 نام: `{full.get('first_name','—')}`\n"
            f"🔗 یوزرنیم: `{'@'+full['username'] if full.get('username') else '—'}`\n"
            f"⭐ VIP: `{'بله' if prefs['is_vip'] else 'خیر'}`\n"
            f"🌍 زبان: `{lang.upper()}`\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"📦 کل دانلود: `{prefs['total_downloads']:,}` کانفیگ\n"
            f"⚙️ پروتکل فعلی: `{prefs['protocol']}`\n"
            f"🌍 کشور فعلی: `{country_display(prefs['country'], lang)}`\n"
            f"📅 اولین ورود: `{(full.get('first_seen') or '—')[:10]}`\n"
            f"🕐 آخرین فعالیت: `{(full.get('last_seen') or '—')[:16].replace('T',' ')}`\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"📈 امروز: درخواست `{reqs}` | کانفیگ `{cfgs}`\n"
        )
    await update.message.reply_text(text, parse_mode="Markdown", **_rk(update))

# ═══════════════════════════════════════════════════════════════════════════════
# هندلر پیام متنی — دریافت تعداد / جستجو
# ═══════════════════════════════════════════════════════════════════════════════
async def user_message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    prefs   = await DatabaseManager.get_user_prefs(user_id)
    lang    = prefs["language"]
    state   = prefs.get("user_state") or ""
    rk      = _rk(update)
    text_in = (update.message.text or "").strip()

    # ── حالت‌های ادمین: پرامپت‌های User Info / Find User / Find Config /
    #    افزودن و حذف دستی کانفیگ تست‌شده ───────────────────────────────────
    if state.startswith("adm_waiting_") and user_id == Config.ADMIN_ID:
        await DatabaseManager.set_user_pref(user_id, "user_state", None)
        back_kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙", callback_data="admin_panel_2")]])

        if state == "adm_waiting_userinfo":
            target = None
            if text_in.lstrip("-").isdigit():
                target = await DatabaseManager.get_user_full(int(text_in))
            if not target:
                matches = await DatabaseManager.find_user(text_in.lstrip("@"))
                if matches:
                    target = await DatabaseManager.get_user_full(matches[0][0])
            if not target:
                await update.message.reply_text("❌ کاربری یافت نشد.", reply_markup=back_kb, **rk)
                return
            txt = (
                f"👤 *اطلاعات کاربر*\n"
                f"🆔 `{target['user_id']}`\n"
                f"📛 `{target.get('first_name') or '—'}`\n"
                f"🔗 `{('@'+target['username']) if target.get('username') else '—'}`\n"
                f"⭐ VIP: `{'بله' if target.get('is_vip') else 'خیر'}`\n"
                f"📦 دانلود کل: `{target.get('total_downloads',0):,}`\n"
                f"📅 اولین ورود: `{(target.get('first_seen') or '—')[:10]}`\n"
                f"🕐 آخرین فعالیت: `{(target.get('last_seen') or '—')[:16].replace('T',' ')}`\n"
            )
            await update.message.reply_text(txt, parse_mode="Markdown", reply_markup=back_kb, **rk)
            return

        if state == "adm_waiting_finduser":
            matches = await DatabaseManager.find_user(text_in)
            if not matches:
                await update.message.reply_text("❌ کاربری یافت نشد.", reply_markup=back_kb, **rk)
                return
            lines = [f"🆔 `{r[0]}` | {('@'+r[1]) if r[1] else (r[2] or '—')}" for r in matches[:20]]
            await update.message.reply_text(
                f"🔍 *{len(matches)} کاربر یافت شد:*\n\n" + "\n".join(lines),
                parse_mode="Markdown", reply_markup=back_kb, **rk)
            return

        if state == "adm_waiting_findconfig":
            total   = CacheManager.count_search(text_in)
            results = CacheManager.search_configs(text_in, limit=10)
            if not results:
                await update.message.reply_text("❌ کانفیگی یافت نشد.", reply_markup=back_kb, **rk)
                return
            body = "\n\n".join(f"`{c}`" for c in results)
            await update.message.reply_text(
                f"🔍 *{total} کانفیگ یافت شد (تا ۱۰ مورد نمایش):*\n\n{body}",
                parse_mode="Markdown", reply_markup=back_kb, **rk)
            return

        if state == "adm_waiting_addtested":
            cfg = text_in.strip()
            proto = None
            for p in ("vless", "vmess", "trojan", "ss"):
                if cfg.lower().startswith(p + "://"):
                    proto = p
                    break
            if not proto:
                await update.message.reply_text(
                    "❌ فرمت کانفیگ نامعتبر است (باید با vless://, vmess://, trojan:// یا ss:// شروع شود).",
                    reply_markup=back_kb, **rk)
                return
            await DatabaseManager.admin_add_tested_config(cfg, proto)
            await update.message.reply_text(
                "✅ کانفیگ به لیست تست‌شده‌ها اضافه شد و بلافاصله قابل‌تحویل است.",
                reply_markup=back_kb, **rk)
            return

        if state == "adm_waiting_deltested":
            if len(text_in) < 4:
                await update.message.reply_text(
                    "❌ عبارت خیلی کوتاه است (حداقل ۴ کاراکتر) تا از حذف اشتباهی جلوگیری شود.",
                    reply_markup=back_kb, **rk)
                return
            n = await DatabaseManager.admin_remove_tested_config(text_in)
            await update.message.reply_text(
                f"✅ `{n}` کانفیگ حذف شد." if n else "ℹ️ چیزی مطابق این عبارت پیدا نشد.",
                parse_mode="Markdown", reply_markup=back_kb, **rk)
            return

        # طبق درخواست ادمین: دریافت تعداد دلخواه از آرشیو کانفیگ‌های حذف‌شده.
        if state == "adm_waiting_archive_count":
            if not text_in.isdigit() or int(text_in) <= 0:
                await update.message.reply_text(T("invalid_number", lang), reply_markup=back_kb, **rk)
                return
            n = min(int(text_in), Config.MAX_ARCHIVED_CONFIGS)
            configs = await DatabaseManager.export_archived_configs_n(n)
            if not configs:
                await update.message.reply_text("❌ آرشیو خالی است.", reply_markup=back_kb, **rk)
                return
            bio = io.BytesIO("\n".join(configs).encode()); bio.seek(0)
            ts  = datetime.now(ZoneInfo("Asia/Tehran")).strftime("%Y%m%d_%H%M")
            await update.message.reply_document(
                document=bio, filename=f"archived_{len(configs)}_{ts}.txt",
                caption=f"📦 {len(configs):,} کانفیگ آرشیوشده (خراب/تکراری)", **rk)
            return

    # ── حالت جستجو: ورود کلمه کلیدی ────────────────────────────────────────
    if state == "waiting_search":
        if not text_in:
            await update.message.reply_text(T("search_empty", lang), **rk)
            return
        total = CacheManager.count_search(text_in)
        await DatabaseManager.set_user_pref(user_id, "user_state", f"search_count:{text_in[:80]}")
        if not total:
            await DatabaseManager.set_user_pref(user_id, "user_state", None)
            await update.message.reply_text(T("search_none", lang), **rk)
            return
        # رفع باگ «بارگذاری تمام کانفیگ‌ها در حافظه»: قبلاً کل نتایج جستجو
        # (که می‌تواند برای یک عبارت پرتکرار ده‌ها هزار مورد باشد) در
        # context.user_data هر کاربر نگه داشته می‌شد. حالا فقط یک نمونه‌ی
        # تصادفی به‌اندازه‌ی سقف واقعی درخواست (MAX_CONFIGS_PER_REQUEST)
        # ذخیره می‌شود — چون کاربر در هر صورت نمی‌تواند بیش از این مقدار
        # درخواست کند. عدد نمایش‌داده‌شده (total) هم‌چنان دقیق و کامل است.
        results = CacheManager.search_configs(text_in, limit=Config.MAX_CONFIGS_PER_REQUEST)
        await DatabaseManager.update_search_time(user_id)
        context.user_data["search_results"] = results
        await update.message.reply_text(
            T("search_results", lang, count=f"{total:,}") + f"\n\n{T('enter_count',lang)}",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(T("cancel",lang), callback_data="main_menu")]]),
            parse_mode="Markdown", **rk)
        return

    # ── حالت جستجو: ورود تعداد ─────────────────────────────────────────────
    if state and state.startswith("search_count:"):
        if not text_in.isdigit() or int(text_in) <= 0:
            await update.message.reply_text(T("invalid_number", lang), **rk)
            return
        results = context.user_data.get("search_results", [])
        if not results:
            await DatabaseManager.set_user_pref(user_id, "user_state", None)
            await update.message.reply_text(T("search_none", lang), **rk)
            return
        requested = min(int(text_in), Config.MAX_CONFIGS_PER_REQUEST, len(results))
        if user_id != Config.ADMIN_ID:
            _, cfgs_today = await DatabaseManager.check_rate_limit(user_id)
            remaining     = max(0, (Config.VIP_MAX_DAILY_CONFIGS if prefs["is_vip"] else Config.MAX_DAILY_CONFIGS) - cfgs_today)
            requested     = min(requested, remaining)
        selected = random.sample(results, requested)
        await DatabaseManager.set_user_pref(user_id, "user_state", None)
        await DatabaseManager.increment_usage(user_id, len(selected))
        # نتایج جستجو از کش خام می‌آیند (جستجوی متنی روی کل استخر منابع)، پس
        # ممکن است تست‌نشده باشند — به کاربر اطلاع می‌دهیم.
        await _deliver_configs(update, context, selected, lang, rk, untested=True)
        return

    # ── حالت عادی: ورود تعداد کانفیگ ───────────────────────────────────────
    if state == "waiting_count":
        if not text_in.isdigit() or int(text_in) <= 0:
            await update.message.reply_text(T("invalid_number", lang), **rk)
            return
        requested = min(int(text_in), Config.MAX_CONFIGS_PER_REQUEST)
        if user_id != Config.ADMIN_ID:
            _, cfgs_today = await DatabaseManager.check_rate_limit(user_id)
            remaining     = max(0, (Config.VIP_MAX_DAILY_CONFIGS if prefs["is_vip"] else Config.MAX_DAILY_CONFIGS) - cfgs_today)
            if remaining <= 0:
                await DatabaseManager.set_user_pref(user_id, "user_state", None)
                await update.message.reply_text(T("daily_limit", lang), **rk)
                return
            requested = min(requested, remaining)
        # اولویت با استخر واقعاً تست‌شده و زنده (Real Ping Tester). فقط اگر این
        # استخر کاملاً خالی بود (مثلاً بلافاصله بعد از اولین استارت بات، قبل از
        # اولین دور تست) به کش خام منابع بازمی‌گردیم تا کاربر بی‌پاسخ نماند —
        # ولی در حالت عادی، تحویل همیشه از کانفیگ‌های واقعاً پینگ‌گرفته‌شده است.
        matches = await DatabaseManager.get_live_configs_for_delivery(
            prefs["protocol"], prefs["country"], limit=requested)
        used_fallback = False
        if not matches:
            matches = CacheManager.get_filtered(prefs["protocol"], prefs["country"], limit=requested)
            used_fallback = True
        if not matches:
            await DatabaseManager.set_user_pref(user_id, "user_state", None)
            await update.message.reply_text(T("no_configs", lang), **rk)
            return
        final    = min(requested, len(matches))
        selected = random.sample(matches, final)
        await DatabaseManager.set_user_pref(user_id, "user_state", None)
        await DatabaseManager.increment_usage(user_id, len(selected))
        # اگر تعداد واقعی کمتر از درخواست کاربر بود (استخر زنده هنوز به آن
        # اندازه پر نشده)، صریح توضیح می‌دهیم — قبلاً این افت سایلنت بود و
        # کاربر فکر می‌کرد باگی رخ داده، نه اینکه فقط همین تعداد زنده موجود بود.
        shortfall = requested - final if not used_fallback else 0
        await _deliver_configs(update, context, selected, lang, rk,
                                untested=used_fallback, shortfall=shortfall)

# ── helper: تحویل کانفیگ ───────────────────────────────────────────────────
async def _deliver_configs(update: Update, context: ContextTypes.DEFAULT_TYPE,
                            selected: list, lang: str, rk: dict, untested: bool = False,
                            shortfall: int = 0) -> None:
    # untested=True یعنی این کانفیگ‌ها از کش خام منابع آمده‌اند، نه از استخر
    # واقعاً پینگ‌گرفته‌شده (Real Ping Tester) — فقط زمانی رخ می‌دهد که هنوز
    # هیچ کانفیگی تست نشده باشد (مثلاً بلافاصله بعد از اولین استارت بات).
    warn = (
        ("⚠️ هنوز اولین دور تست پینگ کامل نشده؛ این کانفیگ‌ها تست‌نشده‌اند و ممکن است برخی کار نکنند.\n\n"
         if lang == "fa" else
         "⚠️ First ping-test round not finished yet; these configs are untested and some may not work.\n\n")
        if untested else ""
    )
    if shortfall > 0:
        warn += (
            f"ℹ️ فقط {len(selected)} کانفیگ زنده موجود بود (کمتر از {len(selected)+shortfall} درخواستی). "
            "دور تست بعدی طی چند دقیقه استخر را بیشتر می‌کند.\n\n" if lang == "fa" else
            f"ℹ️ Only {len(selected)} live configs were available. Next test round will refill the pool soon.\n\n"
        )
    if len(selected) < 10:
        body   = "\n\n".join(f"`{c}`" for c in selected)
        # رفع باگ «برخورد هش»: قبلاً فقط ۶۴ کاراکتر اول یک کانفیگ (selected[0])
        # هش می‌شد؛ چون بسیاری از URI های VLESS/VMess در همان ۶۴ کاراکتر اول
        # (پروتکل + ابتدای UUID) مشترک هستند، دو کانفیگ کاملاً متفاوت هش
        # یکسان می‌گرفتند و فیدبک کاربر به کانفیگ اشتباه نسبت داده می‌شد. حالا
        # کل محتوای همه‌ی کانفیگ‌های این بسته با هم هش می‌شود (نه فقط پیشوند
        # یک نمونه) تا شناسه واقعاً یکتای این بسته‌ی مشخص باشد. طول digest به
        # ۱۶ کاراکتر افزایش یافته (کماکان به‌راحتی داخل سقف ۶۴ بایت
        # callback_data تلگرام جا می‌شود).
        chash  = hashlib.sha256("\n".join(selected).encode()).hexdigest()[:16]
        msg    = await update.message.reply_text(
            f"{warn}📦 *{len(selected)} کانفیگ:*\n\n{body}",
            parse_mode="Markdown",
            reply_markup=make_feedback_keyboard(chash, lang),
            **rk)
    else:
        bio = io.BytesIO("\n".join(selected).encode())
        bio.seek(0)
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=bio,
            filename=f"configs_{len(selected)}.txt",
            caption=f"{warn}📦 `{len(selected):,}` کانفیگ" + (" (✅ پینگ‌تست‌شده)" if not untested else ""),
            parse_mode="Markdown", **rk)
    await send_main_menu(update, context, edit=False)


# ═══════════════════════════════════════════════════════════════════════════════
# دستورات ادمین
# ═══════════════════════════════════════════════════════════════════════════════
@admin_only
async def admin_panel_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = "👑 *پنل مدیریت*\n\nیک بخش را انتخاب کنید:"
    tested_on = await _tested_btn_enabled()
    await update.message.reply_text(text, reply_markup=make_admin_keyboard(1, tested_btn_on=tested_on), parse_mode="Markdown")

@admin_only
async def admin_stats_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(await _build_stats_text(), parse_mode="Markdown")

@admin_only
async def admin_health_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(await _build_health_text(), parse_mode="Markdown")

@admin_only
async def admin_reload_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg   = await update.message.reply_text("🔄 در حال بروزرسانی کش...")
    count = await CacheManager.reload(bot=context.bot)
    await msg.edit_text(f"✅ بروزرسانی کامل شد.\n📦 کانفیگ‌های فعال: `{count:,}`\n🔄 تغییر: `{CacheManager._prev_delta}`", parse_mode="Markdown")

@admin_only
async def admin_vip_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    args = context.args
    if not args or args[0] not in ("add","remove","list"):
        await update.message.reply_text("📝 استفاده:\n`/vip add ID`\n`/vip remove ID`\n`/vip list`", parse_mode="Markdown")
        return
    action = args[0]
    if action == "list":
        vips  = await DatabaseManager.get_vip_users()
        lines = [f"⭐ `{r[0]}` @{r[1] or '—'} {(r[3] or '')[:10]}" for r in vips]
        await update.message.reply_text(
            f"⭐ *VIP Users ({len(vips)}):*\n\n" + "\n".join(lines or ["(خالی)"]),
            parse_mode="Markdown")
        return
    if len(args) < 2:
        await update.message.reply_text("❌ آیدی را وارد کنید."); return
    try:   tid = int(args[1].lstrip("@"))
    except: await update.message.reply_text("❌ آیدی نامعتبر."); return
    await DatabaseManager.set_vip(tid, action == "add")
    await update.message.reply_text(f"{'✅ VIP اضافه' if action=='add' else '❎ VIP حذف'} شد: `{tid}`", parse_mode="Markdown")

@admin_only
async def admin_ban_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args or not context.args[0].lstrip("-").isdigit():
        await update.message.reply_text("📝 `/ban ID [دلیل]`", parse_mode="Markdown"); return
    tid    = int(context.args[0])
    reason = " ".join(context.args[1:])
    if tid == Config.ADMIN_ID:
        await update.message.reply_text("❌ نمی‌توان ادمین را مسدود کرد."); return
    await DatabaseManager.ban_user(tid, reason)
    await update.message.reply_text(f"🚫 کاربر `{tid}` مسدود شد.", parse_mode="Markdown")

@admin_only
async def admin_unban_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args or not context.args[0].lstrip("-").isdigit():
        await update.message.reply_text("📝 `/unban ID`", parse_mode="Markdown"); return
    ok = await DatabaseManager.unban_user(int(context.args[0]))
    await update.message.reply_text("✅ رفع مسدودیت شد." if ok else "❌ در لیست نبود.")

@admin_only
async def admin_broadcast_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text(
            "📝 استفاده:\n`/broadcast MSG` — همه\n"
            "`/broadcast active MSG` — فعالان ۷ روز\n"
            "`/broadcast configs N` — N کانفیگ به همه",
            parse_mode="Markdown"); return
    target = "all"
    args   = context.args[:]
    if args[0] in ("active","vip","inactive","configs"):
        target = args.pop(0)
    msg_text = " ".join(args)
    if target == "configs":
        n   = int(msg_text) if msg_text.isdigit() else 5
        await _broadcast_configs(update, context, n); return
    if target == "active":
        uids = [r[0] for r in await DatabaseManager.get_active_users(7)]
    elif target == "vip":
        uids = [r[0] for r in await DatabaseManager.get_vip_users()]
    elif target == "inactive":
        uids = [r[0] for r in await DatabaseManager.get_inactive_users(30)]
    else:
        uids = await DatabaseManager.get_all_user_ids()
    await _do_broadcast(update, context, uids, msg_text)

async def _do_broadcast(update, context, uids: list, msg_text: str) -> None:
    status = await update.message.reply_text(f"📤 ارسال به `{len(uids):,}` کاربر...", parse_mode="Markdown")
    sent = failed = 0
    for uid in uids:
        for attempt in range(2):
            try:
                await context.bot.send_message(uid, f"📢 *پیام ادمین:*\n\n{msg_text}", parse_mode="Markdown")
                sent += 1; break
            except TelegramError as exc:
                ra = getattr(exc, "retry_after", None)
                if ra and attempt == 0: await asyncio.sleep(float(ra)+0.5)
                else: failed += 1; break
        await asyncio.sleep(0.05)
    await status.edit_text(f"✅ ارسال کامل\n📨 موفق: `{sent:,}`\n❌ ناموفق: `{failed:,}`", parse_mode="Markdown")

async def _broadcast_configs(update, context, n: int) -> None:
    uids    = await DatabaseManager.get_all_user_ids()
    configs = CacheManager.get_filtered("ALL","ALL", limit=n)
    if not configs:
        await update.message.reply_text("❌ کانفیگی موجود نیست."); return
    payload = "📦 *کانفیگ‌های جدید:*\n\n" + "\n\n".join(f"`{c}`" for c in configs[:5])
    msg     = safe_truncate(payload, 4090)
    status  = await update.message.reply_text(f"📤 ارسال {n} کانفیگ به {len(uids):,} کاربر...")
    sent = failed = 0
    for uid in uids:
        try:
            await context.bot.send_message(uid, msg, parse_mode="Markdown")
            sent += 1
        except Exception:
            failed += 1
        await asyncio.sleep(0.07)
    await status.edit_text(f"✅ موفق: `{sent:,}` | ناموفق: `{failed:,}`", parse_mode="Markdown")

@admin_only
async def admin_addsource_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    رفع باگ «/addsource هیچ پاسخی نمی‌دهد»: علت واقعی این بود که
    global_guard (که روی group=-1 برای هر پیامی، حتی پیام‌های ادمین، اجرا
    می‌شد) در چت‌های گروهی هر پیامی را که دقیقاً @username بات را در متن
    نداشت «خطاب‌نشده به بات» تشخیص می‌داد و با ApplicationHandlerStop آن
    را متوقف می‌کرد — پیش از اینکه اصلاً به این handler برسد. این یعنی
    /addsource (و در واقع تقریباً هر دستور دیگری) در گروه‌ها همیشه ساکت
    شکست می‌خورد. آن گیت اصلاح شده (دستورهای اسلش و پیام‌های ادمین همیشه
    «خطاب‌شده» محسوب می‌شوند) — این handler خودش از ابتدا منطق درستی
    داشت. یک try/except عمومی هم اضافه شده تا حتی یک خطای غیرمنتظره هم
    هرگز باعث سکوت کامل بات برای ادمین نشود.
    """
    try:
        if not context.args:
            await update.message.reply_text(
                "📝 استفاده: `/addsource URL`\nمثال:\n`/addsource https://raw.githubusercontent.com/user/repo/main/list.txt`",
                parse_mode="Markdown")
            return
        url = context.args[0].strip()
        # رفع باگ SSRF: قبلاً فقط scheme/netloc چک می‌شد. حالا هاست resolve شده و
        # همه‌ی IP های بازگشتی در برابر بازه‌های خصوصی/loopback/link-local/متادیتا
        # (مثل 169.254.169.254) اعتبارسنجی می‌شوند — و resolve در ترد جداگانه
        # اجرا می‌شود تا event loop اصلی بات را بلاک نکند.
        safe, reason = await SSRFGuard.is_safe_url(url)
        if not safe:
            logger.warning(f"addsource: تلاش برای افزودن URL ناامن توسط ادمین رد شد — {url} — {reason}")
            await update.message.reply_text(f"❌ URL نامعتبر یا ناامن: {reason}")
            return
        ok, reason = await DatabaseManager.add_source(url)
        if ok:
            await update.message.reply_text(f"✅ منبع اضافه شد:\n`{url}`", parse_mode="Markdown")
        elif reason == "duplicate":
            await update.message.reply_text("❌ این URL قبلاً به لیست منابع اضافه شده است.")
        else:
            await update.message.reply_text(f"❌ خطا در افزودن منبع: {reason}")
    except Exception as exc:
        logger.error(f"admin_addsource_cmd: خطای غیرمنتظره: {exc}", exc_info=True)
        await update.message.reply_text(f"❌ خطای غیرمنتظره هنگام افزودن منبع: {type(exc).__name__}: {exc}")

@admin_only
async def admin_removesource_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("📝 `/removesource ID`", parse_mode="Markdown"); return
    ok = await DatabaseManager.remove_source(int(context.args[0]))
    await update.message.reply_text("✅ حذف شد." if ok else "❌ یافت نشد.")

@admin_only
async def admin_backup_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg  = await update.message.reply_text("💾 در حال تهیه پشتیبان...")
    data = await DatabaseManager.backup_db()
    bio  = io.BytesIO(data)
    bio.seek(0)
    ts   = datetime.now(ZoneInfo("Asia/Tehran")).strftime("%Y%m%d_%H%M")
    await context.bot.send_document(
        chat_id=update.effective_chat.id,
        document=bio,
        filename=f"backup_{ts}.db",
        caption=f"💾 پشتیبان دیتابیس — {ts}")
    await msg.delete()

@admin_only
async def admin_export_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    configs = CacheManager.get_filtered("ALL","ALL")
    if not configs:
        await update.message.reply_text("❌ کانفیگی موجود نیست."); return
    bio = io.BytesIO("\n".join(configs).encode())
    bio.seek(0)
    ts  = datetime.now(ZoneInfo("Asia/Tehran")).strftime("%Y%m%d_%H%M")
    await context.bot.send_document(
        chat_id=update.effective_chat.id,
        document=bio,
        filename=f"all_configs_{ts}.txt",
        caption=f"📤 Export — {len(configs):,} کانفیگ")

@admin_only
async def admin_benchmark_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg  = await update.message.reply_text("🔬 *Benchmark در حال اجرا...*", parse_mode="Markdown")
    m0   = _read_mem_mb()
    c0   = _read_cpu_percent()
    t0   = time.monotonic()
    prev = len(CacheManager._cache)
    cnt  = await CacheManager.reload(bot=context.bot)
    dt   = time.monotonic() - t0
    m1   = _read_mem_mb()
    text = (
        "🔬 *نتیجه Benchmark*\n"
        "━━━━━━━━━━━━━━━━━━\n"
        f"⏱ مدت Reload:   `{dt:.2f}` ثانیه\n"
        f"📦 قبل:          `{prev:,}` کانفیگ\n"
        f"📦 بعد:          `{cnt:,}` کانفیگ\n"
        f"🔄 تغییر:        `{CacheManager._prev_delta}`\n"
        f"🧠 RAM قبل:      `{m0:.1f} MB`\n"
        f"🧠 RAM بعد:      `{m1:.1f} MB`\n"
        f"📊 CPU:          `{c0:.1f}%`\n"
        f"⚡ سرعت:         `{cnt/dt if dt>0 else 0:.0f}` cfg/s\n"
    )
    await msg.edit_text(text, parse_mode="Markdown")

# ═══════════════════════════════════════════════════════════════════════════════
# توابع build متن ادمین
# ═══════════════════════════════════════════════════════════════════════════════
async def _build_stats_text() -> str:
    s          = CacheManager.stats()
    srcs       = await DatabaseManager.get_all_sources()
    act_srcs   = sum(1 for r in srcs if r[2]==1)
    total_u    = await DatabaseManager.count_total_users()
    banned     = await DatabaseManager.get_banned_users()
    vips       = await DatabaseManager.get_vip_users()
    active_u   = await DatabaseManager.get_active_users(7)
    top_u      = await DatabaseManager.get_top_users(3)

    proto_lines = "\n".join(
        f"  • {k.upper()}: `{v:,}`"
        for k,v in sorted(s["protocols"].items(), key=lambda x:-x[1]))
    dc_lines = "\n".join(
        f"  • {k}: `{v:,}`"
        for k,v in sorted(s.get("datacenters",{}).items(), key=lambda x:-x[1])[:5])
    top_lines = "\n".join(
        f"  {i+1}. `{r[0]}` @{r[1] or '—'} — `{r[3]:,}`"
        for i,r in enumerate(top_u))

    return safe_truncate(
        "📊 *آمار جامع سیستم*\n"
        "━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📦 کانفیگ: `{s['total']:,}` | 🔄 `{s['delta'] or '---'}`\n"
        f"🕐 آپدیت: `{s['last_update']}`\n"
        f"📡 منابع فعال: `{act_srcs}/{len(srcs)}`\n"
        "━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"👥 کل کاربران: `{total_u:,}`\n"
        f"✅ فعال ۷ روز: `{len(active_u):,}` | ⭐ VIP: `{len(vips)}`\n"
        f"🚫 مسدود: `{len(banned)}`\n\n"
        f"🏆 *برتر دانلود:*\n{top_lines}\n\n"
        f"🔌 *پروتکل‌ها:*\n{proto_lines}\n\n"
        f"🏢 *دیتاسنترها (برتر):*\n{dc_lines}\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"⏱ آپتایم: `{_format_uptime(time.time()-_START_TIME)}`\n"
        f"🧠 RAM: `{_read_mem_mb():.1f} MB`\n"
        f"💻 CPU: `{_read_cpu_percent():.1f}%`\n"
    )

async def _build_health_text() -> str:
    mem  = _read_mem_mb()
    cpu  = _read_cpu_percent()
    srcs = await DatabaseManager.get_all_sources()
    dead = sum(1 for r in srcs if r[2]==0)
    tasks_n = len(asyncio.all_tasks())
    qh      = DatabaseManager.get_write_queue_health()
    status  = "🟢 سالم" if cpu < 80 and mem < Config.MEM_OPTIMIZER_MB else "🟡 هشدار"
    if qh["dropped_total"] > 0:
        status = "🔴 بحرانی (دورریز صف DB)"
    return (
        f"🏥 *وضعیت سیستم — {status}*\n"
        "━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🧠 RAM:        `{mem:.1f} MB`\n"
        f"💻 CPU:        `{cpu:.1f}%`\n"
        f"⏱ آپتایم:     `{_format_uptime(time.time()-_START_TIME)}`\n"
        f"🐍 Python:     `{platform.python_version()}`\n"
        f"🖥 OS:         `{platform.system()} {platform.release()}`\n"
        "━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📦 Cache:      `{len(CacheManager._cache):,}`\n"
        f"⚙️ Tasks:      `{tasks_n}`\n"
        f"📋 DB Queue:   `{qh['queue_size']}` (overflow: `{qh['overflow_size']}`, دورریز کل: `{qh['dropped_total']}`)\n"
        f"📡 Dead Srcs:  `{dead}`\n"
        "━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚠️ RAM Alert > `{Config.MEM_OPTIMIZER_MB}MB`\n"
        f"⚠️ CPU Alert > `{Config.CPU_ALERT_THRESHOLD:.0f}%`\n"
    )

async def _build_cache_text() -> str:
    s = CacheManager.stats()
    proto_txt = " | ".join(f"{k.upper()}:{v:,}" for k,v in sorted(s["protocols"].items(), key=lambda x:-x[1])[:6])
    cty_txt   = " | ".join(
        f"{COUNTRY_MAP.get(k,_UNKNOWN_COUNTRY)[0]}{k}:{v}"
        for k,v in sorted(s["countries"].items(), key=lambda x:-x[1])[:6])
    return (
        f"💾 *Cache Info*\n"
        "━━━━━━━━━━━━━━━━━━\n"
        f"📦 کل: `{s['total']:,}`\n"
        f"🕐 آپدیت: `{s['last_update']}`\n"
        f"🔄 تغییر: `{s['delta'] or '---'}`\n"
        f"🔌 پروتکل:\n`{proto_txt}`\n\n"
        f"🌍 کشورها:\n`{cty_txt}`\n"
    )

async def _build_sources_text(page: int = 1) -> "tuple[str, int, int]":
    # PAGE کاهش یافت (10 → 5): چون حالا لینک کامل (نه بریده‌شده به 60 کاراکتر)
    # نمایش داده می‌شود، فضای بیشتری لازم است تا از سقف پیام تلگرام رد نشویم.
    PAGE   = 5
    srcs   = await DatabaseManager.get_all_sources()
    total  = max(1,(len(srcs)+PAGE-1)//PAGE)
    page   = max(1,min(page,total))
    chunk  = srcs[(page-1)*PAGE:page*PAGE]
    lines  = [f"📡 *منابع (صفحه {page}/{total}):*\n"]
    for r in chunk:
        st = "🟢" if r[2]==1 else "🔴"
        dc = r[5] or "?"
        # لینک کامل و بدون قیچی شدن نمایش داده می‌شود (قبلاً با [:60]... بریده می‌شد).
        lines.append(f"{st} `#{r[0]}` ❌`{r[3]}` 🏢`{dc}`\n`{r[1]}`\n")
    return safe_truncate("\n".join(lines), 4000), page, total


def make_sources_pagination_keyboard(page: int, total: int) -> InlineKeyboardMarkup:
    nav = []
    if page > 1:
        nav.append(InlineKeyboardButton("« قبلی", callback_data=f"adm_srcpage_{page-1}"))
    if page < total:
        nav.append(InlineKeyboardButton("بعدی »", callback_data=f"adm_srcpage_{page+1}"))
    rows = [nav] if nav else []
    rows.append([InlineKeyboardButton("🔙", callback_data="admin_panel")])
    return InlineKeyboardMarkup(rows)


def _ping_color(ping_ms: int) -> str:
    if ping_ms < 0:
        return "🔴"
    if ping_ms <= Config.PING_GOOD_MS:
        return "🟢"
    if ping_ms <= Config.PING_OK_MS:
        return "🟡"
    return "🔴"


async def _build_tested_configs_view(page: int, lang: str = "fa") -> "tuple[str, InlineKeyboardMarkup]":
    PER_PAGE = 5   # با کانفیگ کامل (نه بریده)، ۵ تا در هر صفحه از سقف پیام تلگرام رد نمی‌شود
    rows, page, total = await DatabaseManager.get_tested_configs(page=page, per_page=PER_PAGE)
    if not rows:
        text = ("🛰 *کانفیگ‌های پینگ گرفته‌شده*\n\n"
                 "هنوز کانفیگی تست نشده. کمی صبر کنید تا اولین دور تست انجام شود.")
        kb = InlineKeyboardMarkup([[InlineKeyboardButton(T("back", lang), callback_data="main_menu")]])
        return text, kb

    lines = [f"🛰 *کانفیگ‌های پینگ گرفته‌شده (صفحه {page}/{total}):*\n"]
    for cfg, proto, country, ping_ms, last_tested in rows:
        color = _ping_color(ping_ms)
        ping_txt = f"{ping_ms}ms" if ping_ms >= 0 else "—"
        ago_min  = max(0, int((time.time() - last_tested) / 60))
        lines.append(
            f"{color} `{ping_txt}` | {proto.upper()} | {country_display(country, lang)} | {ago_min}m پیش\n"
            f"`{cfg}`\n"
        )
    text = "\n".join(lines)

    nav = []
    if page > 1:
        nav.append(InlineKeyboardButton("« قبلی", callback_data=f"tested_configs_{page-1}"))
    if page < total:
        nav.append(InlineKeyboardButton("بعدی »", callback_data=f"tested_configs_{page+1}"))
    kb_rows = [nav] if nav else []
    kb_rows.append([InlineKeyboardButton(
        "📄 دریافت همه به‌صورت txt" if lang == "fa" else "📄 Get all as txt",
        callback_data="tested_configs_txt")])
    kb_rows.append([InlineKeyboardButton(T("back", lang), callback_data="main_menu")])
    # اگر با وجود کاهش تعداد، باز هم متن خیلی طولانی شد (کانفیگ‌های غیرعادی بلند)،
    # safe_truncate آخرین خط ناقص را کامل حذف می‌کند تا کانفیگ نصفه نمایش داده نشود.
    return safe_truncate(text, 4000), InlineKeyboardMarkup(kb_rows)


# ═══════════════════════════════════════════════════════════════════════════════
# Callback Router — مرکزی‌ترین هندلر
# ═══════════════════════════════════════════════════════════════════════════════
async def callback_router(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    if not q or not update.effective_user: return
    await q.answer()

    uid   = update.effective_user.id
    data  = q.data or ""
    prefs = await DatabaseManager.get_user_prefs(uid)
    lang  = prefs["language"]

    # ── منوی اصلی ──────────────────────────────────────────────────────────
    if data == "main_menu":
        await DatabaseManager.set_user_pref(uid, "user_state", None)
        await send_main_menu(update, context, edit=True)

    # ── زبان ───────────────────────────────────────────────────────────────
    elif data == "toggle_lang":
        nl = "en" if lang=="fa" else "fa"
        await DatabaseManager.set_user_pref(uid, "language", nl)
        await send_main_menu(update, context, edit=True)

    # ── فیلتر پروتکل ───────────────────────────────────────────────────────
    elif data == "menu_proto":
        try:
            await q.edit_message_text(T("proto_select",lang),
                reply_markup=make_proto_keyboard(prefs["protocol"],lang),
                parse_mode="Markdown")
        except BadRequest: pass

    elif data.startswith("set_proto_"):
        new_p = data.removeprefix("set_proto_")
        await DatabaseManager.set_user_pref(uid,"protocol",new_p)
        prefs["protocol"] = new_p
        try:
            await q.edit_message_text(T("proto_select",lang),
                reply_markup=make_proto_keyboard(new_p,lang), parse_mode="Markdown")
        except BadRequest: pass

    # ── فیلتر کشور ─────────────────────────────────────────────────────────
    elif data == "menu_country":
        try:
            await q.edit_message_text(T("country_select",lang),
                reply_markup=make_country_keyboard(prefs["country"],lang), parse_mode="Markdown")
        except BadRequest: pass

    elif data.startswith("set_cty_"):
        new_c = data.removeprefix("set_cty_")
        await DatabaseManager.set_user_pref(uid,"country",new_c)
        prefs["country"] = new_c
        try:
            await q.edit_message_text(T("country_select",lang),
                reply_markup=make_country_keyboard(new_c,lang), parse_mode="Markdown")
        except BadRequest: pass

    # ── دریافت کانفیگ ──────────────────────────────────────────────────────
    elif data == "get_configs":
        if not await check_channel_membership(context.bot, uid):
            try: await q.edit_message_text(T("force_join_msg",lang), reply_markup=make_join_keyboard(lang), parse_mode="Markdown")
            except BadRequest: pass
            return
        reqs, cfgs = await DatabaseManager.check_rate_limit(uid)
        ok, err    = is_allowed(uid, prefs, reqs, cfgs)
        if not ok:
            try: await q.edit_message_text(err, reply_markup=make_back_keyboard(lang))
            except BadRequest: pass
            return
        total = CacheManager.count_filtered(prefs["protocol"], prefs["country"])
        if not total:
            try: await q.edit_message_text(T("no_configs",lang), reply_markup=make_back_keyboard(lang))
            except BadRequest: pass
            return
        await DatabaseManager.set_user_pref(uid, "user_state", "waiting_count")
        prompt_text = f"{T('enter_count',lang)}\n\n📊 موجودی: `{total:,}` کانفیگ"
        try:
            await q.edit_message_text(
                prompt_text,
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(T("cancel",lang), callback_data="main_menu")]]),
                parse_mode="Markdown")
        except BadRequest: pass
        # رفع باگ «در گروه، پاسخ متنی کاربر (عدد) هرگز به بات نمی‌رسد»:
        # ForceReply فقط روی پیام تازه‌ارسال‌شده کار می‌کند، نه روی ادیت یک
        # پیام قدیمی — پس در گروه، جدا از ادیت بالا، یک پیام کوچک با
        # ForceReplyً می‌فرستیم تا تلگرام خودش پاسخ بعدی کاربر را به‌عنوان
        # ریپلای به بات علامت بزند؛ این باعث می‌شود global_guard آن را
        # «خطاب به بات» تشخیص دهد، حتی اگر کاربر خودش دستی ریپلای نزند.
        if _is_group(update):
            try:
                await context.bot.send_message(
                    q.message.chat_id, T("enter_count", lang),
                    reply_to_message_id=q.message.message_id,
                    reply_markup=ForceReply(selective=True, input_field_placeholder="50"))
            except BadRequest:
                pass

    # ── کانفیگ تصادفی ──────────────────────────────────────────────────────
    elif data == "random_cfg":
        if not await check_channel_membership(context.bot, uid):
            try: await q.edit_message_text(T("force_join_msg",lang), reply_markup=make_join_keyboard(lang), parse_mode="Markdown")
            except BadRequest: pass
            return
        reqs, cfgs = await DatabaseManager.check_rate_limit(uid)
        ok, err    = is_allowed(uid, prefs, reqs, cfgs)
        if not ok:
            try: await q.edit_message_text(err, reply_markup=make_back_keyboard(lang))
            except BadRequest: pass
            return
        # فقط یک کانفیگ لازم است — به‌جای ساخت کل لیست منطبق، با limit=1
        # مستقیماً یک نمونه‌ی تصادفی از reservoir sampling می‌گیریم.
        matches = CacheManager.get_filtered(prefs["protocol"], prefs["country"], limit=1)
        if not matches:
            try: await q.edit_message_text(T("no_configs",lang), reply_markup=make_back_keyboard(lang))
            except BadRequest: pass
            return
        cfg    = matches[0]
        # رفع باگ برخورد هش: کل رشته‌ی کانفیگ هش می‌شود، نه فقط ۶۴ کاراکتر اول.
        chash  = hashlib.sha256(cfg.encode()).hexdigest()[:16]
        display= cfg if len(cfg)<3000 else cfg[:3000]+"…"
        await DatabaseManager.increment_usage(uid, 1)
        try:
            await q.edit_message_text(
                f"🎲 *کانفیگ تصادفی:*\n\n`{display}`",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔄 یکی دیگر", callback_data="random_cfg"),
                     InlineKeyboardButton(T("feedback_prompt",lang), callback_data=f"feedback_{chash}")],
                    [InlineKeyboardButton(T("back",lang), callback_data="main_menu")],
                ]), parse_mode="Markdown")
        except BadRequest: pass

    # ── جستجوی کانفیگ ──────────────────────────────────────────────────────
    elif data == "search_configs":
        if not await check_channel_membership(context.bot, uid):
            try: await q.edit_message_text(T("force_join_msg",lang), reply_markup=make_join_keyboard(lang), parse_mode="Markdown")
            except BadRequest: pass
            return
        if uid != Config.ADMIN_ID:
            wait = await DatabaseManager.check_search_cooldown(uid)
            if wait > 0:
                try: await q.edit_message_text(T("search_cooldown",lang,sec=f"{wait:.0f}"), reply_markup=make_back_keyboard(lang))
                except BadRequest: pass
                return
        await DatabaseManager.set_user_pref(uid, "user_state", "waiting_search")
        try:
            await q.edit_message_text(
                T("enter_search",lang),
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(T("cancel",lang), callback_data="main_menu")]]),
                parse_mode="Markdown")
        except BadRequest: pass
        # مشابه fix بالا برای waiting_count: در گروه یک پیام ForceReply جدا
        # می‌فرستیم تا پاسخ متنی کاربر (عبارت جستجو) به‌عنوان ریپلای به بات
        # علامت‌گذاری شود و از گیت گروهی global_guard رد شود.
        if _is_group(update):
            try:
                await context.bot.send_message(
                    q.message.chat_id, T("enter_search", lang),
                    reply_to_message_id=q.message.message_id,
                    reply_markup=ForceReply(selective=True, input_field_placeholder="germany vless"))
            except BadRequest:
                pass

    # ── پروفایل کاربر ──────────────────────────────────────────────────────
    elif data == "my_profile":
        full = await DatabaseManager.get_user_full(uid)
        reqs, cfgs = await DatabaseManager.check_rate_limit(uid)
        vip_badge  = " ⭐ VIP" if prefs.get("is_vip") else ""
        text = (
            f"👤 *پروفایل{vip_badge}*\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"🆔 `{uid}`\n"
            f"📛 {full.get('first_name','—')}\n"
            f"📦 کل دانلود: `{prefs['total_downloads']:,}`\n"
            f"⚙️ پروتکل: `{prefs['protocol']}`\n"
            f"🌍 کشور: `{country_display(prefs['country'],lang)}`\n"
            f"🕐 آخرین فعالیت: `{(full.get('last_seen') or '—')[:16].replace('T',' ')}`\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"📈 امروز: درخواست `{reqs}` | کانفیگ `{cfgs}`\n"
        )
        try:
            await q.edit_message_text(text, reply_markup=make_back_keyboard(lang), parse_mode="Markdown")
        except BadRequest: pass

    # ── Feedback ────────────────────────────────────────────────────────────
    elif data.startswith("feedback_"):
        chash = data[9:]
        try:
            await q.edit_message_text(
                T("feedback_prompt",lang),
                reply_markup=make_feedback_keyboard(chash, lang))
        except BadRequest: pass

    elif data.startswith("fb_"):
        parts  = data.split("_", 2)   # fb_not_work_HASH  or fb_slow_HASH  or fb_weak_HASH
        reason_map = {"not":"کار نمی‌کند","slow":"پینگ بالا","weak":"اتصال ضعیف"}
        r_key  = parts[1] if len(parts)>1 else "?"
        chash  = parts[2] if len(parts)>2 else "?"
        reason = reason_map.get(r_key, r_key)
        await DatabaseManager.add_feedback(uid, chash, reason)
        try: await q.edit_message_text(T("feedback_sent",lang), reply_markup=make_back_keyboard(lang))
        except BadRequest: pass

    # ── کانفیگ‌های پینگ گرفته‌شده (برای همه کاربران) ────────────────────────
    elif data == "tested_configs_txt":
        if uid != Config.ADMIN_ID and not await _tested_btn_enabled():
            await q.answer(T("tested_disabled", lang), show_alert=True)
            return
        rows = await DatabaseManager.get_all_tested_configs_raw()
        if not rows:
            await q.answer(
                "هنوز کانفیگی تست نشده." if lang == "fa" else "No configs tested yet.",
                show_alert=True)
        else:
            lines = [
                f"{r[0]}  # {r[1].upper()} | {country_display(r[2], lang)} | {r[3]}ms"
                for r in rows
            ]
            bio = io.BytesIO("\n".join(lines).encode())
            bio.seek(0)
            await context.bot.send_document(
                chat_id=q.message.chat_id,
                document=bio,
                filename=f"tested_configs_{len(rows)}.txt",
                caption=(f"🛰 `{len(rows):,}` کانفیگ پینگ‌گرفته‌شده (زنده)"
                         if lang == "fa" else f"🛰 `{len(rows):,}` ping-tested live configs"),
                parse_mode="Markdown")

    elif data.startswith("tested_configs_"):
        if uid != Config.ADMIN_ID and not await _tested_btn_enabled():
            await q.answer(T("tested_disabled", lang), show_alert=True)
            return
        try:
            page = int(data.rsplit("_", 1)[1])
        except (ValueError, IndexError):
            page = 1
        text, kb = await _build_tested_configs_view(page, lang)
        try:
            await q.edit_message_text(text, parse_mode="Markdown", reply_markup=kb)
        except BadRequest:
            pass

    # ── لینک ساب اختصاصی کاربر (پنل تحت وب) ─────────────────────────────────
    elif data == "my_sub_link":
        if not webdash_configured():
            await q.answer(
                "این قابلیت هنوز توسط ادمین فعال نشده." if lang == "fa"
                else "This feature hasn't been enabled by the admin yet.",
                show_alert=True)
            return
        url = user_sub_url(uid)
        back_kb = InlineKeyboardMarkup([[InlineKeyboardButton(T("back", lang), callback_data="main_menu")]])
        if lang == "fa":
            text = (
                "🔗 *لینک ساب اختصاصی شما*\n\n"
                f"`{url}`\n\n"
                "این لینک را در اپلیکیشن کلاینت (v2rayNG، Streisand، Shadowrocket و ...) "
                "به‌عنوان subscription URL وارد کنید. همیشه بر اساس فیلتر پروتکل/کشور فعلی شما "
                "و آخرین کانفیگ‌های زنده به‌روز می‌شود — نیازی به کپی دستی کانفیگ نیست.\n\n"
                "⚠️ این لینک را با کسی به اشتراک نگذارید."
            )
        else:
            text = (
                "🔗 *Your Personal Subscription Link*\n\n"
                f"`{url}`\n\n"
                "Paste this into your VPN client (v2rayNG, Streisand, Shadowrocket, etc.) as the "
                "subscription URL. It always reflects your current protocol/country filter and the "
                "latest live configs — no manual copying needed.\n\n"
                "⚠️ Don't share this link with anyone."
            )
        try:
            await q.edit_message_text(text, parse_mode="Markdown", reply_markup=back_kb)
        except BadRequest:
            pass

    # ── پنل ادمین ───────────────────────────────────────────────────────────
    elif data in ("admin_panel","admin_panel_2") and uid == Config.ADMIN_ID:
        page = 2 if data == "admin_panel_2" else 1
        tested_on = await _tested_btn_enabled()
        try:
            await q.edit_message_text("👑 *پنل مدیریت*\n\nیک بخش را انتخاب کنید:",
                reply_markup=make_admin_keyboard(page, tested_btn_on=tested_on), parse_mode="Markdown")
        except BadRequest: pass

    # ── دستورات ادمین از پنل ────────────────────────────────────────────────
    elif data.startswith("adm_") and uid == Config.ADMIN_ID:
        await _handle_admin_callback(q, data[4:], context)

    # ── Broadcast menu ──────────────────────────────────────────────────────
    elif data.startswith("bc_") and uid == Config.ADMIN_ID:
        await _handle_broadcast_callback(q, data[3:], context)

async def _handle_admin_callback(q, cmd: str, context: ContextTypes.DEFAULT_TYPE) -> None:
    """روتر داخلی callback های ادمین."""
    try:
        if cmd == "stats":
            await q.edit_message_text(await _build_stats_text(), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "health":
            await q.edit_message_text(await _build_health_text(), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "cache":
            await q.edit_message_text(await _build_cache_text(), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "reload":
            await q.edit_message_text("🔄 در حال بروزرسانی کش...", parse_mode="Markdown")
            count = await CacheManager.reload(bot=context.bot)
            await q.edit_message_text(
                f"✅ بروزرسانی کامل\n📦 `{count:,}` | 🔄 `{CacheManager._prev_delta}`",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "sources":
            text, page, total = await _build_sources_text(1)
            await q.edit_message_text(text, parse_mode="Markdown",
                reply_markup=make_sources_pagination_keyboard(page, total))

        elif cmd.startswith("srcpage_"):
            try:
                requested_page = int(cmd.split("_", 1)[1])
            except (ValueError, IndexError):
                requested_page = 1
            text, page, total = await _build_sources_text(requested_page)
            await q.edit_message_text(text, parse_mode="Markdown",
                reply_markup=make_sources_pagination_keyboard(page, total))

        elif cmd == "top_sources":
            rows = await DatabaseManager.get_top_sources(8)
            lines = [f"⭐ `#{r[0]}` fail:`{r[2]}` {'🟢' if r[3] else '🔴'}\n`{r[1][:55]}...`" for r in rows]
            await q.edit_message_text("📈 *بهترین منابع:*\n\n"+"\n\n".join(lines), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "slow_sources":
            rows = await DatabaseManager.get_slow_sources(8)
            lines = [f"🐌 `#{r[0]}` fail:`{r[2]}` {'🟢' if r[3] else '🔴'}\n`{r[1][:55]}...`" for r in rows]
            await q.edit_message_text("🐌 *کندترین منابع:*\n\n"+"\n\n".join(lines), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "benchmark":
            await q.edit_message_text("🔬 Benchmark در حال اجرا...")
            m0 = _read_mem_mb(); c0 = _read_cpu_percent(); t0 = time.monotonic()
            prev = len(CacheManager._cache)
            cnt  = await CacheManager.reload(bot=context.bot)
            dt   = time.monotonic()-t0
            await q.edit_message_text(
                f"🔬 *Benchmark*\n\n"
                f"⏱ `{dt:.2f}s` | 📦 `{prev:,}`→`{cnt:,}` | 🔄 `{CacheManager._prev_delta}`\n"
                f"🧠 RAM: `{m0:.0f}`→`{_read_mem_mb():.0f}MB` | 💻 CPU: `{c0:.1f}%`\n"
                f"⚡ `{cnt/dt if dt>0 else 0:.0f}` cfg/s",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "users":
            total  = await DatabaseManager.count_total_users()
            active = await DatabaseManager.get_active_users(7)
            vips   = await DatabaseManager.get_vip_users()
            banned = await DatabaseManager.get_banned_users()
            text   = (f"👥 *کاربران*\n\n"
                      f"🔢 کل: `{total:,}`\n✅ فعال ۷روز: `{len(active)}`\n"
                      f"⭐ VIP: `{len(vips)}` | 🚫 Ban: `{len(banned)}`")
            await q.edit_message_text(text, parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "top_users":
            rows  = await DatabaseManager.get_top_users(10)
            lines = [f"{i+1}. `{r[0]}` @{r[1] or '—'} — `{r[3]:,}` cfg" for i,r in enumerate(rows)]
            await q.edit_message_text("🏆 *برترین کاربران:*\n\n"+"\n".join(lines), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "broadcast_menu":
            await q.edit_message_text("📤 *نوع Broadcast:*", reply_markup=make_broadcast_menu(), parse_mode="Markdown")

        elif cmd == "ban_menu":
            banned = await DatabaseManager.get_banned_users()
            lines  = [f"🚫 `{r[0]}` — {(r[2] or '---')[:20]}" for r in banned[:10]]
            await q.edit_message_text("🚫 *لیست مسدودان:*\n\n"+"\n".join(lines or ["(خالی)"]), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "vip_menu":
            vips  = await DatabaseManager.get_vip_users()
            lines = [f"⭐ `{r[0]}` @{r[1] or '—'}" for r in vips[:10]]
            await q.edit_message_text("⭐ *VIP Users:*\n\n"+"\n".join(lines or ["(خالی)"]), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "blacklist":
            ips   = await DatabaseManager.get_ip_blacklist()
            lines = [f"🔴 `{r[0]}` — {(r[1] or '---')[:20]}" for r in ips[:10]]
            await q.edit_message_text("🛡 *IP Blacklist:*\n\n"+"\n".join(lines or ["(خالی)"]), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "logs":
            rows  = await DatabaseManager.get_logs(15)
            lines = [f"`[{r[0]}]` {r[3][:16]} — {r[2][:50]}" for r in rows]
            await q.edit_message_text("📋 *آخرین Logs:*\n\n"+"\n".join(lines or ["(خالی)"]), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "errors":
            rows  = await DatabaseManager.get_logs(10, "ERROR")
            lines = [f"❌ `{r[3][:16]}` {r[2][:60]}" for r in rows]
            await q.edit_message_text("❌ *خطاهای اخیر:*\n\n"+"\n".join(lines or ["✅ خطایی نیست"]), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "rules":
            rules = await DatabaseManager.get_rules()
            lines = [f"{'✅' if r['enabled'] else '❌'} `#{r['id']}` {r['name']}\n  `IF {r['condition']} THEN {r['action']}`" for r in rules]
            await q.edit_message_text("⚙️ *Rules:*\n\n"+"\n\n".join(lines or ["(خالی)"]), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "feedback":
            rows  = await DatabaseManager.get_feedback(10)
            lines = [f"`{r[0]}` @{r[1] or '—'} — {r[3] or '?'} `{r[4][:10]}`" for r in rows]
            await q.edit_message_text("💬 *Feedbacks:*\n\n"+"\n".join(lines or ["(خالی)"]), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))

        elif cmd == "backup":
            data = await DatabaseManager.backup_db()
            bio  = io.BytesIO(data); bio.seek(0)
            ts   = datetime.now(ZoneInfo("Asia/Tehran")).strftime("%Y%m%d_%H%M")
            await context.bot.send_document(
                chat_id=Config.ADMIN_ID, document=bio,
                filename=f"backup_{ts}.db", caption=f"💾 DB Backup — {ts}")
            await q.answer("💾 پشتیبان ارسال شد!", show_alert=True)

        elif cmd == "export":
            configs = CacheManager.get_filtered("ALL","ALL")
            bio     = io.BytesIO("\n".join(configs).encode()); bio.seek(0)
            ts      = datetime.now(ZoneInfo("Asia/Tehran")).strftime("%Y%m%d_%H%M")
            await context.bot.send_document(
                chat_id=Config.ADMIN_ID, document=bio,
                filename=f"configs_{ts}.txt", caption=f"📤 {len(configs):,} کانفیگ")
            await q.answer(f"📤 {len(configs):,} کانفیگ export شد!", show_alert=True)

        # ── آرشیو کانفیگ‌های حذف‌شده (خراب/تکراری) ──────────────────────────
        elif cmd.startswith("archive_") and not cmd.startswith("archive_export"):
            try:
                page = int(cmd.rsplit("_", 1)[1])
            except (ValueError, IndexError):
                page = 1
            rows, total = await DatabaseManager.get_archived_configs(page, per_page=15)
            if not rows:
                text = "📦 *آرشیو کانفیگ‌های حذف‌شده*\n\nهنوز چیزی بایگانی نشده است."
            else:
                lines = [f"📦 *آرشیو کانفیگ‌های حذف‌شده* — `{total:,}` مورد\n"]
                reason_fa = {"invalid_structure": "ساختار نامعتبر",
                             "low_quality": "کیفیت پایین",
                             "duplicate_in_batch": "تکراری"}
                for cfg, proto, reason, ts in rows:
                    when = datetime.fromtimestamp(ts, ZoneInfo("Asia/Tehran")).strftime("%m-%d %H:%M")
                    short = cfg if len(cfg) <= 60 else cfg[:57] + "..."
                    lines.append(f"`{short}`\n└ {proto} · {reason_fa.get(reason, reason)} · {when}")
                text = "\n\n".join(lines)
            total_pages = max(1, math.ceil(total / 15))
            nav = []
            if page > 1: nav.append(InlineKeyboardButton("« قبلی", callback_data=f"adm_archive_{page-1}"))
            if page < total_pages: nav.append(InlineKeyboardButton("بعدی »", callback_data=f"adm_archive_{page+1}"))
            kb_rows = ([nav] if nav else []) + [
                [InlineKeyboardButton("📤 دریافت کل آرشیو (txt)", callback_data="adm_archive_export")],
                [InlineKeyboardButton("📥 دریافت تعداد دلخواه", callback_data="adm_archive_export_n_prompt")],
                [InlineKeyboardButton("🔙", callback_data="admin_panel")],
            ]
            await q.edit_message_text(safe_truncate(text), parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup(kb_rows))

        elif cmd == "archive_export":
            configs = await DatabaseManager.export_archived_configs()
            if not configs:
                await q.answer("❌ آرشیو خالی است.", show_alert=True)
            else:
                bio = io.BytesIO("\n".join(configs).encode()); bio.seek(0)
                ts  = datetime.now(ZoneInfo("Asia/Tehran")).strftime("%Y%m%d_%H%M")
                await context.bot.send_document(
                    chat_id=Config.ADMIN_ID, document=bio,
                    filename=f"archived_configs_{ts}.txt",
                    caption=f"📦 {len(configs):,} کانفیگ آرشیوشده (خراب/تکراری)")
                await q.answer(f"📤 {len(configs):,} کانفیگ آرشیوشده ارسال شد!", show_alert=True)

        # طبق درخواست ادمین: امکان دریافت تعداد دلخواه (نه فقط کل آرشیو یک‌جا)
        # از کانفیگ‌های بایگانی‌شده (خراب/تکراری).
        elif cmd == "archive_export_n_prompt":
            await DatabaseManager.set_user_pref(q.from_user.id, "user_state", "adm_waiting_archive_count")
            prompt = "📥 چند کانفیگ از آرشیو می‌خواهید؟ یک عدد بفرستید (مثلاً 500):"
            await q.edit_message_text(prompt,
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="adm_archive_1")]]))
            if q.message and q.message.chat and q.message.chat.type in ("group","supergroup"):
                try:
                    await context.bot.send_message(
                        q.message.chat_id, prompt, reply_to_message_id=q.message.message_id,
                        reply_markup=ForceReply(selective=True, input_field_placeholder="500"))
                except BadRequest:
                    pass

        # ── روشن/خاموش کردن دکمه‌ی «کانفیگ‌های پینگ گرفته‌شده» در منوی اصلی ──
        elif cmd == "toggle_tested_btn":
            cur_on = await _tested_btn_enabled()
            new_on = not cur_on
            await DatabaseManager.set_setting(SETTING_TESTED_BTN, "1" if new_on else "0")
            await q.answer(
                "✅ دکمه روشن شد." if new_on else "❌ دکمه خاموش شد.", show_alert=True)
            await q.edit_message_reply_markup(
                reply_markup=make_admin_keyboard(2, tested_btn_on=new_on))

        elif cmd == "cpu":
            cpu = _read_cpu_percent()
            await q.edit_message_text(f"💻 *CPU Usage*\n\n`{cpu:.1f}%`\n\n⚠️ هشدار بالای `{Config.CPU_ALERT_THRESHOLD:.0f}%`",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel_2")]]))

        elif cmd == "memory":
            mem = _read_mem_mb()
            await q.edit_message_text(f"🧠 *Memory Usage*\n\n`{mem:.1f} MB`\n\n⚠️ Optimizer: `>{Config.MEM_OPTIMIZER_MB}MB`",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel_2")]]))

        elif cmd == "version":
            await q.edit_message_text(
                f"📊 *Version Compare*\n\n"
                f"📦 کانفیگ فعلی: `{len(CacheManager._cache):,}`\n"
                f"🔄 آخرین تغییر: `{CacheManager._prev_delta or '---'}`\n"
                f"🕐 بروزرسانی: `{CacheManager._last_update}`",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel_2")]]))

        elif cmd == "github":
            rows  = await DatabaseManager.get_unnotified_github_sources()
            # (total count not needed here)
            lines = [f"⭐`{r[3]}` [{r[2]}]({r[1]})" for r in rows[:8]]
            await q.edit_message_text(
                f"🌐 *GitHub Sources*\n\nیافت‌نشده: `{len(rows)}`\n\n"+"\n".join(lines or ["(جدید نیست)"]),
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel_2")]]),
                disable_web_page_preview=True)

        elif cmd == "analytics":
            active7  = await DatabaseManager.get_active_users(7)
            active30 = await DatabaseManager.get_active_users(30)
            inactive = await DatabaseManager.get_inactive_users(30)
            a7_lines = [f"  • `{r[0]}` @{r[1] or '—'} {(r[3] or '')[:10]}" for r in active7[:5]]
            text = (
                f"📊 *Analytics*\n\n"
                f"✅ فعال ۷ روز: `{len(active7)}`\n"
                f"✅ فعال ۳۰ روز: `{len(active30)}`\n"
                f"😴 غیرفعال ۳۰+ روز: `{len(inactive)}`\n\n"
                f"🆕 *فعال‌ترین اخیر:*\n" + "\n".join(a7_lines or ["(ندارد)"])
            )
            await q.edit_message_text(text, parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel_2")]]))

        elif cmd == "cleanup":
            n = await DatabaseManager.cleanup_logs(7)
            await q.edit_message_text(f"🗑 *Cleanup*\n\n`{n}` لاگ قدیمی پاک شد.", parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel_2")]]))

        elif cmd == "tasks":
            tasks = asyncio.all_tasks()
            names = [t.get_name() for t in tasks][:15]
            await q.edit_message_text(
                f"📦 *Async Tasks ({len(tasks)}):*\n\n`" + "\n".join(names) + "`",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel_2")]]))

        elif cmd == "pingstatus":
            db = await DatabaseManager.get_conn()
            # یک کوئری واحد به‌جای ۴ کوئری جدا — از race condition بین کوئری‌ها
            # (اگر cron_ping_test_batch هم‌زمان در حال آپدیت دیتابیس باشد) جلوگیری می‌کند.
            async with db.execute(
                """SELECT
                     COUNT(*),
                     SUM(CASE WHEN ping_ms>=0 AND ping_ms<=? THEN 1 ELSE 0 END),
                     SUM(CASE WHEN ping_ms>? AND ping_ms<=? THEN 1 ELSE 0 END),
                     SUM(CASE WHEN ping_ms>=0 THEN 1 ELSE 0 END),
                     AVG(CASE WHEN ping_ms>=0 THEN ping_ms END)
                   FROM tested_configs""",
                (Config.PING_GOOD_MS, Config.PING_GOOD_MS, Config.PING_OK_MS)
            ) as cur:
                total, good, ok_n, alive_n, avg_ping = await cur.fetchone()
            total    = total or 0
            good     = good or 0
            ok_n     = ok_n or 0
            alive_n  = alive_n or 0
            avg_ping = avg_ping or 0
            xray_status = "✅ آماده" if XrayManager.is_ready() else \
                          "❌ ناموفق در دانلود" if XrayManager._download_failed else "⏳ هنوز دانلود نشده"
            socks_status = "✅ نصب شده" if _AIOHTTP_SOCKS_AVAILABLE else "❌ نصب نشده (pip install aiohttp-socks)"
            text = (
                "🛰 *وضعیت Real Ping Tester*\n\n"
                f"Xray-core: {xray_status}\n"
                f"aiohttp-socks: {socks_status}\n"
                f"فعال: {'✅' if Config.PING_TEST_ENABLED else '❌'}\n\n"
                f"📦 کل تست‌شده: `{total:,}`\n"
                f"🟢 خوب (≤{Config.PING_GOOD_MS}ms): `{good:,}`\n"
                f"🟡 قابل قبول: `{ok_n:,}`\n"
                f"🔴 ضعیف/خراب: `{total-alive_n:,}`\n"
                f"⏱ میانگین پینگ (فقط زنده‌ها): `{avg_ping:.0f}ms`\n\n"
                f"دسته هر: `{Config.PING_TEST_INTERVAL_SEC//60}` دقیقه ({Config.PING_TEST_BATCH_SIZE} کانفیگ)\n"
                f"بازتست هر: `{Config.PING_RETEST_INTERVAL_SEC//3600}` ساعت\n"
                f"همزمانی: `{Config.PING_TEST_CONCURRENCY}` پروسه Xray"
            )
            await q.edit_message_text(text, parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel_2")]]))

        elif cmd in ("userinfo_prompt", "finduser_prompt", "findconfig_prompt",
                     "addtested_prompt", "deltested_prompt"):
            prompts = {
                "userinfo_prompt":   "🔍 آیدی عددی یا یوزرنیم را بفرستید:",
                "finduser_prompt":   "🔍 بخشی از نام یا یوزرنیم را بفرستید:",
                "findconfig_prompt": "🔍 بخشی از کانفیگ را بفرستید:",
                "addtested_prompt":  ("➕ کانفیگ کامل را بفرستید (vless://... یا vmess://... و غیره):\n"
                                       "با ping=1ms و 🟢 به‌عنوان زنده ثبت می‌شود و بلافاصله قابل‌تحویل است."),
                "deltested_prompt":  ("➖ برای حذف، بخشی از متن کانفیگ (مثلاً هاست یا پورت) را بفرستید. "
                                       "همه‌ی کانفیگ‌های تست‌شده‌ی مطابق حذف می‌شوند."),
            }
            # قبلاً این پرامپت‌ها فقط پیام راهنما نشان می‌دادند ولی user_state واقعاً
            # ست نمی‌شد، پس user_message_handler هیچ‌وقت پاسخ بعدی ادمین را دریافت
            # نمی‌کرد و این دکمه‌ها عملاً کار نمی‌کردند — این‌جا رفع شد.
            state_map = {
                "userinfo_prompt":   "adm_waiting_userinfo",
                "finduser_prompt":   "adm_waiting_finduser",
                "findconfig_prompt": "adm_waiting_findconfig",
                "addtested_prompt":  "adm_waiting_addtested",
                "deltested_prompt":  "adm_waiting_deltested",
            }
            await DatabaseManager.set_user_pref(q.from_user.id, "user_state", state_map[cmd])
            await q.edit_message_text(prompts[cmd],
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel_2")]]))
            # همان رفع باگ گروهی بالا: اگر ادمین از داخل یک گروه پنل را باز
            # کرده باشد، یک پیام ForceReply جدا هم می‌فرستیم.
            if q.message and q.message.chat and q.message.chat.type in ("group","supergroup"):
                try:
                    await context.bot.send_message(
                        q.message.chat_id, prompts[cmd],
                        reply_to_message_id=q.message.message_id,
                        reply_markup=ForceReply(selective=True))
                except BadRequest:
                    pass

    except BadRequest:
        pass
    except Exception as exc:
        logger.error(f"admin_callback {cmd}: {exc}", exc_info=True)

async def _handle_broadcast_callback(q, target: str, context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        if target == "configs":
            configs = CacheManager.get_filtered("ALL","ALL", limit=10)
            uids    = await DatabaseManager.get_all_user_ids()
            msg_txt = "📦 *کانفیگ‌های جدید:*\n\n" + "\n\n".join(f"`{c}`" for c in configs[:5])
        else:
            target_map = {
                "all":      DatabaseManager.get_all_user_ids,
                "active":   lambda: DatabaseManager.get_active_users(7),
                "inactive": lambda: DatabaseManager.get_inactive_users(30),
                "vip":      DatabaseManager.get_vip_users,
            }
            if target not in target_map:
                await q.answer("❌ هدف نامعتبر"); return
            rows = await target_map[target]()
            uids = [r[0] if isinstance(r, (list,tuple)) else r for r in rows]
            msg_txt = "📢 *پیام ادمین*\n\nاین یک پیام عمومی است."

        await q.edit_message_text(f"📤 در حال ارسال به {len(uids):,} کاربر...")
        sent = failed = 0
        for uid in uids:
            try:
                await context.bot.send_message(uid, safe_truncate(msg_txt, 4090), parse_mode="Markdown")
                sent += 1
            except Exception:
                failed += 1
            await asyncio.sleep(0.05)
        await q.edit_message_text(
            f"✅ ارسال کامل\n📨 موفق: `{sent:,}` | ❌ ناموفق: `{failed:,}`",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙",callback_data="admin_panel")]]))
    except BadRequest:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# پست کانال
# ═══════════════════════════════════════════════════════════════════════════════
async def _do_channel_post(context: ContextTypes.DEFAULT_TYPE) -> bool:
    if not Config.CHANNEL_ID: return False

    proto_filter = Config.CHANNEL_FILTER_PROTOCOL.lower()
    countries    = Config.CHANNEL_FILTER_COUNTRIES

    # اولویت با کانفیگ‌های واقعاً پینگ‌گرفته‌شده (زنده) که هنوز پست نشده‌اند —
    # قبلاً این‌جا random.sample روی کل استخر زنده انجام می‌شد بدون هیچ ردیابی
    # از این‌که کدام کانفیگ قبلاً پست شده، پس همان چند کانفیگ می‌توانستند
    # بارها در پست‌های مختلف تکرار شوند.
    unposted_rows = await DatabaseManager.get_unposted_tested_configs_raw()
    tested_pool = [
        (r[0], r[1]) for r in unposted_rows  # (fp, config)
        if (proto_filter == "all" or r[2] == proto_filter)
        and (not countries or r[3] in countries)
    ]

    if not tested_pool:
        # همه‌ی استخر زنده قبلاً پست شده (یا فیلتر چیزی نداشت) — یک‌بار فلگ‌ها
        # را ریست می‌کنیم تا کانال بدون پست نماند و چرخه از نو آغاز شود.
        await DatabaseManager.reset_channel_post_flags()
        unposted_rows = await DatabaseManager.get_unposted_tested_configs_raw()
        tested_pool = [
            (r[0], r[1]) for r in unposted_rows
            if (proto_filter == "all" or r[2] == proto_filter)
            and (not countries or r[3] in countries)
        ]

    if tested_pool:
        count   = min(Config.CHANNEL_POST_COUNT, len(tested_pool))
        sampled = random.sample(tested_pool, count)
        sampled_fps     = [s[0] for s in sampled]
        sampled_configs = [s[1] for s in sampled]
        header  = "📡 *بروزرسانی کانفیگ‌ها (✅ پینگ‌ تست‌شده):*\n\n"
    else:
        # Fallback: اگر هنوز هیچ کانفیگی تست نشده (مثلاً موقع اولین استارت)،
        # از کش خام استفاده کن تا کانال بی‌پست نماند.
        filtered = CacheManager.get_channel_configs()
        if not filtered:
            logger.warning("⚠️  پست کانال: کانفیگی با فیلتر یافت نشد.")
            return False
        count   = min(Config.CHANNEL_POST_COUNT, len(filtered))
        sampled_configs = random.sample(filtered, count)
        sampled_fps     = []
        header  = "📡 *بروزرسانی کانفیگ‌ها:*\n\n"

    payload = header + "\n\n".join(f"`{c}`" for c in sampled_configs)
    try:
        await context.bot.send_message(
            Config.CHANNEL_ID, safe_truncate(payload), parse_mode="Markdown")
        if sampled_fps:
            await DatabaseManager.mark_posted_to_channel(sampled_fps)
        logger.info(f"✅ پست کانال ارسال شد ({count} کانفیگ).")
        return True
    except TelegramError as exc:
        logger.error(f"❌ پست کانال ناموفق: {exc}")
        await DatabaseManager.add_log("ERROR", str(exc), "channel_post")
        return False

# ═══════════════════════════════════════════════════════════════════════════════
# Cron Jobs
# ═══════════════════════════════════════════════════════════════════════════════
async def cron_refresh(context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        count = await CacheManager.reload(bot=context.bot)
        await SmartNotifier.check_all(context.bot)

        # Memory Optimizer را قبل از RuleEngine اجرا می‌کنیم و با یک flag
        # مشخص می‌کنیم که آیا همین دور کش را برش زده یا نه. اگر بله،
        # RuleEngine را برای همین دور رد می‌کنیم تا یک rule دستی با شرط
        # مشابه (مثلاً mem_mb > N) دوباره روی همان کش تازه‌برش‌خورده
        # برش نزند (تداخل دوگانه‌ی برش کش).
        optimizer_triggered = False
        mem = _read_mem_mb()
        if mem > Config.MEM_OPTIMIZER_MB and len(CacheManager._cache) > 1000:
            optimizer_triggered = True
            old = len(CacheManager._cache)
            CacheManager._cache = CacheManager._cache[:len(CacheManager._cache)*3//4]
            logger.info(f"🧹 Memory Optimizer: {old:,} → {len(CacheManager._cache):,} (RAM={mem:.0f}MB)")
            await DatabaseManager.add_log("INFO", f"Memory optimizer: {old}→{len(CacheManager._cache)}", "cron")

        if not optimizer_triggered:
            await RuleEngine.evaluate_all(context.bot)
        else:
            logger.debug("RuleEngine: این دور رد شد چون Memory Optimizer قبلاً کش را برش زد.")
    except Exception as exc:
        logger.error(f"cron_refresh: {exc}", exc_info=True)

async def cron_channel(context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        await _do_channel_post(context)
    except Exception as exc:
        logger.error(f"cron_channel: {exc}", exc_info=True)

async def cron_cleanup(context: ContextTypes.DEFAULT_TYPE) -> None:
    """پاک‌سازی خودکار لاگ‌های قدیمی + محدودسازی حجم آرشیو کانفیگ‌های حذف‌شده."""
    try:
        n = await DatabaseManager.cleanup_logs(days=7)
        if n > 0:
            logger.info(f"🗑 Auto-cleanup: {n} لاگ قدیمی پاک شد.")
        await DatabaseManager.trim_archived_configs(Config.MAX_ARCHIVED_CONFIGS)
    except Exception as exc:
        logger.error(f"cron_cleanup: {exc}", exc_info=True)

async def cron_github_search(context: ContextTypes.DEFAULT_TYPE) -> None:
    """جستجوی GitHub برای منابع جدید."""
    try:
        found = await GitHubSourceFinder.search(context.bot)
        if found > 0:
            logger.info(f"🔍 GitHub: {found} منبع جدید یافت شد.")
    except Exception as exc:
        logger.error(f"cron_github: {exc}", exc_info=True)

async def cron_memory_leak_check(context: ContextTypes.DEFAULT_TYPE) -> None:
    """تشخیص Memory Leak — اگر RAM مداوم بالا رفت هشدار بده."""
    if not hasattr(cron_memory_leak_check, "_readings"):
        cron_memory_leak_check._readings = []
    mem = _read_mem_mb()
    cron_memory_leak_check._readings.append(mem)
    # فقط آخرین ۶ نمونه (۳۰ دقیقه با اجرای هر ۵ دقیقه)
    cron_memory_leak_check._readings = cron_memory_leak_check._readings[-6:]
    if len(cron_memory_leak_check._readings) >= 4:
        trend = cron_memory_leak_check._readings[-1] - cron_memory_leak_check._readings[0]
        if trend > 50:  # بیش از ۵۰MB رشد در ۳۰ دقیقه
            await SmartNotifier.notify(
                context.bot, "memory_leak",
                f"🚨 *Memory Leak احتمالی*\n\n"
                f"رشد: `+{trend:.1f}MB` در ۳۰ دقیقه\n"
                f"RAM فعلی: `{mem:.1f}MB`")

async def cron_ping_test_batch(context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    هر Config.PING_TEST_INTERVAL_SEC (پیش‌فرض ۵ دقیقه): یک دسته جدید
    (پیش‌فرض ۱۰۰ تا) از کش اصلی را با Xray واقعی تست می‌کند و نتایج زنده را
    در جدول tested_configs ذخیره می‌کند. کانفیگ‌هایی که چند بار پیاپی
    (Config.PING_FAIL_TOLERANCE) شکست بخورند از جدول تست‌شده حذف می‌شوند —
    ولی همچنان در کش خام منابع باقی می‌مانند و دوباره شانس تست دارند.
    """
    if not Config.PING_TEST_ENABLED:
        return
    try:
        mem_now = _read_mem_mb()
        if mem_now > Config.PING_TEST_MEM_SAFETY_MB:
            logger.warning(
                f"🛑 Ping Test رد شد: RAM فعلی {mem_now:.0f}MB بالاتر از سقف امن "
                f"{Config.PING_TEST_MEM_SAFETY_MB}MB است (محافظت OOM).")
            return
        if not CacheManager._cache:
            # رفع باگ «اجرای بی‌نتیجه بدون لاگ»: قبلاً اینجا بی‌سروصدا return
            # می‌شد و هیچ‌کس (نه ادمین، نه لاگ) متوجه نمی‌شد چرا دور تست هیچ
            # کانفیگی را پردازش نکرد.
            logger.warning("🛰 Ping Test: کش خالی است — این دور رد شد (منتظر اولین reload کش).")
            await DatabaseManager.add_log("WARNING", "Ping batch skipped: cache empty", "ping_test")
            return
        pool = CacheManager._cache
        batch_items = random.sample(pool, min(Config.PING_TEST_BATCH_SIZE, len(pool)))
        configs = [i["config"] for i in batch_items]
        meta    = {i["config"]: i for i in batch_items}

        t0 = time.monotonic()
        results = await RealPingTester.test_batch(configs)
        for r in results:
            m = meta.get(r["config"], {})
            r["protocol"] = m.get("protocol", "unknown")
            r["country"]  = m.get("country", "ALL")

        alive_count = sum(1 for r in results if r["alive"])
        await DatabaseManager.upsert_tested_configs(results)
        purged = await DatabaseManager.purge_dead_tested_configs(max_fail_streak=Config.PING_FAIL_TOLERANCE)
        await DatabaseManager.trim_tested_configs(Config.PING_MAX_TESTED_STORE)

        dt = time.monotonic() - t0
        logger.info(f"🛰 Ping Test: {alive_count}/{len(results)} زنده در {dt:.1f}s (حذف‌شده: {purged})")
        await DatabaseManager.add_log(
            "INFO", f"Ping batch: {alive_count}/{len(results)} alive, {purged} purged, {dt:.1f}s", "ping_test")
    except Exception as exc:
        logger.error(f"cron_ping_test_batch: {exc}", exc_info=True)


async def cron_ping_retest(context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    هر Config.PING_RETEST_INTERVAL_SEC (پیش‌فرض ۲ ساعت): قدیمی‌ترین
    کانفیگ‌های تست‌شده (که مدت‌هاست دوباره چک نشده‌اند) را بازتست می‌کند
    و خراب‌شده‌ها را حذف می‌کند.
    """
    if not Config.PING_TEST_ENABLED:
        return
    try:
        mem_now = _read_mem_mb()
        if mem_now > Config.PING_TEST_MEM_SAFETY_MB:
            logger.warning(
                f"🛑 Ping Retest رد شد: RAM فعلی {mem_now:.0f}MB بالاتر از سقف امن "
                f"{Config.PING_TEST_MEM_SAFETY_MB}MB است (محافظت OOM).")
            return
        # پروتکل/کشور اصلی هر کانفیگ را قبل از بازتست نگه می‌داریم — قبلاً این
        # مقادیر بعد از هر بازتست به‌صورت هاردکد "unknown"/"ALL" بازنویسی
        # می‌شدند که باعث می‌شد کانفیگ‌های زنده بعد از اولین بازتست از دید
        # فیلتر پروتکل/کشور کاربر ناپدید شوند (چون دیگر با VLESS/de و امثال
        # آن مطابقت نداشتند).
        stale_rows = await DatabaseManager.get_stale_tested_configs_with_meta(
            older_than_sec=Config.PING_RETEST_INTERVAL_SEC, limit=Config.PING_TEST_BATCH_SIZE)
        if not stale_rows:
            return
        stale = [row["config"] for row in stale_rows]
        meta  = {row["config"]: row for row in stale_rows}
        results = await RealPingTester.test_batch(stale)
        for r in results:
            m = meta.get(r["config"], {})
            r["protocol"] = m.get("protocol", "unknown")
            r["country"]  = m.get("country", "ALL")
        alive_count = sum(1 for r in results if r["alive"])
        await DatabaseManager.upsert_tested_configs(results)
        purged = await DatabaseManager.purge_dead_tested_configs(max_fail_streak=Config.PING_FAIL_TOLERANCE)
        logger.info(f"🔁 Ping Retest: {alive_count}/{len(results)} زنده ماندند (حذف‌شده: {purged})")
        await DatabaseManager.add_log(
            "INFO", f"Ping retest: {alive_count}/{len(results)} alive, {purged} purged", "ping_retest")
    except Exception as exc:
        logger.error(f"cron_ping_retest: {exc}", exc_info=True)


async def cron_ping_full_purge(context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    هر ۲۴ ساعت: طبق درخواست، تمام جدول tested_configs (حتی 🟢 و 🟡) کاملاً
    پاک می‌شود تا بات با یک مجموعه‌ی کاملاً تازه از صفر دوباره شروع به تست
    و ساخت لیست کانفیگ‌های زنده کند — از انباشت کانفیگ‌های قدیمی که ممکن است
    دیگر معتبر نباشند جلوگیری می‌کند.
    """
    try:
        n = await DatabaseManager.purge_all_tested_configs()
        logger.info(f"🧹 Ping Full Purge: {n:,} کانفیگ تست‌شده (۲۴ ساعته) کاملاً پاک شد.")
        await DatabaseManager.add_log("INFO", f"Full purge: {n} tested configs cleared", "ping_full_purge")
    except Exception as exc:
        logger.error(f"cron_ping_full_purge: {exc}", exc_info=True)

# ═══════════════════════════════════════════════════════════════════════════════
# Lifecycle
# ═══════════════════════════════════════════════════════════════════════════════
async def post_init(app: Application) -> None:
    await DatabaseManager.init_db()
    await DatabaseManager.populate_default_sources()
    await DatabaseManager.start_write_worker()
    # بارگذاری IP Blacklist در حافظه
    blocked_ips = await DatabaseManager.load_ip_blacklist()
    IPBlacklist.load(blocked_ips)
    logger.info(f"🛡 {len(blocked_ips)} IP در لیست سیاه بارگذاری شد.")
    # شروع reload اولیه
    asyncio.create_task(CacheManager.reload())
    # دانلود پیش‌کنشی باینری Xray (اگر Ping Test فعال است) — تا آماده باشد
    # قبل از اولین اجرای cron_ping_test_batch.
    if Config.PING_TEST_ENABLED:
        asyncio.create_task(XrayManager.ensure_ready())
    # ثبت دستورات
    await app.bot.set_my_commands([
        BotCommand("start",      "🏠 منوی اصلی"),
        BotCommand("help",       "❓ راهنما"),
        BotCommand("profile",    "👤 پروفایل من"),
        BotCommand("lang",       "🌐 تغییر زبان"),
        BotCommand("admin",      "👑 پنل ادمین"),
    ])
    await DatabaseManager.add_log("INFO", "Bot started v6.0", "post_init")
    logger.info("🚀 Bot v6.0 آماده — کش در حال بارگذاری...")

# ═══════════════════════════════════════════════════════════════════════════════
# main()
# ═══════════════════════════════════════════════════════════════════════════════
def main() -> None:
    Config.validate()

    app = (
        Application.builder()
        .token(Config.BOT_TOKEN)
        .post_init(post_init)
        .build()
    )

    jq = app.job_queue
    jq.run_repeating(cron_refresh,           interval=Config.CACHE_REFRESH_INTERVAL, first=90)
    jq.run_repeating(cron_channel,           interval=Config.CHANNEL_POST_INTERVAL,  first=180)
    jq.run_repeating(cron_cleanup,           interval=Config.AUTO_CLEANUP_INTERVAL,  first=3600)
    jq.run_repeating(cron_github_search,     interval=Config.GITHUB_SEARCH_INTERVAL, first=300)
    jq.run_repeating(cron_memory_leak_check, interval=300,                           first=600)
    if Config.PING_TEST_ENABLED:
        jq.run_repeating(cron_ping_test_batch, interval=Config.PING_TEST_INTERVAL_SEC,   first=120)
        jq.run_repeating(cron_ping_retest,     interval=Config.PING_RETEST_INTERVAL_SEC, first=900)
        jq.run_repeating(cron_ping_full_purge, interval=86400,                           first=86400)

    # ── pre-handler جهانی (group=-1) ─────────────────────────────────────────
    app.add_handler(MessageHandler(filters.ALL,         global_guard), group=-1)
    app.add_handler(CallbackQueryHandler(global_guard),               group=-1)

    # ── دستورات کاربر ─────────────────────────────────────────────────────────
    app.add_handler(CommandHandler("start",   start_command))
    app.add_handler(CommandHandler("help",    help_command))
    app.add_handler(CommandHandler("lang",    lang_command))
    app.add_handler(CommandHandler("profile", profile_command))

    # ── دستورات ادمین ──────────────────────────────────────────────────────────
    app.add_handler(CommandHandler("admin",       admin_panel_command))
    app.add_handler(CommandHandler("stats",       admin_stats_cmd))
    app.add_handler(CommandHandler("health",      admin_health_cmd))
    app.add_handler(CommandHandler("reload",      admin_reload_cmd))
    app.add_handler(CommandHandler("force_update",admin_reload_cmd))
    app.add_handler(CommandHandler("vip",         admin_vip_cmd))
    app.add_handler(CommandHandler("ban",         admin_ban_cmd))
    app.add_handler(CommandHandler("unban",       admin_unban_cmd))
    app.add_handler(CommandHandler("broadcast",   admin_broadcast_cmd))
    app.add_handler(CommandHandler("addsource",   admin_addsource_cmd))
    app.add_handler(CommandHandler("removesource",admin_removesource_cmd))
    app.add_handler(CommandHandler("backup",      admin_backup_cmd))
    app.add_handler(CommandHandler("export",      admin_export_cmd))
    app.add_handler(CommandHandler("benchmark",   admin_benchmark_cmd))

    # ── روتر callback ──────────────────────────────────────────────────────────
    app.add_handler(CallbackQueryHandler(callback_router))

    # ── پیام‌های متنی ────────────────────────────────────────────────────────
    # رفع باگ «فلوی متنی (مثل وارد کردن تعداد کانفیگ یا عبارت جستجو) در گروه
    # کار نمی‌کند»: قبلاً این هندلر با filters.ChatType.PRIVATE محدود شده
    # بود، یعنی حتی اگر کاربر در گروه دقیقاً به بات ریپلای می‌کرد یا آن را
    # منشن می‌کرد، جواب متنی او (مثلاً عدد «50» بعد از زدن «دریافت کانفیگ»)
    # اصلاً به این تابع نمی‌رسید. حالا چت‌های گروهی هم مجازند — این ایمن
    # است چون global_guard (در group=-1، پیش از این هندلر) از قبل تضمین
    # کرده که پیام گروهی فقط وقتی به اینجا می‌رسد که واقعاً خطاب به بات
    # بوده (ریپلای به بات یا @mention)؛ بات هرگز به گفت‌وگوی معمولی اعضای
    # گروه که ربطی به آن ندارد پاسخ نمی‌دهد.
    app.add_handler(MessageHandler(
        filters.TEXT & ~filters.COMMAND,
        user_message_handler))

    logger.info("🚀 Polling شروع شد...")
    app.run_polling(drop_pending_updates=True, allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
