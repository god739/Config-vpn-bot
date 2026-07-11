# -*- coding: utf-8 -*-
"""
پنل تحت وب بات V2Ray — بر پایه‌ی Flask، برای دیپلوی روی Railway کنار فایل
اصلی بات (app.py).

معماری (چرا این‌طور طراحی شده):
  روی Railway، دو "process" جدا در یک "service" واحد می‌توانند هم‌زمان اجرا
  شوند و همان فایل‌سیستم محلی (و درنتیجه همان فایل SQLite) را به اشتراک
  بگذارند — اما دو "service" جدا معمولاً فایل‌سیستم مشترک ندارند مگر با
  Railway Volume (که پیچیدگی و هزینه‌ی اضافه دارد). چون بات از aiosqlite
  با mode=WAL استفاده می‌کند (PRAGMA journal_mode=WAL already در app.py)،
  یک پروسه‌ی دوم می‌تواند هم‌زمان و امن از همان فایل دیتابیس فقط بخواند،
  بدون قفل‌کردن نویسنده‌ی اصلی (بات). بنابراین این فایل به‌عنوان یک پروسه‌ی
  دوم در همان service طراحی شده — نه یک service کاملاً جدا — و از طریق یک
  Procfile با هر دو (بات + این پنل) در کنار هم اجرا می‌شود.

  دیتابیس فقط خوانده می‌شود (read-only) از این پنل؛ هیچ نوشتنی مستقیماً
  روی جدول‌های بات انجام نمی‌شود مگر از طریق endpoint های صریح ادمین که
  دقیقاً همان چیزی را انجام می‌دهند که دستورات بات انجام می‌دهند (مثلاً
  toggle کردن دکمه‌ی تست‌شده، یا فعال/غیرفعال‌کردن یک منبع).

امنیت:
  - پنل ادمین با یک "توکن" محافظت می‌شود (env var ADMIN_PANEL_TOKEN) — نه
    نام‌کاربری/رمز جدا، چون این ابزار داخلی خودِ ادمین است.
  - لینک ساب اختصاصی هر کاربر شامل یک HMAC امضاشده از user_id است، پس
    نمی‌توان با تغییر عدد در URL، ساب کاربر دیگری را حدس زد یا گرفت.
"""
import os, sqlite3, hmac, hashlib, time, math, json
from datetime import datetime
from flask import Flask, request, jsonify, Response, render_template, abort, g

# ══════════════════════════════════════════════════════════════════════════
# تنظیمات
# ══════════════════════════════════════════════════════════════════════════
DB_PATH           = os.environ.get("DB_PATH", "bot_database.db")
ADMIN_PANEL_TOKEN = os.environ.get("ADMIN_PANEL_TOKEN", "")   # حتماً در Railway ست شود
SUB_LINK_SECRET   = os.environ.get("SUB_LINK_SECRET", "change-me-in-railway-env")
PORT              = int(os.environ.get("WEBDASH_PORT", os.environ.get("PORT", "8080")))
MAX_SUB_CONFIGS   = int(os.environ.get("MAX_SUB_CONFIGS", "500"))

app = Flask(__name__, template_folder="templates", static_folder="static")

COUNTRY_NAMES = {
    "de":"Germany","nl":"Netherlands","fi":"Finland","se":"Sweden","fr":"France",
    "gb":"United Kingdom","us":"United States","ca":"Canada","jp":"Japan",
    "sg":"Singapore","ru":"Russia","ua":"Ukraine","br":"Brazil","au":"Australia",
    "in":"India","kr":"South Korea","tr":"Turkey","at":"Austria","ch":"Switzerland",
    "pl":"Poland","cz":"Czechia","ro":"Romania","hu":"Hungary","lt":"Lithuania",
    "lv":"Latvia","ee":"Estonia","no":"Norway","dk":"Denmark","es":"Spain","it":"Italy",
    "ALL":"Unknown",
}

# ══════════════════════════════════════════════════════════════════════════
# دسترسی به دیتابیس (read-only، امن برای هم‌زمانی با WAL بات)
# ══════════════════════════════════════════════════════════════════════════
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        # uri=True + mode=ro یعنی این اتصال حتی در سطح OS هم فقط-خواندنی است —
        # اگر پنل باگی داشته باشد، به هیچ عنوان نمی‌تواند داده‌ی بات را خراب کند.
        uri = f"file:{DB_PATH}?mode=ro"
        g.db = sqlite3.connect(uri, uri=True, timeout=5)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def q(sql: str, params: tuple = ()) -> list:
    try:
        cur = get_db().execute(sql, params)
        return cur.fetchall()
    except sqlite3.OperationalError:
        # دیتابیس ممکن است لحظه‌ی اول (قبل از اولین init_db بات) هنوز وجود
        # نداشته باشد — به‌جای کرش، پنل یک نتیجه‌ی خالی نشان می‌دهد.
        return []

def q_write_via_bot_db(sql: str, params: tuple = ()) -> None:
    """
    برای عملیات نوشتنی محدود پنل ادمین (toggle تنظیمات، فعال/غیرفعال‌کردن
    منبع) — این‌ها اتصال جدای read-write کوتاه‌مدت خودشان را باز می‌کنند،
    نه از طریق اتصال read-only بالا. WAL امکان این هم‌زیستی نویسنده‌های
    متعدد را می‌دهد.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5)
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()

# ══════════════════════════════════════════════════════════════════════════
# احراز هویت پنل ادمین
# ══════════════════════════════════════════════════════════════════════════
def _admin_authed() -> bool:
    if not ADMIN_PANEL_TOKEN:
        return False   # اگر توکن ست نشده، پنل ادمین کاملاً غیرفعال می‌ماند (fail-closed)
    supplied = request.args.get("token") or request.headers.get("X-Admin-Token") or ""
    return hmac.compare_digest(supplied, ADMIN_PANEL_TOKEN)

def require_admin(fn):
    def wrapper(*a, **kw):
        if not _admin_authed():
            abort(403)
        return fn(*a, **kw)
    wrapper.__name__ = fn.__name__
    return wrapper

# ══════════════════════════════════════════════════════════════════════════
# لینک ساب اختصاصی کاربر — امضاشده با HMAC تا قابل حدس‌زدن نباشد
# ══════════════════════════════════════════════════════════════════════════
def sign_user_id(user_id: int) -> str:
    mac = hmac.new(SUB_LINK_SECRET.encode(), str(user_id).encode(), hashlib.sha256)
    return mac.hexdigest()[:16]

def verify_user_sig(user_id: str, sig: str) -> bool:
    try:
        expected = sign_user_id(int(user_id))
    except ValueError:
        return False
    return hmac.compare_digest(expected, sig)

# ══════════════════════════════════════════════════════════════════════════
# صفحات HTML
# ══════════════════════════════════════════════════════════════════════════
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/admin")
def admin_page():
    if not _admin_authed():
        return render_template("admin_login.html"), 403
    return render_template("admin.html", token=request.args.get("token", ""))

# ══════════════════════════════════════════════════════════════════════════
# API عمومی — آمار زنده‌ی بات (بدون داده‌ی حساس) برای صفحه‌ی اصلی
# ══════════════════════════════════════════════════════════════════════════
@app.route("/api/public/stats")
def api_public_stats():
    total_cached  = q("SELECT COUNT(*) c FROM tested_configs")
    live          = q("SELECT COUNT(*) c FROM tested_configs WHERE ping_ms >= 0 AND ping_ms <= 800")
    good          = q("SELECT COUNT(*) c FROM tested_configs WHERE ping_ms >= 0 AND ping_ms <= 300")
    sources       = q("SELECT COUNT(*) c FROM sources WHERE enabled=1")
    users         = q("SELECT COUNT(*) c FROM prefs")
    by_proto      = q("SELECT protocol, COUNT(*) c FROM tested_configs WHERE ping_ms>=0 GROUP BY protocol ORDER BY c DESC")
    by_country    = q("""SELECT country, COUNT(*) c FROM tested_configs
                          WHERE ping_ms>=0 GROUP BY country ORDER BY c DESC LIMIT 12""")
    return jsonify({
        "tested_total": total_cached[0]["c"] if total_cached else 0,
        "live_total":   live[0]["c"] if live else 0,
        "good_total":   good[0]["c"] if good else 0,
        "active_sources": sources[0]["c"] if sources else 0,
        "total_users":  users[0]["c"] if users else 0,
        "by_protocol":  [{"protocol": r["protocol"], "count": r["c"]} for r in by_proto],
        "by_country":   [{"code": r["country"], "name": COUNTRY_NAMES.get(r["country"], r["country"]),
                           "count": r["c"]} for r in by_country],
    })

# ══════════════════════════════════════════════════════════════════════════
# لینک ساب کاربر — /sub/<user_id>/<sig>  و  /sub/<user_id>/<sig>/config
# ══════════════════════════════════════════════════════════════════════════
@app.route("/sub/<user_id>/<sig>")
def user_sub_page(user_id, sig):
    if not verify_user_sig(user_id, sig):
        abort(404)
    prefs = q("SELECT protocol,country,is_vip,total_downloads FROM prefs WHERE user_id=?", (int(user_id),))
    if not prefs:
        abort(404)
    p = prefs[0]
    return render_template("user_sub.html", user_id=user_id, sig=sig,
                            protocol=p["protocol"], country=p["country"],
                            is_vip=bool(p["is_vip"]), total=p["total_downloads"])

@app.route("/sub/<user_id>/<sig>/raw")
def user_sub_raw(user_id, sig):
    """
    خروجی متنی خام کانفیگ‌ها — این همان URL ای است که کاربر در اپ کلاینت
    (v2rayNG, Streisand, Shadowrocket, ...) به‌عنوان subscription URL وارد
    می‌کند. فیلتر بر اساس آخرین protocol/country ذخیره‌شده‌ی کاربر در بات
    اعمال می‌شود — یعنی همان فیلتری که در خودِ بات هم انتخاب کرده.
    """
    if not verify_user_sig(user_id, sig):
        abort(404)
    prefs = q("SELECT protocol,country,is_vip FROM prefs WHERE user_id=?", (int(user_id),))
    if not prefs:
        abort(404)
    p = prefs[0]
    proto, country = p["protocol"], p["country"]

    sql = "SELECT config FROM tested_configs WHERE ping_ms >= 0"
    params: list = []
    if proto and proto != "ALL":
        sql += " AND protocol=?"; params.append(proto)
    if country and country != "ALL":
        sql += " AND country=?"; params.append(country)
    sql += " ORDER BY ping_ms ASC LIMIT ?"
    params.append(MAX_SUB_CONFIGS)

    rows = q(sql, tuple(params))
    body = "\n".join(r["config"] for r in rows)
    return Response(body, mimetype="text/plain; charset=utf-8")

# ══════════════════════════════════════════════════════════════════════════
# لینک ساب ادمین — همه‌چیز، شامل کانفیگ‌های پشت‌پرده (تست‌نشده/آرشیو هم اگر خواست)
# ══════════════════════════════════════════════════════════════════════════
@app.route("/admin/sub/all")
@require_admin
def admin_sub_all():
    rows = q("SELECT config FROM tested_configs WHERE ping_ms >= 0 ORDER BY ping_ms ASC")
    body = "\n".join(r["config"] for r in rows)
    return Response(body, mimetype="text/plain; charset=utf-8")

@app.route("/admin/archive/export")
@require_admin
def admin_archive_export():
    """
    طبق درخواست ادمین: دریافت تعداد دلخواه (نه فقط کل) از کانفیگ‌های
    آرشیوشده (خراب/تکراری)، به‌صورت فایل txt قابل دانلود مستقیم از پنل وب —
    مثال: /admin/archive/export?limit=500&token=...  (بدون limit یعنی همه).
    """
    limit_param = request.args.get("limit", "").strip()
    if limit_param.isdigit() and int(limit_param) > 0:
        rows = q("SELECT config FROM archived_configs ORDER BY archived_at DESC LIMIT ?", (int(limit_param),))
    else:
        rows = q("SELECT config FROM archived_configs ORDER BY archived_at DESC")
    body = "\n".join(r["config"] for r in rows)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M")
    return Response(
        body, mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="archived_{len(rows)}_{ts}.txt"'})

# ══════════════════════════════════════════════════════════════════════════
# API ادمین — فقط-خواندنی
# ══════════════════════════════════════════════════════════════════════════
@app.route("/api/admin/overview")
@require_admin
def api_admin_overview():
    tested       = q("SELECT COUNT(*) c FROM tested_configs")
    live         = q("SELECT COUNT(*) c FROM tested_configs WHERE ping_ms>=0")
    good         = q("SELECT COUNT(*) c FROM tested_configs WHERE ping_ms BETWEEN 0 AND 300")
    ok_          = q("SELECT COUNT(*) c FROM tested_configs WHERE ping_ms BETWEEN 301 AND 800")
    bad          = q("SELECT COUNT(*) c FROM tested_configs WHERE ping_ms > 800 OR ping_ms < 0")
    avg_ping     = q("SELECT AVG(ping_ms) a FROM tested_configs WHERE ping_ms BETWEEN 0 AND 800")
    sources_tot  = q("SELECT COUNT(*) c FROM sources")
    sources_on   = q("SELECT COUNT(*) c FROM sources WHERE enabled=1")
    sources_fail = q("SELECT COUNT(*) c FROM sources WHERE fail_count > 0")
    users_tot    = q("SELECT COUNT(*) c FROM prefs")
    vip_tot      = q("SELECT COUNT(*) c FROM prefs WHERE is_vip=1")
    banned_tot   = q("SELECT COUNT(*) c FROM banned_users")
    archived_tot = q("SELECT COUNT(*) c FROM archived_configs")
    today        = datetime.utcnow().strftime("%Y-%m-%d")
    today_reqs   = q("SELECT SUM(requests_count) s, SUM(configs_received) g FROM daily_usage WHERE date=?", (today,))

    return jsonify({
        "tested_total": tested[0]["c"] if tested else 0,
        "live_total":   live[0]["c"] if live else 0,
        "good_total":   good[0]["c"] if good else 0,
        "ok_total":     ok_[0]["c"] if ok_ else 0,
        "bad_total":    bad[0]["c"] if bad else 0,
        "avg_ping_ms":  round(avg_ping[0]["a"], 1) if avg_ping and avg_ping[0]["a"] else None,
        "sources_total":   sources_tot[0]["c"] if sources_tot else 0,
        "sources_enabled": sources_on[0]["c"] if sources_on else 0,
        "sources_failing": sources_fail[0]["c"] if sources_fail else 0,
        "users_total": users_tot[0]["c"] if users_tot else 0,
        "vip_total":   vip_tot[0]["c"] if vip_tot else 0,
        "banned_total": banned_tot[0]["c"] if banned_tot else 0,
        "archived_total": archived_tot[0]["c"] if archived_tot else 0,
        "today_requests": (today_reqs[0]["s"] or 0) if today_reqs else 0,
        "today_configs_sent": (today_reqs[0]["g"] or 0) if today_reqs else 0,
    })

@app.route("/api/admin/sources")
@require_admin
def api_admin_sources():
    page     = max(1, int(request.args.get("page", 1)))
    per_page = 25
    total    = q("SELECT COUNT(*) c FROM sources")[0]["c"]
    rows = q("""SELECT id,url,enabled,fail_count,last_fail_time,datacenter,found_via
                FROM sources ORDER BY id DESC LIMIT ? OFFSET ?""",
             (per_page, (page-1)*per_page))
    return jsonify({
        "total": total, "page": page, "pages": max(1, math.ceil(total/per_page)),
        "items": [dict(r) for r in rows],
    })

@app.route("/api/admin/sources/<int:source_id>/toggle", methods=["POST"])
@require_admin
def api_admin_toggle_source(source_id):
    row = q("SELECT enabled FROM sources WHERE id=?", (source_id,))
    if not row:
        return jsonify({"ok": False, "error": "not found"}), 404
    new_val = 0 if row[0]["enabled"] else 1
    q_write_via_bot_db("UPDATE sources SET enabled=? WHERE id=?", (new_val, source_id))
    return jsonify({"ok": True, "enabled": bool(new_val)})

@app.route("/api/admin/users")
@require_admin
def api_admin_users():
    page     = max(1, int(request.args.get("page", 1)))
    per_page = 25
    search   = (request.args.get("search") or "").strip()
    if search:
        like = f"%{search}%"
        total = q("SELECT COUNT(*) c FROM prefs WHERE username LIKE ? OR first_name LIKE ? OR CAST(user_id AS TEXT) LIKE ?",
                   (like, like, like))[0]["c"]
        rows = q("""SELECT user_id,username,first_name,is_vip,total_downloads,last_seen
                    FROM prefs WHERE username LIKE ? OR first_name LIKE ? OR CAST(user_id AS TEXT) LIKE ?
                    ORDER BY last_seen DESC LIMIT ? OFFSET ?""",
                  (like, like, like, per_page, (page-1)*per_page))
    else:
        total = q("SELECT COUNT(*) c FROM prefs")[0]["c"]
        rows = q("""SELECT user_id,username,first_name,is_vip,total_downloads,last_seen
                    FROM prefs ORDER BY last_seen DESC LIMIT ? OFFSET ?""",
                  (per_page, (page-1)*per_page))
    return jsonify({
        "total": total, "page": page, "pages": max(1, math.ceil(total/per_page)),
        "items": [dict(r) for r in rows],
    })

@app.route("/api/admin/archived")
@require_admin
def api_admin_archived():
    page     = max(1, int(request.args.get("page", 1)))
    per_page = 30
    total = q("SELECT COUNT(*) c FROM archived_configs")[0]["c"]
    rows  = q("""SELECT config,protocol,reason,archived_at FROM archived_configs
                 ORDER BY archived_at DESC LIMIT ? OFFSET ?""", (per_page, (page-1)*per_page))
    return jsonify({
        "total": total, "page": page, "pages": max(1, math.ceil(total/per_page)),
        "items": [dict(r) for r in rows],
    })

@app.route("/api/admin/logs")
@require_admin
def api_admin_logs():
    rows = q("SELECT timestamp,level,message,context FROM system_logs ORDER BY timestamp DESC LIMIT 100")
    return jsonify({"items": [dict(r) for r in rows]})

@app.route("/api/admin/settings/tested_button", methods=["GET", "POST"])
@require_admin
def api_admin_tested_button():
    if request.method == "POST":
        new_val = "1" if request.json.get("enabled") else "0"
        q_write_via_bot_db(
            "INSERT INTO bot_settings (key,value) VALUES ('show_tested_configs_button', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (new_val,))
        return jsonify({"ok": True, "enabled": new_val == "1"})
    row = q("SELECT value FROM bot_settings WHERE key='show_tested_configs_button'")
    enabled = (row[0]["value"] if row else "1") == "1"
    return jsonify({"enabled": enabled})

@app.route("/api/admin/gen_sub_link")
@require_admin
def api_admin_gen_sub_link():
    user_id = request.args.get("user_id", "")
    if not user_id.lstrip("-").isdigit():
        return jsonify({"ok": False, "error": "invalid user_id"}), 400
    sig = sign_user_id(int(user_id))
    base = request.args.get("base_url") or request.host_url.rstrip("/")
    return jsonify({"ok": True, "url": f"{base}/sub/{user_id}/{sig}"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
