#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════
# start.sh — نقطه‌ی ورود واحد برای Railway
#
# چرا این‌طور: Railway هر "service" را با یک start command واحد اجرا
# می‌کند. برای این‌که هم بات و هم پنل تحت وب در همان service (و درنتیجه
# روی همان فایل‌سیستم محلی و همان bot_database.db) اجرا شوند، این اسکریپت
# پنل وب (dashboard.py) را در پس‌زمینه اجرا می‌کند و بات (app.py) را در
# پیش‌زمینه — تا Railway پروسه‌ی اصلی (بات) را برای health-check/restart
# درست ردیابی کند. اگر پنل وب کرش کند، بات هم‌چنان به کارش ادامه می‌دهد.
# ══════════════════════════════════════════════════════════════════════════
set -e

echo "🚀 Starting web dashboard on port ${PORT:-8080} (background)..."
python3 dashboard.py &
DASHBOARD_PID=$!

cleanup() {
    echo "🛑 Shutting down dashboard (pid $DASHBOARD_PID)..."
    kill "$DASHBOARD_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "🤖 Starting bot (foreground)..."
python3 app.py
