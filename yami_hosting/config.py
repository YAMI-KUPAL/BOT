"""
Core configuration constants and settings for YAMI HOSTING v4.0.
All configurable values centralized here.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ═════════════════════════════════════════════════════════════════
# BRANDING
# ═════════════════════════════════════════════════════════════════
BRAND       = "⚡ YAMI HOSTING ⚡"
BRAND_VER   = "v4.0"
BRAND_TAG   = f"{BRAND} {BRAND_VER}"
SUPPORT_USR = "@LEGITYAMI"
UPDATE_CH   = "https://t.me/SYNTAXYAMICHANNEL"
FOOTER      = f"\n\n<blockquote>{BRAND_TAG}\n👤 @LEGITYAMI | 📢 @SYNTAXYAMICHANNEL\n💳 GCash: 09667664037</blockquote>"

# ══════════════════════════════════════════════════════════════════
# BOT TOKEN & OWNER
# ══════════════════════════════════════════════════════════════════
BOT_TOKEN_HARDCODED = "8848657792:AAFxUhgAcHKY4hfmdx--LAALz9DJ6hBwwrQ"
TOKEN = (
    os.environ.get("BOT_TOKEN")
    or os.environ.get("MAIN_BOT_TOKEN")
    or os.environ.get("TELEGRAM_BOT_TOKEN")
    or BOT_TOKEN_HARDCODED
    or ""
).strip()

try:
    OWNER_ID = int(os.environ.get("OWNER_ID", "7332897870"))
except (TypeError, ValueError):
    OWNER_ID = 0

ANNOUNCE_CHANNEL = os.environ.get("ANNOUNCE_CHANNEL", "-1002865724429").strip()

try:
    KEEPALIVE_PORT = int(os.environ.get("PORT", 10460))
except (TypeError, ValueError):
    KEEPALIVE_PORT = 10000

# ══════════════════════════════════════════════════════════════════
# DIRECTORIES
# ══════════════════════════════════════════════════════════════════
BASE_DIR = Path(__file__).resolve().parent.parent

DIRS: Dict[str, Path] = {
    "uploads":  BASE_DIR / "storage" / "uploads",
    "encfiles": BASE_DIR / "storage" / "encfiles",
    "data":     BASE_DIR / "storage" / "data",
    "logs":     BASE_DIR / "storage" / "logs",
    "backups":  BASE_DIR / "storage" / "backups",
    "sandbox":  BASE_DIR / "sandbox",
    "tickets":  BASE_DIR / "storage" / "tickets",
    "bot_data": BASE_DIR / "storage" / "bot_data",
    "photos":   BASE_DIR / "storage" / "photos",
    "filemanager": BASE_DIR / "storage" / "filemanager",
}
for _p in DIRS.values():
    _p.mkdir(parents=True, exist_ok=True)

GCASH_QR_PATH = DIRS["photos"] / "gcash_qr.png"

DB_FILE       = DIRS["data"] / "panel_db.json"
SETTINGS_FILE = DIRS["data"] / "panel_settings.json"
AUDIT_FILE    = DIRS["data"] / "audit.log"
KEYRING_FILE  = DIRS["data"] / "keyring.json"

# ══════════════════════════════════════════════════════════════════
# FREE HOSTING PLATFORMS
# ══════════════════════════════════════════════════════════════════
FREE_HOSTING_PLATFORMS = {
    "hidencloud": {
        "name": "☁ HidenCloud",
        "url": "https://www.hidencloud.com",
        "specs": "2 vCPU • 3GB RAM • 15GB Disk • 24/7",
        "cost": "FREE (renew weekly)",
        "steps": [
            "Sign up at hidencloud.com",
            "Create server → Python egg",
            "Upload bot files + requirements.txt",
            "Set BOT_TOKEN in Startup tab",
            "Install deps: pip install -r requirements.txt",
            "Start → your bot runs 24/7!"
        ]
    },
    "render": {
        "name": "🔷 Render",
        "url": "https://render.com",
        "specs": "512MB RAM • Web Service • Auto-deploy from GitHub",
        "cost": "FREE (use UptimeRobot to stay awake)",
        "steps": [
            "Sign up at render.com (GitHub login)",
            "New Web Service → connect your repo",
            "Build: pip install -r requirements.txt",
            "Start: python bot.py",
            "Use UptimeRobot (free) to ping every 5 min",
            "Bot stays alive 24/7!"
        ]
    },
    "pella": {
        "name": "🟢 Pella",
        "url": "https://www.pella.app",
        "specs": "0.1 CPU • 100MB RAM • 5GB Disk • Unmetered BW",
        "cost": "FREE forever",
        "steps": [
            "Sign up at pella.app",
            "Upload your bot files",
            "Set environment variables (BOT_TOKEN)",
            "Deploy with 1 click!",
            "Best for lightweight bots"
        ]
    },
    "telebothost": {
        "name": "📱 TeleBotHost (TBH)",
        "url": "https://telebothost.com",
        "specs": "Telegram-native • Browser IDE • 1-click deploy",
        "cost": "FREE",
        "steps": [
            "Sign in with Telegram at telebothost.com",
            "Create new bot project",
            "Paste your code in the browser IDE",
            "Click Deploy → live instantly!"
        ]
    },
    "koyeb": {
        "name": "🚀 Koyeb",
        "url": "https://koyeb.com",
        "specs": "512MB RAM • 0.1 vCPU • 100GB bandwidth",
        "cost": "FREE (monthly credits)",
        "steps": [
            "Sign up at koyeb.com (GitHub)",
            "Deploy from GitHub repo",
            "Set BOT_TOKEN as secret env var",
            "Auto-deploys on git push!"
        ]
    },
}

# ══════════════════════════════════════════════════════════════════
# PLAN LIMITS
# ══════════════════════════════════════════════════════════════════
PLAN_LIMITS: Dict[str, Dict[str, Any]] = {
    "free":       {"name": "Free",       "max_bots": 2,   "ram": 128,  "cpu": 0.1, "disk_mb": 100,  "auto_restart": False, "price": 0,    "days": 0},
    "starter":    {"name": "Starter",    "max_bots": 4,   "ram": 256,  "cpu": 0.25,"disk_mb": 250,  "auto_restart": True,  "price": 99,   "days": 30},
    "basic":      {"name": "Basic",      "max_bots": 6,   "ram": 512,  "cpu": 0.5, "disk_mb": 500,  "auto_restart": True,  "price": 199,  "days": 30},
    "pro":        {"name": "Pro",        "max_bots": 8,   "ram": 2048, "cpu": 1.0, "disk_mb": 1000, "auto_restart": True,  "price": 499,  "days": 30},
    "enterprise": {"name": "Enterprise", "max_bots": 10,  "ram": 4096, "cpu": 2.0, "disk_mb": 2000, "auto_restart": True,  "price": 999,  "days": 30},
    "lifetime":   {"name": "Lifetime",   "max_bots": 15,  "ram": 8192, "cpu": 4.0, "disk_mb": 5000, "auto_restart": True,  "price": 1999, "days": 36500},
}

# ══════════════════════════════════════════════════════════════════
# PAYMENT METHODS (dynamic, can be edited by admin)
# ══════════════════════════════════════════════════════════════════
PAYMENT_METHODS: Dict[str, Dict[str, Any]] = {
    "gcash":    {"name": "GCash",        "number": "09667664037",            "type": "InstaPay QR / Express Send", "tag": "🇵🇭 [GC]", "has_qr": True,  "enabled": True},
    "maya":     {"name": "Maya",         "number": "09667664037",            "type": "Send Money",       "tag": "🇵🇭 [MY]", "has_qr": True,  "enabled": True},
    "fampay":   {"name": "Fampay",       "number": "raj141036@fam",         "type": "Send Money",       "tag": "[B]",  "has_qr": False, "enabled": True},
    "bank":     {"name": "Bank Transfer","number": "Contact @LEGITYAMI",    "type": "Bank Transfer",    "tag": "[BK]", "has_qr": False, "enabled": True},
    "paypal":   {"name": "PayPal",       "number": "paypal@yami.com",       "type": "Send Money",       "tag": "🌍 [PP]", "has_qr": False, "enabled": False},
    "crypto":   {"name": "Crypto (USDT)","number": "0x... (contact admin)", "type": "USDT TRC20",       "tag": "🪙 [CR]", "has_qr": False, "enabled": False},
}

# ══════════════════════════════════════════════════════════════════
# SECRET ENV NAMES (never expose to bots)
# ══════════════════════════════════════════════════════════════════
SECRET_ENV_NAMES = {
    "BOT_TOKEN", "OWNER_ID", "ERROR_BOT_TOKEN",
    "MONGO_URL", "MONGO_URL_BACKUP",
    "GITHUB_TOKEN", "GITHUB_REPO", "GITHUB_BRANCH", "GITHUB_KEY_REPO",
    "OWNER_IDS", "SESSION_SECRET",
    "DATABASE_URL", "PGDATABASE", "PGHOST", "PGPORT", "PGUSER", "PGPASSWORD",
    "REPLIT_DB_URL", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GROQ_API_KEY",
    "AI_INTEGRATIONS_OPENROUTER_BASE_URL", "AI_INTEGRATIONS_OPENROUTER_API_KEY",
    "ANNOUNCE_CHANNEL",
}

# ══════════════════════════════════════════════════════════════════
# ENTRY FILES (per runtime)
# ══════════════════════════════════════════════════════════════════
ENTRY_FILES: Dict[str, Tuple[str, ...]] = {
    "python": ("bot.py", "main.py", "app.py", "run.py", "server.py"),
    "node":   ("index.js", "bot.js", "main.js", "app.js", "server.js"),
    "php":    ("index.php", "bot.php", "main.php", "app.php"),
    "go":     ("main.go", "bot.go", "server.go", "app.go"),
    "java":   ("Main.java", "Bot.java", "App.java", "Server.java"),
    "bun":    ("index.ts", "bot.ts", "main.ts", "index.js", "bot.js"),
    "deno":   ("main.ts", "bot.ts", "server.ts", "index.ts"),
}

ENTRY_NODE = ("index.js", "bot.js", "main.js", "app.js", "server.js")
ENTRY_PY   = ("bot.py", "main.py", "app.py", "run.py", "server.py")

LOG_RING   = 200
MAX_LOG_SEND = 50
MAX_UPLOAD_BYTES = 75 * 1024 * 1024  # 75 MB

# ══════════════════════════════════════════════════════════════════
# RUNTIME → COMMAND MAPPING
# ══════════════════════════════════════════════════════════════════
RUNTIME_COMMANDS: Dict[str, List[str]] = {
    "python": ["python3", "-u"],
    "node":   ["node"],
    "php":    ["php"],
    "go":     ["go", "run"],
    "java":   ["java", "-jar"],
    "bun":    ["bun", "run"],
    "deno":   ["deno", "run", "--allow-net", "--allow-env"],
}

RUNTIME_INSTALL_COMMANDS: Dict[str, List[str]] = {
    "python": ["pip", "install", "--target"],
    "node":   ["npm", "install", "--omit=dev", "--no-audit", "--no-fund"],
    "php":    ["composer", "install", "--no-dev"],
    "go":     ["go", "mod", "tidy"],
    "bun":    ["bun", "install"],
    "deno":   ["deno", "cache"],
}

# ══════════════════════════════════════════════════════════════════
# GLYPHS — smart contextual symbols
# ══════════════════════════════════════════════════════════════════
G: Dict[str, str] = {
    "ok": "✓", "no": "\u2718", "warn": "\u26A0", "arrow": "\u2192",
    "bullet": "\u2022", "tri": "\u25B8", "diamond": "\u25C6", "star": "\u2605",
    "spark": "\u2726", "back": "↲", "fwd": "\u25B6",
    "plus": "\u2295", "minus": "\u2296", "rec": "\u25C9", "rec_off": "\u25CB",
    "div": "\u2501" * 16, "div_eq": "\u2550" * 16,
    "play": "‣", "stop": "\u25A0", "running": "\u25B6", "stopped": "■",
    "refresh": "\u21BB", "lock": "\u25A3", "unlock": "\u25A2",
    "shield": "\u25C7", "ban": "\u2694", "trash": "\u2716", "eye": "\u25C9",
    "user": "\u25C8", "users": "\u25CE", "crown": "\u2654",
    "wallet": "\u25C6", "premium": "⌬", "lifetime": "\u2736",
    "gift": "\u2726", "ticket": "\u273F", "trophy": "\u2605",
    "graph": "\u25AA", "chart_up": "\u25B2",
    "broadcast": "⚑", "chat": "\u25AB",
    "folder": "\u25B8", "upload": "\u25B4", "download": "\u25BE", "cloud": "\u2601",
    "settings": "⚙", "cog": "\u2699", "bolt": "\u26A1", "clock": "\u23F1",
    "server": "🖥", "cpu": "⚡", "ram": "🧠", "disk": "💾", "network": "🌐",
    "ai": "🤖", "code": "💻", "terminal": "⬛", "deploy": "🚀",
    "dashboard": "📊", "security": "🛡", "file": "📄", "dir": "📁",
    "python": "🐍", "nodejs": "💚", "php_icon": "🐘", "go_icon": "🔵",
    "java_icon": "☕", "bun_icon": "🥟", "deno_icon": "🦕",
}

# ══════════════════════════════════════════════════════════════════
# SKIP DIRS (for scanning, not dependencies)
# ══════════════════════════════════════════════════════════════════
SKIP_DIR_PARTS = {".deps", "node_modules", ".tmp_run", "__pycache__",
                  ".git", "venv", ".venv", "env", "vendor", "target"}

# ══════════════════════════════════════════════════════════════════
# REQUIRED GROUPS (for verification)
# ══════════════════════════════════════════════════════════════════
REQUIRED_GROUPS = [
    {"id": -1003715566556, "link": "https://t.me/+OClpzDTPSGxkZWU1", "name": "Group 1"},
    {"id": -1003776599179, "link": "https://t.me/autolikegcrbot",     "name": "Group 2"},
]
