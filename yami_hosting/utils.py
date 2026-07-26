"""
Utility functions for YAMI HOSTING v4.0.
String formatting, time helpers, file operations, logging.
"""
from __future__ import annotations

import json
import os
import random
import re
import shutil
import string
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .config import AUDIT_FILE, DB_FILE, G, SETTINGS_FILE

# ═════════════════════════════════════════════════════════════════
# CACHE (mtime-invalidated, shared across modules)
# ═════════════════════════════════════════════════════════════════
_cache: Dict[str, Any] = {}
_cache_lock = threading.Lock()

def _atomic_write(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    tmp.replace(path)
    _cache.pop(str(path), None)

def _load_json(path: Path, default: Any) -> Any:
    try:
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8") or "null") or default
    except Exception:
        return default

def _cached_load_ro(path: Path, default: Any) -> Any:
    key = str(path)
    with _cache_lock:
        entry = _cache.get(key)
        if entry is not None:
            cached_data, cached_mtime = entry
            try:
                if path.stat().st_mtime <= cached_mtime:
                    return cached_data
            except OSError:
                pass
    data = _load_json(path, default)
    try:
        mtime = path.stat().st_mtime
    except OSError:
        mtime = time.time()
    with _cache_lock:
        _cache[key] = (data, mtime)
    return data

def _cache_invalidate(path: Path) -> None:
    _cache.pop(str(path), None)

# ═════════════════════════════════════════════════════════════════
# DATABASE HELPERS
# ═════════════════════════════════════════════════════════════════
def _ensure_db_defaults(d: Dict[str, Any]) -> Dict[str, Any]:
    d.setdefault("users", {})
    d.setdefault("bots", {})
    d.setdefault("payments", [])
    d.setdefault("tickets", {})
    d.setdefault("coupons", {})
    d.setdefault("rate_violations", {})
    d.setdefault("admin_admins", {})
    d.setdefault("audit_log", [])
    d.setdefault("payment_sessions", {})
    d.setdefault("revenue", {"daily": {}, "weekly": {}, "monthly": {}, "total": 0})
    return d

def db_load() -> Dict[str, Any]:
    return _ensure_db_defaults(dict(_cached_load_ro(DB_FILE, {})))

def db_load_ro() -> Dict[str, Any]:
    return _ensure_db_defaults(dict(_cached_load_ro(DB_FILE, {})))

def db_save(d: Dict[str, Any]) -> None:
    _atomic_write(DB_FILE, d)

def settings_load() -> Dict[str, Any]:
    return dict(_cached_load_ro(SETTINGS_FILE, {}))

def settings_load_ro() -> Dict[str, Any]:
    return dict(_cached_load_ro(SETTINGS_FILE, {}))

def settings_save(d: Dict[str, Any]) -> None:
    _atomic_write(SETTINGS_FILE, d)

def get_setting(key: str, default: Any = None) -> Any:
    return settings_load_ro().get(key, default)

def set_setting(key: str, value: Any) -> None:
    d = settings_load()
    d[key] = value
    settings_save(d)

def cache_clear_all() -> None:
    with _cache_lock:
        _cache.clear()

# ═════════════════════════════════════════════════════════════════
# STRING / HTML HELPERS
# ═════════════════════════════════════════════════════════════════
def esc(s: Any = "") -> str:
    """HTML-escape text for Telegram messages."""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))

def sc(text: Any) -> str:
    """Small-caps wrapper for Telegram (Telegram renders <small>)."""
    return f"<small>{esc(text)}</small>"

def fmt_bytes(n: float) -> str:
    if n < 1024:
        return f"{n:.0f} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    return f"{n / (1024 * 1024 * 1024):.2f} GB"

def fmt_dur(ms: int) -> str:
    if ms <= 0:
        return "—"
    s = ms // 1000
    if s < 60:
        return f"{s}s"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m}m {s}s"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h}h {m}m"
    d, h = divmod(h, 24)
    return f"{d}d {h}h"

def fmt_ts(iso: Optional[str]) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        return dt.strftime("%d %b %Y, %I:%M %p")
    except Exception:
        return str(iso)[:19]

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def ts_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def safe_name(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", s)

def rand_token(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))

def safe_path_join(root: Path, *parts: str) -> Path:
    resolved = (root / Path(*parts)).resolve()
    if not str(resolved).startswith(str(root.resolve())):
        raise ValueError(f"Path escape detected: {parts}")
    return resolved

# ═════════════════════════════════════════════════════════════════
# UI HELPERS
# ═════════════════════════════════════════════════════════════════
def divider(width: int = 22, ch: str = "\u2501") -> str:
    return ch * width

def bullet(label: str, value: Any, glyph: str = G["bullet"]) -> str:
    return f"{glyph} <b>{esc(label)}</b>: {esc(value)}"

def progress_bar(pct: float, width: int = 20) -> str:
    pct = max(0, min(100, int(pct)))
    filled = int(round(width * pct / 100))
    return "▓" * filled + "░" * (width - filled) + f" {pct:>3}%"

# ═════════════════════════════════════════════════════════════════
# FILE OPERATIONS
# ═════════════════════════════════════════════════════════════════
def rmrf(p: Union[str, Path]) -> None:
    p = Path(p)
    if not p.exists():
        return
    if p.is_dir():
        shutil.rmtree(str(p), ignore_errors=True)
    else:
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass

# ═════════════════════════════════════════════════════════════════
# AUDIT LOGGING
# ═════════════════════════════════════════════════════════════════
def audit(uid: int, action: str, detail: str = "") -> None:
    entry = f"[{ts_iso()}] uid={uid} action={action} {detail}\n"
    try:
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception:
        pass

# ═════════════════════════════════════════════════════════════════
# ADMIN HELPERS
# ═════════════════════════════════════════════════════════════════
from .config import OWNER_ID

def is_owner(uid: int) -> bool:
    return uid == OWNER_ID and OWNER_ID > 0

def is_admin(uid: int) -> bool:
    if is_owner(uid):
        return True
    admins = get_setting("admin_admins", {})
    return str(uid) in admins

def admin_role(uid: int) -> str:
    if is_owner(uid):
        return "owner"
    admins = get_setting("admin_admins", {})
    return admins.get(str(uid), {}).get("role", "admin")

def admin_can(uid: int, action: str) -> bool:
    if is_owner(uid):
        return True
    admins = get_setting("admin_admins", {})
    entry = admins.get(str(uid), {})
    perms = entry.get("permissions", [])
    return "*" in perms or action in perms

# ═════════════════════════════════════════════════════════════════
# SECURITY — TOKEN MASKING
# ═════════════════════════════════════════════════════════════════
def mask_number(number: str) -> str:
    """Mask a phone/payment number: 09667664037 → 09•• ••• •4037"""
    if len(number) <= 4:
        return number
    return number[:2] + "•• ••• •" + number[-4:]

def mask_email(email: str) -> str:
    """Mask an email: raj141036@fam → ra••••••@fam"""
    if "@" not in email:
        return mask_string(email)
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        return f"{local}••••@{domain}"
    return local[:2] + "••••••@" + domain

def mask_string(s: str, visible: int = 2) -> str:
    if len(s) <= visible * 2:
        return s
    return s[:visible] + "••••" + s[-visible:]
