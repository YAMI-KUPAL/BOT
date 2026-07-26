"""
⚡ YAMI HOSTING v4.0 — ROOT ENTRY POINT
Standalone main.py for PXXL.app / Railway / Render deployment.
Uses absolute imports so it works when run directly with `python main.py`.
"""
from __future__ import annotations

import os
import sys
import time
import json
import threading
import traceback
import subprocess
import re
import random
import secrets
import shutil
from pathlib import Path
from collections import deque
from typing import Any, Dict, List, Optional, Tuple

# ══════════════════════════════════════════════════════════════
# AUTO-INSTALL MISSING PACKAGES
# ══════════════════════════════════════════════════════════════
_REQUIRED_PKGS = [
    ("telebot", "pyTelegramBotAPI"),
    ("requests", "requests"),
    ("cryptography.fernet", "cryptography"),
    ("flask", "flask"),
    ("apscheduler", "APScheduler"),
    ("PIL", "Pillow"),
]


def _auto_install_missing():
    import importlib
    missing = []
    for mod, pip_name in _REQUIRED_PKGS:
        try:
            importlib.import_module(mod)
        except ImportError:
            missing.append(pip_name)
    if not missing:
        return
    print(f"[setup] installing: {', '.join(missing)}")
    strategies = [
        [sys.executable, "-m", "pip", "install", "--upgrade", "--quiet", *missing],
        [sys.executable, "-m", "pip", "install", "--upgrade", "--quiet", "--break-system-packages", *missing],
        [sys.executable, "-m", "pip", "install", "--user", "--upgrade", "--quiet", *missing],
        [sys.executable, "-m", "pip", "install", "--user", "--upgrade", "--quiet", "--break-system-packages", *missing],
    ]
    for cmd in strategies:
        try:
            subprocess.run(cmd, check=True)
            print("[setup] install ok")
            return
        except Exception:
            continue
    print(f"[setup] could not install: {missing} — continuing anyway")


_auto_install_missing()

# Third-party imports
import telebot
from telebot import types
from telebot.apihelper import ApiTelegramException
import requests
from flask import Flask, jsonify
from cryptography.fernet import Fernet, InvalidToken

# ══════════════════════════════════════════════════════════════
# Add current directory to path so we can import yami_hosting
# ══════════════════════════════════════════════════════════════
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

# Now import from the package
from yami_hosting.config import (
    TOKEN, OWNER_ID, BRAND, BRAND_VER, BRAND_TAG, FOOTER,
    SUPPORT_USR, UPDATE_CH, KEEPALIVE_PORT, ANNOUNCE_CHANNEL,
    DIRS, DB_FILE, SETTINGS_FILE, AUDIT_FILE, GCASH_QR_PATH,
    PLAN_LIMITS, PAYMENT_METHODS, FREE_HOSTING_PLATFORMS,
    SECRET_ENV_NAMES, REQUIRED_GROUPS,
    ENTRY_PY, ENTRY_NODE, LOG_RING, MAX_LOG_SEND, MAX_UPLOAD_BYTES,
    G, SKIP_DIR_PARTS,
)
from yami_hosting.utils import (
    esc, sc, fmt_bytes, fmt_dur, fmt_ts, now_utc, ts_iso,
    safe_name, rand_token, safe_path_join, rmrf, audit,
    bullet, divider, progress_bar,
    db_load, db_load_ro, db_save,
    get_setting, set_setting,
    is_owner, is_admin, admin_role, admin_can,
    mask_number, mask_email, mask_string,
)
from yami_hosting.crypto_db import (
    KEYRING, encrypt_file, decrypt_with, write_encrypted, read_encrypted,
    store_uploaded_file, materialize_bot_files, encrypted_dump_for_download,
)
from yami_hosting.runtime.detectors import detect_entry, detect_runtime, get_runtime_command, get_runtime_icon
from yami_hosting.runtime.runner import (
    RUNNING, TUNNELS, START_TIME, safe_env,
    start_child, stop_child, restart_child, child_status, install_deps,
    _start_tunnel, _stop_tunnel, _ensure_cloudflared,
)
from yami_hosting.security import combined_scan as _run_security_scan

# ══════════════════════════════════════════════════════════════
# BOT INIT
# ══════════════════════════════════════════════════════════════
if not TOKEN:
    sys.exit("Set BOT_TOKEN env var and redeploy.")

bot = telebot.TeleBot(TOKEN, parse_mode="HTML", threaded=True, num_threads=8)

# ══════════════════════════════════════════════════════════════
# INLINE KEYBOARD BUTTON WITH STYLE SUPPORT (API 9.4)
# ══════════════════════════════════════════════════════════════
class Btn(types.InlineKeyboardButton):
    def __init__(self, *args, style: str = "", **kwargs):
        super().__init__(*args, **kwargs)
        if style:
            self.style = style

    def to_dict(self):
        d = super().to_dict()
        if getattr(self, "style", ""):
            d["style"] = self.style
        return d


# ══════════════════════════════════════════════════════════════
# RATE LIMITER
# ══════════════════════════════════════════════════════════════
class RateLimiter:
    def __init__(self, max_actions: int = 40, window_s: float = 60):
        self.max = max_actions
        self.window = window_s
        self._bucket: Dict[int, deque] = {}
        self._lock = threading.Lock()

    def allow(self, uid: int) -> bool:
        now = time.time()
        with self._lock:
            q = self._bucket.get(uid)
            if q is None:
                q = deque()
                self._bucket[uid] = q
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.max:
                return False
            q.append(now)
            return True


RATE = RateLimiter(40, 60)
UPLOAD_RATE = RateLimiter(8, 300)


def maybe_auto_ban(uid: int, reason: str):
    d = db_load()
    rv = d.get("rate_violations", {})
    rv[str(uid)] = int(rv.get(str(uid), 0)) + 1
    d["rate_violations"] = rv
    db_save(d)
    if rv[str(uid)] >= 5:
        u = d["users"].get(str(uid))
        if u and not u.get("banned"):
            u["banned"] = True
            u["ban_reason"] = f"auto: {reason}"
            db_save(d)
            audit(0, "auto_ban", f"uid={uid} reason={reason}")
            notify_owner(f"<b>{G['warn']} Auto-Ban</b>\nUser <code>{uid}</code> ({esc(reason)}).")


# ══════════════════════════════════════════════════════════════
# UI STYLE WRAPPER (blockquote + bold)
# ══════════════════════════════════════════════════════════════
_QUOTE_OPEN = "<blockquote><b>"
_QUOTE_CLOSE = "</b></blockquote>"


def _is_html_mode(pm) -> bool:
    if pm is None:
        return True
    try:
        return str(pm).strip().lower() == "html"
    except Exception:
        return False


def _wrap_quote_bold(text):
    if text is None:
        return text
    s = str(text)
    if not s.strip():
        return s
    if s.startswith(_QUOTE_OPEN):
        return s
    return f"{_QUOTE_OPEN}{s}{_QUOTE_CLOSE}"


def _patch_bot_styling(b):
    orig_send = b.send_message
    orig_reply = b.reply_to
    orig_edit_text = b.edit_message_text
    orig_edit_caption = b.edit_message_caption
    orig_send_photo = b.send_photo
    orig_send_doc = b.send_document

    def send_message(chat_id, text, *args, **kwargs):
        if _is_html_mode(kwargs.get("parse_mode")):
            text = _wrap_quote_bold(text)
        return orig_send(chat_id, text, *args, **kwargs)

    def reply_to(message, text, *args, **kwargs):
        if _is_html_mode(kwargs.get("parse_mode")):
            text = _wrap_quote_bold(text)
        return orig_reply(message, text, *args, **kwargs)

    def edit_message_text(text, *args, **kwargs):
        if _is_html_mode(kwargs.get("parse_mode")):
            text = _wrap_quote_bold(text)
        return orig_edit_text(text, *args, **kwargs)

    def edit_message_caption(*args, **kwargs):
        if _is_html_mode(kwargs.get("parse_mode")):
            if "caption" in kwargs:
                kwargs["caption"] = _wrap_quote_bold(kwargs.get("caption"))
        return orig_edit_caption(*args, **kwargs)

    def send_photo(chat_id, photo, *args, **kwargs):
        if _is_html_mode(kwargs.get("parse_mode")) and kwargs.get("caption"):
            kwargs["caption"] = _wrap_quote_bold(kwargs["caption"])
        return orig_send_photo(chat_id, photo, *args, **kwargs)

    def send_document(chat_id, document, *args, **kwargs):
        if _is_html_mode(kwargs.get("parse_mode")) and kwargs.get("caption"):
            kwargs["caption"] = _wrap_quote_bold(kwargs["caption"])
        return orig_send_doc(chat_id, document, *args, **kwargs)

    b.send_message = send_message
    b.reply_to = reply_to
    b.edit_message_text = edit_message_text
    b.edit_message_caption = edit_message_caption
    b.send_photo = send_photo
    b.send_document = send_document


_patch_bot_styling(bot)

# ══════════════════════════════════════════════════════════════
# GLOBAL STATE
# ══════════════════════════════════════════════════════════════
USER_STATES: Dict[int, Dict[str, Any]] = {}
VERIFY_STATES: Dict[int, Dict[str, Any]] = {}
_verify_lock = threading.Lock()

# ══════════════════════════════════════════════════════════════
# FLASK KEEP-ALIVE
# ══════════════════════════════════════════════════════════════
_ka = Flask(__name__)


@_ka.route("/")
def _ka_root():
    return jsonify({
        "ok": True, "brand": BRAND_TAG,
        "uptime_ms": int(time.time() * 1000) - int(START_TIME * 1000),
        "running_bots": len(RUNNING),
        "version": "4.0.0",
    })


@_ka.route("/health")
def _ka_health():
    return jsonify({"status": "alive"})


def _start_keepalive():
    def _run():
        try:
            _ka.run(host="0.0.0.0", port=KEEPALIVE_PORT, debug=False, use_reloader=False)
        except Exception as e:
            print(f"[keepalive] {e}")

    threading.Thread(target=_run, daemon=True).start()


# ══════════════════════════════════════════════════════════════
# PHOTO BUILDER
# ══════════════════════════════════════════════════════════════
_PHOTO_SPECS: Dict[str, Tuple[str, str, str]] = {
    "main": ("Mᴀɪɴ Mᴇɴᴜ", "#1E1B4B", "Cʜᴏᴏsᴇ Aɴ Oᴘᴛɪᴏɴ"),
    "dashboard": ("Dᴀsʜʙᴏᴀʀᴅ", "#0F766E", "Lɪᴠᴇ Sᴛᴀᴛs"),
    "bots": ("Yᴏᴜʀ Bᴏᴛs", "#0E7490", "Mᴀɴᴀɢᴇ & Dᴇᴘʟᴏʏ"),
    "upload": ("Uᴘʟᴏᴀᴅ & Dᴇᴘʟᴏʏ", "#4338CA", "Sᴇɴᴅ Yᴏᴜʀ Fɪʟᴇs"),
    "plans": ("Pʟᴀɴs", "#B45309", "Pɪᴄᴋ A Tɪᴇʀ"),
    "buy": ("Bᴜʏ Pʟᴀɴ", "#065F46", "Cʜᴇᴄᴋᴏᴜᴛ"),
    "pay": ("Pᴀʏᴍᴇɴᴛ", "#0E7490", "Sᴇɴᴅ Pʀᴏᴏғ"),
    "profile": ("Pʀᴏғɪʟᴇ", "#1E3A8A", "Yᴏᴜʀ Aᴄᴄᴏᴜɴᴛ"),
    "wallet": ("Wᴀʟʟᴇᴛ", "#047857", "Tᴏᴘ-Uᴘ & Bᴀʟᴀɴᴄᴇ"),
    "referral": ("Rᴇғᴇʀʀᴀʟ", "#9333EA", "Iɴᴠɪᴛᴇ & Eᴀʀɴ"),
    "help": ("Hᴇʟᴘ", "#334155", "Hᴏᴡ Iᴛ Wᴏʀᴋs"),
    "support": ("Sᴜᴘᴘᴏʀᴛ", "#0F766E", "Tᴀʟᴋ Tᴏ Us"),
    "ticket": ("Tɪᴄᴋᴇᴛs", "#0F766E", "Oᴘᴇɴ A Tɪᴄᴋᴇᴛ"),
    "admin": ("Aᴅᴍɪɴ Pᴀɴᴇʟ", "#7C2D12", "Rᴇsᴛʀɪᴄᴛᴇᴅ"),
    "stats": ("Sᴛᴀᴛs", "#14532D", "Lɪᴠᴇ Nᴜᴍʙᴇʀs"),
    "github": ("GɪᴛHᴜʙ", "#24292E", "Sʏɴᴄ & Rᴇsᴛᴏʀᴇ"),
    "security": ("Sᴇᴄᴜʀɪᴛʏ", "#991B1B", "Aᴜᴅɪᴛ & Kᴇʏs"),
    "bot": ("Bᴏᴛ Cᴏɴᴛʀᴏʟ", "#1F2937", "Sᴛᴀʀᴛ • Sᴛᴏᴘ • Lᴏɢs"),
    "freehost": ("Fʀᴇᴇ Hᴏsᴛɪɴɢ", "#065F46", "Dᴇᴘʟᴏʏ Fᴏʀ Fʀᴇᴇ"),
    "gcash": ("GCᴀsʜ", "#0066CC", "Sᴄᴀɴ & Pᴀʏ"),
    "trial": ("Fʀᴇᴇ Tʀɪᴀʟ", "#A21CAF", "Tʀʏ Pʀᴇᴍɪᴜᴍ"),
    "coupon": ("Cᴏᴜᴘᴏɴ", "#B91C1C", "Rᴇᴅᴇᴇᴍ Cᴏᴅᴇ"),
    "deploy": ("Dᴇᴘʟᴏʏ", "#059669", "GɪᴛHᴜʙ • Zɪᴘ • Cʟɪ"),
}
PHOTOS: Dict[str, str] = {}
_PHOTO_FILE_IDS: Dict[str, str] = {}


def _build_local_photos():
    for k in _PHOTO_SPECS:
        PHOTOS.setdefault(k, "")
    try:
        from PIL import Image, ImageDraw, ImageFont
    except Exception:
        return
    out_dir = DIRS["photos"]
    out_dir.mkdir(parents=True, exist_ok=True)
    font_paths = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
    ]
    font_path = None
    for fp in font_paths:
        if Path(fp).exists():
            font_path = fp
            break

    def _hex(c):
        c = c.lstrip("#")
        return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)

    for key, (text, color, sub) in _PHOTO_SPECS.items():
        custom_out = out_dir / f"custom_{key}.png"
        if custom_out.exists() and custom_out.stat().st_size > 1024:
            PHOTOS[key] = str(custom_out)
            continue
        out = out_dir / f"{key}.png"
        if out.exists() and out.stat().st_size > 1024:
            PHOTOS[key] = str(out)
            continue
        try:
            r, g, b = _hex(color)
            img = Image.new("RGB", (900, 460), (r, g, b))
            d = ImageDraw.Draw(img)
            for y in range(460):
                t = y / 459.0
                k = 1.0 - 0.55 * t
                d.line([(0, y), (900, y)], fill=(int(r * k), int(g * k), int(b * k)))
            d.rectangle([(0, 430), (900, 460)], fill=(255, 255, 255))
            d.rectangle([(0, 432), (900, 458)], fill=(r, g, b))
            big = ImageFont.truetype(font_path, 78) if font_path else ImageFont.load_default()
            small = ImageFont.truetype(font_path, 28) if font_path else ImageFont.load_default()

            def _wh(s, f):
                try:
                    bb = d.textbbox((0, 0), s, font=f)
                    return bb[2] - bb[0], bb[3] - bb[1]
                except Exception:
                    return d.textsize(s, font=f)

            tw, th = _wh(text, big)
            sw, sh = _wh(sub, small)
            cy = (460 - (th + sh + 18)) // 2
            d.text(((900 - tw) // 2 + 3, cy + 3), text, fill=(0, 0, 0), font=big)
            d.text(((900 - tw) // 2, cy), text, fill=(255, 255, 255), font=big)
            d.text(((900 - sw) // 2, cy + th + 18), sub, fill=(230, 230, 230), font=small)
            img.save(out, "PNG", optimize=True)
            PHOTOS[key] = str(out)
        except Exception:
            pass


_build_local_photos()


def _resolve_photo(ref: str):
    fid = _PHOTO_FILE_IDS.get(ref)
    if fid:
        return fid
    path = PHOTOS.get(ref, "")
    if path and Path(path).exists():
        try:
            return open(path, "rb")
        except Exception:
            pass
    return path


def _remember_file_id(ref: str, msg):
    try:
        if msg.photo and len(msg.photo) > 0:
            _PHOTO_FILE_IDS[ref] = msg.photo[-1].file_id
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════
# UI HELPERS
# ══════════════════════════════════════════════════════════════
_TAG_RE = re.compile(r"<(/?)([a-zA-Z][a-zA-Z0-9]*)(\s[^>]*)?>")


def _html_safe_truncate(s: str, limit: int = 1024) -> str:
    if len(s) <= limit:
        return s
    cut = s[:limit - 1]
    last_lt = cut.rfind("<")
    last_gt = cut.rfind(">")
    if last_lt > last_gt:
        cut = cut[:last_lt]
    stack: List[str] = []
    for m in _TAG_RE.finditer(cut):
        closing, name = m.group(1), m.group(2).lower()
        if closing:
            if stack and stack[-1] == name:
                stack.pop()
        else:
            stack.append(name)
    closes = "".join(f"</{t}>" for t in reversed(stack))
    return cut + "…" + closes


def _log_err(where: str, exc: BaseException):
    try:
        print(f"[ui:{where}] {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
    except Exception:
        pass


_LOADING_STOPS: Dict[Tuple[int, int], threading.Event] = {}
_LOADING_LOCK = threading.Lock()


def _cancel_loading(chat_id: int, message_id: int):
    with _LOADING_LOCK:
        evt = _LOADING_STOPS.pop((chat_id, message_id), None)
    if evt:
        evt.set()


def show_menu(chat_id: int, photo_ref: str, caption: str,
              kb: types.InlineKeyboardMarkup,
              call: Optional[types.CallbackQuery] = None):
    cap = _html_safe_truncate(caption, 1024)
    if call and call.message:
        _cancel_loading(call.message.chat.id, call.message.message_id)

    if call and call.message and call.message.content_type == "photo":
        msg = call.message
        cached_fid = _PHOTO_FILE_IDS.get(photo_ref)
        media_ref = cached_fid if cached_fid else _resolve_photo(photo_ref)
        try:
            bot.edit_message_media(
                media=types.InputMediaPhoto(media_ref, caption=cap, parse_mode="HTML"),
                chat_id=chat_id, message_id=msg.message_id, reply_markup=kb)
            return
        except ApiTelegramException as e:
            if "message is not modified" in str(e).lower():
                return
            _log_err("edit_media", e)
        finally:
            try:
                if hasattr(media_ref, "close"):
                    media_ref.close()
            except Exception:
                pass
        try:
            bot.edit_message_caption(cap, chat_id=chat_id, message_id=msg.message_id,
                                     reply_markup=kb, parse_mode="HTML")
            return
        except ApiTelegramException as e:
            if "message is not modified" in str(e).lower():
                return
        except Exception:
            pass

    new_msg_id = None
    try:
        m = bot.send_photo(chat_id, _resolve_photo(photo_ref), caption=cap,
                           parse_mode="HTML", reply_markup=kb)
        new_msg_id = m.message_id
        _remember_file_id(photo_ref, m)
    except Exception:
        pass
    if new_msg_id is None:
        try:
            m = bot.send_message(chat_id, cap, parse_mode="HTML", reply_markup=kb,
                                 disable_web_page_preview=True)
            new_msg_id = m.message_id
        except Exception:
            pass
    if new_msg_id is not None and call and call.message:
        try:
            bot.delete_message(chat_id, call.message.message_id)
        except Exception:
            pass


def show_text(chat_id: int, text: str, kb: Optional[types.InlineKeyboardMarkup] = None,
              call: Optional[types.CallbackQuery] = None):
    text = _html_safe_truncate(text, 4096)
    if call and call.message:
        _cancel_loading(call.message.chat.id, call.message.message_id)
    if call and call.message and call.message.content_type == "text":
        try:
            bot.edit_message_text(text, chat_id=chat_id, message_id=call.message.message_id,
                                  reply_markup=kb, parse_mode="HTML", disable_web_page_preview=True)
            return
        except ApiTelegramException as e:
            if "message is not modified" in str(e).lower():
                return
        except Exception:
            pass
    new_msg_id = None
    try:
        m = bot.send_message(chat_id, text, parse_mode="HTML", reply_markup=kb,
                             disable_web_page_preview=True)
        new_msg_id = m.message_id
    except Exception:
        pass
    if new_msg_id is not None and call and call.message and call.message.content_type != "text":
        try:
            bot.delete_message(chat_id, call.message.message_id)
        except Exception:
            pass


def ack(call: types.CallbackQuery, text: str = ""):
    try:
        bot.answer_callback_query(call.id, text=text)
    except Exception:
        pass


def loading(call: types.CallbackQuery, label: str = "Loading"):
    if not (call and call.message):
        try:
            bot.answer_callback_query(call.id, text=f"⏳ {label}…")
        except Exception:
            pass
        return
    chat_id = call.message.chat.id
    msg_id = call.message.message_id
    is_photo = call.message.content_type == "photo"
    label_safe = esc(label)
    _cancel_loading(chat_id, msg_id)
    try:
        bot.answer_callback_query(call.id, text=f"↻ {label}…")
    except Exception:
        pass

    def _render(pct: int) -> bool:
        body = (f"<b>↻ {label_safe}…</b>\n{G['div']}\n"
                f"<code>{progress_bar(pct)}</code>\n<i>{sc('Please wait')}</i>{FOOTER}")
        try:
            if is_photo:
                bot.edit_message_caption(body, chat_id=chat_id, message_id=msg_id, parse_mode="HTML")
            else:
                bot.edit_message_text(body, chat_id=chat_id, message_id=msg_id,
                                      parse_mode="HTML", disable_web_page_preview=True)
            return True
        except ApiTelegramException as e:
            s = str(e).lower()
            if "message is not modified" in s:
                return True
            if "message to edit not found" in s:
                return False
            return True
        except Exception:
            return True

    _render(15)
    stop_evt = threading.Event()
    with _LOADING_LOCK:
        _LOADING_STOPS[(chat_id, msg_id)] = stop_evt

    def _animate():
        for pct in [25, 38, 52, 65, 78, 88, 92]:
            if stop_evt.wait(0.7):
                return
            if not _render(pct):
                return
        while not stop_evt.wait(1.5):
            pass

    threading.Thread(target=_animate, daemon=True).start()


# ══════════════════════════════════════════════════════════════
# NOTIFICATIONS
# ══════════════════════════════════════════════════════════════
def notify_owner(html: str):
    if not OWNER_ID:
        return
    try:
        bot.send_message(OWNER_ID, html, parse_mode="HTML")
    except Exception as e:
        print(f"[notify] {e}")


# ══════════════════════════════════════════════════════════════
# USER MANAGEMENT
# ══════════════════════════════════════════════════════════════
def get_or_create_user(u: types.User, ref: Optional[int] = None):
    d = db_load()
    key = str(u.id)
    is_new = key not in d["users"]
    if is_new:
        d["users"][key] = {
            "_id": u.id, "name": u.first_name or "", "username": u.username or "",
            "plan": "free", "plan_expires": None,
            "joined": ts_iso(), "last_seen": ts_iso(),
            "banned": False, "ban_reason": "",
            "wallet": 0, "kyc": False,
            "verified": False, "verified_at": None,
            "ref_by": ref if ref and ref != u.id else None,
            "ref_count": 0, "ref_credit": 0, "trial_used": False,
            "bot_slots_bonus": 0,
            "stats": {"commands": 0, "bots_uploaded": 0, "logins": 1},
        }
        db_save(d)
        if ref and ref != u.id and str(ref) in d["users"]:
            d["users"][str(ref)]["ref_count"] = int(d["users"][str(ref)].get("ref_count", 0)) + 1
            d["users"][str(ref)]["ref_credit"] = int(d["users"][str(ref)].get("ref_credit", 0)) + 1
            d["users"][str(ref)]["bot_slots_bonus"] = int(d["users"][str(ref)].get("bot_slots_bonus", 0)) + 1
            db_save(d)
            try:
                bot.send_message(ref, f"<b>{G['plus']} Referral Bonus!</b>\n"
                                 f"{bullet('From', '@' + (u.username or u.first_name))}\n"
                                 f"{bullet('Bonus', '+1 bot slot, +1 credit')}")
            except Exception:
                pass
        notify_owner(f"<b>{G['plus']} New User</b>\n"
                     f"{bullet('Name', u.first_name)}\n"
                     f"{bullet('Username', '@' + (u.username or '—'))}\n"
                     f"{bullet('ID', u.id)}")
    else:
        d["users"][key]["last_seen"] = ts_iso()
        d["users"][key]["stats"]["logins"] = int(d["users"][key]["stats"].get("logins", 0)) + 1
        db_save(d)
    return d["users"][key], is_new


def list_user_bots(uid: int) -> List[Dict[str, Any]]:
    import copy
    return [copy.deepcopy(b) for b in db_load_ro()["bots"].values() if b.get("owner") == uid]


def find_bot(bot_id: str) -> Optional[Dict[str, Any]]:
    import copy
    b = db_load_ro()["bots"].get(bot_id)
    return copy.deepcopy(b) if b else None


def save_bot(doc: Dict[str, Any]):
    d = db_load()
    d["bots"][doc["_id"]] = doc
    db_save(d)
    return doc


def delete_bot_doc(bot_id: str):
    d = db_load()
    d["bots"].pop(bot_id, None)
    db_save(d)


def user_max_bots(u: Dict[str, Any]) -> int:
    plan = u.get("plan", "free")
    default = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])["max_bots"]
    base = int(get_setting(f"plan_max_bots_{plan}", default))
    return base + int(u.get("bot_slots_bonus", 0))


def user_plan_active(u: Dict[str, Any]) -> bool:
    if u.get("plan") == "free":
        return True
    exp = u.get("plan_expires")
    if not exp:
        return False
    try:
        from datetime import datetime
        return datetime.fromisoformat(str(exp).replace("Z", "+00:00")) > now_utc()
    except Exception:
        return False


def grant_plan(uid: int, plan: str, days: Optional[int] = None) -> bool:
    d = db_load()
    key = str(uid)
    if key not in d["users"] or plan not in PLAN_LIMITS:
        return False
    u = d["users"][key]
    pl = PLAN_LIMITS[plan]
    days = days if days is not None else pl["days"]
    if plan == "free":
        u["plan"] = "free"
        u["plan_expires"] = None
    else:
        u["plan"] = plan
        try:
            from datetime import datetime, timedelta
            cur_exp = datetime.fromisoformat(str(u.get("plan_expires") or "").replace("Z", "+00:00"))
        except Exception:
            cur_exp = now_utc()
        if cur_exp < now_utc() or u.get("plan") != plan:
            cur_exp = now_utc()
        u["plan_expires"] = (cur_exp + timedelta(days=days)).isoformat()
        u["last_expiry_warn"] = -1
    db_save(d)
    try:
        bot.send_message(uid, f"<b>{G['ok']} Plan Activated</b>\n\n"
                         + bullet('Plan', pl['name']) + "\n"
                         + bullet('Bots', str(pl['max_bots'])) + "\n"
                         + bullet('RAM', str(pl['ram']) + ' MB') + "\n"
                         + bullet('Until', fmt_ts(u.get('plan_expires')) if u.get('plan_expires') else 'Lifetime')
                         + FOOTER)
    except Exception:
        pass
    return True


def downgrade_expired_users():
    d = db_load()
    changed = False
    for uid, u in d["users"].items():
        if u.get("plan") == "free":
            continue
        if not user_plan_active(u):
            u["plan"] = "free"
            u["plan_expires"] = None
            changed = True
            try:
                bot.send_message(int(uid), f"<b>{G['warn']} Plan Expired</b>\n\nDowngraded to Free. Renew anytime.{FOOTER}")
            except Exception:
                pass
    if changed:
        db_save(d)


# ══════════════════════════════════════════════════════════════
# VERIFICATION
# ══════════════════════════════════════════════════════════════
def _is_verified(uid: int) -> bool:
    if uid == OWNER_ID and OWNER_ID > 0:
        return True
    u = db_load_ro()["users"].get(str(uid)) or {}
    return bool(u.get("verified"))


def _mark_verified(uid: int):
    d = db_load()
    if str(uid) in d["users"]:
        d["users"][str(uid)]["verified"] = True
        d["users"][str(uid)]["verified_at"] = ts_iso()
        db_save(d)


_CAPTCHA_POOL = "ABCDEFGHJKLMNPRSTUVWXYZ23456789"


def _gen_captcha_image():
    try:
        from PIL import Image, ImageDraw, ImageFont
    except Exception:
        return None, random.choice(_CAPTCHA_POOL), list(random.sample(_CAPTCHA_POOL, 4))

    text = "".join(random.choice(_CAPTCHA_POOL) for _ in range(4))
    correct_idx = random.randrange(4)
    correct_ch = text[correct_idx]
    options = list(set(text))
    while len(options) < 6:
        c = random.choice(_CAPTCHA_POOL)
        if c not in options:
            options.append(c)
    random.shuffle(options)
    W, H = 720, 320
    bg = (15, 23, 42)
    img = Image.new("RGB", (W, H), bg)
    draw = ImageDraw.Draw(img)
    for _ in range(8):
        x1, y1 = random.randint(-50, W), random.randint(-50, H)
        draw.line([(x1, y1), (x1 + random.randint(150, 400), y1 + random.randint(-80, 80))],
                  fill=(40, 50, 70), width=random.randint(2, 4))
    fp = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
    font = ImageFont.truetype(fp, 140) if Path(fp).exists() else ImageFont.load_default()
    palette = [(250, 204, 21), (96, 165, 250), (236, 72, 153), (52, 211, 153)]
    char_centers = []
    slot_w = W // 4
    for i, ch in enumerate(text):
        tile = Image.new("RGBA", (200, 240), (0, 0, 0, 0))
        td = ImageDraw.Draw(tile)
        col = random.choice(palette)
        td.text((30, 30), ch, font=font, fill=col + (255,))
        tile = tile.rotate(random.randint(-22, 22), resample=Image.BILINEAR)
        cx = slot_w * i + slot_w // 2 - 100 + random.randint(-10, 10)
        cy = (H - 240) // 2 + random.randint(-15, 15)
        img.paste(tile, (cx, cy), tile)
        char_centers.append((cx + 100, cy + 120))
    cx, cy = char_centers[correct_idx]
    r = 90
    for dr in range(0, 5):
        draw.ellipse([cx - r - dr, cy - r - dr, cx + r + dr, cy + r + dr], outline=(239, 68, 68))
    import io
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue(), correct_ch, options


def _send_captcha(chat_id: int, uid: int):
    png, correct, opts = _gen_captcha_image()
    kb = types.InlineKeyboardMarkup()
    btns = [Btn(c, callback_data=f"verify_{c}") for c in opts]
    for i in range(0, len(btns), 3):
        kb.row(*btns[i:i + 3])
    kb.row(Btn(f"{G.get('refresh', '↻')} New captcha", callback_data="verify_new"))
    cap = (f"<b>{G['shield']} Human verification</b>\n{G['div']}\n"
           f"One character has a <b>red circle</b>.\n"
           f"<b>Tap that exact character below</b>.\n{G['div']}\n{bullet('Tries', '3')}{FOOTER}")
    sent_id = None
    try:
        if png is not None:
            m = bot.send_photo(chat_id, png, caption=cap, parse_mode="HTML", reply_markup=kb)
        else:
            m = bot.send_message(chat_id, f"{cap}\n\nTap: <b><code>{correct}</code></b>",
                                 parse_mode="HTML", reply_markup=kb)
        sent_id = m.message_id
    except Exception:
        return
    with _verify_lock:
        VERIFY_STATES[uid] = {
            "answer": correct, "options": opts, "msg_id": sent_id,
            "chat_id": chat_id, "tries": 0, "regens": 0, "ts": time.time(),
        }


def require_verified(chat_id: int, uid: int) -> bool:
    if _is_verified(uid):
        return True
    with _verify_lock:
        st = VERIFY_STATES.get(uid)
        now = time.time()
        if st and (st.get("msg_id") or now - st.get("ts", 0) < 6):
            return False
        VERIFY_STATES[uid] = {"answer": "", "options": [], "msg_id": None,
                              "chat_id": chat_id, "tries": 0, "regens": 0,
                              "ts": now, "starting": True}
    threading.Thread(target=_send_captcha, args=(chat_id, uid), daemon=True).start()
    return False


def _check_group_membership(uid: int) -> List[Dict]:
    not_joined = []
    for grp in REQUIRED_GROUPS:
        try:
            member = bot.get_chat_member(grp["id"], uid)
            if member.status in ("left", "kicked", "banned"):
                not_joined.append(grp)
        except Exception:
            not_joined.append(grp)
    return not_joined


def _send_join_verification(chat_id: int, uid: int, not_joined: List[Dict]):
    kb = types.InlineKeyboardMarkup(row_width=2)
    for grp in not_joined:
        kb.add(Btn(f"{G['fwd']} Join {grp['name']}", url=grp["link"]))
    kb.add(Btn(f"{G['ok']} Verified", callback_data="group_verify_check"))
    cap = (f"<b>{G['shield']} Group Join Required</b>\n{G['div_eq']}\n"
           f"You must join these groups:\n{G['div']}\n"
           + "\n".join(f"{G['bullet']} <a href='{g['link']}'>{esc(g['name'])}</a>" for g in not_joined)
           + f"\n{G['div']}\nAfter joining, tap <b>Verified</b> below.{FOOTER}")
    try:
        bot.send_message(chat_id, cap, parse_mode="HTML", reply_markup=kb, disable_web_page_preview=True)
    except Exception:
        pass


def require_group_membership(chat_id: int, uid: int) -> bool:
    if uid == OWNER_ID and OWNER_ID > 0:
        return True
    if is_admin(uid):
        return True
    not_joined = _check_group_membership(uid)
    if not not_joined:
        return True
    _send_join_verification(chat_id, uid, not_joined)
    return False


def maintenance_block(uid: int) -> bool:
    return bool(get_setting("maintenance", False) and not is_admin(uid))


def banned_block(call_or_msg: Any) -> bool:
    uid = call_or_msg.from_user.id
    u = db_load_ro()["users"].get(str(uid))
    if u and u.get("banned"):
        try:
            chat = call_or_msg.message.chat.id if hasattr(call_or_msg, "message") else call_or_msg.chat.id
            bot.send_message(chat, f"<b>{G['no']} You are banned</b>\n"
                             f"{bullet('Reason', u.get('ban_reason') or '—')}\nContact {SUPPORT_USR}.")
        except Exception:
            pass
        return True
    return False


def admin_only_call(call: types.CallbackQuery, action: str = "view_stats") -> bool:
    if not is_admin(call.from_user.id):
        ack(call, "Admin only."); return False
    if not admin_can(call.from_user.id, action):
        ack(call, "No permission."); return False
    return True


# ══════════════════════════════════════════════════════════════
# KEYBOARDS
# ══════════════════════════════════════════════════════════════
def back_main_kb():
    return types.InlineKeyboardMarkup().add(
        Btn(f"{G['back']} Mᴀɪɴ Mᴇɴᴜ", callback_data="menu_main", style="danger"))


def back_admin_kb():
    return types.InlineKeyboardMarkup().add(
        Btn(f"{G['back']} Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))


def back_kb(target: str, label: str = "Back"):
    return types.InlineKeyboardMarkup().add(
        Btn(f"{G['back']}  {sc(label)}", callback_data=target, style="danger"))


def main_menu_kb(admin: bool = False):
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(Btn("  Mʏ Bᴏᴛꜱ", callback_data="menu_bots", style="primary"),
           Btn(" Uᴘʟᴏᴀᴅ Bᴏᴛ", callback_data="menu_upload", style="primary"))
    kb.add(Btn("Pʟᴀɴꜱ", callback_data="menu_plans", style="primary"),
           Btn(" Bᴜʏ Pʟᴀɴ", callback_data="menu_buy", style="primary"))
    kb.add(Btn("Rᴇꜰᴇʀʀᴀʟ", callback_data="menu_referral", style="primary"),
           Btn("Pʀᴏꜰɪʟᴇ", callback_data="menu_profile", style="primary"))
    kb.add(Btn(" Wᴀʟʟᴇᴛ", callback_data="menu_wallet", style="primary"),
           Btn("Tɪᴄᴋᴇᴛꜱ", callback_data="menu_tickets", style="primary"))
    kb.add(Btn("🆕 Fʀᴇᴇ Hᴏsᴛ", callback_data="menu_freehost", style="primary"),
           Btn(" Fʀᴇᴇ Tʀɪᴀʟ", callback_data="menu_trial", style="primary"))
    kb.add(Btn(" Cᴏᴜᴘᴏɴ", callback_data="menu_coupon", style="primary"),
           Btn("💳 GCᴀsʜ", callback_data="menu_gcash", style="success"))
    kb.add(Btn("📊 Dᴀsʜʙᴏᴀʀᴅ", callback_data="menu_dashboard", style="primary"),
           Btn("🚀 Dᴇᴘʟᴏʏ", callback_data="menu_deploy", style="success"))
    kb.add(Btn("Hᴇʟᴘ", callback_data="menu_help", style="primary"),
           Btn("Sᴜᴘᴘᴏʀᴛ", callback_data="menu_support", style="primary"))
    kb.add(Btn(" Mʏ Sᴛᴀᴛꜱ", callback_data="menu_stats", style="primary"))
    if admin:
        kb.add(Btn("Aᴅᴍɪɴ Pᴀɴᴇʟ", callback_data="menu_admin", style="danger"))
    return kb


def plans_kb():
    kb = types.InlineKeyboardMarkup()
    for k, v in PLAN_LIMITS.items():
        price = "Free" if v["price"] == 0 else f"{v['price']}৳"
        style = "success" if v["price"] == 0 else "primary"
        kb.add(Btn(f"{G['star']}  {sc(v['name'])}  {G['bullet']}  {price}",
                   callback_data=f"plan_view_{k}", style=style))
    kb.add(Btn(f"{G['back']}  Mᴀɪɴ Mᴇɴᴜ", callback_data="menu_main", style="danger"))
    return kb


def payments_kb(plan: Optional[str] = None):
    kb = types.InlineKeyboardMarkup(row_width=2)
    suffix = f"_{plan}" if plan else ""
    for k, v in PAYMENT_METHODS.items():
        if v.get("enabled", True):
            kb.add(Btn(f"{v['tag']}  {sc(v['name'])}", callback_data=f"pay_{k}{suffix}", style="success"))
    kb.add(Btn(f"{G['back']}  Pʟᴀɴꜱ", callback_data="menu_plans", style="primary"))
    return kb


def admin_kb():
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(Btn(f"{G['graph']}  Sᴛᴀᴛꜱ", callback_data="adm_stats", style="primary"),
           Btn(f"{G['users']}  Uꜱᴇʀꜱ", callback_data="adm_users", style="primary"))
    kb.add(Btn(f"{G['diamond']}  Aʟʟ Bᴏᴛꜱ", callback_data="adm_allbots", style="primary"),
           Btn(f"{G['wallet']}  Pᴀʏᴍᴇɴᴛꜱ", callback_data="adm_payments", style="success"))
    kb.add(Btn(f"{G['broadcast']}  Bʀᴏᴀᴅᴄᴀꜱᴛ", callback_data="adm_broadcast", style="success"),
           Btn(f"{G['no']}  Bᴀɴ / Uɴʙᴀɴ", callback_data="adm_ban", style="danger"))
    kb.add(Btn(f"{G['plus']}  Gɪᴠᴇ Pʟᴀɴ", callback_data="adm_giveplan", style="success"),
           Btn(f"{G['ok']}  Aᴘᴘʀᴏᴠᴇ Pᴀʏ", callback_data="adm_approve", style="success"))
    kb.add(Btn(f"{G['key']}  Cᴏᴜᴘᴏɴꜱ", callback_data="adm_coupons", style="primary"),
           Btn(f"{G['ticket']}  Tɪᴄᴋᴇᴛꜱ", callback_data="adm_tickets", style="primary"))
    kb.add(Btn(f"{G['shield']}  Aᴅᴍɪɴꜱ", callback_data="adm_admins", style="primary"),
           Btn(f"{G['eye']}  Aᴜᴅɪᴛ Lᴏɢ", callback_data="adm_audit", style="primary"))
    kb.add(Btn(f"{G['cog']}  Gɪᴛʜᴜʙ", callback_data="adm_github", style="primary"),
           Btn(f"{G['lock']}  Sᴇᴄᴜʀɪᴛʏ", callback_data="adm_security", style="danger"))
    kb.add(Btn(f"{G['warn']}  Mᴀɪɴᴛ", callback_data="adm_maint", style="danger"),
           Btn(f"{G['settings']}  Sᴇᴛᴛɪɴɢꜱ", callback_data="adm_settings", style="primary"))
    kb.add(Btn(f"{G['back']}  Mᴀɪɴ Mᴇɴᴜ", callback_data="menu_main", style="primary"))
    return kb


def bot_actions_kb(bot_id: str, running: bool, premium: bool = False):
    kb = types.InlineKeyboardMarkup(row_width=2)
    if running:
        kb.add(Btn(f"{G['stop']}  Sᴛᴏᴘ", callback_data=f"bot_stop_{bot_id}", style="danger"),
               Btn(f"{G['refresh']}  Rᴇꜱᴛᴀʀᴛ", callback_data=f"bot_restart_{bot_id}", style="success"))
    else:
        kb.add(Btn(f"{G['play']}  Sᴛᴀʀᴛ", callback_data=f"bot_start_{bot_id}", style="success"),
               Btn(f"{G['refresh']}  Rᴇꜱᴛᴀʀᴛ", callback_data=f"bot_restart_{bot_id}", style="primary"))
    kb.add(Btn(f"{G['bolt']}  Lɪᴠᴇ Lᴏɢꜱ", callback_data=f"bot_logs_{bot_id}", style="primary"),
           Btn(f"{G['eye']}  Iɴꜰᴏ", callback_data=f"bot_info_{bot_id}", style="primary"))
    kb.add(Btn(f"{G['settings']}  Eɴᴠ Vᴀʀꜱ", callback_data=f"bot_env_{bot_id}", style="primary"),
           Btn(f"{G['cog']}  Cʀᴏɴ", callback_data=f"bot_cron_{bot_id}", style="primary"))
    kb.add(Btn(f"{G['download']}  Iɴꜱᴛᴀʟʟ Pᴋɢ", callback_data=f"bot_pip_{bot_id}", style="primary"),
           Btn(f"{G['plus']}  Cʟᴏɴᴇ", callback_data=f"bot_clone_{bot_id}", style="primary"))
    if premium:
        is_open = bot_id in TUNNELS and TUNNELS[bot_id].get("proc") and TUNNELS[bot_id]["proc"].poll() is None
        label = "Sᴛᴏᴘ Pᴜʙʟɪᴄ URL" if is_open else "Pᴜʙʟɪᴄ URL"
        glyph = G['no'] if is_open else G['cloud']
        kb.add(Btn(f"{glyph}  {label}", callback_data=f"bot_tunnel_{bot_id}",
                   style="danger" if is_open else "success"))
    kb.add(Btn(f"{G['arrow']}  Dᴏᴡɴʟᴏᴀᴅ", callback_data=f"bot_dl_{bot_id}", style="primary"))
    kb.add(Btn(f"{G['no']}  Dᴇʟᴇᴛᴇ", callback_data=f"bot_delete_{bot_id}", style="danger"))
    kb.add(Btn(f"{G['back']}  Mʏ Bᴏᴛꜱ", callback_data="menu_bots", style="primary"))
    return kb


def confirm_kb(yes_cb: str, no_cb: str = "menu_main", yes_label: str = "Confirm",
               no_label: str = "Cancel"):
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(Btn(f"{G['ok']}  {sc(yes_label)}", callback_data=yes_cb, style="success"),
           Btn(f"{G['no']}  {sc(no_label)}", callback_data=no_cb, style="danger"))
    return kb


# ══════════════════════════════════════════════════════════════
# MENU RENDERS
# ══════════════════════════════════════════════════════════════
def render_main_menu(chat_id: int, uid: int,
                     call: Optional[types.CallbackQuery] = None,
                     intro: Optional[str] = None):
    u = db_load()["users"].get(str(uid)) or {}
    plan = PLAN_LIMITS.get(u.get("plan", "free"), PLAN_LIMITS["free"])
    bots_list = list_user_bots(uid)
    running = sum(1 for b in bots_list if b["_id"] in RUNNING and RUNNING[b["_id"]]["proc"].poll() is None)
    intro_block = f"{intro}\n{G['div']}\n" if intro else ""
    cap = (f"<b>{esc(BRAND)} v4.0</b>\n{G['div_eq']}\n{intro_block}"
           f"<b>{sc('Welcome')}</b>, {esc(u.get('name') or 'friend')}\n"
           f"{bullet('Plan', plan['name'])}\n"
           f"{bullet('Until', fmt_ts(u.get('plan_expires')) if u.get('plan_expires') else ('Forever' if plan['price'] == 0 else '—'))}\n"
           f"{bullet('Bots', str(len(bots_list)) + ' / ' + str(user_max_bots(u)) + '  (running ' + str(running) + ')')}\n"
           f"{bullet('Wallet', str(u.get('wallet', 0)) + '৳')}\n"
           f"{bullet('Runtime', 'Python • Node • PHP • Go • Java • Bun • Deno')}\n"
           f"{G['div']}\nChoose an option below.{FOOTER}")
    show_menu(chat_id, PHOTOS.get("main", ""), cap, main_menu_kb(is_admin(uid)), call=call)


def render_bots_menu(call: types.CallbackQuery):
    uid = call.from_user.id
    bots_list = list_user_bots(uid)
    u = db_load()["users"][str(uid)]
    cap = (f"<b>{G['diamond']} {sc('Your Bots')}</b>\n{G['div_eq']}\n"
           f"{bullet('Slots', str(len(bots_list)) + ' / ' + str(user_max_bots(u)))}\n")
    kb = types.InlineKeyboardMarkup()
    if not bots_list:
        cap += f"\n{sc('You have not deployed any bots yet')}.\n{sc('Tap upload bot to begin')}."
    else:
        for b in sorted(bots_list, key=lambda x: x.get("name", "")):
            running = b["_id"] in RUNNING and RUNNING[b["_id"]]["proc"].poll() is None
            runtime_icon = get_runtime_icon(b.get("runtime", "python"))
            mark = G["play"] if running else G["stop"]
            kb.add(Btn(f"{mark}  {runtime_icon} {sc(b['name'])[:28]}", callback_data=f"bot_view_{b['_id']}"))
    kb.add(Btn(f"{G['plus']}  {sc('Upload')}", callback_data="menu_upload", style="success"),
           Btn(f"{G['back']}  {sc('Main Menu')}", callback_data="menu_main", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("bots", ""), cap + FOOTER, kb, call=call)


def render_upload_menu(call: types.CallbackQuery):
    uid = call.from_user.id
    u = db_load()["users"][str(uid)]
    used = len(list_user_bots(uid))
    cap = (f"<b>{G['plus']} {sc('Upload Bot')}</b>\n{G['div_eq']}\n"
           f"{bullet('Plan', PLAN_LIMITS[u['plan']]['name'])}\n"
           f"{bullet('Slots', str(used) + ' / ' + str(user_max_bots(u)))}\n"
           f"{G['div']}\n"
           f"<b>{sc('Send your bot file as a document')}.</b>\n"
           f"Accepted: <code>.zip  .py  .js  .php  .go  .java  .ts</code>\n"
           f"<b>7 Runtimes:</b> Python • Node • PHP • Go • Java • Bun • Deno\n"
           f"All files <b>encrypted at rest</b> with AES-128.")
    USER_STATES[uid] = {"flow": "await_upload"}
    show_menu(call.message.chat.id, PHOTOS.get("upload", ""), cap + FOOTER, back_main_kb(), call=call)


def render_dashboard(call: types.CallbackQuery):
    d = db_load_ro()
    total_users = len(d.get("users", {}))
    active_users = sum(1 for u in d.get("users", {}).values() if u.get("plan") != "free")
    total_bots = len(d.get("bots", {}))
    running = len(RUNNING)
    offline = total_bots - running
    total_revenue = d.get("revenue", {}).get("total", 0)
    active_plans = sum(1 for u in d.get("users", {}).values() if u.get("plan") not in ("free",) and u.get("plan_expires"))
    cap = (f"<b>📊 Live Dashboard</b>\n{G['div_eq']}\n"
           f"<b>👥 Users</b>\n{bullet('Total', str(total_users))}\n{bullet('Premium', str(active_users))}\n"
           f"{G['div']}\n<b>🤖 Bots</b>\n"
           f"{bullet('Total', str(total_bots))}\n{bullet('Running', G['play'] + ' ' + str(running))}\n{bullet('Stopped', G['stop'] + ' ' + str(offline))}\n"
           f"{G['div']}\n<b>💰 Revenue</b>\n{bullet('Total', str(total_revenue) + '৳')}\n{bullet('Active Plans', str(active_plans))}\n"
           f"{G['div']}\n<b>⚙️ System</b>\n"
           f"{bullet('Uptime', fmt_dur(int(time.time() * 1000 - START_TIME * 1000)))}\n"
           f"{bullet('Runtimes', 'Python • Node • PHP • Go • Java • Bun • Deno')}\n{FOOTER}")
    kb = types.InlineKeyboardMarkup()
    kb.add(Btn("🔄 Rᴇꜰʀᴇsʜ", callback_data="menu_dashboard", style="primary"))
    kb.add(Btn(f"{G['back']}  Mᴀɪɴ Mᴇɴᴜ", callback_data="menu_main", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("dashboard", PHOTOS.get("main", "")), cap, kb, call=call)


def render_plans_menu(call: types.CallbackQuery):
    lines = []
    for v in PLAN_LIMITS.values():
        price_txt = "Free" if v["price"] == 0 else str(v["price"]) + "৳"
        detail = str(v["max_bots"]) + " bots " + G["bullet"] + " " + str(v["ram"]) + " MB RAM " + G["bullet"] + " " + price_txt
        lines.append(bullet(v["name"], detail))
    cap = (f"<b>{G['star']} {sc('Plans')}</b>\n{G['div_eq']}\n" + "\n".join(lines)
           + f"\n{G['div']}\nTap a plan for full details.{FOOTER}")
    show_menu(call.message.chat.id, PHOTOS.get("plans", ""), cap, plans_kb(), call=call)


def render_plan_detail(call: types.CallbackQuery, plan: str):
    p = PLAN_LIMITS.get(plan)
    if not p:
        ack(call, "Unknown plan"); return
    cap = (f"<b>{G['star']} {esc(p['name'])} {sc('Plan')}</b>\n{G['div_eq']}\n"
           f"{bullet('Max bots', str(p['max_bots']))}\n"
           f"{bullet('RAM per bot', str(p['ram']) + ' MB')}\n"
           f"{bullet('CPU', str(p.get('cpu', 0.1)) + ' vCPU')}\n"
           f"{bullet('Disk', str(p.get('disk_mb', 100)) + ' MB')}\n"
           f"{bullet('Auto-restart', 'Yes' if p['auto_restart'] else 'No')}\n"
           f"{bullet('Duration', 'Lifetime' if plan == 'lifetime' else str(p['days']) + ' days')}\n"
           f"{bullet('Price', 'Free' if p['price'] == 0 else str(p['price']) + '৳')}\n"
           f"{G['div']}\n{sc('Tap buy to choose a payment method')}.{FOOTER}")
    kb = types.InlineKeyboardMarkup()
    if plan != "free":
        kb.add(Btn(f"{G['spark']}  {sc('Buy')} {p['name']}", callback_data=f"plan_buy_{plan}"))
    kb.add(Btn(f"{G['back']}  {sc('Plans')}", callback_data="menu_plans"))
    show_menu(call.message.chat.id, PHOTOS.get("buy", ""), cap, kb, call=call)


def render_buy_menu(call: types.CallbackQuery):
    cap = (f"<b>{G['spark']} {sc('Buy a Plan')}</b>\n{G['div_eq']}\n{sc('Pick a plan first')}.{FOOTER}")
    show_menu(call.message.chat.id, PHOTOS.get("buy", ""), cap, plans_kb(), call=call)


def render_payment_methods_for(call: types.CallbackQuery, plan: str):
    p = PLAN_LIMITS.get(plan)
    if not p:
        ack(call, "Unknown plan"); return
    cap = (f"<b>{G['wallet']} {sc('Choose Payment Method')}</b>\n{G['div_eq']}\n"
           f"{bullet('Plan', p['name'])}\n{bullet('Price', str(p['price']) + '৳')}\n"
           f"{G['div']}\n{sc('Pick the method you will pay with')}.{FOOTER}")
    show_menu(call.message.chat.id, PHOTOS.get("pay", ""), cap, payments_kb(plan), call=call)


def render_payment_screen(call: types.CallbackQuery, data: str):
    parts = data.split("_")
    method = parts[1]
    plan = parts[2] if len(parts) >= 3 else None
    pm = PAYMENT_METHODS.get(method)
    if not pm:
        ack(call, "Unknown method"); return
    p = PLAN_LIMITS.get(plan or "")
    masked = mask_number(pm["number"]) if len(pm["number"]) >= 8 else mask_email(pm["number"])
    cap = (f"<b>{pm['tag']} {esc(pm['name'])} — {sc('Payment')}</b>\n{G['div_eq']}\n"
           f"{bullet('Number', masked)}\n{bullet('Type', pm['type'])}\n")
    if p:
        cap += f"{bullet('Plan', p['name'])}\n{bullet('Amount', str(p['price']) + '৳')}\n"
    cap += (f"{G['div']}\n<b>🔒 Privacy Protected</b>\n"
            f"Full details revealed after tapping <b>I'm Ready To Pay</b>.\n"
            f"Session expires in 5 minutes.{FOOTER}")
    kb = types.InlineKeyboardMarkup()
    kb.add(Btn("🔓 I'ᴍ Rᴇᴀᴅʏ Tᴏ Pᴀʏ", callback_data=f"pay_reveal_{method}" + (f"_{plan}" if plan else ""), style="danger"))
    kb.add(Btn("📎 Sᴇɴᴅ Pʀᴏᴏꜰ Dɪʀᴇᴄᴛʟʏ", callback_data="pay_proof", style="success"))
    plan_cb = f"plan_buy_{plan}" if plan else "menu_buy"
    kb.add(Btn(f"{G['back']}  Mᴇᴛʜᴏᴅs", callback_data=plan_cb))
    show_menu(call.message.chat.id, PHOTOS.get("pay", ""), cap, kb, call=call)


def render_payment_revealed(call: types.CallbackQuery, data: str):
    parts = data.split("_")
    method = parts[2]
    plan = parts[3] if len(parts) >= 4 else None
    pm = PAYMENT_METHODS.get(method)
    if not pm:
        ack(call, "Unknown method"); return
    p = PLAN_LIMITS.get(plan or "")
    uid = call.from_user.id
    session_id = secrets.token_hex(8)
    d = db_load()
    d.setdefault("payment_sessions", {})
    d["payment_sessions"][session_id] = {"uid": uid, "method": method, "plan": plan,
                                         "created": time.time(), "expires_at": time.time() + 300}
    db_save(d)
    cap = (f"<b>🔓 {pm['tag']} {esc(pm['name'])} — Full Details</b>\n{G['div_eq']}\n"
           f"<b>📱 Number:</b> <code>{esc(pm['number'])}</code>\n"
           f"<b>📋 Type:</b> {esc(pm['type'])}\n")
    if p:
        cap += f"<b>💰 Amount:</b> <code>{p['price']}৳</code>\n"
    cap += (f"{G['div']}\n<b>⚠️ Session expires in 5 minutes!</b>\n"
            f"{bullet('Session ID', session_id[:8])}\n{G['div']}\n"
            f"1. Send exact amount to number above\n2. Tap Send Proof\n3. Wait for admin approval\n{G['div']}{FOOTER}")
    kb = types.InlineKeyboardMarkup()
    USER_STATES[uid] = {"flow": "await_payment_proof", "method": method, "plan": plan, "session": session_id}
    kb.add(Btn("📎 Sᴇɴᴅ Pʀᴏᴏꜰ", callback_data="pay_proof", style="success"))
    kb.add(Btn(f"{G['back']}  Bᴀᴄᴋ", callback_data=f"pay_{method}" + (f"_{plan}" if plan else "")))
    if pm.get("has_qr") and method == "gcash" and GCASH_QR_PATH.exists():
        try:
            with open(GCASH_QR_PATH, "rb") as qr:
                bot.send_photo(call.message.chat.id, qr, caption="📱 Scan this QR code to pay")
        except Exception:
            pass
    show_menu(call.message.chat.id, PHOTOS.get("gcash" if method == "gcash" else "pay", ""), cap, kb, call=call)


def start_proof_flow(call: types.CallbackQuery):
    st = USER_STATES.get(call.from_user.id) or {}
    if st.get("flow") != "await_payment_proof":
        st = {"flow": "await_payment_proof"}
        USER_STATES[call.from_user.id] = st
    bot.send_message(call.message.chat.id,
                     f"{G['plus']} {sc('Send your payment screenshot or transaction id text now')}.\n{sc('Use')} /cancel {sc('to abort')}.")


def render_profile(call: types.CallbackQuery):
    uid = call.from_user.id
    u = db_load()["users"][str(uid)]
    p = PLAN_LIMITS.get(u["plan"], PLAN_LIMITS["free"])
    bots_list = list_user_bots(uid)
    cap = (f"<b>{G['user']} {sc('Profile')}</b>\n{G['div_eq']}\n"
           f"{bullet('Name', u.get('name'))}\n"
           f"{bullet('Username', '@' + (u.get('username') or '—'))}\n"
           f"{bullet('User ID', str(uid))}\n"
           f"{bullet('Plan', p['name'])}\n"
           f"{bullet('Until', fmt_ts(u.get('plan_expires')) if u.get('plan_expires') else ('Forever' if p['price'] == 0 else '—'))}\n"
           f"{bullet('Wallet', str(u.get('wallet', 0)) + '৳')}\n"
           f"{bullet('Bots', str(len(bots_list)) + ' / ' + str(user_max_bots(u)))}\n"
           f"{bullet('Joined', fmt_ts(u.get('joined')))}\n"
           f"{bullet('KYC', 'Verified' if u.get('kyc') else 'No')}\n"
           f"{bullet('Referrals', str(u.get('ref_count', 0)))}\n"
           f"{G['div']}{FOOTER}")
    show_menu(call.message.chat.id, PHOTOS.get("profile", ""), cap, back_main_kb(), call=call)


def render_referral(call: types.CallbackQuery):
    uid = call.from_user.id
    u = db_load()["users"][str(uid)]
    me = bot.get_me()
    link = f"https://t.me/{me.username}?start={uid}"
    cap = (f"<b>{G['users']} {sc('Referral')}</b>\n{G['div_eq']}\n"
           f"{bullet('Your link', link)}\n"
           f"{bullet('Referrals', str(u.get('ref_count', 0)))}\n"
           f"{bullet('Bonus slots', str(u.get('bot_slots_bonus', 0)))}\n"
           f"{G['div']}\n{sc('Each friend who joins via your link gives you')} +1 {sc('bot slot and')} +1৳ {sc('credit')}.\n{FOOTER}")
    show_menu(call.message.chat.id, PHOTOS.get("referral", ""), cap, back_main_kb(), call=call)


def render_wallet(call: types.CallbackQuery):
    uid = call.from_user.id
    u = db_load()["users"][str(uid)]
    cap = (f"<b>{G['wallet']} {sc('Wallet')}</b>\n{G['div_eq']}\n"
           f"{bullet('Balance', str(u.get('wallet', 0)) + '৳')}\n"
           f"{G['div']}\n{sc('Top up by sending payment proof. Admin will credit your wallet')}.\n"
           f"{sc('You can also gift your active plan to another user')}.{FOOTER}")
    kb = types.InlineKeyboardMarkup()
    kb.add(Btn(f"{G['plus']}  {sc('Top Up')}", callback_data="wallet_topup"))
    if u.get("plan") not in ("free",):
        kb.add(Btn(f"{G['spark']}  {sc('Gift Plan')}", callback_data="wallet_gift"))
    kb.add(Btn(f"{G['back']}  {sc('Main Menu')}", callback_data="menu_main"))
    show_menu(call.message.chat.id, PHOTOS.get("wallet", ""), cap, kb, call=call)


def render_help(call: types.CallbackQuery):
    cap = (f"<b>{G['rec']} {sc('Help')}</b>\n{G['div_eq']}\n"
           f"{bullet('Upload', 'Send .py / .js / .zip / .php / .go file')}\n"
           f"{bullet('Run', 'My Bots → pick → Start')}\n"
           f"{bullet('Deploy', 'Deploy menu → GitHub / ZIP')}\n"
           f"{bullet('Logs', 'My Bots → pick → Live Logs')}\n"
           f"{bullet('Env', 'My Bots → pick → Env Vars')}\n"
           f"{bullet('Plans', 'Plans → Buy Plan → method')}\n"
           f"{bullet('Runtimes', 'Python • Node • PHP • Go • Java • Bun • Deno')}\n"
           f"{bullet('Trial', 'One-time 48h Pro trial')}\n"
           f"{bullet('Refer', 'Earn slots by inviting friends')}\n"
           f"{bullet('Tickets', 'Open a private support ticket')}\n"
           f"{G['div']}\nUpdates: {UPDATE_CH}{FOOTER}")
    show_menu(call.message.chat.id, PHOTOS.get("help", ""), cap, back_main_kb(), call=call)


def render_support(call: types.CallbackQuery):
    cap = (f"<b>{G['broadcast']} {sc('Support')}</b>\n{G['div_eq']}\n"
           f"{bullet('DM', SUPPORT_USR)}\n{bullet('Channel', UPDATE_CH)}\n"
           f"{G['div']}\n{sc('Or open a ticket from the Tickets menu for tracked help')}.{FOOTER}")
    show_menu(call.message.chat.id, PHOTOS.get("support", ""), cap, back_main_kb(), call=call)


def render_freehost(call: types.CallbackQuery):
    div = G["div"]
    text = (f"☁️ <b>FREE BOT HOSTING</b>\n{div}\n"
            "<i>Deploy your bots 24/7 — completely FREE!</i>\n"
            f"{div}\nChoose a platform below:\n")
    kb = types.InlineKeyboardMarkup(row_width=1)
    for key, pf in FREE_HOSTING_PLATFORMS.items():
        kb.add(Btn(pf["name"] + " — " + pf["cost"], callback_data=f"freehost_{key}"))
    kb.add(Btn(G["back"] + "  Mᴀɪɴ Mᴇɴᴜ", callback_data="menu_main"))
    try:
        bot.edit_message_caption(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                 caption=text, parse_mode="HTML", reply_markup=kb)
    except Exception:
        bot.send_message(call.message.chat.id, text, parse_mode="HTML", reply_markup=kb)
    ack(call)


def render_freehost_platform(call: types.CallbackQuery, platform_key: str):
    pf = FREE_HOSTING_PLATFORMS.get(platform_key)
    if not pf:
        ack(call, "Not found"); return
    steps_text = "\n".join(G["bullet"] + " " + s for s in pf["steps"])
    text = (pf["name"] + "\n" + G["div"] + "\n"
            + G["bullet"] + " <b>Specs:</b> " + pf["specs"] + "\n"
            + G["bullet"] + " <b>Cost:</b> " + pf["cost"] + "\n"
            + G["bullet"] + " <b>URL:</b> " + pf["url"] + "\n"
            + G["div"] + "\n<b>📋 Steps to Deploy:</b>\n" + steps_text + "\n"
            + G["div"] + "\n<i>💡 Tip: Use @LEGITYAMI for support!</i>")
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(Btn("🔗 Oᴘᴇɴ Sɪᴛᴇ", url=pf["url"]),
           Btn(G["back"] + "  Fʀᴇᴇ Hᴏsᴛ Lɪsᴛ", callback_data="menu_freehost"))
    try:
        bot.edit_message_caption(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                 caption=text, parse_mode="HTML", reply_markup=kb)
    except Exception:
        bot.send_message(call.message.chat.id, text, parse_mode="HTML", reply_markup=kb)
    ack(call)


def render_gcash_menu(call: types.CallbackQuery):
    text = (f"📱 <b>GCash Payment — YAMI HOSTING</b>\n{G['div']}\n"
            f"{bullet('Number', mask_number('09667664037'))}\n"
            f"{bullet('Name', 'DEAN CLAUD')}\n"
            f"{bullet('Admin', '@LEGITYAMI')}\n"
            f"{bullet('Channel', '@SYNTAXYAMICHANNEL')}\n"
            f"{G['div']}\n<b>📸 2 Ways to Pay:</b>\n"
            f"{G['arrow']} <b>Scan QR</b> with GCash/Maya\n"
            f"{G['arrow']} <b>Manual:</b> Send → Express Send → 09667664037\n"
            f"{G['div']}\n<i>✅ Send screenshot to @LEGITYAMI</i>\n<i>✅ Then use /buy to activate plan</i>")
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(Btn("💳 Bᴜʏ Pʟᴀɴ", callback_data="menu_buy"),
           Btn(G["back"] + "  Mᴀɪɴ Mᴇɴᴜ", callback_data="menu_main"))
    if GCASH_QR_PATH.exists():
        try:
            with open(GCASH_QR_PATH, "rb") as qr:
                bot.send_photo(call.message.chat.id, qr, caption=text, parse_mode="HTML", reply_markup=kb)
        except Exception:
            bot.send_message(call.message.chat.id, text, parse_mode="HTML", reply_markup=kb)
    else:
        bot.send_message(call.message.chat.id, text, parse_mode="HTML", reply_markup=kb)
    ack(call)


def render_trial(call: types.CallbackQuery):
    uid = call.from_user.id
    u = db_load()["users"][str(uid)]
    cap = (f"<b>{G['eye']} {sc('Free Trial')}</b>\n{G['div_eq']}\n"
           f"{sc('Get a free 48-hour Pro trial — one time per account')}.\n"
           f"{bullet('Status', 'Already used' if u.get('trial_used') else 'Available')}{FOOTER}")
    kb = types.InlineKeyboardMarkup()
    if not u.get("trial_used"):
        kb.add(Btn(f"{G['ok']}  {sc('Claim 48h Pro Trial')}", callback_data="trial_claim"))
    kb.add(Btn(f"{G['back']}  {sc('Main Menu')}", callback_data="menu_main"))
    show_menu(call.message.chat.id, PHOTOS.get("trial", ""), cap, kb, call=call)


def action_trial_claim(call: types.CallbackQuery):
    uid = call.from_user.id
    d = db_load()
    u = d["users"][str(uid)]
    if u.get("trial_used"):
        ack(call, "Already used"); return
    u["trial_used"] = True
    db_save(d)
    grant_plan(uid, "pro", days=2)
    audit(0, "trial_grant", f"uid={uid}")
    ack(call, "Trial activated")
    render_main_menu(call.message.chat.id, uid, call)


def render_coupon(call: types.CallbackQuery):
    cap = (f"<b>{G['key']} {sc('Coupon')}</b>\n{G['div_eq']}\n"
           f"{sc('Have a discount code? Tap redeem and send the code')}.{FOOTER}")
    kb = types.InlineKeyboardMarkup()
    kb.add(Btn(f"{G['plus']}  {sc('Redeem Code')}", callback_data="coupon_redeem"))
    kb.add(Btn(f"{G['back']}  {sc('Main Menu')}", callback_data="menu_main"))
    show_menu(call.message.chat.id, PHOTOS.get("coupon", ""), cap, kb, call=call)


def render_user_stats(call: types.CallbackQuery):
    uid = call.from_user.id
    d = db_load()
    u = d["users"][str(uid)]
    p = PLAN_LIMITS.get(u.get("plan", "free"), PLAN_LIMITS["free"])
    bots_list = list_user_bots(uid)
    running = sum(1 for b in bots_list if b["_id"] in RUNNING and RUNNING[b["_id"]]["proc"].poll() is None)
    cap = (f"<b>{G['graph']} {sc('My Stats')}</b>\n{G['div_eq']}\n"
           f"<b>{sc('Account')}</b>\n"
           f"{bullet('Name', u.get('name', '—'))}\n"
           f"{bullet('User ID', str(uid))}\n"
           f"{bullet('Joined', fmt_ts(u.get('joined')))}\n"
           f"{G['div']}\n<b>{sc('Plan')}</b>\n"
           f"{bullet('Current Plan', p['name'])}\n"
           f"{bullet('RAM Limit', str(p['ram']) + ' MB')}\n"
           f"{G['div']}\n<b>{sc('Bots')}</b>\n"
           f"{bullet('Total', str(len(bots_list)))}\n"
           f"{bullet('Running', str(running))}\n"
           f"{bullet('Slots', str(len(bots_list)) + ' / ' + str(user_max_bots(u)))}\n"
           f"{G['div']}\n<b>{sc('Other')}</b>\n"
           f"{bullet('Wallet', str(u.get('wallet', 0)) + '৳')}\n"
           f"{bullet('Referrals', str(u.get('ref_count', 0)))}\n"
           f"{bullet('Trial', 'Used' if u.get('trial_used') else 'Available')}\n"
           f"{G['div']}{FOOTER}")
    show_menu(call.message.chat.id, PHOTOS.get("stats", ""), cap, back_main_kb(), call=call)


def start_coupon_flow(call: types.CallbackQuery):
    USER_STATES[call.from_user.id] = {"flow": "await_coupon"}
    bot.send_message(call.message.chat.id, f"{G['key']} {sc('Send your coupon code')} (Text Only). /cancel {sc('to abort')}.")


def start_wallet_topup(call: types.CallbackQuery):
    USER_STATES[call.from_user.id] = {"flow": "await_topup_proof"}
    bot.send_message(call.message.chat.id, f"{G['plus']} {sc('Send a screenshot of your top-up payment')}.\n{sc('Include the amount in the caption')}, e.g. <code>200</code>.", parse_mode="HTML")


def start_wallet_gift(call: types.CallbackQuery):
    USER_STATES[call.from_user.id] = {"flow": "await_gift_target"}
    bot.send_message(call.message.chat.id, f"{G['spark']} {sc('Send the user id of the person you want to gift your plan to')}.")


# ══════════════════════════════════════════════════════════════
# BOT VIEW / ACTIONS
# ══════════════════════════════════════════════════════════════
def render_bot_view(call: types.CallbackQuery, bot_id: str):
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    if b["owner"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    st = child_status(bot_id, b)
    err_block = ""
    if not st["running"]:
        rc = b.get("last_exit_code")
        last_err = (b.get("last_error") or "").strip()
        if last_err or (rc not in (None, 0)):
            head = f"{G['no']} {sc('Last error')}"
            if rc not in (None, 0):
                head += f"  (exit {rc})"
            err_block = f"\n{G['div']}\n<b>{head}</b>\n<pre>{esc(last_err or '(no log captured)')[:900]}</pre>"
    appr = (b.get("approval_status") or "").lower()
    if appr == "pending":
        status_lbl = "⏳ Pᴇɴᴅɪɴɢ Aᴘᴘʀᴏᴠᴀʟ"
    elif appr == "rejected":
        status_lbl = "🚫 Rᴇᴊᴇᴄᴛᴇᴅ"
    elif st["running"]:
        status_lbl = "▶️ Rᴜɴɴɪɴɢ"
    elif b.get("status") == "crashed":
        status_lbl = "💥 Cʀᴀsʜᴇᴅ"
    else:
        status_lbl = "⏹ Sᴛᴏᴘᴘᴇᴅ"
    runtime_icon = get_runtime_icon(b.get("runtime", st.get("runtime", "python")))
    cap = (f"<b>{runtime_icon} {esc(b['name'])}</b>\n{G['div_eq']}\n"
           f"{bullet('Status', status_lbl)}\n"
           f"{bullet('Runtime', b.get('runtime', st.get('runtime', '—')))}\n"
           f"{bullet('PID', '••••' if st['pid'] else '—')}\n"
           f"{bullet('Uptime', fmt_dur(st['uptimeMs']))}\n"
           f"{bullet('Size', fmt_bytes(st['sizeBytes']))}\n"
           f"{bullet('CPU', str(round(st['cpuPct'], 1)) + '%')}\n"
           f"{bullet('Memory', fmt_bytes(st['memBytes']))}\n"
           f"{bullet('Created', fmt_ts(b.get('created')))}{err_block}\n{G['div']}{FOOTER}")
    owner_doc = db_load()["users"].get(str(b["owner"])) or {}
    is_premium = owner_doc.get("plan", "free") != "free" and user_plan_active(owner_doc)
    tun = TUNNELS.get(bot_id)
    if tun and tun.get("proc") and tun["proc"].poll() is None and tun.get("url"):
        cap = (cap[:-len(FOOTER)] + f"\n{G['div']}\n{bullet('Public URL', tun['url'])}\n{bullet('Port', str(tun.get('port', '—')))})" + FOOTER)
    show_menu(call.message.chat.id, PHOTOS.get("bot", ""), cap,
              bot_actions_kb(bot_id, st["running"], premium=is_premium), call=call)


def action_bot_start(call: types.CallbackQuery, bot_id: str):
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    if b["owner"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    loading(call, "Starting bot")
    res = start_child(b)
    ack(call, "Started" if res["ok"] else f"Err: {res.get('error')}")
    render_bot_view(call, bot_id)


def action_bot_stop(call: types.CallbackQuery, bot_id: str):
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    if b["owner"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    loading(call, "Stopping bot")
    stop_child(bot_id, manual=True)
    ack(call, "Stopped")
    render_bot_view(call, bot_id)


def action_bot_restart(call: types.CallbackQuery, bot_id: str):
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    if b["owner"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    loading(call, "Restarting bot")
    res = restart_child(b)
    ack(call, "Restarted" if res["ok"] else f"Err: {res.get('error')}")
    render_bot_view(call, bot_id)


def action_bot_logs(call: types.CallbackQuery, bot_id: str):
    info = RUNNING.get(bot_id)
    if not info or not info.get("log"):
        ack(call, "No logs yet"); return
    lines = info["log"][-MAX_LOG_SEND:]
    txt = "\n".join(f"<code>{esc(l)}</code>" for l in lines[-30:]) or "(empty)"
    bot.send_message(call.message.chat.id,
                     f"<b>📋 Lᴏɢs — {esc(info.get('name', bot_id))}</b>\n{G['div']}\n{txt}\n{G['div']}{FOOTER}",
                     parse_mode="HTML")
    ack(call, "Logs sent")


def action_bot_info(call: types.CallbackQuery, bot_id: str):
    ack(call, "See info above")


def render_env_menu(call: types.CallbackQuery, bot_id: str):
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    env = b.get("env") or {}
    lines = "\n".join(f"{bullet(k, '***' if any(s in k.upper() for s in ['TOKEN','KEY','SECRET','PASS']) else v)}"
                      for k, v in env.items()) or "(none)"
    cap = f"<b>⚙️ Eɴᴠ Vᴀʀs — {esc(b['name'])}</b>\n{G['div_eq']}\n{lines}\n{G['div']}{FOOTER}"
    kb = types.InlineKeyboardMarkup()
    kb.add(Btn(f"{G['plus']}  Aᴅᴅ Vᴀʀ", callback_data=f"env_add_{bot_id}", style="success"))
    for k in env:
        kb.add(Btn(f"{G['trash']}  Dᴇʟᴇᴛᴇ {esc(k)[:20]}", callback_data=f"env_del_{bot_id}_{k}"))
    kb.add(Btn(f"{G['back']}  Bᴏᴛ", callback_data=f"bot_view_{bot_id}"))
    show_text(call.message.chat.id, cap, kb, call=call)


def start_env_add(call: types.CallbackQuery, bot_id: str):
    USER_STATES[call.from_user.id] = {"flow": "await_env_kv", "bot_id": bot_id}
    bot.send_message(call.message.chat.id, "Sᴇɴᴅ ᴇɴᴠ ᴠᴀʀ ᴀs: <code>KEY=VALUE</code>", parse_mode="HTML")


def action_env_delete(call: types.CallbackQuery, bot_id: str, key: str):
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    env = dict(b.get("env") or {})
    env.pop(key, None)
    b["env"] = env
    save_bot(b)
    ack(call, f"Deleted {key}")
    render_env_menu(call, bot_id)


def render_cron(call: types.CallbackQuery, bot_id: str):
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    cron = b.get("cron") or {}
    cap = (f"<b>⏰ Cʀᴏɴ — {esc(b['name'])}</b>\n{G['div_eq']}\n"
           f"{bullet('Expression', cron.get('expr', '—'))}\n"
           f"{bullet('Enabled', 'Yes' if cron.get('enabled') else 'No')}\n"
           f"{G['div']}\nSᴇɴᴅ ᴀ ᴄʀᴏɴ ᴇxᴘʀᴇssɪᴏɴ: <code>*/5 * * * *</code> ᴛᴏ sᴇᴛ.{FOOTER}")
    kb = types.InlineKeyboardMarkup()
    if cron.get("enabled"):
        kb.add(Btn("⏹ Dɪsᴀʙʟᴇ Cʀᴏɴ", callback_data=f"cron_disable_{bot_id}", style="danger"))
    else:
        kb.add(Btn("▶️ Eɴᴀʙʟᴇ Cʀᴏɴ", callback_data=f"cron_enable_{bot_id}", style="success"))
    kb.add(Btn(f"{G['back']}  Bᴏᴛ", callback_data=f"bot_view_{bot_id}"))
    show_text(call.message.chat.id, cap, kb, call=call)


def start_pip_install_flow(call: types.CallbackQuery, bot_id: str):
    USER_STATES[call.from_user.id] = {"flow": "await_pip_install", "bot_id": bot_id}
    bot.send_message(call.message.chat.id, "Sᴇɴᴅ ᴘᴀᴄᴋᴀɢᴇ ɴᴀᴍᴇ ᴛᴏ ɪɴsᴛᴀʟʟ:\nᴇ.ɢ. <code>requests</code> ᴏʀ <code>discord.py</code>", parse_mode="HTML")


def start_tunnel_flow(call: types.CallbackQuery, bot_id: str):
    USER_STATES[call.from_user.id] = {"flow": "await_tunnel_port", "bot_id": bot_id}
    bot.send_message(call.message.chat.id, "Sᴇɴᴅ ᴛʜᴇ ᴘᴏʀᴛ ɴᴜᴍʙᴇʀ ʏᴏᴜʀ ʙᴏᴛ ɪs ʟɪsᴛᴇɴɪɴɢ ᴏɴ:\nᴇ.ɢ. <code>8080</code>", parse_mode="HTML")


def action_bot_clone(call: types.CallbackQuery, bot_id: str):
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    import copy
    new = copy.deepcopy(b)
    new["_id"] = rand_token(8)
    new["name"] = f"{b['name']} (clone)"
    new["created"] = ts_iso()
    new["status"] = "stopped"
    new_dir = DIRS["sandbox"] / f"{b['owner']}_{new['_id']}"
    new_dir.mkdir(parents=True, exist_ok=True)
    new["dir"] = str(new_dir)
    save_bot(new)
    ack(call, "Cloned!")
    render_bots_menu(call)


def render_bot_delete_confirm(call: types.CallbackQuery, bot_id: str):
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    cap = f"<b>{G['trash']} Dᴇʟᴇᴛᴇ {esc(b['name'])}?</b>\n\nTʜɪs ᴄᴀɴɴᴏᴛ ʙᴇ ᴜɴᴅᴏɴᴇ."
    show_text(call.message.chat.id, cap,
              confirm_kb(f"bot_delyes_{bot_id}", f"bot_view_{bot_id}", "Yes, Delete", "Cancel"), call=call)


def action_bot_delete(call: types.CallbackQuery, bot_id: str):
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    stop_child(bot_id, manual=True)
    rmrf(b.get("dir", ""))
    delete_bot_doc(bot_id)
    ack(call, "Deleted")
    render_bots_menu(call)


def action_bot_download(call: types.CallbackQuery, bot_id: str):
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    zip_path = encrypted_dump_for_download(b)
    if not zip_path:
        ack(call, "No files"); return
    try:
        with open(zip_path, "rb") as f:
            bot.send_document(call.message.chat.id, f, visible_file_name=f"{b['name']}.zip",
                              caption=f"🔒 Encrypted backup of {esc(b['name'])}")
    except Exception as e:
        ack(call, f"Error: {e}")
    ack(call, "Sent")


# ══════════════════════════════════════════════════════════════
# ADMIN PANEL RENDERS
# ══════════════════════════════════════════════════════════════
def render_admin(call: types.CallbackQuery):
    d = db_load_ro()
    cap = (f"<b>⚔️ Aᴅᴍɪɴ Pᴀɴᴇʟ</b>\n{G['div_eq']}\n"
           f"{bullet('Users', str(len(d.get('users', {}))))}\n"
           f"{bullet('Bots', str(len(d.get('bots', {}))))}\n"
           f"{bullet('Running', str(len(RUNNING)))}\n"
           f"{bullet('Revenue', str(d.get('revenue', {}).get('total', 0)) + '৳')}\n"
           f"{G['div']}{FOOTER}")
    show_menu(call.message.chat.id, PHOTOS.get("admin", ""), cap, admin_kb(), call=call)


def render_adm_stats(call: types.CallbackQuery):
    d = db_load_ro()
    bots = d.get("bots", {})
    users = d.get("users", {})
    running = len(RUNNING)
    revenue = d.get("revenue", {}).get("total", 0)
    cap = (f"<b>📊 Sᴛᴀᴛs</b>\n{G['div_eq']}\n"
           f"{bullet('Total Users', str(len(users)))}\n"
           f"{bullet('Active Plans', str(sum(1 for u in users.values() if u.get('plan') not in ('free',))))}\n"
           f"{bullet('Total Bots', str(len(bots)))}\n"
           f"{bullet('Running', str(running))}\n"
           f"{bullet('Offline', str(len(bots) - running))}\n"
           f"{bullet('Revenue', str(revenue) + '৳')}\n{G['div']}{FOOTER}")
    show_text(call.message.chat.id, cap, back_admin_kb(), call=call)


def render_adm_users(call: types.CallbackQuery):
    d = db_load_ro()
    users = list(d.get("users", {}).values())[:20]
    lines = "\n".join(
        f"{bullet(u.get('name', '?'), '@' + (u.get('username', '—')) + ' | Plan: ' + u.get('plan', 'free') + ' | ID: ' + str(u['_id']))}"
        for u in users
    ) or "(none)"
    cap = f"<b>👥 Uꜱᴇʀs ({len(d.get('users', {}))})</b>\n{G['div_eq']}\n{lines}\n{G['div']}{FOOTER}"
    show_text(call.message.chat.id, cap, back_admin_kb(), call=call)


def render_adm_allbots(call: types.CallbackQuery):
    d = db_load_ro()
    bots = list(d.get("bots", {}).values())[:20]
    lines = "\n".join(
        f"{bullet(b.get('name', '?'), 'Owner: ' + str(b.get('owner')) + ' | Status: ' + b.get('status', '?'))}"
        for b in bots
    ) or "(none)"
    cap = f"<b>🤖 Aʟʟ Bᴏᴛs ({len(d.get('bots', {}))})</b>\n{G['div_eq']}\n{lines}\n{G['div']}{FOOTER}"
    show_text(call.message.chat.id, cap, back_admin_kb(), call=call)


def render_adm_payments(call: types.CallbackQuery):
    d = db_load_ro()
    pays = d.get("payments", [])[-15:]
    lines = "\n".join(
        f"{bullet('Payment ' + str(p.get('pid','?')), 'UID: ' + str(p.get('uid')) + ' | ' + str(p.get('amount','?')) + '৳ | ' + p.get('status','?'))}"
        for p in pays
    ) or "(none)"
    cap = f"<b>💳 Pᴀʏᴍᴇɴᴛs</b>\n{G['div_eq']}\n{lines}\n{G['div']}{FOOTER}"
    show_text(call.message.chat.id, cap, back_admin_kb(), call=call)


def render_adm_broadcast(call: types.CallbackQuery):
    cap = f"<b>📢 Bʀᴏᴀᴅᴄᴀsᴛ</b>\n{G['div_eq']}\nSᴇɴᴅ ʏᴏᴜʀ ʙʀᴏᴀᴅᴄᴀsᴛ ᴍᴇssᴀɢᴇ ɴᴏᴡ.{FOOTER}"
    USER_STATES[call.from_user.id] = {"flow": "await_broadcast"}
    show_text(call.message.chat.id, cap, back_admin_kb(), call=call)


# ══════════════════════════════════════════════════════════════
# TICKET SYSTEM
# ══════════════════════════════════════════════════════════════
def render_user_tickets(call: types.CallbackQuery):
    uid = call.from_user.id
    d = db_load()
    tickets = d.get("tickets", {})
    my = [t for t in tickets.values() if t.get("uid") == uid]
    lines = "\n".join(
        f"{bullet('Ticket ' + str(t['_id'])[:8], 'Status: ' + t.get('status', '?') + ' | ' + t.get('subject', '?'))}"
        for t in my[-10:]
    ) or "(no tickets)"
    cap = f"<b>🎫 Mʏ Tɪᴄᴋᴇᴛs</b>\n{G['div_eq']}\n{lines}\n{G['div']}{FOOTER}"
    kb = types.InlineKeyboardMarkup()
    kb.add(Btn("➕ Oᴘᴇɴ Tɪᴄᴋᴇᴛ", callback_data="ticket_open", style="success"))
    for t in my[-5:]:
        kb.add(Btn("Vɪᴇᴡ: " + esc(str(t.get('subject', str(t['_id'])[:8])))[:25],
                   callback_data=f"ticket_view_{t['_id']}"))
    kb.add(Btn(f"{G['back']}  Mᴀɪɴ Mᴇɴᴜ", callback_data="menu_main"))
    show_menu(call.message.chat.id, PHOTOS.get("ticket", ""), cap, kb, call=call)


def start_ticket_flow(call: types.CallbackQuery):
    USER_STATES[call.from_user.id] = {"flow": "await_ticket_subject"}
    bot.send_message(call.message.chat.id, "Sᴇɴᴅ ʏᴏᴜʀ ɪssᴜᴇ sᴜʙᴊᴇᴄᴛ:")


def render_ticket_view(call: types.CallbackQuery, tid: str):
    d = db_load()
    t = d.get("tickets", {}).get(tid)
    if not t:
        ack(call, "Not found"); return
    cap = (f"<b>🎫 Tɪᴄᴋᴇᴛ</b>\n{G['div_eq']}\n"
           f"{bullet('Subject', t.get('subject', '?'))}\n"
           f"{bullet('Status', t.get('status', '?'))}\n"
           f"{bullet('Created', fmt_ts(t.get('created')))}\n"
           f"{G['div']}\n<b>Messages:</b>\n"
           + "\n".join(f"<b>{esc(m.get('from', '?'))}:</b> {esc(m.get('text', ''))[:200]}"
                       for m in t.get("messages", [])[-10:])
           + f"\n{G['div']}{FOOTER}")
    kb = types.InlineKeyboardMarkup()
    kb.add(Btn("💬 Rᴇᴘʟʏ", callback_data=f"ticket_reply_{tid}", style="success"))
    if t.get("status") == "open":
        kb.add(Btn("🔒 Cʟᴏsᴇ", callback_data=f"ticket_close_{tid}", style="danger"))
    kb.add(Btn(f"{G['back']}  Tɪᴄᴋᴇᴛs", callback_data="menu_tickets"))
    show_text(call.message.chat.id, cap, kb, call=call)


def action_ticket_close(call: types.CallbackQuery, tid: str):
    d = db_load()
    t = d.get("tickets", {}).get(tid)
    if t:
        t["status"] = "closed"
        db_save(d)
    ack(call, "Closed")
    render_user_tickets(call)


def start_ticket_reply(call: types.CallbackQuery, tid: str):
    USER_STATES[call.from_user.id] = {"flow": "await_ticket_reply", "ticket_id": tid}
    bot.send_message(call.message.chat.id, "Sᴇɴᴅ ʏᴏᴜʀ ʀᴇᴘʟʏ:")


def action_payment_approve(call: types.CallbackQuery, pid: str):
    d = db_load()
    for p in d.get("payments", []):
        if p.get("pid") == pid:
            p["status"] = "approved"
            p["approved_at"] = ts_iso()
            db_save(d)
            ack(call, "Approved"); return
    ack(call, "Not found")


def action_payment_reject(call: types.CallbackQuery, pid: str):
    d = db_load()
    for p in d.get("payments", []):
        if p.get("pid") == pid:
            p["status"] = "rejected"
            p["rejected_at"] = ts_iso()
            db_save(d)
            ack(call, "Rejected"); return
    ack(call, "Not found")


# ══════════════════════════════════════════════════════════════
# CALLBACK DEDUPLICATOR
# ══════════════════════════════════════════════════════════════
_CB_DEDUP = deque(maxlen=512)
_CB_DEDUP_LOCK = threading.Lock()


def _is_duplicate_callback(call_id: str) -> bool:
    if not call_id:
        return False
    now = time.time()
    with _CB_DEDUP_LOCK:
        while _CB_DEDUP and now - _CB_DEDUP[0][1] > 12:
            _CB_DEDUP.popleft()
        for cid, _ in _CB_DEDUP:
            if cid == call_id:
                return True
        _CB_DEDUP.append((call_id, now))
    return False


# ══════════════════════════════════════════════════════════════
# CALLBACK HANDLERS
# ══════════════════════════════════════════════════════════════
@bot.callback_query_handler(func=lambda c: c.data == "group_verify_check")
def cb_group_verify(call: types.CallbackQuery):
    uid = call.from_user.id
    chat_id = call.message.chat.id
    not_joined = _check_group_membership(uid)
    if not_joined:
        ack(call, "Not all groups joined yet!")
        try:
            bot.delete_message(chat_id, call.message.message_id)
        except Exception:
            pass
        _send_join_verification(chat_id, uid, not_joined)
    else:
        ack(call, "✓ Verified! Welcome.")
        try:
            bot.delete_message(chat_id, call.message.message_id)
        except Exception:
            pass
        render_main_menu(chat_id, uid)


@bot.callback_query_handler(func=lambda c: bool(c.data) and c.data.startswith("verify_"))
def cb_verify(call: types.CallbackQuery):
    uid = call.from_user.id
    chat_id = call.message.chat.id
    data = call.data[len("verify_"):]

    if data == "new":
        with _verify_lock:
            st = VERIFY_STATES.get(uid)
            if st and st.get("regens", 0) >= 5:
                ack(call, "Too many regenerations."); return
        try:
            bot.delete_message(chat_id, call.message.message_id)
        except Exception:
            pass
        ack(call, "New captcha…")
        _send_captcha(chat_id, uid)
        with _verify_lock:
            if uid in VERIFY_STATES:
                VERIFY_STATES[uid]["regens"] = VERIFY_STATES[uid].get("regens", 0) + 1
        return

    with _verify_lock:
        state = VERIFY_STATES.get(uid)
    if not state:
        ack(call, "Session expired — /start again."); return
    if data == state["answer"]:
        with _verify_lock:
            VERIFY_STATES.pop(uid, None)
        _mark_verified(uid)
        ack(call, "✓ Verified")
        try:
            bot.delete_message(chat_id, state["msg_id"])
        except Exception:
            pass
        intro = f"<b>{G['ok']} Verification complete</b> — welcome, <b>{esc(call.from_user.first_name or 'friend')}</b>!"
        render_main_menu(chat_id, uid, intro=intro)
        return
    state["tries"] = state.get("tries", 0) + 1
    left = max(0, 3 - state["tries"])
    if state["tries"] >= 3:
        with _verify_lock:
            VERIFY_STATES.pop(uid, None)
        try:
            bot.delete_message(chat_id, state["msg_id"])
        except Exception:
            pass
        ack(call, "Wrong 3 times — new captcha.")
        _send_captcha(chat_id, uid)
    else:
        ack(call, f"Wrong. {left} tries left.")


@bot.callback_query_handler(func=lambda c: True)
def cb_root(call: types.CallbackQuery):
    if _is_duplicate_callback(getattr(call, "id", "")):
        try:
            bot.answer_callback_query(call.id)
        except Exception:
            pass
        return
    uid = call.from_user.id
    if not RATE.allow(uid):
        ack(call, "Slow down.")
        maybe_auto_ban(uid, "callback rate")
        return
    if banned_block(call):
        ack(call); return
    get_or_create_user(call.from_user)
    if maintenance_block(uid):
        ack(call, "Maintenance mode"); return
    if not _is_verified(uid):
        ack(call, "Solve captcha first — /start"); return
    data = call.data or ""
    try:
        _route_callback(call, data)
    except Exception as e:
        traceback.print_exc()
        try:
            bot.send_message(call.message.chat.id, f"<b>{G['no']}</b> Eʀʀᴏʀ: <code>{esc(e)}</code>")
        except Exception:
            pass


def _route_callback(call: types.CallbackQuery, data: str):
    # Main navigation
    if data == "menu_main":
        ack(call); render_main_menu(call.message.chat.id, call.from_user.id, call); return
    if data == "menu_bots":
        ack(call); render_bots_menu(call); return
    if data == "menu_upload":
        ack(call); render_upload_menu(call); return
    if data == "menu_plans":
        ack(call); render_plans_menu(call); return
    if data == "menu_buy":
        ack(call); render_buy_menu(call); return
    if data == "menu_profile":
        ack(call); render_profile(call); return
    if data == "menu_referral":
        ack(call); render_referral(call); return
    if data == "menu_wallet":
        ack(call); render_wallet(call); return
    if data == "menu_help":
        ack(call); render_help(call); return
    if data == "menu_support":
        ack(call); render_support(call); return
    if data == "menu_tickets":
        ack(call); render_user_tickets(call); return
    if data == "menu_freehost":
        ack(call); render_freehost(call); return
    if data.startswith("freehost_"):
        ack(call); render_freehost_platform(call, data.split("_", 1)[1]); return
    if data == "menu_gcash":
        ack(call); render_gcash_menu(call); return
    if data == "menu_trial":
        ack(call); render_trial(call); return
    if data == "menu_coupon":
        ack(call); render_coupon(call); return
    if data == "menu_stats":
        ack(call); render_user_stats(call); return
    if data == "menu_dashboard":
        ack(call); render_dashboard(call); return
    if data == "menu_admin":
        ack(call); render_admin(call); return

    # Plans
    if data.startswith("plan_view_"):
        ack(call); render_plan_detail(call, data.split("_", 2)[2]); return
    if data.startswith("plan_buy_"):
        ack(call); render_payment_methods_for(call, data.split("_", 2)[2]); return

    # Payment
    if data.startswith("pay_reveal_"):
        ack(call); render_payment_revealed(call, data); return
    if data.startswith("pay_"):
        ack(call); render_payment_screen(call, data); return
    if data == "pay_proof":
        ack(call); start_proof_flow(call); return

    # Bot actions
    if data.startswith("bot_view_"):
        ack(call); render_bot_view(call, data.split("_", 2)[2]); return
    if data.startswith("bot_start_"):
        ack(call); action_bot_start(call, data.split("_", 2)[2]); return
    if data.startswith("bot_stop_"):
        ack(call); action_bot_stop(call, data.split("_", 2)[2]); return
    if data.startswith("bot_restart_"):
        ack(call); action_bot_restart(call, data.split("_", 2)[2]); return
    if data.startswith("bot_logs_"):
        ack(call); action_bot_logs(call, data.split("_", 2)[2]); return
    if data.startswith("bot_info_"):
        ack(call); action_bot_info(call, data.split("_", 2)[2]); return
    if data.startswith("bot_env_"):
        ack(call); render_env_menu(call, data.split("_", 2)[2]); return
    if data.startswith("env_add_"):
        ack(call); start_env_add(call, data.split("_", 2)[2]); return
    if data.startswith("env_del_"):
        parts = data.split("_", 3)
        if len(parts) >= 4:
            ack(call); action_env_delete(call, parts[2], parts[3]); return
    if data.startswith("bot_cron_"):
        ack(call); render_cron(call, data.split("_", 2)[2]); return
    if data.startswith("bot_clone_"):
        ack(call); action_bot_clone(call, data.split("_", 2)[2]); return
    if data.startswith("bot_dl_"):
        ack(call); action_bot_download(call, data.split("_", 2)[2]); return
    if data.startswith("bot_pip_"):
        ack(call); start_pip_install_flow(call, data.split("_", 2)[2]); return
    if data.startswith("bot_tunnel_"):
        ack(call); start_tunnel_flow(call, data.split("_", 2)[2]); return
    if data.startswith("bot_delete_"):
        ack(call); render_bot_delete_confirm(call, data.split("_", 2)[2]); return
    if data.startswith("bot_delyes_"):
        ack(call); action_bot_delete(call, data.split("_", 2)[2]); return

    # Approval
    if data.startswith("appr_ok_"):
        if not admin_only_call(call, "approve_payment"): return
        bid = data[len("appr_ok_"):]
        _approve_bot(bid, call.from_user.id)
        ack(call, "Approved"); return
    if data.startswith("appr_no_"):
        if not admin_only_call(call, "approve_payment"): return
        bid = data[len("appr_no_"):]
        _reject_bot(bid, call.from_user.id)
        ack(call, "Rejected"); return

    # Admin
    if data.startswith("adm_"):
        if not admin_only_call(call): return
        ack(call); _admin_subroute(call, data); return

    # Trial
    if data == "trial_claim":
        ack(call); action_trial_claim(call); return

    # Coupon
    if data == "coupon_redeem":
        ack(call); start_coupon_flow(call); return

    # Tickets
    if data == "ticket_open":
        ack(call); start_ticket_flow(call); return
    if data.startswith("ticket_view_"):
        ack(call); render_ticket_view(call, data.split("_", 2)[2]); return
    if data.startswith("ticket_close_"):
        ack(call); action_ticket_close(call, data.split("_", 2)[2]); return
    if data.startswith("ticket_reply_"):
        ack(call); start_ticket_reply(call, data.split("_", 2)[2]); return

    # Wallet
    if data == "wallet_topup":
        ack(call); start_wallet_topup(call); return
    if data == "wallet_gift":
        ack(call); start_wallet_gift(call); return

    # Payment approve/reject
    if data.startswith("payapprove_"):
        ack(call); action_payment_approve(call, data.split("_", 1)[1]); return
    if data.startswith("payreject_"):
        ack(call); action_payment_reject(call, data.split("_", 1)[1]); return

    ack(call, "?")


def _admin_subroute(call: types.CallbackQuery, data: str):
    if data == "adm_stats":
        render_adm_stats(call)
    elif data == "adm_users":
        render_adm_users(call)
    elif data == "adm_allbots":
        render_adm_allbots(call)
    elif data == "adm_payments":
        render_adm_payments(call)
    elif data == "adm_broadcast":
        render_adm_broadcast(call)
    elif data == "adm_dashboard":
        render_dashboard(call)
    else:
        ack(call, f"Coming soon: {data}")


def _approve_bot(bid: str, admin_uid: int):
    d = db_load()
    b = d["bots"].get(bid)
    if not b:
        return {"ok": False, "error": "Not found"}
    b["approval_status"] = "approved"
    b["approved_by"] = admin_uid
    b["approved_at"] = ts_iso()
    db_save(d)
    return {"ok": True}


def _reject_bot(bid: str, admin_uid: int):
    d = db_load()
    b = d["bots"].get(bid)
    if not b:
        return {"ok": False, "error": "Not found"}
    b["approval_status"] = "rejected"
    b["rejected_by"] = admin_uid
    b["rejected_at"] = ts_iso()
    db_save(d)
    return {"ok": True}


# ══════════════════════════════════════════════════════════════
# COMMAND HANDLERS
# ══════════════════════════════════════════════════════════════
def _is_private(m) -> bool:
    try:
        return m.chat.type == "private"
    except Exception:
        return True


@bot.message_handler(commands=["start"])
def cmd_start(m: types.Message):
    if not _is_private(m):
        return
    uid = m.from_user.id
    if not RATE.allow(uid):
        maybe_auto_ban(uid, "rate"); return
    if banned_block(m):
        return
    global OWNER_ID
    if OWNER_ID <= 0:
        stored = int(get_setting("owner_id", 0) or 0)
        if stored > 0:
            OWNER_ID = stored
        else:
            OWNER_ID = uid
            set_setting("owner_id", uid)
            audit(uid, "owner_claim", f"first /start, uid={uid}")
    ref = None
    parts = (m.text or "").split(maxsplit=1)
    if len(parts) == 2 and parts[1].isdigit():
        ref = int(parts[1])
    u, is_new = get_or_create_user(m.from_user, ref=ref)
    if maintenance_block(uid):
        bot.send_message(m.chat.id, f"<b>{G['warn']} Under maintenance</b>\n\nBack shortly. {SUPPORT_USR}")
        return
    if not require_verified(m.chat.id, uid):
        return
    if not require_group_membership(m.chat.id, uid):
        return
    intro = (f"{sc('You are now registered')}. Tap Plans or Upload Bot." if is_new
             else f"{sc('Welcome back')}, <b>{esc(m.from_user.first_name or 'friend')}</b>!")
    render_main_menu(m.chat.id, uid, intro=intro)


@bot.message_handler(commands=["freehost"])
def cmd_freehost(message: types.Message):
    render_freehost_msg(message.chat.id)


def render_freehost_msg(chat_id: int):
    div = G["div"]
    text = (f"☁️ <b>FREE BOT HOSTING</b>\n{div}\n"
            "<i>Deploy 24/7 — completely FREE!</i>\n"
            f"{div}\nChoose a platform:\n")
    kb = types.InlineKeyboardMarkup(row_width=1)
    for key, pf in FREE_HOSTING_PLATFORMS.items():
        kb.add(Btn(pf["name"] + " — " + pf["cost"], callback_data=f"freehost_{key}"))
    kb.add(Btn(G["back"] + "  Mᴀɪɴ Mᴇɴᴜ", callback_data="menu_main"))
    bot.send_message(chat_id, text, parse_mode="HTML", reply_markup=kb)


@bot.message_handler(commands=["gcash"])
def cmd_gcash_cmd(message: types.Message):
    render_gcash_menu_msg(message.chat.id)


def render_gcash_menu_msg(chat_id: int):
    text = (f"📱 <b>GCash Payment</b>\n{G['div']}\n"
            f"{bullet('Number', mask_number('09667664037'))}\n"
            f"{bullet('Name', 'DEAN CLAUD')}\n"
            f"{G['div']}\n✅ Send screenshot to @LEGITYAMI\n✅ Use /buy for plan")
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(Btn("💳 Bᴜʏ Pʟᴀɴ", callback_data="menu_buy"),
           Btn(G["back"] + "  Mᴀɪɴ Mᴇɴᴜ", callback_data="menu_main"))
    if GCASH_QR_PATH.exists():
        try:
            with open(GCASH_QR_PATH, "rb") as qr:
                bot.send_photo(chat_id, qr, caption=text, parse_mode="HTML", reply_markup=kb)
        except Exception:
            bot.send_message(chat_id, text, parse_mode="HTML", reply_markup=kb)
    else:
        bot.send_message(chat_id, text, parse_mode="HTML", reply_markup=kb)


@bot.message_handler(commands=["help"])
def cmd_help(m: types.Message):
    if not _is_private(m) or banned_block(m):
        return
    if not require_verified(m.chat.id, m.from_user.id):
        return
    cap = (f"<b>❓ Hᴇʟᴘ</b>\n{G['div_eq']}\n"
           f"{bullet('Upload', 'Send .py/.js/.zip/.php/.go file')}\n"
           f"{bullet('Run', 'My Bots → pick → Start')}\n"
           f"{bullet('Deploy', 'Deploy menu → GitHub/ZIP')}\n"
           f"{bullet('Runtimes', 'Python • Node • PHP • Go • Java • Bun • Deno')}\n"
           f"{bullet('Plans', 'Plans → Buy Plan')}\n"
           f"{bullet('Trial', '48h Pro trial')}\n"
           f"{bullet('Tickets', 'Open support ticket')}\n"
           f"{G['div']}{FOOTER}")
    bot.send_message(m.chat.id, cap, parse_mode="HTML", reply_markup=back_main_kb(), disable_web_page_preview=True)


@bot.message_handler(commands=["menu"])
def cmd_menu(m: types.Message):
    if not _is_private(m) or banned_block(m):
        return
    get_or_create_user(m.from_user)
    if not require_verified(m.chat.id, m.from_user.id):
        return
    render_main_menu(m.chat.id, m.from_user.id)


@bot.message_handler(commands=["id"])
def cmd_id(m: types.Message):
    if not _is_private(m):
        return
    bot.reply_to(m, f"<code>{m.from_user.id}</code>")


@bot.message_handler(commands=["cancel"])
def cmd_cancel(m: types.Message):
    if not _is_private(m):
        return
    USER_STATES.pop(m.from_user.id, None)
    bot.reply_to(m, f"{G['ok']} Cᴀɴᴄᴇʟʟᴇᴅ")


@bot.message_handler(commands=["admin"])
def cmd_admin(m: types.Message):
    if not _is_private(m) or banned_block(m):
        return
    if not is_admin(m.from_user.id):
        bot.reply_to(m, "Admin only."); return
    render_admin_from_msg(m)


def render_admin_from_msg(m: types.Message):
    d = db_load_ro()
    cap = (f"<b>⚔️ Aᴅᴍɪɴ Pᴀɴᴇʟ</b>\n{G['div_eq']}\n"
           f"{bullet('Users', str(len(d.get('users', {}))))}\n"
           f"{bullet('Bots', str(len(d.get('bots', {}))))}\n"
           f"{bullet('Running', str(len(RUNNING)))}\n"
           f"{G['div']}{FOOTER}")
    show_menu(m.chat.id, PHOTOS.get("admin", ""), cap, admin_kb())


# ══════════════════════════════════════════════════════════════
# MESSAGE HANDLERS
# ══════════════════════════════════════════════════════════════
@bot.message_handler(content_types=["document"])
def on_document(m: types.Message):
    if not _is_private(m):
        return
    uid = m.from_user.id
    if banned_block(m):
        return
    st = USER_STATES.get(uid) or {}
    if st.get("flow") != "await_upload":
        return
    doc = m.document
    if not doc:
        bot.reply_to(m, "No document found."); return
    if doc.file_size and doc.file_size > MAX_UPLOAD_BYTES:
        bot.reply_to(m, f"File too large (max {MAX_UPLOAD_BYTES // (1024*1024)} MB)."); return
    fname = doc.file_name or "upload.zip"
    ext = Path(fname).suffix.lower()
    allowed = {".py", ".js", ".zip", ".tar.gz", ".tgz", ".tar", ".php", ".go", ".java", ".ts", ".mjs", ".mts"}
    if ext not in allowed and not any(fname.endswith(a) for a in [".tar.gz", ".tgz"]):
        bot.reply_to(m, f"Unsupported: {fname}\nAllowed: .py .js .zip .php .go .java .ts"); return
    u = db_load()["users"][str(uid)]
    used = len(list_user_bots(uid))
    if used >= user_max_bots(u):
        bot.reply_to(m, f"Slot limit ({used}/{user_max_bots(u)}). Upgrade plan."); return

    # Download file
    tmp_dir = DIRS["uploads"] / str(uid)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = tmp_dir / f"{int(time.time())}_{safe_name(fname)}"
    try:
        file_info = bot.get_file(doc.file_id)
        data = bot.download_file(file_info.file_path)
        with open(tmp_path, "wb") as f:
            f.write(data)
    except Exception as e:
        bot.reply_to(m, f"Download failed: {e}"); return

    # Security scan
    scan = _run_security_scan(str(tmp_path))
    verdict = scan.get("verdict", "SAFE")
    risk = scan.get("risk_score", 0)

    if verdict == "DANGEROUS":
        scan_msg = (f"⚠️ <b>FILE BLOCKED — {verdict}</b>\n{G['div']}\n"
                    f"Risk Score: <b>{risk}/100</b>\n"
                    f"Summary: {scan.get('summary', 'Malicious code detected')}\n{FOOTER}")
        bot.reply_to(m, scan_msg, parse_mode="HTML")
        notify_owner(f"<b>🚫 Blocked upload</b>\n{bullet('User', '@' + (m.from_user.username or str(m.from_user.id)))}\n"
                     f"{bullet('File', fname)}\n{bullet('Risk', str(risk))}\n{bullet('Verdict', verdict)}")
        try:
            tmp_path.unlink()
        except Exception:
            pass
        return

    # Store bot
    bot_id = rand_token(8)
    bot_dir = DIRS["sandbox"] / f"{uid}_{bot_id}"
    bot_dir.mkdir(parents=True, exist_ok=True)

    if ext == ".zip":
        import zipfile
        try:
            with zipfile.ZipFile(tmp_path, "r") as z:
                z.extractall(bot_dir)
        except Exception as e:
            bot.reply_to(m, f"ZIP extraction failed: {e}"); return
        try:
            tmp_path.unlink()
        except Exception:
            pass
    else:
        shutil.move(str(tmp_path), str(bot_dir / fname))

    # Detect runtime
    runtime, entry = detect_entry(bot_dir)
    if not runtime:
        bot.reply_to(m, "No entry file found. Supported: bot.py, main.py, index.js, index.php, main.go"); return

    # Encrypt files
    enc_files = []
    for root, _, files in os.walk(bot_dir):
        for fn in files:
            fp = Path(root) / fn
            if fp.suffix in (".enc",):
                continue
            rel = str(fp.relative_to(bot_dir))
            plain = fp.read_bytes()
            meta = store_uploaded_file(uid, m.from_user.username or "", f"{bot_id}/{rel}", plain)
            meta["rel_path"] = rel
            enc_files.append(meta)

    bot_doc = {
        "_id": bot_id, "name": Path(fname).stem[:30], "owner": uid,
        "dir": str(bot_dir), "enc_files": enc_files, "status": "stopped",
        "runtime": runtime, "env": {}, "cron": {},
        "created": ts_iso(), "approval_status": "approved",
    }
    save_bot(bot_doc)
    u["stats"]["bots_uploaded"] = int(u.get("stats", {}).get("bots_uploaded", 0)) + 1
    db_save(db_load())

    scan_emoji = "✅" if verdict == "SAFE" else "🔍"
    result = (f"<b>🚀 Bot Uploaded!</b>\n{G['div_eq']}\n"
              f"{bullet('Name', esc(bot_doc['name']))}\n"
              f"{bullet('Runtime', get_runtime_icon(runtime) + ' ' + runtime.title())}\n"
              f"{bullet('Entry', entry)}\n"
              f"{bullet('Files', str(len(enc_files)))}\n"
              f"{scan_emoji} Security: <b>{verdict}</b> (score: {risk}/100)\n"
              f"{G['div']}\nTap <b>My Bots</b> to start!{FOOTER}")
    bot.reply_to(m, result, parse_mode="HTML", reply_markup=back_main_kb())


@bot.message_handler(content_types=["photo"])
def on_photo(m: types.Message):
    if not _is_private(m):
        return
    uid = m.from_user.id
    st = USER_STATES.get(uid) or {}
    flow = st.get("flow", "")
    if flow == "await_payment_proof":
        _handle_payment_proof(m, st)
    elif flow == "await_topup_proof":
        _handle_topup_proof(m)


@bot.message_handler(func=lambda m: True, content_types=["text"])
def on_text(m: types.Message):
    if not _is_private(m):
        return
    uid = m.from_user.id
    text = (m.text or "").strip()
    if text.startswith("/"):
        return
    st = USER_STATES.get(uid) or {}
    flow = st.get("flow", "")
    if flow == "await_env_kv":
        _handle_env_kv(m, st)
    elif flow == "await_pip_install":
        _handle_pip_install(m, st)
    elif flow == "await_tunnel_port":
        _handle_tunnel_port(m, st)
    elif flow == "await_cron":
        _handle_cron(m, st)
    elif flow == "await_coupon":
        _handle_coupon_user(m)
    elif flow == "await_ticket_subject":
        _handle_ticket_subject(m)
    elif flow == "await_ticket_body":
        _handle_ticket_body(m, st)
    elif flow == "await_ticket_reply":
        _handle_ticket_reply(m, st)
    elif flow == "await_payment_proof":
        _handle_payment_proof_text(m, st)
    elif flow == "await_topup_proof":
        _handle_topup_proof(m)
    elif flow == "await_gift_target":
        _handle_gift_target(m, st)
    elif flow == "await_gift_confirm":
        _handle_gift_confirm(m, st)
    elif flow == "await_broadcast":
        _handle_broadcast(m)
    elif flow == "await_admin_finduser":
        _handle_admin_finduser(m)
    elif flow == "await_admin_ban":
        _handle_ban_cmd(m)
    elif flow == "await_admin_giveplan":
        _handle_giveplan_cmd(m)


# ══════════════════════════════════════════════════════════════
# FLOW HANDLERS
# ══════════════════════════════════════════════════════════════
def _handle_env_kv(m: types.Message, st: Dict[str, Any]):
    bid = st["bot_id"]
    b = find_bot(bid)
    if not b:
        bot.reply_to(m, "Bot not found"); return
    text = (m.text or "").strip()
    if "=" not in text:
        bot.reply_to(m, "Format: KEY=VALUE"); return
    k, v = text.split("=", 1)
    env = dict(b.get("env") or {})
    env[k.strip()] = v.strip()
    b["env"] = env
    save_bot(b)
    USER_STATES.pop(m.from_user.id, None)
    bot.reply_to(m, f"{G['ok']} Env var set: {esc(k)}")


def _handle_pip_install(m: types.Message, st: Dict[str, Any]):
    bid = st["bot_id"]
    b = find_bot(bid)
    if not b:
        bot.reply_to(m, "Bot not found"); return
    pkg = (m.text or "").strip()
    bot_dir = Path(b["dir"])
    deps_dir = bot_dir / ".deps"
    deps_dir.mkdir(parents=True, exist_ok=True)
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--target", str(deps_dir),
             "--upgrade", "--quiet", pkg],
            cwd=str(bot_dir), timeout=120, capture_output=True, text=True)
        USER_STATES.pop(m.from_user.id, None)
        if r.returncode == 0:
            bot.reply_to(m, f"{G['ok']} Installed: {esc(pkg)}")
        else:
            bot.reply_to(m, f"{G['no']} Failed:\n<code>{esc(r.stderr[-500:])}</code>")
    except Exception as e:
        bot.reply_to(m, f"Error: {e}")


def _handle_tunnel_port(m: types.Message, st: Dict[str, Any]):
    bid = st["bot_id"]
    try:
        port = int((m.text or "").strip())
    except ValueError:
        bot.reply_to(m, "Invalid port number."); return
    USER_STATES.pop(m.from_user.id, None)
    res = _start_tunnel(bid, port)
    if res.get("ok"):
        bot.reply_to(m, f"{G['cloud']} Tunnel open!\n{bullet('URL', res['url'])}\n{bullet('Port', str(port))}")
    else:
        bot.reply_to(m, f"{G['no']} Tunnel failed: {res.get('error')}")


def _handle_cron(m: types.Message, st: Dict[str, Any]):
    bid = st["bot_id"]
    b = find_bot(bid)
    if not b:
        bot.reply_to(m, "Bot not found"); return
    expr = (m.text or "").strip()
    b["cron"] = {"expr": expr, "enabled": True}
    save_bot(b)
    USER_STATES.pop(m.from_user.id, None)
    bot.reply_to(m, f"{G['ok']} Cron set: <code>{esc(expr)}</code>")


def _handle_coupon_user(m: types.Message):
    code = (m.text or "").strip()
    d = db_load()
    coupon = d.get("coupons", {}).get(code)
    if not coupon:
        bot.reply_to(m, "Invalid coupon code."); return
    uid = m.from_user.id
    grant_plan(uid, coupon.get("plan", "basic"), days=coupon.get("days", 30))
    d["coupons"].pop(code, None)
    db_save(d)
    USER_STATES.pop(uid, None)
    audit(uid, "coupon_redeem", f"code={code}")


def _handle_ticket_subject(m: types.Message):
    uid = m.from_user.id
    subject = (m.text or "").strip()[:100]
    USER_STATES[uid] = {"flow": "await_ticket_body", "subject": subject}
    bot.reply_to(m, "Describe your issue:")


def _handle_ticket_body(m: types.Message, st: Dict[str, Any]):
    uid = m.from_user.id
    tid = secrets.token_hex(6)
    d = db_load()
    d.setdefault("tickets", {})
    d["tickets"][tid] = {
        "_id": tid, "uid": uid, "subject": st["subject"],
        "status": "open", "created": ts_iso(),
        "messages": [{"from": str(uid), "text": (m.text or "").strip()[:2000], "ts": ts_iso()}],
    }
    db_save(d)
    USER_STATES.pop(uid, None)
    bot.reply_to(m, f"{G['ok']} Ticket opened! ID: <code>{tid[:8]}</code>")
    notify_owner(f"<b>🎫 New Ticket</b>\n{bullet('ID', tid[:8])}\n{bullet('User', str(uid))}\n{bullet('Subject', st['subject'])}")


def _handle_ticket_reply(m: types.Message, st: Dict[str, Any]):
    uid = m.from_user.id
    tid = st["ticket_id"]
    d = db_load()
    t = d.get("tickets", {}).get(tid)
    if not t:
        bot.reply_to(m, "Ticket not found"); return
    t["messages"].append({"from": str(uid), "text": (m.text or "").strip()[:2000], "ts": ts_iso()})
    db_save(d)
    USER_STATES.pop(uid, None)
    bot.reply_to(m, f"{G['ok']} Reply sent!")


def _handle_payment_proof(m: types.Message, st: Dict[str, Any]):
    uid = m.from_user.id
    if not m.photo:
        return
    file_id = m.photo[-1].file_id
    d = db_load()
    pid = secrets.token_hex(6)
    d.setdefault("payments", [])
    d["payments"].append({
        "pid": pid, "uid": uid, "method": st.get("method", "?"),
        "plan": st.get("plan"),
        "amount": PLAN_LIMITS.get(st.get("plan", ""), {}).get("price", 0) if st.get("plan") else 0,
        "proof_file_id": file_id, "status": "pending", "created": ts_iso(),
    })
    db_save(d)
    USER_STATES.pop(uid, None)
    bot.reply_to(m, f"{G['ok']} Payment proof submitted!\n{bullet('Payment ID', pid[:8])}\nAdmin will review shortly.")
    notify_owner(f"<b>💳 New Payment</b>\n{bullet('ID', pid[:8])}\n{bullet('User', str(uid))}\n"
                 f"{bullet('Plan', st.get('plan', '?'))}\n{bullet('Method', st.get('method', '?'))}")


def _handle_payment_proof_text(m: types.Message, st: Dict[str, Any]):
    uid = m.from_user.id
    text = (m.text or "").strip()
    d = db_load()
    pid = secrets.token_hex(6)
    d.setdefault("payments", [])
    d["payments"].append({
        "pid": pid, "uid": uid, "method": st.get("method", "?"),
        "plan": st.get("plan"), "txn_id": text,
        "status": "pending", "created": ts_iso(),
    })
    db_save(d)
    USER_STATES.pop(uid, None)
    bot.reply_to(m, f"{G['ok']} Payment proof submitted!\n{bullet('Payment ID', pid[:8])}\n{bullet('TxID', text[:20])}")


def _handle_topup_proof(m: types.Message):
    uid = m.from_user.id
    amount = 0
    if m.caption:
        try:
            amount = int(re.search(r'\d+', m.caption).group(0))
        except Exception:
            pass
    d = db_load()
    pid = secrets.token_hex(6)
    d.setdefault("payments", [])
    d["payments"].append({
        "pid": pid, "uid": uid, "type": "topup", "amount": amount,
        "proof_file_id": m.photo[-1].file_id if m.photo else "",
        "status": "pending", "created": ts_iso(),
    })
    db_save(d)
    USER_STATES.pop(uid, None)
    bot.reply_to(m, f"{G['ok']} Top-up proof submitted!\n{bullet('Amount', str(amount) + '৳')}")


def _handle_gift_target(m: types.Message, st: Dict[str, Any]):
    uid = m.from_user.id
    try:
        target = int((m.text or "").strip())
    except ValueError:
        bot.reply_to(m, "Invalid user ID"); return
    d = db_load()
    if str(target) not in d["users"]:
        bot.reply_to(m, "User not found"); return
    USER_STATES[uid] = {"flow": "await_gift_confirm", "target": target}
    bot.reply_to(m, f"Send <b>YES</b> to confirm gifting your plan to user <code>{target}</code>.", parse_mode="HTML")


def _handle_gift_confirm(m: types.Message, st: Dict[str, Any]):
    uid = m.from_user.id
    if (m.text or "").strip().upper() != "YES":
        USER_STATES.pop(uid, None)
        bot.reply_to(m, "Cancelled."); return
    target = st["target"]
    d = db_load()
    u = d["users"][str(uid)]
    plan = u.get("plan", "free")
    exp = u.get("plan_expires")
    u["plan"] = "free"
    u["plan_expires"] = None
    d["users"][str(target)]["plan"] = plan
    d["users"][str(target)]["plan_expires"] = exp
    db_save(d)
    USER_STATES.pop(uid, None)
    bot.reply_to(m, f"{G['ok']} Plan gifted to user <code>{target}</code>!")
    try:
        bot.send_message(target, f"<b>{G['gift']} Gift received!</b>\n"
                         f"You received a <b>{PLAN_LIMITS.get(plan, {}).get('name', plan)}</b> plan from user {uid}.")
    except Exception:
        pass
    notify_owner(f"<b>🎁 Plan Gifted</b>\n{bullet('From', str(uid))}\n{bullet('To', str(target))}\n{bullet('Plan', plan)}")


def _handle_broadcast(m: types.Message):
    uid = m.from_user.id
    if not is_admin(uid):
        return
    USER_STATES.pop(uid, None)
    text = m.text or m.caption or ""
    d = db_load()
    sent = 0
    for uid_str in d.get("users", {}):
        try:
            bot.send_message(int(uid_str), text, parse_mode="HTML")
            sent += 1
            time.sleep(0.05)
        except Exception:
            pass
    bot.reply_to(m, f"{G['ok']} Broadcast sent to {sent} users.")


def _handle_admin_finduser(m: types.Message):
    uid = m.from_user.id
    if not is_admin(uid):
        return
    query = (m.text or "").strip()
    d = db_load()
    found = []
    for k, u in d.get("users", {}).items():
        if query.lower() in str(u.get("username", "")).lower() or query == k:
            found.append(u)
    USER_STATES.pop(uid, None)
    if not found:
        bot.reply_to(m, "No users found."); return
    lines = "\n".join(f"{bullet(u.get('name', '?'), '@' + (u.get('username', '—')) + ' | ID: ' + str(u['_id']) + ' | Plan: ' + u.get('plan', 'free'))}"
                      for u in found[:10])
    bot.reply_to(m, f"<b>👥 Found {len(found)} users:</b>\n{lines}")


def _handle_ban_cmd(m: types.Message):
    uid = m.from_user.id
    if not is_admin(uid):
        return
    text = (m.text or "").strip()
    try:
        target = int(text)
    except ValueError:
        bot.reply_to(m, "Send user ID to ban/unban"); return
    d = db_load()
    u = d["users"].get(str(target))
    if not u:
        bot.reply_to(m, "User not found"); return
    u["banned"] = not u.get("banned", False)
    db_save(d)
    USER_STATES.pop(uid, None)
    status = "BANNED" if u["banned"] else "UNBANNED"
    bot.reply_to(m, f"{G['ok' if not u['banned'] else 'ban']} User {target} {status}.")


def _handle_giveplan_cmd(m: types.Message):
    uid = m.from_user.id
    if not is_admin(uid):
        return
    text = (m.text or "").strip()
    parts = text.split()
    if len(parts) < 2:
        bot.reply_to(m, "Format: UID PLAN\nExample: 123456 basic"); return
    try:
        target = int(parts[0])
    except ValueError:
        bot.reply_to(m, "Invalid UID"); return
    plan = parts[1].lower()
    if plan not in PLAN_LIMITS:
        bot.reply_to(m, f"Invalid plan. Options: {', '.join(PLAN_LIMITS.keys())}"); return
    USER_STATES.pop(uid, None)
    if grant_plan(target, plan):
        bot.reply_to(m, f"{G['ok']} Granted {plan} to user {target}")
    else:
        bot.reply_to(m, "Failed to grant plan.")


# ══════════════════════════════════════════════════════════════
# CRON RUNNER
# ══════════════════════════════════════════════════════════════
def cron_runner():
    while True:
        try:
            time.sleep(300)
            downgrade_expired_users()
            d = db_load()
            sessions = d.get("payment_sessions", {})
            now = time.time()
            stale = [sid for sid, s in sessions.items() if s.get("expires_at", 0) < now]
            for sid in stale:
                sessions.pop(sid, None)
            if stale:
                db_save(d)
        except Exception as e:
            print(f"[cron] {e}", flush=True)


# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════
def banner():
    print(f"""
╔══════════════════════════════════════════╗
║   ⚡ YAMI HOSTING v4.0                   ║
║   Universal Hosting Platform             ║
║   Python • Node • PHP • Go • Java        ║
║   Bun • Deno • 7 Runtimes                ║
║   @LEGITYAMI | @SYNTAXYAMICHANNEL       ║
╚══════════════════════════════════════════╝
""")


def main() -> int:
    banner()
    _start_keepalive()
    threading.Thread(target=cron_runner, daemon=True).start()
    print(f"[{BRAND_TAG}] Bot polling...")
    try:
        bot.infinity_polling(skip_pending=True, timeout=60, long_polling_timeout=60)
    except KeyboardInterrupt:
        print("\n[boot] shutting down...")
    except Exception as e:
        print(f"\n[boot] fatal: {e}")
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
