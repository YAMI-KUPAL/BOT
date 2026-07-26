"""
Universal runtime runner for YAMI HOSTING v4.0.
Process management with auto-dependency install, crash recovery,
CPU/RAM monitoring, and sandboxed execution.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

from ..config import (
    DIRS, G, LOG_RING, PLAN_LIMITS, SECRET_ENV_NAMES,
    SKIP_DIR_PARTS, RUNTIME_COMMANDS, RUNTIME_INSTALL_COMMANDS,
)
from ..utils import audit, fmt_bytes, ts_iso

# ═════════════════════════════════════════════════════════════════
# GLOBAL STATE
# ═════════════════════════════════════════════════════════════════
RUNNING: Dict[str, Dict[str, Any]] = {}     # bot_id -> {proc, kind, started, log, ...}
TUNNELS: Dict[str, Dict[str, Any]] = {}     # bot_id -> {proc, port, url, started}
START_TIME: float = time.time()
_runner_lock = threading.Lock()
_tunnel_lock = threading.Lock()

try:
    import psutil
except ImportError:
    psutil = None

# ═════════════════════════════════════════════════════════════════
# DEPENDENCY INSTALL — per runtime
# ═════════════════════════════════════════════════════════════════
_PYPI_ALIAS: Dict[str, str] = {
    "telebot": "pyTelegramBotAPI",
    "telegram": "python-telegram-bot",
    "telethon": "Telethon",
    "pyrogram": "Pyrogram",
    "PIL": "Pillow",
    "cv2": "opencv-python",
    "bs4": "beautifulsoup4",
    "yaml": "PyYAML",
    "dotenv": "python-dotenv",
    "Crypto": "pycryptodome",
    "discord": "discord.py",
    "httpx": "httpx",
    "aiohttp": "aiohttp",
    "aiogram": "aiogram",
    "fastapi": "fastapi",
    "flask": "flask",
    "redis": "redis",
    "pymongo": "pymongo",
    "psutil": "psutil",
    "apscheduler": "APScheduler",
    "cryptography": "cryptography",
    "github": "PyGithub",
    "requests": "requests",
    "nacl": "PyNaCl",
    "git": "GitPython",
    "lxml": "lxml",
    "psycopg2": "psycopg2-binary",
    "pkg_resources": "setuptools",
    "dateutil": "python-dateutil",
    "serial": "pyserial",
    "OpenSSL": "pyOpenSSL",
    "ujson": "ujson",
    "uvloop": "uvloop",
}

_VALIDATE_SYMBOLS: Dict[str, List[str]] = {
    "telegram": ["Update", "Bot"],
}

_PIP_BASE_FLAGS = ["--upgrade", "--no-input", "--no-warn-script-location",
                   "--disable-pip-version-check"]

def _pip_env(deps_dir: Path) -> Dict[str, str]:
    env = {**os.environ,
           "PIP_DISABLE_PIP_VERSION_CHECK": "1",
           "PIP_NO_INPUT": "1",
           "PIP_ROOT_USER_ACTION": "ignore"}
    env.pop("PYTHONUSERBASE", None)
    env.pop("PIP_USER", None)
    return env

def _filter_third_party(modules: List[str], deps_dir: Path) -> List[str]:
    """Drop stdlib and already-installed modules."""
    import importlib, importlib.util as _ilu
    stdlib = set(getattr(sys, "stdlib_module_names", set()))
    skip = stdlib | {"__future__", ""}
    deps_str = str(deps_dir)
    in_path = deps_str in sys.path
    if not in_path and deps_dir.exists():
        sys.path.insert(0, deps_str)

    out: List[str] = []
    seen: set = set()
    try:
        for m in modules:
            if not m or m in skip:
                continue
            try:
                if _ilu.find_spec(m) is not None:
                    needed = _VALIDATE_SYMBOLS.get(m)
                    if needed:
                        try:
                            _real = importlib.import_module(m)
                            if all(hasattr(_real, s) for s in needed):
                                continue
                        except Exception:
                            pass
                        import shutil
                        try:
                            del sys.modules[m]
                        except KeyError:
                            pass
                        _purge_bad_install(deps_dir, m)
                    else:
                        continue
            except (ImportError, ValueError):
                pass
            pip_name = _PYPI_ALIAS.get(m, m)
            if pip_name in seen:
                continue
            seen.add(pip_name)
            out.append(pip_name)
    finally:
        if not in_path and deps_dir.exists():
            try:
                sys.path.remove(deps_str)
            except ValueError:
                pass
    return out

def _purge_bad_install(deps_dir: Path, mod_name: str) -> None:
    import shutil
    try:
        target = deps_dir / mod_name
        if target.exists():
            shutil.rmtree(str(target), ignore_errors=True)
        for child in list(deps_dir.iterdir()):
            n = child.name.lower()
            if n.endswith((".dist-info", ".egg-info")) and n.startswith(mod_name.lower()):
                try:
                    shutil.rmtree(str(child), ignore_errors=True)
                except Exception:
                    try:
                        child.unlink()
                    except Exception:
                        pass
    except Exception as e:
        print(f"[purge] {mod_name}: {e}", file=sys.stderr)

def _scan_imports(bot_dir: Path) -> List[str]:
    import ast as _ast
    found: set = set()
    for pyfile in bot_dir.rglob("*.py"):
        if ".deps" in pyfile.parts:
            continue
        try:
            tree = _ast.parse(pyfile.read_text(errors="ignore"))
        except Exception:
            continue
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                for n in node.names:
                    if n.name:
                        found.add(n.name.split(".")[0])
            elif isinstance(node, _ast.ImportFrom):
                if node.level and node.level > 0:
                    continue
                if node.module:
                    found.add(node.module.split(".")[0])
    return sorted(found)

def install_deps(bot_dir: Path, runtime: str, log: List[str]) -> bool:
    """Install dependencies based on detected runtime."""
    try:
        if runtime == "python":
            return _install_python_deps(bot_dir, log)
        elif runtime in ("node", "bun"):
            return _install_node_deps(bot_dir, runtime, log)
        elif runtime == "php":
            return _install_php_deps(bot_dir, log)
        elif runtime == "go":
            return _install_go_deps(bot_dir, log)
        else:
            log.append(f"[{G['ok']}] No dependency manager for {runtime} — skipping")
            return True
    except subprocess.TimeoutExpired:
        log.append(f"[{G['warn']}] Dependency install timeout (>5min)")
    except FileNotFoundError as e:
        log.append(f"[{G['warn']}] Tool not found: {e}")
    except Exception as e:
        log.append(f"[{G['warn']}] Install error: {e}")
    return False

def _install_python_deps(bot_dir: Path, log: List[str]) -> bool:
    deps_dir = bot_dir / ".deps"
    deps_dir.mkdir(parents=True, exist_ok=True)
    req = bot_dir / "requirements.txt"
    pip_env = _pip_env(deps_dir)

    if req.exists():
        log.append(f"{G['div']} pip install (requirements.txt) {G['div']}")
        r = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--target", str(deps_dir),
             *_PIP_BASE_FLAGS, "-r", str(req)],
            cwd=str(bot_dir), timeout=600, capture_output=True, text=True, env=pip_env)
        for line in (r.stdout or "").splitlines()[-15:]:
            log.append(line)
        log.append(f"[{G['ok']}] requirements.txt done (rc={r.returncode})")

    try:
        modules = _scan_imports(bot_dir)
        third_party = _filter_third_party(modules, deps_dir)
        if third_party:
            log.append(f"{G['div']} auto-install {G['div']}")
            log.append(f"📦 {', '.join(third_party)}")
            r2 = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--target", str(deps_dir),
                 *_PIP_BASE_FLAGS, *third_party],
                cwd=str(bot_dir), timeout=600, capture_output=True, text=True, env=pip_env)
            for line in (r2.stdout or "").splitlines()[-10:]:
                log.append(line)
            log.append(f"[{G['ok']}] auto-install done (rc={r2.returncode})")
    except Exception as e:
        log.append(f"[{G['warn']}] scan error: {e}")
    return True

def _install_node_deps(bot_dir: Path, runtime: str, log: List[str]) -> bool:
    pkg = bot_dir / "package.json"
    if not pkg.exists():
        return False
    if (bot_dir / "node_modules").exists():
        log.append(f"[{G['ok']}] node_modules cached, skipping")
        return False
    installer = "bun" if runtime == "bun" else "npm"
    log.append(f"{G['div']} {installer} install {G['div']}")
    r = subprocess.run(
        [installer, "install", "--omit=dev", "--no-audit", "--no-fund"] if installer == "npm"
        else [installer, "install", "--production"],
        cwd=str(bot_dir), timeout=300, capture_output=True, text=True)
    for line in (r.stdout or "").splitlines()[-15:]:
        log.append(line)
    log.append(f"[{G['ok']}] {installer} done (rc={r.returncode})")
    return True

def _install_php_deps(bot_dir: Path, log: List[str]) -> bool:
    comp = bot_dir / "composer.json"
    if not comp.exists():
        return False
    if (bot_dir / "vendor").exists():
        log.append(f"[{G['ok']}] vendor cached, skipping")
        return False
    log.append(f"{G['div']} composer install {G['div']}")
    r = subprocess.run(
        ["composer", "install", "--no-dev", "--no-interaction", "--quiet"],
        cwd=str(bot_dir), timeout=300, capture_output=True, text=True)
    for line in (r.stdout or "").splitlines()[-10:]:
        log.append(line)
    log.append(f"[{G['ok']}] composer done (rc={r.returncode})")
    return True

def _install_go_deps(bot_dir: Path, log: List[str]) -> bool:
    mod = bot_dir / "go.mod"
    if not mod.exists():
        return False
    log.append(f"{G['div']} go mod tidy {G['div']}")
    r = subprocess.run(
        ["go", "mod", "tidy"],
        cwd=str(bot_dir), timeout=300, capture_output=True, text=True)
    for line in (r.stdout or "").splitlines()[-10:]:
        log.append(line)
    log.append(f"[{G['ok']}] go mod done (rc={r.returncode})")
    return True

# ═════════════════════════════════════════════════════════════════
# SANDBOXED ENVIRONMENT
# ═════════════════════════════════════════════════════════════════
def safe_env(bot_dir: Path, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in SECRET_ENV_NAMES}
    env["HOME"] = str(bot_dir)
    env["TMPDIR"] = str(bot_dir / ".tmp_run")
    env["PATH"] = "/usr/local/bin:/usr/bin:/bin"

    # Runtime-specific path additions
    deps_dir = str(bot_dir / ".deps")
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{deps_dir}:{existing_pp}" if existing_pp else deps_dir

    # Node
    node_modules = str(bot_dir / "node_modules" / ".bin")
    if ":" in env.get("PATH", ""):
        env["PATH"] = f"{node_modules}:{env['PATH']}"

    env.setdefault("NODE_ENV", "production")
    Path(env["TMPDIR"]).mkdir(parents=True, exist_ok=True)
    Path(deps_dir).mkdir(parents=True, exist_ok=True)

    if extra:
        for k, v in extra.items():
            if k in SECRET_ENV_NAMES:
                continue
            env[str(k)] = str(v)
    return env

# ═════════════════════════════════════════════════════════════════
# PROCESS LIFECYCLE
# ═════════════════════════════════════════════════════════════════
from .detectors import detect_entry

def start_child(b: Dict[str, Any]) -> Dict[str, Any]:
    """Start a bot process."""
    bid = b["_id"]
    if (b or {}).get("approval_status") == "pending":
        return {"ok": False, "error": "Bot is waiting for admin approval."}
    if (b or {}).get("approval_status") == "rejected":
        return {"ok": False, "error": "Bot was rejected by admin."}

    with _runner_lock:
        existing = RUNNING.get(bid)
        if existing and existing["proc"].poll() is None:
            return {"ok": False, "error": "Already running."}

    bot_dir = Path(b["dir"])
    if not bot_dir.exists():
        return {"ok": False, "error": "Bot folder missing."}

    # Decrypt source files
    try:
        from ..crypto_db import materialize_bot_files
        materialize_bot_files(b)
    except Exception as e:
        return {"ok": False, "error": f"decrypt failed: {e}"}

    # Detect runtime and entry
    runtime, entry = detect_entry(bot_dir)
    if not runtime or not entry:
        return {"ok": False, "error": "No entry file found. Supported: .py .js .php .go .java .ts"}

    log: List[str] = [f"{G['div_eq']} START {ts_iso()} [{runtime}] {G['div_eq']}"]

    # Install dependencies
    install_deps(bot_dir, runtime, log)

    # Build command
    cmd = get_runtime_command(runtime, entry)
    extra_env = b.get("env") or {}

    try:
        proc = subprocess.Popen(
            cmd, cwd=str(bot_dir), env=safe_env(bot_dir, extra_env),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            preexec_fn=os.setsid if os.name == "posix" else None,
        )
    except Exception as e:
        return {"ok": False, "error": f"spawn: {e}"}

    info = {
        "proc": proc, "runtime": runtime, "started": time.time() * 1000,
        "log": log, "dir": str(bot_dir), "name": b["name"],
        "owner": b["owner"], "manual_stop": False,
    }
    with _runner_lock:
        RUNNING[bid] = info
    threading.Thread(target=_drain_proc, args=(bid, proc, log, runtime), daemon=True).start()

    # Sandbox: wipe source files after load
    def _wipe():
        time.sleep(6)
        ext_map = {
            "python": (".py",), "node": (".js", ".mjs"), "php": (".php",),
            "go": (".go",), "java": (".java",), "bun": (".ts", ".js", ".mts", ".mjs"),
            "deno": (".ts", ".js", ".mts"),
        }
        exts = ext_map.get(runtime, (".py",))
        for _f in bot_dir.iterdir():
            try:
                if _f.is_file() and _f.suffix in exts and _f.name != "__init__.py":
                    _f.write_bytes(b"# sandboxed\n")
            except Exception:
                pass
    threading.Thread(target=_wipe, daemon=True).start()

    b["status"] = "running"
    b["runtime"] = runtime
    b["last_started"] = ts_iso()
    b["last_error"] = ""
    b["last_exit_code"] = None
    from ..utils import db_load, db_save
    _save_bot_simple(b)
    return {"ok": True, "pid": proc.pid, "runtime": runtime}

def _save_bot_simple(doc: Dict[str, Any]) -> None:
    from ..utils import db_load, db_save
    d = db_load()
    d["bots"][doc["_id"]] = doc
    db_save(d)

def _drain_proc(bot_id: str, proc: subprocess.Popen, log: List[str], runtime: str) -> None:
    """Read stdout/stderr and handle crash recovery."""
    try:
        if not proc.stdout:
            return
        for line in iter(proc.stdout.readline, b""):
            try:
                txt = line.decode("utf-8", "replace").rstrip()
            except Exception:
                txt = repr(line)
            log.append(txt)
            if len(log) > LOG_RING:
                del log[:len(log) - LOG_RING]
    except Exception:
        pass

    try:
        rc = proc.wait()
        log.append(f"{G['div']} process exited rc={rc} {G['div']}")
        info = RUNNING.get(bot_id)
        was_manual = (info is None) or info.get("manual_stop", False)

        from ..utils import db_load, db_save
        d = db_load()
        b_doc = d["bots"].get(bot_id)

        if b_doc is not None:
            tail = [ln for ln in log[-15:] if ln and not ln.startswith(G["div"])]
            err_text = "\n".join(tail[-8:])[:1500]
            b_doc["last_error"] = err_text
            b_doc["last_exit_code"] = int(rc) if rc is not None else None
            b_doc["last_exit_at"] = ts_iso()
            if rc not in (0, None) and not was_manual:
                b_doc["status"] = "crashed"
            db_save(d)

        if not info or not b_doc:
            return
        owner = d["users"].get(str(b_doc.get("owner", 0)))
        plan = (owner or {}).get("plan", "free")
        if PLAN_LIMITS.get(plan, {}).get("auto_restart") and not was_manual:
            log.append(f"[{G['refresh']}] auto-restart in 3s...")
            time.sleep(3)
            start_child(b_doc)
    except Exception:
        pass

def stop_child(bot_id: str, manual: bool = True) -> Dict[str, Any]:
    """Stop a bot process. Kills process group and descendants."""
    with _runner_lock:
        info = RUNNING.get(bot_id)
    if not info:
        from ..utils import db_load, db_save
        d = db_load()
        b = d["bots"].get(bot_id)
        if b and b.get("status") != "stopped":
            b["status"] = "stopped"
            db_save(d)
        return {"ok": True}

    info["manual_stop"] = manual
    proc = info["proc"]
    child_pids: List[int] = []
    if psutil is not None:
        try:
            parent = psutil.Process(proc.pid)
            for ch in parent.children(recursive=True):
                child_pids.append(ch.pid)
        except Exception:
            pass

    def _kill_pid(pid: int, sig: int) -> None:
        try:
            os.kill(pid, sig)
        except (ProcessLookupError, PermissionError):
            pass

    try:
        if os.name == "posix":
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            for pid in child_pids:
                _kill_pid(pid, signal.SIGTERM)
        else:
            proc.terminate()

        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            if os.name == "posix":
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                for pid in child_pids:
                    _kill_pid(pid, signal.SIGKILL)
            else:
                proc.kill()
            try:
                proc.wait(timeout=3)
            except Exception:
                pass
    except ProcessLookupError:
        pass

    _stop_tunnel(bot_id)
    with _runner_lock:
        RUNNING.pop(bot_id, None)

    from ..utils import db_load, db_save
    d = db_load()
    b = d["bots"].get(bot_id)
    if b:
        b["status"] = "stopped"
        db_save(d)
    return {"ok": True}

def restart_child(b: Dict[str, Any]) -> Dict[str, Any]:
    stop_child(b["_id"], manual=False)
    time.sleep(1)
    return start_child(b)

def child_status(bot_id: str, b_doc: Dict[str, Any]) -> Dict[str, Any]:
    """Get live status of a bot process."""
    info = RUNNING.get(bot_id)
    running = bool(info and info["proc"].poll() is None)
    bot_dir = Path(b_doc.get("dir") or "")
    runtime, _ = detect_entry(bot_dir) if bot_dir.exists() else (b_doc.get("runtime"), None)
    sz = 0
    try:
        for root, _, files in os.walk(bot_dir):
            for f in files:
                try:
                    sz += (Path(root) / f).stat().st_size
                except OSError:
                    pass
    except Exception:
        pass
    cpu = mem = 0.0
    if running and psutil is not None:
        try:
            p = psutil.Process(info["proc"].pid)
            cpu = p.cpu_percent(interval=0.05)
            mem = p.memory_info().rss
        except Exception:
            pass
    return {
        "running": running, "pid": info["proc"].pid if running else None,
        "runtime": (info.get("runtime") if info else runtime) or "—",
        "uptimeMs": int(time.time() * 1000 - info["started"]) if running else 0,
        "sizeBytes": sz, "logs": info["log"] if info else [],
        "cpuPct": cpu, "memBytes": mem, "sandboxed": True,
    }

# ═════════════════════════════════════════════════════════════════
# TUNNEL MANAGEMENT (Cloudflare trycloudflare)
# ═════════════════════════════════════════════════════════════════
CLOUDFLARED_CACHE = Path.home() / ".cache" / "cloudflared"
CLOUDFLARED_BIN = CLOUDFLARED_CACHE / "cloudflared"

_CF_DOWNLOAD = {
    ("linux", "x86_64"): "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64",
    ("linux", "aarch64"): "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64",
}

_TRYCLOUDFLARE_RE = __import__("re").compile(r"https?://[a-z0-9-]+\.trycloudflare\.com", __import__("re").IGNORECASE)

def _ensure_cloudflared() -> Optional[Path]:
    if CLOUDFLARED_BIN.exists() and os.access(CLOUDFLARED_BIN, os.X_OK):
        return CLOUDFLARED_BIN
    on_path = __import__("shutil").which("cloudflared")
    if on_path:
        return Path(on_path)
    try:
        import platform, requests
        sysname = platform.system().lower()
        machine = platform.machine().lower()
        url = _CF_DOWNLOAD.get((sysname, machine))
        if not url:
            return None
        CLOUDFLARED_CACHE.mkdir(parents=True, exist_ok=True)
        tmp = CLOUDFLARED_BIN.with_suffix(".part")
        with requests.get(url, stream=True, timeout=120) as r:
            r.raise_for_status()
            with open(tmp, "wb") as f:
                for chunk in r.iter_content(chunk_size=1 << 16):
                    if chunk:
                        f.write(chunk)
        tmp.chmod(0o755)
        tmp.rename(CLOUDFLARED_BIN)
        return CLOUDFLARED_BIN
    except Exception:
        return None

def _port_in_use(port: int) -> bool:
    import socket as _s
    for fam, addr in ((_s.AF_INET, ("127.0.0.1", port)), (_s.AF_INET6, ("::1", port))):
        try:
            with _s.socket(fam, _s.SOCK_STREAM) as sk:
                sk.settimeout(0.4)
                if sk.connect_ex(addr) == 0:
                    return True
        except Exception:
            continue
    return False

def _start_tunnel(bot_id: str, port: int) -> Dict[str, Any]:
    if not (1 <= port <= 65535):
        return {"ok": False, "error": "Port must be between 1 and 65535"}
    with _tunnel_lock:
        existing = TUNNELS.get(bot_id)
        if existing and existing.get("proc") and existing["proc"].poll() is None:
            return {"ok": False, "error": "Tunnel already running."}
    if not _port_in_use(port):
        return {"ok": False, "error": f"Nothing listening on port {port}."}
    bin_path = _ensure_cloudflared()
    if not bin_path:
        return {"ok": False, "error": "cloudflared not available."}

    log_buf: Deque[str] = deque(maxlen=200)
    try:
        proc = subprocess.Popen(
            [str(bin_path), "tunnel", "--no-autoupdate", "--url", f"http://localhost:{port}"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            preexec_fn=os.setsid if os.name == "posix" else None,
        )
    except Exception as e:
        return {"ok": False, "error": f"cloudflared: {e}"}

    rec: Dict[str, Any] = {"proc": proc, "port": port, "url": None,
                            "started": int(time.time()), "log": log_buf}
    with _tunnel_lock:
        TUNNELS[bot_id] = rec

    def _drain():
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip()
            log_buf.append(line)
            if rec["url"] is None:
                m = _TRYCLOUDFLARE_RE.search(line)
                if m:
                    rec["url"] = m.group(0)

    threading.Thread(target=_drain, daemon=True).start()
    deadline = time.time() + 15
    while time.time() < deadline and rec["url"] is None and proc.poll() is None:
        time.sleep(0.3)

    if proc.poll() is not None and rec["url"] is None:
        with _tunnel_lock:
            TUNNELS.pop(bot_id, None)
        return {"ok": False, "error": "cloudflared exited early."}

    if rec["url"] is None:
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.terminate()
        except Exception:
            pass
        with _tunnel_lock:
            TUNNELS.pop(bot_id, None)
        return {"ok": False, "error": "Tunnel timed out."}

    return {"ok": True, "url": rec["url"], "port": port}

def _stop_tunnel(bot_id: str) -> bool:
    with _tunnel_lock:
        rec = TUNNELS.pop(bot_id, None)
    if not rec:
        return False
    proc = rec.get("proc")
    if not proc:
        return True
    try:
        if os.name == "posix":
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
        else:
            proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            try:
                if os.name == "posix":
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                else:
                    proc.kill()
            except Exception:
                pass
    except Exception:
        pass
    return True
