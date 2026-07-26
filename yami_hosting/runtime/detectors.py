"""
Runtime detection for YAMI HOSTING v4.0.
Automatically detects project language and entry files.
Supports: Python, Node.js, PHP, Go, Java, Bun, Deno.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..config import ENTRY_FILES, SKIP_DIR_PARTS, RUNTIME_COMMANDS

# ═════════════════════════════════════════════════════════════════
# RUNTIME DETECTION
# ═════════════════════════════════════════════════════════════════
def _iter_source_files(bot_dir: Path) -> List[Path]:
    """Recursive scan skipping dependency/cache/VCS folders."""
    out: List[Path] = []
    for p in bot_dir.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIR_PARTS for part in p.parts):
            continue
        out.append(p)
    return sorted(out, key=lambda x: (len(x.parts), str(x)))

def _has_file(bot_dir: Path, pattern: str) -> bool:
    """Check if any file matching pattern exists (shallow or recursive)."""
    for p in _iter_source_files(bot_dir):
        if p.match(pattern):
            return True
    return False

def _has_config(bot_dir: Path, names: List[str]) -> bool:
    for name in names:
        if (bot_dir / name).exists():
            return True
    return False

def detect_runtime(bot_dir: Path) -> str:
    """Detect the primary runtime for a project directory.
    Returns one of: python, node, php, go, java, bun, deno, unknown."""
    files = _iter_source_files(bot_dir)
    exts = {f.suffix.lower() for f in files}
    fnames = {f.name for f in files}

    # Count dominant extensions
    py_count = sum(1 for f in files if f.suffix == ".py")
    js_count = sum(1 for f in files if f.suffix in (".js", ".mjs"))
    ts_count = sum(1 for f in files if f.suffix in (".ts", ".mts"))
    php_count = sum(1 for f in files if f.suffix == ".php")
    go_count = sum(1 for f in files if f.suffix == ".go")
    java_count = sum(1 for f in files if f.suffix == ".java")

    # Config-file based detection (strongest signal)
    if _has_config(bot_dir, ["go.mod"]):
        return "go"
    if _has_config(bot_dir, ["pom.xml", "build.gradle", "build.gradle.kts"]):
        return "java"
    if _has_config(bot_dir, ["composer.json"]):
        return "php"
    if _has_config(bot_dir, ["bun.lockb", "bun.lock"]):
        return "bun"
    if _has_config(bot_dir, ["deno.json", "deno.jsonc", "import_map.json"]):
        return "deno"
    if _has_config(bot_dir, ["package.json"]):
        # Could be Node.js or Bun — check for bun indicators
        if ts_count > js_count and _has_config(bot_dir, ["bun.lockb", "bun.lock"]):
            return "bun"
        return "node"

    # Count-based (most likely runtime)
    counts = [
        ("python", py_count),
        ("node", js_count),
        ("php", php_count),
        ("go", go_count),
        ("java", java_count),
        ("deno", ts_count),
    ]
    counts.sort(key=lambda x: -x[1])
    best = counts[0]
    if best[1] > 0:
        # TypeScript could be Deno or Bun
        if best[0] == "deno" and _has_config(bot_dir, ["package.json"]):
            return "bun" if _has_config(bot_dir, ["bun.lockb"]) else "node"
        return best[0]

    return "unknown"

def detect_entry(bot_dir: Path, runtime: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
    """Find the entry file. Returns (runtime, relative_path).
    Args:
        bot_dir: Project directory
        runtime: Force a specific runtime (python, node, php, go, java, bun, deno)
    """
    if runtime is None:
        runtime = detect_runtime(bot_dir)

    entry_names = ENTRY_FILES.get(runtime, ENTRY_FILES["python"])

    # Try shallow first (most projects)
    for name in entry_names:
        p = bot_dir / name
        if p.exists():
            return (runtime, name)

    # Try recursive
    for name in entry_names:
        for p in _iter_source_files(bot_dir):
            if p.name == name:
                return (runtime, str(p.relative_to(bot_dir)))

    # Brute force: any file matching runtime extension
    ext_map = {
        "python": (".py",),
        "node": (".js", ".mjs"),
        "php": (".php",),
        "go": (".go",),
        "java": (".java",),
        "bun": (".ts", ".js", ".mts", ".mjs"),
        "deno": (".ts", ".js", ".mts"),
    }
    exts = ext_map.get(runtime, (".py",))
    for p in _iter_source_files(bot_dir):
        if p.suffix in exts:
            return (runtime, str(p.relative_to(bot_dir)))

    # Inner zip extraction fallback
    import zipfile
    zip_files = [p for p in bot_dir.rglob("*.zip")
                 if not any(part in SKIP_DIR_PARTS for part in p.parts)]
    if zip_files:
        try:
            with zipfile.ZipFile(zip_files[0], "r") as z:
                z.extractall(bot_dir)
        except Exception:
            return (None, None)
        return detect_entry(bot_dir, runtime)

    return (None, None)

def get_runtime_command(runtime: str, entry: str) -> List[str]:
    """Build the command to run a project based on runtime."""
    from ..config import RUNTIME_COMMANDS
    base = RUNTIME_COMMANDS.get(runtime, ["python3", "-u"])
    if runtime == "java":
        # For Java, the entry should be a JAR or class
        return base + [entry]
    return base + [entry]

def get_runtime_icon(runtime: str) -> str:
    from ..config import G
    icons = {
        "python": G.get("python", "🐍"),
        "node": G.get("nodejs", "💚"),
        "php": G.get("php_icon", "🐘"),
        "go": G.get("go_icon", "🔵"),
        "java": G.get("java_icon", "☕"),
        "bun": G.get("bun_icon", "🥟"),
        "deno": G.get("deno_icon", "🦕"),
    }
    return icons.get(runtime, "📄")

def get_runtime_name(runtime: str) -> str:
    names = {
        "python": "Python",
        "node": "Node.js",
        "php": "PHP",
        "go": "Go",
        "java": "Java",
        "bun": "Bun",
        "deno": "Deno",
    }
    return names.get(runtime, runtime.capitalize())

