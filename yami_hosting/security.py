"""
Enhanced security scanner for YAMI HOSTING v4.0.
Multi-layer: pattern matching + AST analysis + AI-powered review.
"""
from __future__ import annotations

import ast as _ast
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..config import G

# ═════════════════════════════════════════════════════════════════
# SECURITY PATTERNS
# ═════════════════════════════════════════════════════════════════
_SEC_PATTERNS = {
    "🔴 Data Theft": [
        (r'os\.walk\s*\(\s*["\'][/\\](?:root|home|etc|var|proc)["\']',
         "System directory traversal — stealing server files"),
        (r'send_document\s*\(.*open\s*\(\s*["\'][/\\](?:root|etc|proc|sys)',
         "System file exfiltration detected"),
        (r'zipfile\.ZipFile.*["\']w["\'].*\bos\.walk\b.*["\'][/\\](?:root|etc|home)',
         "System files being zipped for exfiltration"),
        (r'glob\.glob\s*\(["\'][/\\]\*', "Root glob scan — searching server files"),
        (r'shutil\.copy.*["\'][/\\]root', "Copying /root files"),
        (r'ROOT_DIR\s*=\s*["\'][/\\]["\']', "Root directory targeted"),
    ],
    "🔴 Backdoor": [
        (r'subprocess\s*\.\s*(?:Popen|call|run)\s*\([^\n]*shell\s*=\s*True[^\n]*(?:input|stdin)',
         "Shell injection with user input"),
        (r'marshal\.loads\s*\(', "Marshalled bytecode — obfuscated execution"),
    ],
    "🔴 Exposed Credentials": [],
    "🟡 Obfuscation": [
        (r'base64\.b64decode\s*\(.*\)\s*[\)\s]*\bexec\b',
         "Base64 decode + execute — hidden code"),
        (r'(?:\\x[0-9a-fA-F]{2}){6,}', "Long hex strings — obfuscated code"),
        (r'zlib\.decompress\s*\(.*\)\s*[\)\s]*\bexec\b',
         "Compressed + executed hidden code"),
    ],
    "🟡 Suspicious Network": [
        (r'devil-api\.com|elementfx\.io', "Known malicious API endpoint"),
        (r'open\s*\(\s*["\'][/\\](?:root|etc|proc|sys).*(?:requests|urllib).*(?:post|put)',
         "System file HTTP POST — data exfiltration"),
        (r'pastebin\.com/raw', "Pastebin raw fetch — remote code load"),
    ],
    "🟠 Resource Abuse": [
        (r'multiprocessing\.Pool\s*\(\s*(?:None|\d{3,})',
         "Massive process pool — resource abuse"),
        (r'fork\s*\(\s*\).*fork\s*\(', "Fork bomb pattern"),
    ],
}

_SEC_TOKEN_RE = re.compile(r'\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b')

# ═════════════════════════════════════════════════════════════════
# STATIC SCAN (regex)
# ═════════════════════════════════════════════════════════════════
def _sec_static_scan(code: str) -> dict:
    results: Dict[str, List[str]] = {}
    for category, pattern_list in _SEC_PATTERNS.items():
        hits = []
        for pattern, description in pattern_list:
            if re.search(pattern, code, re.IGNORECASE | re.MULTILINE):
                hits.append(description)
        if hits:
            results[category] = hits
    tokens = _SEC_TOKEN_RE.findall(code)
    if tokens:
        results.setdefault("🔴 Exposed Credentials", [])
        results["🔴 Exposed Credentials"].append(f"Bot Token found: {tokens[0][:15]}...")
    return results

# ═════════════════════════════════════════════════════════════════
# AST SCAN
# ═════════════════════════════════════════════════════════════════
def _sec_ast_scan(code: str) -> List[str]:
    findings: List[str] = []
    try:
        tree = _ast.parse(code)
    except SyntaxError as e:
        findings.append(f"Code parsing failed: {e} — may be obfuscated")
        return findings

    for node in _ast.walk(tree):
        if isinstance(node, _ast.Call):
            func = node.func
            # os.walk with system paths
            if isinstance(func, _ast.Attribute):
                if (func.attr == 'walk' and isinstance(func.value, _ast.Name)
                        and func.value.id == 'os' and node.args):
                    arg = node.args[0]
                    if isinstance(arg, _ast.Constant) and isinstance(arg.value, str):
                        if arg.value in ['/root', '/etc', '/home', '/proc', '/var']:
                            findings.append(f"os.walk('{arg.value}') - sensitive directory scan")
            # eval/exec with dynamic input
            if isinstance(func, _ast.Name) and func.id in ('eval', 'exec'):
                if node.args:
                    arg0 = node.args[0]
                    if isinstance(arg0, _ast.Call):
                        findings.append(f"Dangerous: {func.id}() — dynamic code execution")
                    elif isinstance(arg0, _ast.Attribute):
                        findings.append(f"Dangerous: {func.id}() — attribute-based input")
            # __import__('os')
            if isinstance(func, _ast.Name) and func.id == '__import__':
                if node.args and isinstance(node.args[0], _ast.Constant):
                    if node.args[0].value == 'os':
                        findings.append("Dynamic __import__('os') — code injection")
    return findings

# ═════════════════════════════════════════════════════════════════
# RISK CALCULATION
# ═════════════════════════════════════════════════════════════════
def _sec_calculate_risk(static_findings: dict, ast_findings: List[str]) -> int:
    weights = {
        "🔴 Data Theft": 40, "🔴 Backdoor": 40,
        "🔴 Exposed Credentials": 10, "🟡 Suspicious Network": 12,
        "🟡 Obfuscation": 10, "🟠 Resource Abuse": 8,
    }
    score = sum(weights.get(cat, 5) * min(len(hits), 3)
                for cat, hits in static_findings.items() if hits)
    unique_ast = list(dict.fromkeys(ast_findings))
    score += min(len(unique_ast) * 5, 20)
    return min(score, 100)

def _sec_get_verdict(risk_score: int, static_findings: dict) -> Tuple[str, str]:
    has_blocking = any(static_findings.get(c) for c in ("🔴 Data Theft", "🔴 Backdoor"))
    has_credentials = bool(static_findings.get("🔴 Exposed Credentials"))

    if has_blocking and risk_score >= 70:
        return "DANGEROUS", "REJECT"
    if risk_score >= 85:
        return "DANGEROUS", "REJECT"
    if has_credentials and not has_blocking and risk_score < 40:
        return "SUSPICIOUS", "MANUAL_REVIEW"
    if has_blocking and risk_score >= 35:
        return "SUSPICIOUS", "MANUAL_REVIEW"
    if risk_score >= 55:
        return "SUSPICIOUS", "MANUAL_REVIEW"
    return "SAFE", "APPROVE"

# ═════════════════════════════════════════════════════════════════
# AI SCANNER (OpenRouter)
# ═════════════════════════════════════════════════════════════════
import urllib.request as _urllib_req

_AI_SCAN_PROMPT = """You are a security expert reviewing uploaded bot code.
Analyze the code below for malicious behavior. Look for:
1. Data theft — reading/sending server files, credentials, databases
2. Backdoors — eval/exec with remote payloads, hidden commands
3. Spyware — logging user data secretly and sending it out
4. Credential theft — stealing tokens, passwords, API keys
5. Resource abuse — fork bombs, crypto mining

Reply ONLY with a JSON object (no markdown, no extra text):
{
  "verdict": "SAFE" | "SUSPICIOUS" | "DANGEROUS",
  "risk_score": <0-100>,
  "reason": "<one sentence summary>",
  "threats": ["<threat1>", "<threat2>"]
}

IMPORTANT: Normal Telegram bots using telebot, python-telegram-bot, etc.
are SAFE. Do NOT flag standard bot patterns as malicious.

CODE TO ANALYZE:
"""

def _ai_scan_code(code: str, filename: str = "file.py") -> Optional[Dict[str, Any]]:
    base_url = os.environ.get("AI_INTEGRATIONS_OPENROUTER_BASE_URL", "").rstrip("/")
    api_key = os.environ.get("AI_INTEGRATIONS_OPENROUTER_API_KEY", "no-key")
    if not base_url:
        return None

    code_snippet = code[:6000]
    payload = json.dumps({
        "model": "google/gemma-4-31b-it:free",
        "max_tokens": 512, "temperature": 0.1,
        "messages": [{"role": "user", "content": f"{_AI_SCAN_PROMPT}{code_snippet}"}]
    }).encode("utf-8")

    req = _urllib_req.Request(
        f"{base_url}/chat/completions", data=payload,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST")
    try:
        with _urllib_req.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read())
        content = body["choices"][0]["message"]["content"].strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        result = json.loads(content)
        return {
            "ai_verdict": result.get("verdict", "SAFE"),
            "ai_risk_score": int(result.get("risk_score", 0)),
            "ai_reason": result.get("reason", ""),
            "ai_threats": result.get("threats", []),
        }
    except Exception as e:
        print(f"[ai_scan] error: {e}", file=sys.stderr)
        return None

# ═════════════════════════════════════════════════════════════════
# MAIN SCAN FUNCTIONS
# ═════════════════════════════════════════════════════════════════
def _sec_scan_code(code: str, filename: str = "file.py") -> dict:
    sf = _sec_static_scan(code)
    af = _sec_ast_scan(code)
    risk = _sec_calculate_risk(sf, af)
    verdict, recommendation = _sec_get_verdict(risk, sf)
    all_threats: List[str] = [f"{c}: {h}" for c, hits in sf.items() for h in hits] + af
    if verdict == "DANGEROUS":
        summary = f"⚠️ DANGEROUS! {len(all_threats)} threats found."
    elif verdict == "SUSPICIOUS":
        summary = "🔍 Suspicious — manual review needed."
    else:
        summary = "✅ Appears safe."
    return {"verdict": verdict, "risk_score": risk, "findings": sf,
            "ast_findings": af, "all_threats": all_threats,
            "recommendation": recommendation, "summary": summary, "filename": filename}

def _sec_scan_archive(file_path: str) -> dict:
    tmp = tempfile.mkdtemp()
    try:
        if file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as z:
                for name in z.namelist():
                    if name.startswith('/') or '..' in name:
                        return {"verdict": "DANGEROUS", "risk_score": 99,
                                "findings": {"🔴 Zip Slip": ["Dangerous paths in ZIP"]},
                                "ast_findings": [], "recommendation": "REJECT",
                                "summary": "ZIP Slip attack!", "all_threats": []}
                z.extractall(tmp)
        elif file_path.endswith(('.tar.gz', '.tgz', '.tar')):
            with tarfile.open(file_path, 'r:*') as t:
                t.extractall(tmp)
        py_files = list(Path(tmp).rglob("*.py"))
        if not py_files:
            return {"verdict": "SUSPICIOUS", "risk_score": 20,
                    "findings": {"🟡 Warning": ["No .py files in archive"]},
                    "ast_findings": [], "recommendation": "MANUAL_REVIEW",
                    "summary": "No Python files found.", "all_threats": []}
        worst = None
        for py_file in py_files[:10]:
            try:
                result = _sec_scan_code(py_file.read_text(errors='ignore'), py_file.name)
                if worst is None or result['risk_score'] > worst['risk_score']:
                    worst = result
            except Exception:
                continue
        return worst or {"verdict": "SAFE", "risk_score": 0, "recommendation": "APPROVE",
                         "summary": "Appears safe", "all_threats": []}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def scan_file(file_path: str) -> dict:
    """Single-file scan: detects archives and delegates."""
    filename = os.path.basename(file_path)
    try:
        if filename.lower().endswith(('.zip', '.tar.gz', '.tgz', '.tar')):
            return _sec_scan_archive(file_path)
        elif filename.lower().endswith(('.py', '.pyc', '.pyo', '.js', '.ts', '.php', '.go', '.java')):
            with open(file_path, 'r', errors='ignore') as f:
                return _sec_scan_code(f.read(), filename)
        else:
            return {"verdict": "SUSPICIOUS", "risk_score": 30,
                    "findings": {"🟡 Warning": [f"Unknown type: {filename}"]},
                    "ast_findings": [], "recommendation": "MANUAL_REVIEW",
                    "summary": f"File type not allowed.", "all_threats": [], "filename": filename}
    except Exception as e:
        return {"verdict": "ERROR", "risk_score": 50, "findings": {},
                "ast_findings": [], "recommendation": "MANUAL_REVIEW",
                "summary": f"Scan error: {e}", "all_threats": [], "filename": filename}

def combined_scan(file_path: str) -> dict:
    """Pattern + AI scan with merged results."""
    pattern_result = scan_file(file_path)
    filename = os.path.basename(file_path)

    ai_result = None
    if filename.lower().endswith(('.py', '.js', '.ts', '.php')):
        try:
            with open(file_path, 'r', errors='ignore') as f:
                ai_result = _ai_scan_code(f.read(), filename)
        except Exception:
            pass

    if ai_result is None:
        return pattern_result

    ai_risk = ai_result["ai_risk_score"]
    pat_risk = pattern_result.get("risk_score", 0)
    merged_risk = int(ai_risk * 0.6 + pat_risk * 0.4)

    ai_v = ai_result["ai_verdict"]
    pat_v = pattern_result.get("verdict", "SAFE")

    if ai_v == "DANGEROUS":
        verdict, recommendation = "DANGEROUS", "REJECT"
    elif ai_v == "SUSPICIOUS" or pat_v == "DANGEROUS":
        verdict, recommendation = "SUSPICIOUS", "MANUAL_REVIEW"
    elif pat_v == "SUSPICIOUS":
        verdict, recommendation = "SUSPICIOUS", "MANUAL_REVIEW"
    else:
        verdict, recommendation = "SAFE", "APPROVE"

    all_threats = list(pattern_result.get("all_threats", []))
    for t in ai_result.get("ai_threats", []):
        entry = f"🤖 AI: {t}"
        if entry not in all_threats:
            all_threats.append(entry)

    ai_label = f"🤖 AI ({ai_v} {ai_risk}/100): {ai_result['ai_reason']}"
    if verdict == "DANGEROUS":
        summary = f"⚠️ DANGEROUS! {ai_label}"
    elif verdict == "SUSPICIOUS":
        summary = f"🔍 Suspicious. {ai_label}"
    else:
        summary = f"✅ Safe. {ai_label}"

    return {
        **pattern_result,
        "verdict": verdict, "risk_score": merged_risk,
        "recommendation": recommendation, "summary": summary,
        "all_threats": all_threats, "ai_result": ai_result,
    }
