
from __future__ import annotations

import ast
import io
import re
import zipfile
from pathlib import PurePosixPath
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile

APP_VERSION = "3.0.0"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_EXPANDED_BYTES = 50 * 1024 * 1024
MAX_FILES = 1000
MAX_FILE_BYTES = 1_500_000

app = FastAPI(
    title="OMEGA Defensive Security Auditor",
    version=APP_VERSION,
    description="Static source-code analysis only."
)

SOURCE_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".php", ".java", ".go", ".rb", ".sol", ".sql", ".sh"
}

SKIP_PARTS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    "dist", "build", "vendor", ".next", "coverage"
}

RULES: list[dict[str, Any]] = [
    {
        "id": "JS-HTML-INJECTION",
        "title": "Potential unsafe HTML insertion",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "ext": {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
        "pattern": r"\.innerHTML\s*=",
        "why": "Untrusted HTML assigned to innerHTML may cause DOM XSS.",
        "fix": "Prefer textContent or a trusted HTML sanitizer."
    },
    {
        "id": "JS-EVAL",
        "title": "Dynamic JavaScript evaluation",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "ext": {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
        "pattern": r"\beval\s*\(|\bnew\s+Function\s*\(",
        "why": "Dynamic evaluation can execute strings as code.",
        "fix": "Avoid eval and new Function; use explicit parsing."
    },
    {
        "id": "PY-SHELL-TRUE",
        "title": "Subprocess uses shell=True",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "ext": {".py"},
        "pattern": r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\([\s\S]{0,500}?\bshell\s*=\s*True",
        "why": "Command injection may occur if untrusted input reaches the command.",
        "fix": "Use shell=False with a fixed argument list."
    },
    {
        "id": "PY-OS-COMMAND",
        "title": "OS command API used",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "ext": {".py"},
        "pattern": r"\bos\.(?:system|popen)\s*\(",
        "why": "OS command APIs require review of their arguments.",
        "fix": "Prefer subprocess with shell=False and validated arguments."
    },
    {
        "id": "PY-EVAL",
        "title": "Dynamic Python evaluation",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "ext": {".py"},
        "pattern": r"\b(?:eval|exec)\s*\(",
        "why": "Dynamic evaluation may execute untrusted code.",
        "fix": "Avoid eval and exec for untrusted input."
    },
    {
        "id": "SQL-DYNAMIC",
        "title": "Potential dynamically constructed SQL",
        "severity": "HIGH",
        "confidence": "LOW",
        "ext": {".py", ".php", ".js", ".ts", ".java", ".rb", ".go", ".sql"},
        "pattern": r"(?:execute|executemany|query)\s*\(\s*(?:f[\"']|[\"'][^\"']*(?:\+|\.format\s*\())",
        "why": "Query formatting or concatenation may introduce SQL injection.",
        "fix": "Use parameterized queries and bind values separately."
    },
    {
        "id": "PY-UNSAFE-DESERIALIZATION",
        "title": "Potential unsafe deserialization",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "ext": {".py"},
        "pattern": r"\b(?:pickle\.loads?|marshal\.loads?)\s*\(",
        "why": "Loading untrusted serialized data may be dangerous.",
        "fix": "Avoid pickle/marshal for untrusted data; consider JSON."
    },
    {
        "id": "PY-YAML-UNSAFE",
        "title": "Potential unsafe YAML loading",
        "severity": "MEDIUM",
        "confidence": "LOW",
        "ext": {".py"},
        "pattern": r"\byaml\.(?:load|unsafe_load)\s*\(",
        "why": "Safety depends on the YAML loader and library version.",
        "fix": "Use yaml.safe_load or an explicitly safe loader."
    },
    {
        "id": "TLS-VERIFY-DISABLED",
        "title": "TLS verification disabled",
        "severity": "HIGH",
        "confidence": "HIGH",
        "ext": {".py"},
        "pattern": r"\bverify\s*=\s*False",
        "why": "Disabling TLS verification can expose connections to interception.",
        "fix": "Keep certificate verification enabled."
    },
    {
        "id": "HARDCODED-SECRET",
        "title": "Possible hard-coded credential",
        "severity": "MEDIUM",
        "confidence": "LOW",
        "ext": {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".java", ".go", ".rb", ".sol"},
        "pattern": r"""(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|password|passwd)\b\s*[:=]\s*["'][^"']{8,}["']""",
        "why": "A credential-like variable may contain a hard-coded value.",
        "fix": "Use environment variables or a secret manager."
    },
    {
        "id": "SOL-TX-ORIGIN",
        "title": "Solidity tx.origin requires review",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "ext": {".sol"},
        "pattern": r"\btx\.origin\b",
        "why": "Using tx.origin for authorization may permit phishing-style bypasses.",
        "fix": "Review authorization and normally use msg.sender."
    },
    {
        "id": "SOL-DELEGATECALL",
        "title": "Solidity delegatecall requires review",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "ext": {".sol"},
        "pattern": r"\.delegatecall\s*\(",
        "why": "delegatecall executes code in the caller's storage context.",
        "fix": "Review target validation, access control and storage layout."
    },
    {
        "id": "PHP-COMMAND",
        "title": "PHP command execution function",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "ext": {".php"},
        "pattern": r"\b(?:system|shell_exec|exec|passthru|popen|proc_open)\s*\(",
        "why": "Command execution may be unsafe when arguments contain untrusted data.",
        "fix": "Avoid shell execution or strictly validate arguments."
    }
]

COMPILED_RULES = [
    (rule, re.compile(rule["pattern"], re.MULTILINE))
    for rule in RULES
]


def safe_member_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)

    if path.is_absolute() or ".." in path.parts:
        return False

    if re.match(r"^[A-Za-z]:", normalized):
        return False

    if any(part in SKIP_PARTS for part in path.parts):
        return False

    return True


def scan_source(name: str, source: str) -> list[dict[str, Any]]:
    suffix = PurePosixPath(name).suffix.lower()
    lines = source.splitlines()
    findings = []

    for rule, pattern in COMPILED_RULES:
        if suffix not in rule["ext"]:
            continue

        for match in pattern.finditer(source):
            line_no = source.count("\n", 0, match.start()) + 1

            evidence = (
                lines[line_no - 1].strip()[:240]
                if 0 < line_no <= len(lines)
                else ""
            )

            findings.append({
                "rule_id": rule["id"],
                "title": rule["title"],
                "severity": rule["severity"],
                "confidence": rule["confidence"],
                "file": name,
                "line": line_no,
                "evidence": evidence,
                "confirmed": False,
                "explanation": rule["why"],
                "recommendation": rule["fix"]
            })

    # AST check supplements the regex check for Python.
    if suffix == ".py":
        try:
            tree = ast.parse(source, filename=name)

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue

                func = node.func
                parts = []

                while isinstance(func, ast.Attribute):
                    parts.append(func.attr)
                    func = func.value

                if isinstance(func, ast.Name):
                    parts.append(func.id)

                call_name = ".".join(reversed(parts))

                subprocess_calls = {
                    "subprocess.run", "subprocess.Popen",
                    "subprocess.call", "subprocess.check_call",
                    "subprocess.check_output"
                }

                shell_true = any(
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                    for kw in node.keywords
                )

                already_found = any(
                    item["rule_id"] == "PY-SHELL-TRUE"
                    and item["line"] == node.lineno
                    for item in findings
                )

                if (
                    call_name in subprocess_calls
                    and shell_true
                    and not already_found
                ):
                    line_no = node.lineno
                    evidence = (
                        lines[line_no - 1].strip()[:240]
                        if line_no <= len(lines)
                        else ""
                    )

                    findings.append({
                        "rule_id": "PY-SHELL-TRUE",
                        "title": "Subprocess uses shell=True",
                        "severity": "HIGH",
                        "confidence": "MEDIUM",
                        "file": name,
                        "line": line_no,
                        "evidence": evidence,
                        "confirmed": False,
                        "explanation": (
                            "AST found shell=True. Impact depends on "
                            "whether untrusted data reaches the command."
                        ),
                        "recommendation": (
                            "Use shell=False with a fixed argument list."
                        )
                    })

        except (SyntaxError, ValueError):
            pass

    # Remove duplicate matches for the same rule, file and line.
    unique = {}

    for finding in findings:
        key = (
            finding["rule_id"],
            finding["file"],
            finding["line"]
        )
        unique[key] = finding

    return sorted(
        unique.values(),
        key=lambda item: (
            item["file"],
            item["line"],
            item["rule_id"]
        )
    )


def analyze_zip(raw: bytes, filename: str) -> dict[str, Any]:
    if not raw:
        raise HTTPException(400, "Uploaded ZIP is empty.")

    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "Upload exceeds the size limit.")

    if not zipfile.is_zipfile(io.BytesIO(raw)):
        raise HTTPException(400, "Invalid ZIP file.")

    findings = []
    warnings = []
    files_scanned = 0
    expanded_total = 0

    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()

            if len(members) > MAX_FILES:
                raise HTTPException(413, "ZIP contains too many entries.")

            for member in members:
                if member.is_dir():
                    continue

                if not safe_member_name(member.filename):
                    warnings.append(
                        "Skipped unsafe/excluded path: "
                        + member.filename[:180]
                    )
                    continue

                suffix = PurePosixPath(member.filename).suffix.lower()

                if suffix not in SOURCE_SUFFIXES:
                    continue

                if member.file_size > MAX_FILE_BYTES:
                    warnings.append(
                        "Skipped oversized file: "
                        + member.filename[:180]
                    )
                    continue

                expanded_total += member.file_size

                if expanded_total > MAX_EXPANDED_BYTES:
                    raise HTTPException(
                        413,
                        "Expanded ZIP content exceeds the safety limit."
                    )

                try:
                    data = archive.read(member)
                    source = data.decode("utf-8", errors="replace")
                except (
                    RuntimeError, zipfile.BadZipFile, OSError
                ) as exc:
                    warnings.append(
                        f"Could not read {member.filename[:180]}: "
                        f"{type(exc).__name__}"
                    )
                    continue

                files_scanned += 1
                findings.extend(
                    scan_source(member.filename, source)
                )

    except zipfile.BadZipFile:
        raise HTTPException(400, "ZIP could not be read.")

    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4
    }

    findings.sort(
        key=lambda item: (
            severity_order.get(item["severity"], 9),
            item["file"],
            item["line"]
        )
    )

    return {
        "scanner": "OMEGA Defensive Security Auditor",
        "version": APP_VERSION,
        "filename": filename[:200],
        "status": (
            "REVIEW_REQUIRED"
            if findings
            else "NO_MATCHING_PATTERNS"
        ),
        "mode": "static_analysis_only",
        "files_processed": files_scanned,
        "findings_count": len(findings),
        "findings": findings,
        "warnings": warnings,
        "limits": {
            "upload_bytes": MAX_UPLOAD_BYTES,
            "expanded_bytes": MAX_EXPANDED_BYTES,
            "max_files": MAX_FILES,
            "max_file_bytes": MAX_FILE_BYTES
        },
        "note": (
            "Pattern matches are not proof of exploitability. "
            "Findings remain unconfirmed until manually validated. "
            "Uploaded source code is never executed."
        )
    }


@app.get("/")
def home():
    return {
        "name": "OMEGA Defensive Security Auditor",
        "version": APP_VERSION,
        "mode": "static_analysis_only",
        "docs": "/docs"
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": APP_VERSION
    }


@app.post("/audit/file")
async def audit_file(file: UploadFile = File(...)):
    filename = file.filename or "upload.zip"

    if not filename.lower().endswith(".zip"):
        raise HTTPException(
            400,
            "Please upload a .zip file."
        )

    try:
        raw = await file.read(MAX_UPLOAD_BYTES + 1)
    finally:
        await file.close()

    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "Upload exceeds the size limit.")

    return analyze_zip(raw, filename)


@app.post("/audit/text")
async def audit_text(
    text: str = Form(...),
    filename: str = Form("snippet.py")
):
    if len(text.encode("utf-8")) > 500_000:
        raise HTTPException(413, "Text input exceeds 500 KB.")

    suffix = PurePosixPath(filename).suffix.lower()

    if suffix not in SOURCE_SUFFIXES:
        raise HTTPException(
            400,
            f"Unsupported source extension: {suffix or '(none)'}"
        )

    findings = scan_source(filename, text)

    return {
        "scanner": "OMEGA Defensive Security Auditor",
        "version": APP_VERSION,
        "filename": filename,
        "mode": "static_analysis_only",
        "files_processed": 1,
        "findings_count": len(findings),
        "findings": findings,
        "note": (
            "Pattern matches are not proof of exploitability. "
            "Manually validate each finding."
        )
    }
