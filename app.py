"""
OMEGA Protocol Auditor — FastAPI Upgrade Scaffold

Evidence-based, language-aware static source-code security triage.

Install:
    pip install fastapi uvicorn python-multipart pydantic

Run:
    uvicorn app:app --host 127.0.0.1 --port 8000

Security notes:
    - Uploaded code is read as text and never executed.
    - Production deployments should add authentication, rate limits,
      upload limits, and retention controls.
    - Findings are investigation leads, not proof of vulnerabilities.
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from pathlib import PurePosixPath
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel, Field


# ============================================================
# Application configuration
# ============================================================

app = FastAPI(
    title="OMEGA Protocol Auditor",
    version="4.0.0",
    description=(
        "Evidence-first static triage scaffold "
        "for authorized source-code reviews."
    ),
)

MAX_UPLOAD_BYTES = 15 * 1024 * 1024
MAX_FILES = 500
MAX_FILE_BYTES = 2 * 1024 * 1024

ALLOWED_SINGLE_EXTS = {
    ".sol",
    ".rs",
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".php",
    ".go",
    ".java",
    ".kt",
    ".vy",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
}

EXCLUDED_PARTS = {
    ".git",
    "node_modules",
    ".yarn",
    "vendor",
    "lib",
    "out",
    "cache",
    "artifacts",
    "broadcast",
    "target",
    "dist",
    "build",
    "__pycache__",
}


# ============================================================
# Response models
# ============================================================

class Finding(BaseModel):
    rule_id: str
    title: str
    status: str = "INVESTIGATION_LEAD"
    severity_hint: str = "LOW"
    confidence: str = "LOW"
    file: str
    line: int
    evidence: str
    why_it_matters: str
    validation_needed: list[str] = Field(default_factory=list)


class AuditResult(BaseModel):
    filename: str
    sha256: str
    status: str
    security_score: int
    score_note: str
    files_processed: int
    lines_inspected: int
    findings_count: int
    confirmed_vulnerabilities: int
    findings: list[Finding]
    limitations: list[str]


class TextAuditRequest(BaseModel):
    filename: str = "snippet.sol"
    code: str = Field(min_length=1, max_length=500_000)


# ============================================================
# Security scanning rules
# ============================================================

RULES: list[dict[str, Any]] = [
    {
        "id": "SOL_DELEGATECALL",
        "ext": {".sol"},
        "regex": r"\bdelegatecall\s*\(",
        "title": "Delegatecall requires context and target review",
        "severity": "MEDIUM",
        "why": (
            "Delegatecall executes code in the caller's storage context. "
            "Risk depends on target control, authorization, and design."
        ),
        "validate": [
            "Trace whether the target is attacker-controlled or changeable.",
            "Review storage layout and authorization.",
            "Build a local test only if a concrete unsafe path is found.",
        ],
    },
    {
        "id": "SOL_LOW_LEVEL_CALL",
        "ext": {".sol"},
        "regex": r"\.(?:call|staticcall|delegatecall)\s*(?:\{|\()",
        "title": "Low-level call requires control-flow review",
        "severity": "LOW",
        "why": (
            "Low-level calls can fail, re-enter, or call unexpected targets. "
            "The syntax alone is not a vulnerability."
        ),
        "validate": [
            "Check target and calldata control.",
            "Check return values and failure handling.",
            "Trace state updates before and after the call.",
        ],
    },
    {
        "id": "SOL_TX_ORIGIN",
        "ext": {".sol"},
        "regex": r"\btx\.origin\b",
        "title": "tx.origin usage",
        "severity": "MEDIUM",
        "why": (
            "Using tx.origin for authorization can enable phishing-style "
            "authorization bypasses, but not every use is unsafe."
        ),
        "validate": [
            "Determine whether it gates a privileged action.",
            "Trace caller-controlled paths and alternative checks.",
        ],
    },
    {
        "id": "SOL_SELFDESTRUCT",
        "ext": {".sol"},
        "regex": r"\bselfdestruct\s*\(",
        "title": "Self-destruct semantics and authorization",
        "severity": "MEDIUM",
        "why": (
            "Impact depends on compiler/EVM version, reachability, "
            "and access control."
        ),
        "validate": [
            "Confirm compiler and EVM target.",
            "Trace who can reach this operation and its actual impact.",
        ],
    },
    {
        "id": "SOL_ECRECOVER",
        "ext": {".sol"},
        "regex": r"\becrecover\s*\(",
        "title": "Signature verification review",
        "severity": "LOW",
        "why": (
            "Signature recovery should be checked for domain separation, "
            "replay protection, signer authorization, and malformed signatures."
        ),
        "validate": [
            "Trace nonce/deadline and chain/domain binding.",
            "Check signer authorization and signature malleability protections.",
        ],
    },
    {
        "id": "SOL_ASSEMBLY",
        "ext": {".sol", ".vy"},
        "regex": r"\bassembly\b",
        "title": "Assembly block needs manual review",
        "severity": "INFO",
        "why": (
            "Assembly bypasses some high-level language safeguards. "
            "Its presence alone is not a bug."
        ),
        "validate": [
            "Review memory and storage assumptions.",
            "Check bounds, return-data handling, and call semantics.",
        ],
    },
    {
        "id": "RUST_UNSAFE",
        "ext": {".rs"},
        "regex": r"\bunsafe\b",
        "title": "Rust unsafe block/function review",
        "severity": "INFO",
        "why": (
            "Unsafe Rust requires checking safety invariants. "
            "The keyword alone does not establish memory unsafety."
        ),
        "validate": [
            "Identify the invariant required by each unsafe operation.",
            "Check pointer validity, aliasing, lifetime, and bounds assumptions.",
        ],
    },
    {
        "id": "RUST_RAW_POINTER",
        "ext": {".rs"},
        "regex": r"\b(?:\*const|\*mut)\s+[A-Za-z_]",
        "title": "Rust raw pointer use",
        "severity": "INFO",
        "why": (
            "Raw pointers require careful validity and aliasing reasoning. "
            "Their declaration alone is not a vulnerability."
        ),
        "validate": [
            "Trace pointer provenance and lifetime.",
            "Inspect dereferences and bounds checks.",
        ],
    },
    {
        "id": "PY_DYNAMIC_EXEC",
        "ext": {".py"},
        "regex": r"\b(?:eval|exec)\s*\(",
        "title": "Dynamic code execution sink",
        "severity": "MEDIUM",
        "why": (
            "Dynamic execution can be dangerous if untrusted input "
            "reaches the execution sink."
        ),
        "validate": [
            "Trace input sources to the sink.",
            "Determine whether input is attacker-controlled and safely constrained.",
        ],
    },
    {
        "id": "PY_COMMAND_EXEC",
        "ext": {".py"},
        "regex": r"\b(?:os\.system|subprocess\.(?:run|Popen|call))\s*\(",
        "title": "Operating-system command execution",
        "severity": "LOW",
        "why": (
            "Command execution needs review for shell use "
            "and untrusted argument flow."
        ),
        "validate": [
            "Trace untrusted inputs.",
            "Check shell=True and argument-array usage.",
            "Verify allowlisting and escaping.",
        ],
    },
    {
        "id": "JS_HTML_SINK",
        "ext": {".js", ".jsx", ".ts", ".tsx"},
        "regex": r"\b(?:innerHTML|outerHTML|dangerouslySetInnerHTML)\b",
        "title": "HTML injection-sensitive sink",
        "severity": "LOW",
        "why": (
            "HTML sinks can cause XSS if attacker-controlled content "
            "is inserted without context-appropriate sanitization."
        ),
        "validate": [
            "Trace source-to-sink data flow.",
            "Check framework escaping and sanitizer configuration.",
        ],
    },
    {
        "id": "GEN_SECRET_LITERAL",
        "ext": ALLOWED_SINGLE_EXTS,
        "regex": (
            r"""(?i)\b(?:api[_-]?key|secret|password|private[_-]?key|"""
            r"""access[_-]?token)\b\s*[:=]\s*['"][^'"]{8,}['"]"""
        ),
        "title": "Possible hard-coded secret",
        "severity": "MEDIUM",
        "why": (
            "A string literal may contain a credential. "
            "Evidence is redacted to avoid leaking secrets in reports."
        ),
        "validate": [
            "Inspect locally without sharing the secret.",
            (
                "If real, rotate it and move it to a secret manager "
                "or environment variable."
            ),
        ],
        "redact": True,
    },
]


# ============================================================
# Source-code scanning helpers
# ============================================================

def _is_comment_or_blank(line: str, ext: str) -> bool:
    """Check whether a line is blank or appears to be a comment."""
    stripped = line.strip()

    if not stripped:
        return True

    if ext in {".py", ".yml", ".yaml", ".toml"}:
        if stripped.startswith("#"):
            return True

    comment_extensions = {
        ".sol",
        ".rs",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".go",
        ".java",
        ".kt",
        ".php",
        ".vy",
    }

    if ext in comment_extensions:
        if (
            stripped.startswith("//")
            or stripped.startswith("/*")
            or stripped.startswith("*")
        ):
            return True

    return False


def _scan_text(path: str, content: str) -> tuple[list[Finding], int]:
    """Scan source text and return investigation leads and line count."""
    ext = PurePosixPath(path).suffix.lower()
    lines = content.splitlines()
    findings: list[Finding] = []

    for line_number, line in enumerate(lines, start=1):
        if _is_comment_or_blank(line, ext):
            continue

        for rule in RULES:
            if ext not in rule["ext"]:
                continue

            if not re.search(rule["regex"], line):
                continue

            if rule.get("redact"):
                evidence = "[REDACTED: possible secret literal]"
            else:
                evidence = line.strip()[:350]

            findings.append(
                Finding(
                    rule_id=rule["id"],
                    title=rule["title"],
                    status="INVESTIGATION_LEAD",
                    severity_hint=rule["severity"],
                    confidence="LOW",
                    file=path,
                    line=line_number,
                    evidence=evidence,
                    why_it_matters=rule["why"],
                    validation_needed=rule["validate"],
                )
            )

    return findings, len(lines)


# ============================================================
# Safe ZIP source extraction
# ============================================================

def _safe_zip_sources(data: bytes) -> list[tuple[str, str]]:
    """Extract supported text files from a ZIP archive."""
    sources: list[tuple[str, str]] = []

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()

            if len(infos) > MAX_FILES:
                raise HTTPException(
                    status_code=413,
                    detail=f"Archive has too many entries (max {MAX_FILES}).",
                )

            for info in infos:
                path = PurePosixPath(info.filename)

                if info.is_dir():
                    continue

                if path.is_absolute() or ".." in path.parts:
                    continue

                if any(
                    part in EXCLUDED_PARTS or part.startswith(".")
                    for part in path.parts
                ):
                    continue

                if path.suffix.lower() not in ALLOWED_SINGLE_EXTS:
                    continue

                if info.file_size > MAX_FILE_BYTES or info.file_size == 0:
                    continue

                with archive.open(info) as source_file:
                    raw = source_file.read(MAX_FILE_BYTES + 1)

                if len(raw) > MAX_FILE_BYTES:
                    continue

                sources.append(
                    (
                        str(path),
                        raw.decode("utf-8", errors="replace"),
                    )
                )

    except zipfile.BadZipFile as exc:
        raise HTTPException(
            status_code=400,
            detail="Invalid ZIP archive.",
        ) from exc

    return sources


# ============================================================
# Audit result generation
# ============================================================

def _make_result(
    filename: str,
    sha: str,
    sources: list[tuple[str, str]],
) -> AuditResult:
    """Scan sources and assemble the final audit response."""
    findings: list[Finding] = []
    total_lines = 0

    for path, content in sources:
        matches, line_count = _scan_text(path, content)
        findings.extend(matches)
        total_lines += line_count

    # This is a triage index, not a security guarantee or probability.
    # Absence of pattern matches does not prove that a repository is safe.
    score = max(0, 100 - min(100, len(findings) * 3))

    return AuditResult(
        filename=filename,
        sha256=sha,
        status="TRIAGE_COMPLETE_REVIEW_REQUIRED",
        security_score=score,
        score_note=(
            "Heuristic triage index only; not a probability, certification, "
            "or proof of safety. Lower scores mean more pattern leads were found."
        ),
        files_processed=len(sources),
        lines_inspected=total_lines,
        findings_count=len(findings),
        confirmed_vulnerabilities=0,
        findings=findings,
        limitations=[
            "No finding is confirmed by pattern matching alone.",
            "This version does not compile or execute uploaded code.",
            "No complete semantic call graph, symbolic execution, or fuzzing is performed.",
            "No findings does not mean the code is secure.",
            "Only selected file types and configured rules are inspected.",
        ],
    )


# ============================================================
# API routes
# ============================================================

@app.get("/")
async def root():
    """Return basic service information."""
    return {
        "name": "OMEGA Protocol Auditor",
        "version": app.version,
        "mode": "read-only static triage",
        "routes": [
            "/audit/upload",
            "/audit/text",
            "/health",
        ],
        "warning": (
            "Findings are investigation leads, "
            "not confirmed vulnerabilities."
        ),
    }


@app.get("/health")
async def health():
    """Return service health information."""
    return {
        "ok": True,
        "version": app.version,
    }


@app.post("/audit/upload", response_model=AuditResult)
async def audit_upload(file: UploadFile = File(...)):
    """Audit an uploaded source file or ZIP archive."""
    filename = file.filename or "uploaded-source"
    lower_filename = filename.lower()

    raw = await file.read(MAX_UPLOAD_BYTES + 1)

    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Upload too large (maximum 15 MiB).",
        )

    digest = hashlib.sha256(raw).hexdigest()

    if lower_filename.endswith(".zip"):
        sources = _safe_zip_sources(raw)

        if not sources:
            raise HTTPException(
                status_code=400,
                detail="No supported source files found in ZIP.",
            )

    else:
        extension = PurePosixPath(filename).suffix.lower()

        if extension not in ALLOWED_SINGLE_EXTS:
            raise HTTPException(
                status_code=400,
                detail="Unsupported file type.",
            )

        safe_filename = PurePosixPath(filename).name

        sources = [
            (
                safe_filename,
                raw.decode("utf-8", errors="replace"),
            )
        ]

    return _make_result(filename, digest, sources)


@app.post("/audit/text", response_model=AuditResult)
async def audit_text(request: TextAuditRequest):
    """Audit a source-code snippet submitted as text."""
    extension = PurePosixPath(request.filename).suffix.lower()

    if extension not in ALLOWED_SINGLE_EXTS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file extension.",
        )

    filename = PurePosixPath(request.filename).name
    raw = request.code.encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()

    return _make_result(
        filename,
        digest,
        [
            (
                filename,
                request.code,
            )
        ],
    )
