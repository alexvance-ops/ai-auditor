OMEGA Protocol Auditor — FastAPI upgrade scaffold
Replaces keyword-count scoring with evidence-based, language-aware triage.

Install:
    pip install fastapi uvicorn python-multipart pydantic

Run:
    uvicorn app:app --host 127.0.0.1 --port 8000

Security notes:
- This service reads uploaded text only; it does not execute uploaded code.
- For production, add authentication, rate limits, upload limits, retention controls,
  and sandbox any future compiler/fuzzer integrations.
- Pattern findings are investigation leads, never proof of exploitability.
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

app = FastAPI(
    title="OMEGA Protocol Auditor",
    version="4.0.0",
    description="Evidence-first static triage scaffold for authorized source-code reviews.",
)

MAX_UPLOAD_BYTES = 15 * 1024 * 1024
MAX_FILES = 500
MAX_FILE_BYTES = 2 * 1024 * 1024
ALLOWED_SINGLE_EXTS = {
    ".sol", ".rs", ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".go",
    ".java", ".kt", ".vy", ".json", ".toml", ".yaml", ".yml",
}
EXCLUDED_PARTS = {
    ".git", "node_modules", ".yarn", "vendor", "lib", "out", "cache",
    "artifacts", "broadcast", "target", "dist", "build", "__pycache__",
}

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

RULES: list[dict[str, Any]] = [
    {
        "id": "SOL_DELEGATECALL",
        "ext": {".sol"},
        "regex": r"\bdelegatecall\s*\(",
        "title": "Delegatecall requires context and target review",
        "severity": "MEDIUM",
        "why": "Delegatecall executes code in the caller's storage context. Risk depends on target control, authorization, and surrounding design.",
        "validate": ["Trace whether the target is attacker-controlled or can be changed.", "Review storage layout and authorization.", "Build a local test only if a concrete unsafe path is found."],
    },
    {
        "id": "SOL_LOW_LEVEL_CALL",
        "ext": {".sol"},
        "regex": r"\.(?:call|staticcall|delegatecall)\s*(?:\{|\()",
        "title": "Low-level call requires control-flow review",
        "severity": "LOW",
        "why": "Low-level calls can fail, re-enter, or call unexpected targets; the syntax alone is not a vulnerability.",
        "validate": ["Check target and calldata control.", "Check return value and failure handling.", "Trace state updates before and after the call."],
    },
    {
        "id": "SOL_TX_ORIGIN",
        "ext": {".sol"},
        "regex": r"\btx\.origin\b",
        "title": "tx.origin usage",
        "severity": "MEDIUM",
        "why": "Using tx.origin for authorization can enable phishing-style authorization bypasses, but not every use is unsafe.",
        "validate": ["Determine whether it gates a privileged action.", "Trace caller-controlled paths and any alternative checks."],
    },
    {
        "id": "SOL_SELFDESTRUCT",
        "ext": {".sol"},
        "regex": r"\bselfdestruct\s*\(",
        "title": "Self-destruct semantics and authorization",
        "severity": "MEDIUM",
        "why": "Impact depends on compiler/EVM version, reachability, and access control.",
        "validate": ["Confirm compiler and EVM target.", "Trace who can reach this operation and its actual impact."],
    },
    {
        "id": "SOL_ECRECOVER",
        "ext": {".sol"},
        "regex": r"\becrecover\s*\(",
        "title": "Signature verification review",
        "severity": "LOW",
        "why": "Signature recovery should be checked for domain separation, replay protection, signer authorization, and malformed signatures.",
        "validate": ["Trace nonce/deadline and chain/domain binding.", "Check signer authorization and signature malleability protections."],
    },
    {
        "id": "SOL_ASSEMBLY",
        "ext": {".sol", ".vy"},
        "regex": r"\bassembly\b",
        "title": "Assembly block needs manual review",
        "severity": "INFO",
        "why": "Assembly bypasses some high-level language safeguards; the presence of assembly is not itself a bug.",
        "validate": ["Review memory and storage assumptions.", "Check bounds, return-data handling, and call semantics."],
    },
    {
        "id": "RUST_UNSAFE",
        "ext": {".rs"},
        "regex": r"\bunsafe\b",
        "title": "Rust unsafe block/function review",
        "severity": "INFO",
        "why": "Unsafe Rust requires checking its safety invariants; the keyword alone does not establish memory unsafety.",
        "validate": ["Identify the invariant required by each unsafe operation.", "Check pointer validity, aliasing, lifetime, and bounds assumptions."],
    },
    {
        "id": "RUST_RAW_POINTER",
        "ext": {".rs"},
        "regex": r"\b(?:\*const|\*mut)\s+[A-Za-z_]",
        "title": "Rust raw pointer use",
        "severity": "INFO",
        "why": "Raw pointers require careful validity and aliasing reasoning; declaration alone is not a vulnerability.",
        "validate": ["Trace pointer provenance and lifetime.", "Inspect dereferences and bounds checks."],
    },
    {
        "id": "PY_DYNAMIC_EXEC",
        "ext": {".py"},
        "regex": r"\b(?:eval|exec)\s*\(",
        "title": "Dynamic code execution sink",
        "severity": "MEDIUM",
        "why": "Dynamic execution can be dangerous if untrusted input reaches the sink.",
        "validate": ["Trace input sources to the sink.", "Determine whether input is attacker-controlled and safely constrained."],
    },
    {
        "id": "PY_COMMAND_EXEC",
        "ext": {".py"},
        "regex": r"\b(?:os\.system|subprocess\.(?:run|Popen|call))\s*\(",
        "title": "Operating-system command execution",
        "severity": "LOW",
        "why": "Command execution needs review for shell use and untrusted argument flow.",
        "validate": ["Trace untrusted inputs.", "Check shell=True and argument-array usage.", "Verify allowlisting and escaping."],
    },
    {
        "id": "JS_HTML_SINK",
        "ext": {".js", ".jsx", ".ts", ".tsx"},
        "regex": r"\b(?:innerHTML|outerHTML|dangerouslySetInnerHTML)\b",
        "title": "HTML injection-sensitive sink",
        "severity": "LOW",
        "why": "HTML sinks can cause XSS if attacker-controlled content is inserted without context-appropriate sanitization.",
        "validate": ["Trace source-to-sink data flow.", "Check framework escaping and sanitizer configuration."],
    },
    {
        "id": "GEN_SECRET_LITERAL",
        "ext": ALLOWED_SINGLE_EXTS,
        "regex": r"""(?i)\b(?:api[_-]?key|secret|password|private[_-]?key|access[_-]?token)\b\s*[:=]\s*['"][^'"]{8,}['"]""",
        "title": "Possible hard-coded secret",
        "severity": "MEDIUM",
        "why": "A string literal may contain a credential. This detector redacts the evidence to avoid leaking it in reports.",
        "validate": ["Inspect locally without sharing the secret.", "If real, rotate it and move it to a secret manager/environment variable."],
        "redact": True,
    },
]

def _is_comment_or_blank(line: str, ext: str) -> bool:
    s = line.strip()
    if not s:
        return True
    if ext in {".py", ".yml", ".yaml", ".toml"} and s.startswith("#"):
        return True
    if ext in {".sol", ".rs", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".kt", ".php", ".vy"}:
        if s.startswith("//") or s.startswith("/*") or s.startswith("*"):
            return True
    return False

def _scan_text(path: str, content: str) -> tuple[list[Finding], int]:
    ext = PurePosixPath(path).suffix.lower()
    lines = content.splitlines()
    results: list[Finding] = []
    for i, line in enumerate(lines, start=1):
        if _is_comment_or_blank(line, ext):
            continue
        for rule in RULES:
            if ext not in rule["ext"]:
                continue
            if re.search(rule["regex"], line):
                evidence = "[REDACTED: possible secret literal]" if rule.get("redact") else line.strip()[:350]
                results.append(Finding(
                    rule_id=rule["id"],
                    title=rule["title"],
                    status="INVESTIGATION_LEAD",
                    severity_hint=rule["severity"],
                    confidence="LOW",
                    file=path,
                    line=i,
                    evidence=evidence,
                    why_it_matters=rule["why"],
                    validation_needed=rule["validate"],
                ))
    return results, len(lines)

def _safe_zip_sources(data: bytes) -> list[tuple[str, str]]:
    sources = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_FILES:
                raise HTTPException(status_code=413, detail=f"Archive has too many entries (max {MAX_FILES}).")
            for info in infos:
                p = PurePosixPath(info.filename)
                if info.is_dir() or p.is_absolute() or ".." in p.parts:
                    continue
                if any(part in EXCLUDED_PARTS or part.startswith(".") for part in p.parts):
                    continue
                if p.suffix.lower() not in ALLOWED_SINGLE_EXTS:
                    continue
                if info.file_size > MAX_FILE_BYTES:
                    continue
                if info.file_size == 0:
                    continue
                with zf.open(info) as f:
                    raw = f.read(MAX_FILE_BYTES + 1)
                if len(raw) > MAX_FILE_BYTES:
                    continue
                sources.append((str(p), raw.decode("utf-8", errors="replace")))
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid ZIP archive.")
    return sources

def _make_result(filename: str, sha: str, sources: list[tuple[str, str]]) -> AuditResult:
    findings: list[Finding] = []
    total_lines = 0
    for path, content in sources:
        hits, lines = _scan_text(path, content)
        findings.extend(hits)
        total_lines += lines

    # This is a triage index, not a security guarantee or probability.
    # Do not label a repository safe based on absence of pattern matches.
    score = max(0, 100 - min(100, len(findings) * 3))
    return AuditResult(
        filename=filename,
        sha256=sha,
        status="TRIAGE_COMPLETE_REVIEW_REQUIRED",
        security_score=score,
        score_note="Heuristic triage index only; not a probability, certification, or proof of safety. Lower scores mean more pattern leads were found.",
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

@app.get("/")
async def root():
    return {
        "name": "OMEGA Protocol Auditor",
        "version": app.version,
        "mode": "read-only static triage",
        "routes": ["/audit/upload", "/audit/text", "/health"],
        "warning": "Findings are investigation leads, not confirmed vulnerabilities.",
    }

@app.get("/health")
async def health():
    return {"ok": True, "version": app.version}

@app.post("/audit/upload", response_model=AuditResult)
async def audit_upload(file: UploadFile = File(...)):
    filename = file.filename or "uploaded-source"
    lower = filename.lower()
    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Upload too large (maximum 15 MiB).")
    digest = hashlib.sha256(raw).hexdigest()

    if lower.endswith(".zip"):
        sources = _safe_zip_sources(raw)
        if not sources:
            raise HTTPException(status_code=400, detail="No supported source files found in ZIP.")
    else:
        ext = PurePosixPath(filename).suffix.lower()
        if ext not in ALLOWED_SINGLE_EXTS:
            raise HTTPException(status_code=400, detail="Unsupported file type.")
        sources = [(PurePosixPath(filename).name, raw.decode("utf-8", errors="replace"))]
    return _make_result(filename, digest, sources)

class TextAuditRequest(BaseModel):
    filename: str = "snippet.sol"
    code: str = Field(min_length=1, max_length=500_000)

@app.post("/audit/text", response_model=AuditResult)
async def audit_text(request: TextAuditRequest):
    ext = PurePosixPath(request.filename).suffix.lower()
    if ext not in ALLOWED_SINGLE_EXTS:
        raise HTTPException(status_code=400, detail="Unsupported file extension.")
    raw = request.code.encode("utf-8")
    return _make_result(
        PurePosixPath(request.filename).name,
        hashlib.sha256(raw).hexdigest(),
        [(PurePosixPath(request.filename).name, request.code)],
)OMEGA Protocol Auditor — FastAPI upgrade scaffold
Replaces keyword-count scoring with evidence-based, language-aware triage.

Install:
    pip install fastapi uvicorn python-multipart pydantic

Run:
    uvicorn app:app --host 127.0.0.1 --port 8000

Security notes:
- This service reads uploaded text only; it does not execute uploaded code.
- For production, add authentication, rate limits, upload limits, retention controls,
  and sandbox any future compiler/fuzzer integrations.
- Pattern findings are investigation leads, never proof of exploitability.
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

app = FastAPI(
    title="OMEGA Protocol Auditor",
    version="4.0.0",
    description="Evidence-first static triage scaffold for authorized source-code reviews.",
)

MAX_UPLOAD_BYTES = 15 * 1024 * 1024
MAX_FILES = 500
MAX_FILE_BYTES = 2 * 1024 * 1024
ALLOWED_SINGLE_EXTS = {
    ".sol", ".rs", ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".go",
    ".java", ".kt", ".vy", ".json", ".toml", ".yaml", ".yml",
}
EXCLUDED_PARTS = {
    ".git", "node_modules", ".yarn", "vendor", "lib", "out", "cache",
    "artifacts", "broadcast", "target", "dist", "build", "__pycache__",
}

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

RULES: list[dict[str, Any]] = [
    {
        "id": "SOL_DELEGATECALL",
        "ext": {".sol"},
        "regex": r"\bdelegatecall\s*\(",
        "title": "Delegatecall requires context and target review",
        "severity": "MEDIUM",
        "why": "Delegatecall executes code in the caller's storage context. Risk depends on target control, authorization, and surrounding design.",
        "validate": ["Trace whether the target is attacker-controlled or can be changed.", "Review storage layout and authorization.", "Build a local test only if a concrete unsafe path is found."],
    },
    {
        "id": "SOL_LOW_LEVEL_CALL",
        "ext": {".sol"},
        "regex": r"\.(?:call|staticcall|delegatecall)\s*(?:\{|\()",
        "title": "Low-level call requires control-flow review",
        "severity": "LOW",
        "why": "Low-level calls can fail, re-enter, or call unexpected targets; the syntax alone is not a vulnerability.",
        "validate": ["Check target and calldata control.", "Check return value and failure handling.", "Trace state updates before and after the call."],
    },
    {
        "id": "SOL_TX_ORIGIN",
        "ext": {".sol"},
        "regex": r"\btx\.origin\b",
        "title": "tx.origin usage",
        "severity": "MEDIUM",
        "why": "Using tx.origin for authorization can enable phishing-style authorization bypasses, but not every use is unsafe.",
        "validate": ["Determine whether it gates a privileged action.", "Trace caller-controlled paths and any alternative checks."],
    },
    {
        "id": "SOL_SELFDESTRUCT",
        "ext": {".sol"},
        "regex": r"\bselfdestruct\s*\(",
        "title": "Self-destruct semantics and authorization",
        "severity": "MEDIUM",
        "why": "Impact depends on compiler/EVM version, reachability, and access control.",
        "validate": ["Confirm compiler and EVM target.", "Trace who can reach this operation and its actual impact."],
    },
    {
        "id": "SOL_ECRECOVER",
        "ext": {".sol"},
        "regex": r"\becrecover\s*\(",
        "title": "Signature verification review",
        "severity": "LOW",
        "why": "Signature recovery should be checked for domain separation, replay protection, signer authorization, and malformed signatures.",
        "validate": ["Trace nonce/deadline and chain/domain binding.", "Check signer authorization and signature malleability protections."],
    },
    {
        "id": "SOL_ASSEMBLY",
        "ext": {".sol", ".vy"},
        "regex": r"\bassembly\b",
        "title": "Assembly block needs manual review",
        "severity": "INFO",
        "why": "Assembly bypasses some high-level language safeguards; the presence of assembly is not itself a bug.",
        "validate": ["Review memory and storage assumptions.", "Check bounds, return-data handling, and call semantics."],
    },
    {
        "id": "RUST_UNSAFE",
        "ext": {".rs"},
        "regex": r"\bunsafe\b",
        "title": "Rust unsafe block/function review",
        "severity": "INFO",
        "why": "Unsafe Rust requires checking its safety invariants; the keyword alone does not establish memory unsafety.",
        "validate": ["Identify the invariant required by each unsafe operation.", "Check pointer validity, aliasing, lifetime, and bounds assumptions."],
    },
    {
        "id": "RUST_RAW_POINTER",
        "ext": {".rs"},
        "regex": r"\b(?:\*const|\*mut)\s+[A-Za-z_]",
        "title": "Rust raw pointer use",
        "severity": "INFO",
        "why": "Raw pointers require careful validity and aliasing reasoning; declaration alone is not a vulnerability.",
        "validate": ["Trace pointer provenance and lifetime.", "Inspect dereferences and bounds checks."],
    },
    {
        "id": "PY_DYNAMIC_EXEC",
        "ext": {".py"},
        "regex": r"\b(?:eval|exec)\s*\(",
        "title": "Dynamic code execution sink",
        "severity": "MEDIUM",
        "why": "Dynamic execution can be dangerous if untrusted input reaches the sink.",
        "validate": ["Trace input sources to the sink.", "Determine whether input is attacker-controlled and safely constrained."],
    },
    {
        "id": "PY_COMMAND_EXEC",
        "ext": {".py"},
        "regex": r"\b(?:os\.system|subprocess\.(?:run|Popen|call))\s*\(",
        "title": "Operating-system command execution",
        "severity": "LOW",
        "why": "Command execution needs review for shell use and untrusted argument flow.",
        "validate": ["Trace untrusted inputs.", "Check shell=True and argument-array usage.", "Verify allowlisting and escaping."],
    },
    {
        "id": "JS_HTML_SINK",
        "ext": {".js", ".jsx", ".ts", ".tsx"},
        "regex": r"\b(?:innerHTML|outerHTML|dangerouslySetInnerHTML)\b",
        "title": "HTML injection-sensitive sink",
        "severity": "LOW",
        "why": "HTML sinks can cause XSS if attacker-controlled content is inserted without context-appropriate sanitization.",
        "validate": ["Trace source-to-sink data flow.", "Check framework escaping and sanitizer configuration."],
    },
    {
        "id": "GEN_SECRET_LITERAL",
        "ext": ALLOWED_SINGLE_EXTS,
        "regex": r"""(?i)\b(?:api[_-]?key|secret|password|private[_-]?key|access[_-]?token)\b\s*[:=]\s*['"][^'"]{8,}['"]""",
        "title": "Possible hard-coded secret",
        "severity": "MEDIUM",
        "why": "A string literal may contain a credential. This detector redacts the evidence to avoid leaking it in reports.",
        "validate": ["Inspect locally without sharing the secret.", "If real, rotate it and move it to a secret manager/environment variable."],
        "redact": True,
    },
]

def _is_comment_or_blank(line: str, ext: str) -> bool:
    s = line.strip()
    if not s:
        return True
    if ext in {".py", ".yml", ".yaml", ".toml"} and s.startswith("#"):
        return True
    if ext in {".sol", ".rs", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".kt", ".php", ".vy"}:
        if s.startswith("//") or s.startswith("/*") or s.startswith("*"):
            return True
    return False

def _scan_text(path: str, content: str) -> tuple[list[Finding], int]:
    ext = PurePosixPath(path).suffix.lower()
    lines = content.splitlines()
    results: list[Finding] = []
    for i, line in enumerate(lines, start=1):
        if _is_comment_or_blank(line, ext):
            continue
        for rule in RULES:
            if ext not in rule["ext"]:
                continue
            if re.search(rule["regex"], line):
                evidence = "[REDACTED: possible secret literal]" if rule.get("redact") else line.strip()[:350]
                results.append(Finding(
                    rule_id=rule["id"],
                    title=rule["title"],
                    status="INVESTIGATION_LEAD",
                    severity_hint=rule["severity"],
                    confidence="LOW",
                    file=path,
                    line=i,
                    evidence=evidence,
                    why_it_matters=rule["why"],
                    validation_needed=rule["validate"],
                ))
    return results, len(lines)

def _safe_zip_sources(data: bytes) -> list[tuple[str, str]]:
    sources = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_FILES:
                raise HTTPException(status_code=413, detail=f"Archive has too many entries (max {MAX_FILES}).")
            for info in infos:
                p = PurePosixPath(info.filename)
                if info.is_dir() or p.is_absolute() or ".." in p.parts:
                    continue
                if any(part in EXCLUDED_PARTS or part.startswith(".") for part in p.parts):
                    continue
                if p.suffix.lower() not in ALLOWED_SINGLE_EXTS:
                    continue
                if info.file_size > MAX_FILE_BYTES:
                    continue
                if info.file_size == 0:
                    continue
                with zf.open(info) as f:
                    raw = f.read(MAX_FILE_BYTES + 1)
                if len(raw) > MAX_FILE_BYTES:
                    continue
                sources.append((str(p), raw.decode("utf-8", errors="replace")))
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid ZIP archive.")
    return sources

def _make_result(filename: str, sha: str, sources: list[tuple[str, str]]) -> AuditResult:
    findings: list[Finding] = []
    total_lines = 0
    for path, content in sources:
        hits, lines = _scan_text(path, content)
        findings.extend(hits)
        total_lines += lines

    # This is a triage index, not a security guarantee or probability.
    # Do not label a repository safe based on absence of pattern matches.
    score = max(0, 100 - min(100, len(findings) * 3))
    return AuditResult(
        filename=filename,
        sha256=sha,
        status="TRIAGE_COMPLETE_REVIEW_REQUIRED",
        security_score=score,
        score_note="Heuristic triage index only; not a probability, certification, or proof of safety. Lower scores mean more pattern leads were found.",
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

@app.get("/")
async def root():
    return {
        "name": "OMEGA Protocol Auditor",
        "version": app.version,
        "mode": "read-only static triage",
        "routes": ["/audit/upload", "/audit/text", "/health"],
        "warning": "Findings are investigation leads, not confirmed vulnerabilities.",
    }

@app.get("/health")
async def health():
    return {"ok": True, "version": app.version}

@app.post("/audit/upload", response_model=AuditResult)
async def audit_upload(file: UploadFile = File(...)):
    filename = file.filename or "uploaded-source"
    lower = filename.lower()
    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Upload too large (maximum 15 MiB).")
    digest = hashlib.sha256(raw).hexdigest()

    if lower.endswith(".zip"):
        sources = _safe_zip_sources(raw)
        if not sources:
            raise HTTPException(status_code=400, detail="No supported source files found in ZIP.")
    else:
        ext = PurePosixPath(filename).suffix.lower()
        if ext not in ALLOWED_SINGLE_EXTS:
            raise HTTPException(status_code=400, detail="Unsupported file type.")
        sources = [(PurePosixPath(filename).name, raw.decode("utf-8", errors="replace"))]
    return _make_result(filename, digest, sources)

class TextAuditRequest(BaseModel):
    filename: str = "snippet.sol"
    code: str = Field(min_length=1, max_length=500_000)

@app.post("/audit/text", response_model=AuditResult)
async def audit_text(request: TextAuditRequest):
    ext = PurePosixPath(request.filename).suffix.lower()
    if ext not in ALLOWED_SINGLE_EXTS:
        raise HTTPException(status_code=400, detail="Unsupported file extension.")
    raw = request.code.encode("utf-8")
    return _make_result(
        PurePosixPath(request.filename).name,
        hashlib.sha256(raw).hexdigest(),
        [(PurePosixPath(request.filename).name, request.code)],
    )OMEGA Protocol Auditor — FastAPI upgrade scaffold
Replaces keyword-count scoring with evidence-based, language-aware triage.

Install:
    pip install fastapi uvicorn python-multipart pydantic

Run:
    uvicorn app:app --host 127.0.0.1 --port 8000

Security notes:
- This service reads uploaded text only; it does not execute uploaded code.
- For production, add authentication, rate limits, upload limits, retention controls,
  and sandbox any future compiler/fuzzer integrations.
- Pattern findings are investigation leads, never proof of exploitability.
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

app = FastAPI(
    title="OMEGA Protocol Auditor",
    version="4.0.0",
    description="Evidence-first static triage scaffold for authorized source-code reviews.",
)

MAX_UPLOAD_BYTES = 15 * 1024 * 1024
MAX_FILES = 500
MAX_FILE_BYTES = 2 * 1024 * 1024
ALLOWED_SINGLE_EXTS = {
    ".sol", ".rs", ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".go",
    ".java", ".kt", ".vy", ".json", ".toml", ".yaml", ".yml",
}
EXCLUDED_PARTS = {
    ".git", "node_modules", ".yarn", "vendor", "lib", "out", "cache",
    "artifacts", "broadcast", "target", "dist", "build", "__pycache__",
}

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

RULES: list[dict[str, Any]] = [
    {
        "id": "SOL_DELEGATECALL",
        "ext": {".sol"},
        "regex": r"\bdelegatecall\s*\(",
        "title": "Delegatecall requires context and target review",
        "severity": "MEDIUM",
        "why": "Delegatecall executes code in the caller's storage context. Risk depends on target control, authorization, and surrounding design.",
        "validate": ["Trace whether the target is attacker-controlled or can be changed.", "Review storage layout and authorization.", "Build a local test only if a concrete unsafe path is found."],
    },
    {
        "id": "SOL_LOW_LEVEL_CALL",
        "ext": {".sol"},
        "regex": r"\.(?:call|staticcall|delegatecall)\s*(?:\{|\()",
        "title": "Low-level call requires control-flow review",
        "severity": "LOW",
        "why": "Low-level calls can fail, re-enter, or call unexpected targets; the syntax alone is not a vulnerability.",
        "validate": ["Check target and calldata control.", "Check return value and failure handling.", "Trace state updates before and after the call."],
    },
    {
        "id": "SOL_TX_ORIGIN",
        "ext": {".sol"},
        "regex": r"\btx\.origin\b",
        "title": "tx.origin usage",
        "severity": "MEDIUM",
        "why": "Using tx.origin for authorization can enable phishing-style authorization bypasses, but not every use is unsafe.",
        "validate": ["Determine whether it gates a privileged action.", "Trace caller-controlled paths and any alternative checks."],
    },
    {
        "id": "SOL_SELFDESTRUCT",
        "ext": {".sol"},
        "regex": r"\bselfdestruct\s*\(",
        "title": "Self-destruct semantics and authorization",
        "severity": "MEDIUM",
        "why": "Impact depends on compiler/EVM version, reachability, and access control.",
        "validate": ["Confirm compiler and EVM target.", "Trace who can reach this operation and its actual impact."],
    },
    {
        "id": "SOL_ECRECOVER",
        "ext": {".sol"},
        "regex": r"\becrecover\s*\(",
        "title": "Signature verification review",
        "severity": "LOW",
        "why": "Signature recovery should be checked for domain separation, replay protection, signer authorization, and malformed signatures.",
        "validate": ["Trace nonce/deadline and chain/domain binding.", "Check signer authorization and signature malleability protections."],
    },
    {
        "id": "SOL_ASSEMBLY",
        "ext": {".sol", ".vy"},
        "regex": r"\bassembly\b",
        "title": "Assembly block needs manual review",
        "severity": "INFO",
        "why": "Assembly bypasses some high-level language safeguards; the presence of assembly is not itself a bug.",
        "validate": ["Review memory and storage assumptions.", "Check bounds, return-data handling, and call semantics."],
    },
    {
        "id": "RUST_UNSAFE",
        "ext": {".rs"},
        "regex": r"\bunsafe\b",
        "title": "Rust unsafe block/function review",
        "severity": "INFO",
        "why": "Unsafe Rust requires checking its safety invariants; the keyword alone does not establish memory unsafety.",
        "validate": ["Identify the invariant required by each unsafe operation.", "Check pointer validity, aliasing, lifetime, and bounds assumptions."],
    },
    {
        "id": "RUST_RAW_POINTER",
        "ext": {".rs"},
        "regex": r"\b(?:\*const|\*mut)\s+[A-Za-z_]",
        "title": "Rust raw pointer use",
        "severity": "INFO",
        "why": "Raw pointers require careful validity and aliasing reasoning; declaration alone is not a vulnerability.",
        "validate": ["Trace pointer provenance and lifetime.", "Inspect dereferences and bounds checks."],
    },
    {
        "id": "PY_DYNAMIC_EXEC",
        "ext": {".py"},
        "regex": r"\b(?:eval|exec)\s*\(",
        "title": "Dynamic code execution sink",
        "severity": "MEDIUM",
        "why": "Dynamic execution can be dangerous if untrusted input reaches the sink.",
        "validate": ["Trace input sources to the sink.", "Determine whether input is attacker-controlled and safely constrained."],
    },
    {
        "id": "PY_COMMAND_EXEC",
        "ext": {".py"},
        "regex": r"\b(?:os\.system|subprocess\.(?:run|Popen|call))\s*\(",
        "title": "Operating-system command execution",
        "severity": "LOW",
        "why": "Command execution needs review for shell use and untrusted argument flow.",
        "validate": ["Trace untrusted inputs.", "Check shell=True and argument-array usage.", "Verify allowlisting and escaping."],
    },
    {
        "id": "JS_HTML_SINK",
        "ext": {".js", ".jsx", ".ts", ".tsx"},
        "regex": r"\b(?:innerHTML|outerHTML|dangerouslySetInnerHTML)\b",
        "title": "HTML injection-sensitive sink",
        "severity": "LOW",
        "why": "HTML sinks can cause XSS if attacker-controlled content is inserted without context-appropriate sanitization.",
        "validate": ["Trace source-to-sink data flow.", "Check framework escaping and sanitizer configuration."],
    },
    {
        "id": "GEN_SECRET_LITERAL",
        "ext": ALLOWED_SINGLE_EXTS,
        "regex": r"""(?i)\b(?:api[_-]?key|secret|password|private[_-]?key|access[_-]?token)\b\s*[:=]\s*['"][^'"]{8,}['"]""",
        "title": "Possible hard-coded secret",
        "severity": "MEDIUM",
        "why": "A string literal may contain a credential. This detector redacts the evidence to avoid leaking it in reports.",
        "validate": ["Inspect locally without sharing the secret.", "If real, rotate it and move it to a secret manager/environment variable."],
        "redact": True,
    },
]

def _is_comment_or_blank(line: str, ext: str) -> bool:
    s = line.strip()
    if not s:
        return True
    if ext in {".py", ".yml", ".yaml", ".toml"} and s.startswith("#"):
        return True
    if ext in {".sol", ".rs", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".kt", ".php", ".vy"}:
        if s.startswith("//") or s.startswith("/*") or s.startswith("*"):
            return True
    return False

def _scan_text(path: str, content: str) -> tuple[list[Finding], int]:
    ext = PurePosixPath(path).suffix.lower()
    lines = content.splitlines()
    results: list[Finding] = []
    for i, line in enumerate(lines, start=1):
        if _is_comment_or_blank(line, ext):
            continue
        for rule in RULES:
            if ext not in rule["ext"]:
                continue
            if re.search(rule["regex"], line):
                evidence = "[REDACTED: possible secret literal]" if rule.get("redact") else line.strip()[:350]
                results.append(Finding(
                    rule_id=rule["id"],
                    title=rule["title"],
                    status="INVESTIGATION_LEAD",
                    severity_hint=rule["severity"],
                    confidence="LOW",
                    file=path,
                    line=i,
                    evidence=evidence,
                    why_it_matters=rule["why"],
                    validation_needed=rule["validate"],
                ))
    return results, len(lines)

def _safe_zip_sources(data: bytes) -> list[tuple[str, str]]:
    sources = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_FILES:
                raise HTTPException(status_code=413, detail=f"Archive has too many entries (max {MAX_FILES}).")
            for info in infos:
                p = PurePosixPath(info.filename)
                if info.is_dir() or p.is_absolute() or ".." in p.parts:
                    continue
                if any(part in EXCLUDED_PARTS or part.startswith(".") for part in p.parts):
                    continue
                if p.suffix.lower() not in ALLOWED_SINGLE_EXTS:
                    continue
                if info.file_size > MAX_FILE_BYTES:
                    continue
                if info.file_size == 0:
                    continue
                with zf.open(info) as f:
                    raw = f.read(MAX_FILE_BYTES + 1)
                if len(raw) > MAX_FILE_BYTES:
                    continue
                sources.append((str(p), raw.decode("utf-8", errors="replace")))
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid ZIP archive.")
    return sources

def _make_result(filename: str, sha: str, sources: list[tuple[str, str]]) -> AuditResult:
    findings: list[Finding] = []
    total_lines = 0
    for path, content in sources:
        hits, lines = _scan_text(path, content)
        findings.extend(hits)
        total_lines += lines

    # This is a triage index, not a security guarantee or probability.
    # Do not label a repository safe based on absence of pattern matches.
    score = max(0, 100 - min(100, len(findings) * 3))
    return AuditResult(
        filename=filename,
        sha256=sha,
        status="TRIAGE_COMPLETE_REVIEW_REQUIRED",
        security_score=score,
        score_note="Heuristic triage index only; not a probability, certification, or proof of safety. Lower scores mean more pattern leads were found.",
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

@app.get("/")
async def root():
    return {
        "name": "OMEGA Protocol Auditor",
        "version": app.version,
        "mode": "read-only static triage",
        "routes": ["/audit/upload", "/audit/text", "/health"],
        "warning": "Findings are investigation leads, not confirmed vulnerabilities.",
    }

@app.get("/health")
async def health():
    return {"ok": True, "version": app.version}

@app.post("/audit/upload", response_model=AuditResult)
async def audit_upload(file: UploadFile = File(...)):
    filename = file.filename or "uploaded-source"
    lower = filename.lower()
    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Upload too large (maximum 15 MiB).")
    digest = hashlib.sha256(raw).hexdigest()

    if lower.endswith(".zip"):
        sources = _safe_zip_sources(raw)
        if not sources:
            raise HTTPException(status_code=400, detail="No supported source files found in ZIP.")
    else:
        ext = PurePosixPath(filename).suffix.lower()
        if ext not in ALLOWED_SINGLE_EXTS:
            raise HTTPException(status_code=400, detail="Unsupported file type.")
        sources = [(PurePosixPath(filename).name, raw.decode("utf-8", errors="replace"))]
    return _make_result(filename, digest, sources)

class TextAuditRequest(BaseModel):
    filename: str = "snippet.sol"
    code: str = Field(min_length=1, max_length=500_000)

@app.post("/audit/text", response_model=AuditResult)
async def audit_text(request: TextAuditRequest):
    ext = PurePosixPath(request.filename).suffix.lower()
    if ext not in ALLOWED_SINGLE_EXTS:
        raise HTTPException(status_code=400, detail="Unsupported file extension.")
    raw = request.code.encode("utf-8")
    return _make_result(
        PurePosixPath(request.filename).name,
        hashlib.sha256(raw).hexdigest(),
        [(PurePosixPath(request.filename).name, request.code)],
)OMEGA Protocol Auditor — FastAPI upgrade scaffold
Replaces keyword-count scoring with evidence-based, language-aware triage.

Install:
    pip install fastapi uvicorn python-multipart pydantic

Run:
    uvicorn app:app --host 127.0.0.1 --port 8000

Security notes:
- This service reads uploaded text only; it does not execute uploaded code.
- For production, add authentication, rate limits, upload limits, retention controls,
  and sandbox any future compiler/fuzzer integrations.
- Pattern findings are investigation leads, never proof of exploitability.
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

app = FastAPI(
    title="OMEGA Protocol Auditor",
    version="4.0.0",
    description="Evidence-first static triage scaffold for authorized source-code reviews.",
)

MAX_UPLOAD_BYTES = 15 * 1024 * 1024
MAX_FILES = 500
MAX_FILE_BYTES = 2 * 1024 * 1024
ALLOWED_SINGLE_EXTS = {
    ".sol", ".rs", ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".go",
    ".java", ".kt", ".vy", ".json", ".toml", ".yaml", ".yml",
}
EXCLUDED_PARTS = {
    ".git", "node_modules", ".yarn", "vendor", "lib", "out", "cache",
    "artifacts", "broadcast", "target", "dist", "build", "__pycache__",
}

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

RULES: list[dict[str, Any]] = [
    {
        "id": "SOL_DELEGATECALL",
        "ext": {".sol"},
        "regex": r"\bdelegatecall\s*\(",
        "title": "Delegatecall requires context and target review",
        "severity": "MEDIUM",
        "why": "Delegatecall executes code in the caller's storage context. Risk depends on target control, authorization, and surrounding design.",
        "validate": ["Trace whether the target is attacker-controlled or can be changed.", "Review storage layout and authorization.", "Build a local test only if a concrete unsafe path is found."],
    },
    {
        "id": "SOL_LOW_LEVEL_CALL",
        "ext": {".sol"},
        "regex": r"\.(?:call|staticcall|delegatecall)\s*(?:\{|\()",
        "title": "Low-level call requires control-flow review",
        "severity": "LOW",
        "why": "Low-level calls can fail, re-enter, or call unexpected targets; the syntax alone is not a vulnerability.",
        "validate": ["Check target and calldata control.", "Check return value and failure handling.", "Trace state updates before and after the call."],
    },
    {
        "id": "SOL_TX_ORIGIN",
        "ext": {".sol"},
        "regex": r"\btx\.origin\b",
        "title": "tx.origin usage",
        "severity": "MEDIUM",
        "why": "Using tx.origin for authorization can enable phishing-style authorization bypasses, but not every use is unsafe.",
        "validate": ["Determine whether it gates a privileged action.", "Trace caller-controlled paths and any alternative checks."],
    },
    {
        "id": "SOL_SELFDESTRUCT",
        "ext": {".sol"},
        "regex": r"\bselfdestruct\s*\(",
        "title": "Self-destruct semantics and authorization",
        "severity": "MEDIUM",
        "why": "Impact depends on compiler/EVM version, reachability, and access control.",
        "validate": ["Confirm compiler and EVM target.", "Trace who can reach this operation and its actual impact."],
    },
    {
        "id": "SOL_ECRECOVER",
        "ext": {".sol"},
        "regex": r"\becrecover\s*\(",
        "title": "Signature verification review",
        "severity": "LOW",
        "why": "Signature recovery should be checked for domain separation, replay protection, signer authorization, and malformed signatures.",
        "validate": ["Trace nonce/deadline and chain/domain binding.", "Check signer authorization and signature malleability protections."],
    },
    {
        "id": "SOL_ASSEMBLY",
        "ext": {".sol", ".vy"},
        "regex": r"\bassembly\b",
        "title": "Assembly block needs manual review",
        "severity": "INFO",
        "why": "Assembly bypasses some high-level language safeguards; the presence of assembly is not itself a bug.",
        "validate": ["Review memory and storage assumptions.", "Check bounds, return-data handling, and call semantics."],
    },
    {
        "id": "RUST_UNSAFE",
        "ext": {".rs"},
        "regex": r"\bunsafe\b",
        "title": "Rust unsafe block/function review",
        "severity": "INFO",
        "why": "Unsafe Rust requires checking its safety invariants; the keyword alone does not establish memory unsafety.",
        "validate": ["Identify the invariant required by each unsafe operation.", "Check pointer validity, aliasing, lifetime, and bounds assumptions."],
    },
    {
        "id": "RUST_RAW_POINTER",
        "ext": {".rs"},
        "regex": r"\b(?:\*const|\*mut)\s+[A-Za-z_]",
        "title": "Rust raw pointer use",
        "severity": "INFO",
        "why": "Raw pointers require careful validity and aliasing reasoning; declaration alone is not a vulnerability.",
        "validate": ["Trace pointer provenance and lifetime.", "Inspect dereferences and bounds checks."],
    },
    {
        "id": "PY_DYNAMIC_EXEC",
        "ext": {".py"},
        "regex": r"\b(?:eval|exec)\s*\(",
        "title": "Dynamic code execution sink",
        "severity": "MEDIUM",
        "why": "Dynamic execution can be dangerous if untrusted input reaches the sink.",
        "validate": ["Trace input sources to the sink.", "Determine whether input is attacker-controlled and safely constrained."],
    },
    {
        "id": "PY_COMMAND_EXEC",
        "ext": {".py"},
        "regex": r"\b(?:os\.system|subprocess\.(?:run|Popen|call))\s*\(",
        "title": "Operating-system command execution",
        "severity": "LOW",
        "why": "Command execution needs review for shell use and untrusted argument flow.",
        "validate": ["Trace untrusted inputs.", "Check shell=True and argument-array usage.", "Verify allowlisting and escaping."],
    },
    {
        "id": "JS_HTML_SINK",
        "ext": {".js", ".jsx", ".ts", ".tsx"},
        "regex": r"\b(?:innerHTML|outerHTML|dangerouslySetInnerHTML)\b",
        "title": "HTML injection-sensitive sink",
        "severity": "LOW",
        "why": "HTML sinks can cause XSS if attacker-controlled content is inserted without context-appropriate sanitization.",
        "validate": ["Trace source-to-sink data flow.", "Check framework escaping and sanitizer configuration."],
    },
    {
        "id": "GEN_SECRET_LITERAL",
        "ext": ALLOWED_SINGLE_EXTS,
        "regex": r"""(?i)\b(?:api[_-]?key|secret|password|private[_-]?key|access[_-]?token)\b\s*[:=]\s*['"][^'"]{8,}['"]""",
        "title": "Possible hard-coded secret",
        "severity": "MEDIUM",
        "why": "A string literal may contain a credential. This detector redacts the evidence to avoid leaking it in reports.",
        "validate": ["Inspect locally without sharing the secret.", "If real, rotate it and move it to a secret manager/environment variable."],
        "redact": True,
    },
]

def _is_comment_or_blank(line: str, ext: str) -> bool:
    s = line.strip()
    if not s:
        return True
    if ext in {".py", ".yml", ".yaml", ".toml"} and s.startswith("#"):
        return True
    if ext in {".sol", ".rs", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".kt", ".php", ".vy"}:
        if s.startswith("//") or s.startswith("/*") or s.startswith("*"):
            return True
    return False

def _scan_text(path: str, content: str) -> tuple[list[Finding], int]:
    ext = PurePosixPath(path).suffix.lower()
    lines = content.splitlines()
    results: list[Finding] = []
    for i, line in enumerate(lines, start=1):
        if _is_comment_or_blank(line, ext):
            continue
        for rule in RULES:
            if ext not in rule["ext"]:
                continue
            if re.search(rule["regex"], line):
                evidence = "[REDACTED: possible secret literal]" if rule.get("redact") else line.strip()[:350]
                results.append(Finding(
                    rule_id=rule["id"],
                    title=rule["title"],
                    status="INVESTIGATION_LEAD",
                    severity_hint=rule["severity"],
                    confidence="LOW",
                    file=path,
                    line=i,
                    evidence=evidence,
                    why_it_matters=rule["why"],
                    validation_needed=rule["validate"],
                ))
    return results, len(lines)

def _safe_zip_sources(data: bytes) -> list[tuple[str, str]]:
    sources = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_FILES:
                raise HTTPException(status_code=413, detail=f"Archive has too many entries (max {MAX_FILES}).")
            for info in infos:
                p = PurePosixPath(info.filename)
                if info.is_dir() or p.is_absolute() or ".." in p.parts:
                    continue
                if any(part in EXCLUDED_PARTS or part.startswith(".") for part in p.parts):
                    continue
                if p.suffix.lower() not in ALLOWED_SINGLE_EXTS:
                    continue
                if info.file_size > MAX_FILE_BYTES:
                    continue
                if info.file_size == 0:
                    continue
                with zf.open(info) as f:
                    raw = f.read(MAX_FILE_BYTES + 1)
                if len(raw) > MAX_FILE_BYTES:
                    continue
                sources.append((str(p), raw.decode("utf-8", errors="replace")))
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid ZIP archive.")
    return sources

def _make_result(filename: str, sha: str, sources: list[tuple[str, str]]) -> AuditResult:
    findings: list[Finding] = []
    total_lines = 0
    for path, content in sources:
        hits, lines = _scan_text(path, content)
        findings.extend(hits)
        total_lines += lines

    # This is a triage index, not a security guarantee or probability.
    # Do not label a repository safe based on absence of pattern matches.
    score = max(0, 100 - min(100, len(findings) * 3))
    return AuditResult(
        filename=filename,
        sha256=sha,
        status="TRIAGE_COMPLETE_REVIEW_REQUIRED",
        security_score=score,
        score_note="Heuristic triage index only; not a probability, certification, or proof of safety. Lower scores mean more pattern leads were found.",
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

@app.get("/")
async def root():
    return {
        "name": "OMEGA Protocol Auditor",
        "version": app.version,
        "mode": "read-only static triage",
        "routes": ["/audit/upload", "/audit/text", "/health"],
        "warning": "Findings are investigation leads, not confirmed vulnerabilities.",
    }

@app.get("/health")
async def health():
    return {"ok": True, "version": app.version}

@app.post("/audit/upload", response_model=AuditResult)
async def audit_upload(file: UploadFile = File(...)):
    filename = file.filename or "uploaded-source"
    lower = filename.lower()
    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Upload too large (maximum 15 MiB).")
    digest = hashlib.sha256(raw).hexdigest()

    if lower.endswith(".zip"):
        sources = _safe_zip_sources(raw)
        if not sources:
            raise HTTPException(status_code=400, detail="No supported source files found in ZIP.")
    else:
        ext = PurePosixPath(filename).suffix.lower()
        if ext not in ALLOWED_SINGLE_EXTS:
            raise HTTPException(status_code=400, detail="Unsupported file type.")
        sources = [(PurePosixPath(filename).name, raw.decode("utf-8", errors="replace"))]
    return _make_result(filename, digest, sources)

class TextAuditRequest(BaseModel):
    filename: str = "snippet.sol"
    code: str = Field(min_length=1, max_length=500_000)

@app.post("/audit/text", response_model=AuditResult)
async def audit_text(request: TextAuditRequest):
    ext = PurePosixPath(request.filename).suffix.lower()
    if ext not in ALLOWED_SINGLE_EXTS:
        raise HTTPException(status_code=400, detail="Unsupported file extension.")
    raw = request.code.encode("utf-8")
    return _make_result(
        PurePosixPath(request.filename).name,
        hashlib.sha256(raw).hexdigest(),
        [(PurePosixPath(request.filename).name, request.code)],
)OMEGA Protocol Auditor — FastAPI upgrade scaffold
Replaces keyword-count scoring with evidence-based, language-aware triage.

Install:
    pip install fastapi uvicorn python-multipart pydantic

Run:
    uvicorn app:app --host 127.0.0.1 --port 8000

Security notes:
- This service reads uploaded text only; it does not execute uploaded code.
- For production, add authentication, rate limits, upload limits, retention controls,
  and sandbox any future compiler/fuzzer integrations.
- Pattern findings are investigation leads, never proof of exploitability.
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

app = FastAPI(
    title="OMEGA Protocol Auditor",
    version="4.0.0",
    description="Evidence-first static triage scaffold for authorized source-code reviews.",
)

MAX_UPLOAD_BYTES = 15 * 1024 * 1024
MAX_FILES = 500
MAX_FILE_BYTES = 2 * 1024 * 1024
ALLOWED_SINGLE_EXTS = {
    ".sol", ".rs", ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".go",
    ".java", ".kt", ".vy", ".json", ".toml", ".yaml", ".yml",
}
EXCLUDED_PARTS = {
    ".git", "node_modules", ".yarn", "vendor", "lib", "out", "cache",
    "artifacts", "broadcast", "target", "dist", "build", "__pycache__",
}

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

RULES: list[dict[str, Any]] = [
    {
        "id": "SOL_DELEGATECALL",
        "ext": {".sol"},
        "regex": r"\bdelegatecall\s*\(",
        "title": "Delegatecall requires context and target review",
        "severity": "MEDIUM",
        "why": "Delegatecall executes code in the caller's storage context. Risk depends on target control, authorization, and surrounding design.",
        "validate": ["Trace whether the target is attacker-controlled or can be changed.", "Review storage layout and authorization.", "Build a local test only if a concrete unsafe path is found."],
    },
    {
        "id": "SOL_LOW_LEVEL_CALL",
        "ext": {".sol"},
        "regex": r"\.(?:call|staticcall|delegatecall)\s*(?:\{|\()",
        "title": "Low-level call requires control-flow review",
        "severity": "LOW",
        "why": "Low-level calls can fail, re-enter, or call unexpected targets; the syntax alone is not a vulnerability.",
        "validate": ["Check target and calldata control.", "Check return value and failure handling.", "Trace state updates before and after the call."],
    },
    {
        "id": "SOL_TX_ORIGIN",
        "ext": {".sol"},
        "regex": r"\btx\.origin\b",
        "title": "tx.origin usage",
        "severity": "MEDIUM",
        "why": "Using tx.origin for authorization can enable phishing-style authorization bypasses, but not every use is unsafe.",
        "validate": ["Determine whether it gates a privileged action.", "Trace caller-controlled paths and any alternative checks."],
    },
    {
        "id": "SOL_SELFDESTRUCT",
        "ext": {".sol"},
        "regex": r"\bselfdestruct\s*\(",
        "title": "Self-destruct semantics and authorization",
        "severity": "MEDIUM",
        "why": "Impact depends on compiler/EVM version, reachability, and access control.",
        "validate": ["Confirm compiler and EVM target.", "Trace who can reach this operation and its actual impact."],
    },
    {
        "id": "SOL_ECRECOVER",
        "ext": {".sol"},
        "regex": r"\becrecover\s*\(",
        "title": "Signature verification review",
        "severity": "LOW",
        "why": "Signature recovery should be checked for domain separation, replay protection, signer authorization, and malformed signatures.",
        "validate": ["Trace nonce/deadline and chain/domain binding.", "Check signer authorization and signature malleability protections."],
    },
    {
        "id": "SOL_ASSEMBLY",
        "ext": {".sol", ".vy"},
        "regex": r"\bassembly\b",
        "title": "Assembly block needs manual review",
        "severity": "INFO",
        "why": "Assembly bypasses some high-level language safeguards; the presence of assembly is not itself a bug.",
        "validate": ["Review memory and storage assumptions.", "Check bounds, return-data handling, and call semantics."],
    },
    {
        "id": "RUST_UNSAFE",
        "ext": {".rs"},
        "regex": r"\bunsafe\b",
        "title": "Rust unsafe block/function review",
        "severity": "INFO",
        "why": "Unsafe Rust requires checking its safety invariants; the keyword alone does not establish memory unsafety.",
        "validate": ["Identify the invariant required by each unsafe operation.", "Check pointer validity, aliasing, lifetime, and bounds assumptions."],
    },
    {
        "id": "RUST_RAW_POINTER",
        "ext": {".rs"},
        "regex": r"\b(?:\*const|\*mut)\s+[A-Za-z_]",
        "title": "Rust raw pointer use",
        "severity": "INFO",
        "why": "Raw pointers require careful validity and aliasing reasoning; declaration alone is not a vulnerability.",
        "validate": ["Trace pointer provenance and lifetime.", "Inspect dereferences and bounds checks."],
    },
    {
        "id": "PY_DYNAMIC_EXEC",
        "ext": {".py"},
        "regex": r"\b(?:eval|exec)\s*\(",
        "title": "Dynamic code execution sink",
        "severity": "MEDIUM",
        "why": "Dynamic execution can be dangerous if untrusted input reaches the sink.",
        "validate": ["Trace input sources to the sink.", "Determine whether input is attacker-controlled and safely constrained."],
    },
    {
        "id": "PY_COMMAND_EXEC",
        "ext": {".py"},
        "regex": r"\b(?:os\.system|subprocess\.(?:run|Popen|call))\s*\(",
        "title": "Operating-system command execution",
        "severity": "LOW",
        "why": "Command execution needs review for shell use and untrusted argument flow.",
        "validate": ["Trace untrusted inputs.", "Check shell=True and argument-array usage.", "Verify allowlisting and escaping."],
    },
    {
        "id": "JS_HTML_SINK",
        "ext": {".js", ".jsx", ".ts", ".tsx"},
        "regex": r"\b(?:innerHTML|outerHTML|dangerouslySetInnerHTML)\b",
        "title": "HTML injection-sensitive sink",
        "severity": "LOW",
        "why": "HTML sinks can cause XSS if attacker-controlled content is inserted without context-appropriate sanitization.",
        "validate": ["Trace source-to-sink data flow.", "Check framework escaping and sanitizer configuration."],
    },
    {
        "id": "GEN_SECRET_LITERAL",
        "ext": ALLOWED_SINGLE_EXTS,
        "regex": r"""(?i)\b(?:api[_-]?key|secret|password|private[_-]?key|access[_-]?token)\b\s*[:=]\s*['"][^'"]{8,}['"]""",
        "title": "Possible hard-coded secret",
        "severity": "MEDIUM",
        "why": "A string literal may contain a credential. This detector redacts the evidence to avoid leaking it in reports.",
        "validate": ["Inspect locally without sharing the secret.", "If real, rotate it and move it to a secret manager/environment variable."],
        "redact": True,
    },
]

def _is_comment_or_blank(line: str, ext: str) -> bool:
    s = line.strip()
    if not s:
        return True
    if ext in {".py", ".yml", ".yaml", ".toml"} and s.startswith("#"):
        return True
    if ext in {".sol", ".rs", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".kt", ".php", ".vy"}:
        if s.startswith("//") or s.startswith("/*") or s.startswith("*"):
            return True
    return False

def _scan_text(path: str, content: str) -> tuple[list[Finding], int]:
    ext = PurePosixPath(path).suffix.lower()
    lines = content.splitlines()
    results: list[Finding] = []
    for i, line in enumerate(lines, start=1):
        if _is_comment_or_blank(line, ext):
            continue
        for rule in RULES:
            if ext not in rule["ext"]:
                continue
            if re.search(rule["regex"], line):
                evidence = "[REDACTED: possible secret literal]" if rule.get("redact") else line.strip()[:350]
                results.append(Finding(
                    rule_id=rule["id"],
                    title=rule["title"],
                    status="INVESTIGATION_LEAD",
                    severity_hint=rule["severity"],
                    confidence="LOW",
                    file=path,
                    line=i,
                    evidence=evidence,
                    why_it_matters=rule["why"],
                    validation_needed=rule["validate"],
                ))
    return results, len(lines)

def _safe_zip_sources(data: bytes) -> list[tuple[str, str]]:
    sources = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_FILES:
                raise HTTPException(status_code=413, detail=f"Archive has too many entries (max {MAX_FILES}).")
            for info in infos:
                p = PurePosixPath(info.filename)
                if info.is_dir() or p.is_absolute() or ".." in p.parts:
                    continue
                if any(part in EXCLUDED_PARTS or part.startswith(".") for part in p.parts):
                    continue
                if p.suffix.lower() not in ALLOWED_SINGLE_EXTS:
                    continue
                if info.file_size > MAX_FILE_BYTES:
                    continue
                if info.file_size == 0:
                    continue
                with zf.open(info) as f:
                    raw = f.read(MAX_FILE_BYTES + 1)
                if len(raw) > MAX_FILE_BYTES:
                    continue
                sources.append((str(p), raw.decode("utf-8", errors="replace")))
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid ZIP archive.")
    return sources

def _make_result(filename: str, sha: str, sources: list[tuple[str, str]]) -> AuditResult:
    findings: list[Finding] = []
    total_lines = 0
    for path, content in sources:
        hits, lines = _scan_text(path, content)
        findings.extend(hits)
        total_lines += lines

    # This is a triage index, not a security guarantee or probability.
    # Do not label a repository safe based on absence of pattern matches.
    score = max(0, 100 - min(100, len(findings) * 3))
    return AuditResult(
        filename=filename,
        sha256=sha,
        status="TRIAGE_COMPLETE_REVIEW_REQUIRED",
        security_score=score,
        score_note="Heuristic triage index only; not a probability, certification, or proof of safety. Lower scores mean more pattern leads were found.",
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

@app.get("/")
async def root():
    return {
        "name": "OMEGA Protocol Auditor",
        "version": app.version,
        "mode": "read-only static triage",
        "routes": ["/audit/upload", "/audit/text", "/health"],
        "warning": "Findings are investigation leads, not confirmed vulnerabilities.",
    }

@app.get("/health")
async def health():
    return {"ok": True, "version": app.version}

@app.post("/audit/upload", response_model=AuditResult)
async def audit_upload(file: UploadFile = File(...)):
    filename = file.filename or "uploaded-source"
    lower = filename.lower()
    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Upload too large (maximum 15 MiB).")
    digest = hashlib.sha256(raw).hexdigest()

    if lower.endswith(".zip"):
        sources = _safe_zip_sources(raw)
        if not sources:
            raise HTTPException(status_code=400, detail="No supported source files found in ZIP.")
    else:
        ext = PurePosixPath(filename).suffix.lower()
        if ext not in ALLOWED_SINGLE_EXTS:
            raise HTTPException(status_code=400, detail="Unsupported file type.")
        sources = [(PurePosixPath(filename).name, raw.decode("utf-8", errors="replace"))]
    return _make_result(filename, digest, sources)

class TextAuditRequest(BaseModel):
    filename: str = "snippet.sol"
    code: str = Field(min_length=1, max_length=500_000)

@app.post("/audit/text", response_model=AuditResult)
async def audit_text(request: TextAuditRequest):
    ext = PurePosixPath(request.filename).suffix.lower()
    if ext not in ALLOWED_SINGLE_EXTS:
        raise HTTPException(status_code=400, detail="Unsupported file extension.")
    raw = request.code.encode("utf-8")
    return _make_result(
        PurePosixPath(request.filename).name,
        hashlib.sha256(raw).hexdigest(),
        [(PurePosixPath(request.filename).name, request.code)],
    )
