
import ast
import hashlib
import io
import json
import re
import zipfile
from pathlib import PurePosixPath

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

app = FastAPI(title="OMEGA Defensive Security Auditor", version="6.0.0")

MAX_UPLOAD = 25 * 1024 * 1024
MAX_TOTAL = 50 * 1024 * 1024
MAX_FILES = 1000
MAX_MEMBER = 2 * 1024 * 1024

EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java",
    ".go", ".rb", ".json", ".yaml", ".yml", ".toml",
    ".env", ".xml", ".html", ".sql", ".sh"
}

RULES = [
    ("SEC001", "Possible hard-coded credential", "HIGH",
     r"""(?i)\b(api_key|secret_key|password|client_secret|access_token)\b\s*[:=]\s*["'][^"'\r\n]{8,}["']""",
     "Move credentials to a secret manager and rotate exposed values."),
    ("PY001", "Dynamic Python execution", "HIGH",
     r"\b(eval|exec)\s*\(",
     "Avoid dynamic execution of untrusted input."),
    ("PY002", "Possible unsafe deserialization", "HIGH",
     r"\b(pickle\.loads?|yaml\.load)\s*\(",
     "Use safe data formats and safe YAML loading."),
    ("PY003", "Process execution requires review", "MEDIUM",
     r"\bsubprocess\.(run|Popen|call|check_output)\s*\(",
     "Validate arguments; avoid shell=True with untrusted data."),
    ("PY004", "TLS certificate verification disabled", "HIGH",
     r"""verify\s*=\s*False""",
     "Enable TLS certificate verification."),
    ("SQL001", "Possible SQL string interpolation", "HIGH",
     r"""(?i)(execute|executemany)\s*\(\s*f["']""",
     "Use parameterized SQL queries."),
    ("JS001", "Unsafe HTML insertion", "MEDIUM",
     r"\.innerHTML\s*=",
     "Prefer textContent or trusted HTML sanitization."),
    ("JS002", "Dynamic code execution", "HIGH",
     r"\beval\s*\(",
     "Avoid eval when processing external input."),
    ("PHP001", "PHP deserialization", "HIGH",
     r"\bunserialize\s*\(",
     "Do not deserialize untrusted input."),
    ("CRYPTO001", "Weak hash algorithm", "MEDIUM",
     r"""(?i)\b(md5|sha1)\s*\(""",
     "Use SHA-256 or a suitable modern cryptographic algorithm.")
]

class TextRequest(BaseModel):
    filename: str = "source.py"
    code: str = Field(min_length=1, max_length=300_000)

def scan_source(filename: str, source: str) -> list:
    findings = []
    ext = PurePosixPath(filename).suffix.lower()

    for line_no, line in enumerate(source.splitlines(), 1):
        for rule_id, title, severity, pattern, fix in RULES:
            if re.search(pattern, line) and (
                rule_id.startswith("SEC") or
                rule_id.startswith("CRYPTO") or
                rule_id.startswith("SQL") or
                (rule_id.startswith("PY") and ext == ".py") or
                (rule_id.startswith("JS") and ext in {".js", ".ts", ".jsx", ".tsx"}) or
                (rule_id.startswith("PHP") and ext == ".php")
            ):
                findings.append({
                    "rule_id": rule_id,
                    "title": title,
                    "severity": severity,
                    "file": filename,
                    "line": line_no,
                    "evidence": line.strip()[:200],
                    "recommendation": fix,
                    "confirmed": False
                })

    if ext == ".py":
        try:
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = ""
                    if isinstance(node.func, ast.Name):
                        name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        name = node.func.attr

                    if name == "assert":
                        continue

                    if name == "open" and node.args:
                        first = node.args[0]
                        if isinstance(first, ast.Call):
                            findings.append({
                                "rule_id": "PY-AST-001",
                                "title": "Dynamic file path requires review",
                                "severity": "LOW",
                                "file": filename,
                                "line": getattr(node, "lineno", 1),
                                "evidence": "File path is computed dynamically",
                                "recommendation": "Validate file paths and restrict access to approved directories.",
                                "confirmed": False
                            })
        except SyntaxError as exc:
            findings.append({
                "rule_id": "PY-SYNTAX",
                "title": "Python syntax error",
                "severity": "MEDIUM",
                "file": filename,
                "line": exc.lineno or 1,
                "evidence": (exc.msg or "Syntax error")[:200],
                "recommendation": "Fix the syntax error and rerun tests.",
                "confirmed": False
            })

    return findings

def build_report(filename, source, findings):
    return {
        "tool": "OMEGA Defensive Security Auditor",
        "version": "6.0.0",
        "filename": filename,
        "sha256": hashlib.sha256(source.encode()).hexdigest(),
        "files_processed": 1,
        "lines_scanned": len(source.splitlines()),
        "findings_count": len(findings),
        "findings": findings,
        "limitations": [
            "Static heuristic checks; not equivalent to Mythos.",
            "Findings are unconfirmed and may be false positives.",
            "No findings does not mean the code is secure.",
            "Uploaded code is never executed."
        ]
    }

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!doctype html><html lang="en"><meta name="viewport"
    content="width=device-width,initial-scale=1">
    <title>OMEGA Auditor</title>
    <style>
    body{font:16px system-ui;max-width:900px;margin:25px auto;padding:16px;
    background:#101522;color:#edf2ff}
    textarea,input,button{box-sizing:border-box;width:100%;padding:12px;
    margin:8px 0;border-radius:8px}
    textarea,input{background:#202a3b;color:white;border:1px solid #526078}
    button{background:#4285f4;color:white;border:0}
    pre{white-space:pre-wrap;overflow-wrap:anywhere}
    a{color:#8cb8ff}
    </style>
    <h1>OMEGA Security Auditor</h1>
    <p>Defensive source-code review</p>
    <form id="scan">
    <input id="filename" value="source.py">
    <textarea id="code" rows="12" required
    placeholder="Paste source code"></textarea>
    <button>Scan source</button></form>
    <hr><h3>ZIP archive scan</h3>
    <form id="zipscan"><input type="file" id="archive"
    accept=".zip" required><button>Scan ZIP</button></form>
    <a href="/docs">API documentation</a><pre id="result">Ready</pre>
    <script>
    const out=document.getElementById('result');
    document.getElementById('scan').onsubmit=async e=>{
      e.preventDefault();out.textContent='Scanning...';
      try{
        const r=await fetch('/audit/text',{method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({filename:filename.value,code:code.value})});
        out.textContent=JSON.stringify(await r.json(),null,2);
      }catch(_){out.textContent='Request failed';}
    };
    document.getElementById('zipscan').onsubmit=async e=>{
      e.preventDefault();out.textContent='Scanning ZIP...';
      try{
        const fd=new FormData();
        fd.append('file',archive.files[0]);
        const r=await fetch('/audit/file',{method:'POST',body:fd});
        out.textContent=JSON.stringify(await r.json(),null,2);
      }catch(_){out.textContent='Request failed';}
    };
    </script></html>
    """

@app.get("/health")
def health():
    return {"status": "healthy", "version": "6.0.0"}

@app.post("/audit/text")
def audit_text(req: TextRequest):
    findings = scan_source(req.filename, req.code)
    return build_report(req.filename, req.code, findings)

@app.post("/audit/file")
async def audit_file(file: UploadFile = File(...)):
    filename = PurePosixPath(file.filename or "upload.zip").name
    if not filename.lower().endswith(".zip"):
        raise HTTPException(400, "Upload a ZIP file.")

    raw = await file.read(MAX_UPLOAD + 1)
    if len(raw) > MAX_UPLOAD:
        raise HTTPException(413, "ZIP exceeds 25 MiB.")

    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_FILES:
                raise HTTPException(413, "Too many archive entries.")

            findings = []
            skipped = []
            processed = 0
            lines = 0
            total_size = 0

            for item in entries:
                if item.is_dir():
                    continue

                path = PurePosixPath(item.filename)
                if path.is_absolute() or ".." in path.parts:
                    skipped.append({"file": item.filename[:120],
                                    "reason": "Unsafe path"})
                    continue

                if path.suffix.lower() not in EXTENSIONS:
                    continue

                if item.file_size > MAX_MEMBER:
                    skipped.append({"file": path.name,
                                    "reason": "File exceeds 2 MiB"})
                    continue

                total_size += item.file_size
                if total_size > MAX_TOTAL:
                    raise HTTPException(413, "Expanded source exceeds 50 MiB.")

                with archive.open(item) as stream:
                    data = stream.read(MAX_MEMBER + 1)

                if len(data) > MAX_MEMBER:
                    skipped.append({"file": path.name,
                                    "reason": "Actual size exceeds limit"})
                    continue

                source = data.decode("utf-8", errors="replace")
                findings.extend(scan_source(item.filename, source))
                processed += 1
                lines += len(source.splitlines())

            return {
                "filename": filename,
                "status": "REVIEW_REQUIRED" if findings else "NO_MATCHING_RULES",
                "files_processed": processed,
                "lines_scanned": lines,
                "findings_count": len(findings),
                "findings": findings,
                "skipped_files": skipped,
                "limits": {
                    "upload_mib": 25,
                    "expanded_mib": 50,
                    "max_files": MAX_FILES
                },
                "note": "Static analysis only; uploaded code is never executed."
            }
    except zipfile.BadZipFile:
        raise HTTPException(400, "Invalid ZIP archive.")
    except (OSError, RuntimeError, EOFError):
        raise HTTPException(400, "Could not safely read this ZIP.")
