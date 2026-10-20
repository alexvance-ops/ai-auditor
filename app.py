
import ast
import hashlib
import io
import re
import zipfile
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

APP_VERSION = "5.0.0"
MAX_UPLOAD = 5 * 1024 * 1024
MAX_FILES = 300

app = FastAPI(
    title="OMEGA AI Security Auditor",
    version=APP_VERSION,
    description="Evidence-first security analysis for authorized code reviews."
)

EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".php",
    ".java", ".go", ".rb", ".json", ".yaml", ".yml"
}

RULES = [
    {
        "id": "PY001",
        "title": "Dynamic code execution",
        "severity": "HIGH",
        "ext": {".py"},
        "pattern": r"\b(eval|exec)\s*\(",
        "why": "Dynamic execution may become code injection with untrusted input.",
        "fix": "Avoid eval/exec; parse input with a strict schema."
    },
    {
        "id": "PY002",
        "title": "Possible SQL injection",
        "severity": "HIGH",
        "ext": {".py"},
        "pattern": r"""(?i)execute\s*\(\s*(f["']|["'][^"']*%s)""",
        "why": "SQL string construction may allow untrusted data into a query.",
        "fix": "Use parameterized queries."
    },
    {
        "id": "JS001",
        "title": "Potential unsafe HTML insertion",
        "severity": "MEDIUM",
        "ext": {".js", ".ts", ".jsx", ".tsx"},
        "pattern": r"\.innerHTML\s*=",
        "why": "Untrusted HTML may create cross-site scripting risk.",
        "fix": "Prefer textContent or framework-safe escaping."
    },
    {
        "id": "SEC001",
        "title": "Possible hard-coded secret",
        "severity": "HIGH",
        "ext": EXTENSIONS,
        "pattern": r"""(?i)\b(api_key|api-key|password|client_secret|access_token)\b\s*[:=]\s*["'][^"']{8,}["']""",
        "why": "Credentials in source code may leak through version control.",
        "fix": "Use environment variables or a secret manager; rotate exposed secrets."
    },
    {
        "id": "PY003",
        "title": "Process execution requires review",
        "severity": "MEDIUM",
        "ext": {".py"},
        "pattern": r"\bsubprocess\.(run|Popen|call|check_output)\s*\(",
        "why": "Process execution is risky when arguments contain untrusted data.",
        "fix": "Use argument lists, avoid shell=True, and validate input."
    },
    {
        "id": "PHP001",
        "title": "PHP deserialization requires review",
        "severity": "HIGH",
        "ext": {".php"},
        "pattern": r"\bunserialize\s*\(",
        "why": "Deserializing untrusted data may introduce object injection.",
        "fix": "Avoid deserializing untrusted input."
    }
]

class AuditRequest(BaseModel):
    filename: str = "snippet.py"
    code: str = Field(min_length=1, max_length=300_000)

def analyze(filename: str, code: str) -> list:
    ext = Path(filename).suffix.lower()
    findings = []

    for number, line in enumerate(code.splitlines(), 1):
        for rule in RULES:
            if ext not in rule["ext"]:
                continue

            if re.search(rule["pattern"], line):
                findings.append({
                    "rule_id": rule["id"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "confidence": "LOW",
                    "file": Path(filename).name,
                    "line": number,
                    "evidence": line.strip()[:250],
                    "why_it_matters": rule["why"],
                    "recommendation": rule["fix"],
                    "validation_required": True
                })

    # Python syntax errors are useful findings too.
    if ext == ".py":
        try:
            ast.parse(code)
        except SyntaxError as exc:
            findings.append({
                "rule_id": "PY-SYNTAX",
                "title": "Python syntax error",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "file": Path(filename).name,
                "line": exc.lineno or 1,
                "evidence": (exc.msg or "Syntax error")[:250],
                "why_it_matters": "Invalid syntax can prevent the program from running.",
                "recommendation": "Fix the reported syntax error and rerun tests.",
                "validation_required": True
            })

    return findings

def make_report(filename, code, findings):
    return {
        "service": "OMEGA AI Security Auditor",
        "version": APP_VERSION,
        "filename": Path(filename).name,
        "sha256": hashlib.sha256(code.encode()).hexdigest(),
        "status": "REVIEW_REQUIRED" if findings else "NO_MATCHING_RULES",
        "files_processed": 1,
        "lines_inspected": len(code.splitlines()),
        "findings_count": len(findings),
        "confirmed_vulnerabilities": 0,
        "findings": findings,
        "limitations": [
            "Pattern-based analysis only.",
            "Findings may be false positives.",
            "No findings does not prove the code is secure.",
            "Manual review and additional tests are necessary."
        ]
    }

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!doctype html>
    <html lang="en">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>OMEGA Security Auditor</title>
    <style>
    body{font:16px system-ui;background:#101522;color:#eef2ff;
    max-width:850px;margin:30px auto;padding:16px}
    textarea,input,button{box-sizing:border-box;width:100%;padding:12px;
    margin:8px 0;border-radius:8px}
    textarea,input{background:#202a3b;color:white;border:1px solid #526078}
    button{background:#4285f4;color:white;border:0;font-weight:bold}
    a{color:#8cb8ff}
    </style>
    <h1>OMEGA Security Auditor</h1>
    <p>Analyze source code you own or are authorized to review.</p>
    <form id="audit">
      <input id="filename" value="sample.py" aria-label="Filename">
      <textarea id="code" rows="12" required
        placeholder="Paste source code here"></textarea>
      <button>Analyze Code</button>
    </form>
    <p><a href="/docs">Open API documentation</a></p>
    <pre id="result">Ready.</pre>
    <script>
    document.getElementById('audit').onsubmit = async function(e) {
      e.preventDefault();
      const out = document.getElementById('result');
      out.textContent = 'Analyzing...';
      try {
        const r = await fetch('/audit/text', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body:JSON.stringify({
            filename:document.getElementById('filename').value,
            code:document.getElementById('code').value
          })
        });
        const data = await r.json();
        out.textContent = JSON.stringify(data, null, 2);
      } catch (_) {
        out.textContent = 'Request failed. Check server status.';
      }
    };
    </script>
    </html>
    """

@app.get("/health")
def health():
    return {"status": "healthy", "version": APP_VERSION}

@app.post("/audit/text")
def audit_text(req: AuditRequest):
    findings = analyze(req.filename, req.code)
    return make_report(req.filename, req.code, findings)

@app.post("/audit/file")
async def audit_file(file: UploadFile = File(...)):
    name = Path(file.filename or "upload.txt").name
    raw = await file.read(MAX_UPLOAD + 1)

    if len(raw) > MAX_UPLOAD:
        raise HTTPException(413, "Maximum upload size is 5 MiB.")

    if Path(name).suffix.lower() != ".zip":
        if Path(name).suffix.lower() not in EXTENSIONS:
            raise HTTPException(400, "Unsupported source file type.")
        try:
            code = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(400, "File must be UTF-8 text.")
        result = make_report(name, code, analyze(name, code))
        result["sha256"] = hashlib.sha256(raw).hexdigest()
        return result

    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_FILES:
                raise HTTPException(413, "Too many ZIP entries.")

            findings = []
            processed = 0
            total_lines = 0
            total_size = 0

            for item in entries:
                path = Path(item.filename)
                if item.is_dir() or path.is_absolute() or ".." in path.parts:
                    continue
                if path.suffix.lower() not in EXTENSIONS:
                    continue
                if item.file_size > 500_000:
                    continue

                total_size += item.file_size
                if total_size > 15 * 1024 * 1024:
                    raise HTTPException(413, "Uncompressed source limit exceeded.")

                source = archive.read(item).decode("utf-8", errors="replace")
                findings.extend(analyze(item.filename, source))
                processed += 1
                total_lines += len(source.splitlines())

        return {
            "filename": name,
            "status": "REVIEW_REQUIRED" if findings else "NO_MATCHING_RULES",
            "files_processed": processed,
            "lines_inspected": total_lines,
            "findings_count": len(findings),
            "confirmed_vulnerabilities": 0,
            "findings": findings,
            "limitations": [
                "Heuristic static analysis only.",
                "No matching rules does not prove security."
            ]
        }
    except zipfile.BadZipFile:
        raise HTTPException(400, "Invalid ZIP archive.")
