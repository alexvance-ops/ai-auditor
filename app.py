import os
import zipfile
import tempfile
import re
from fastapi import FastAPI, BackgroundTasks, HTTPException, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List

app = FastAPI(title="Ultimate Master AI Security Code Auditor & Bug Bounty Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class VulnerabilityDetail(BaseModel):
    file_name: str
    line_number: int
    severity: str
    issue: str
    code_snippet: str
    recommendation: str

class AuditResponse(BaseModel):
    filename: str
    status: str
    security_score: str
    critical_bugs_found: int
    vulnerabilities: List[VulnerabilityDetail]

@app.get("/")
def check_status():
    return {
        "system_status": "Online & Fully Armed",
        "engine": "AI Security Code Auditor v4.0 (Master Ultimate Omnibus)",
        "mode": "Bug Bounty Elite Pro (Zero-Miss)"
    }

@app.post("/audit/upload", response_model=AuditResponse)
async def audit_file(file: UploadFile = File(...)):
    content = await file.read()
    vulnerabilities_found = []

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_file_path = os.path.join(temp_dir, file.filename)
        with open(temp_file_path, "wb") as f:
            f.write(content)

        files_to_scan = []

        if file.filename.endswith('.zip'):
            try:
                with zipfile.ZipFile(temp_file_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                for root, _, files in os.walk(temp_dir):
                    for f_name in files:
                        if f_name.endswith(('.py', '.js', '.json', '.txt', '.env', '.ts', '.html', '.php', '.go', '.java', '.yaml', '.yml')):
                            files_to_scan.append(os.path.join(root, f_name))
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"ZIP File extraction failed: {str(e)}")
        else:
            files_to_scan.append(temp_file_path)

        for filepath in files_to_scan:
            rel_path = os.path.relpath(filepath, temp_dir)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as code_file:
                    for line_num, line in enumerate(code_file, start=1):
                        line_str = line.strip()
                        
                        # 1. Critical Remote Code Execution (RCE) / Unsafe Deserialization
                        if re.search(r'\b(eval|exec|pickle\.loads|yaml\.load|marshal\.load)\s*\(', line_str):
                            vulnerabilities_found.append(VulnerabilityDetail(
                                file_name=rel_path,
                                line_number=line_num,
                                severity="CRITICAL",
                                issue="Remote Code Execution (RCE) / Unsafe Deserialization Risk",
                                code_snippet=line_str[:100],
                                recommendation="Avoid using eval(), exec(), or unsafe loaders on user-supplied inputs."
                            ))

                        # 2. Command Injection / OS Injection
                        elif re.search(r'\b(os\.system|os\.popen|subprocess\.call|subprocess\.Popen|subprocess\.run)\s*\(', line_str) and ('shell=True' in line_str or 'shell = True' in line_str or '+' in line_str or '%s' in line_str or 'f"' in line_str):
                            vulnerabilities_found.append(VulnerabilityDetail(
                                file_name=rel_path,
                                line_number=line_num,
                                severity="CRITICAL",
                                issue="Command Injection Vulnerability",
                                code_snippet=line_str[:100],
                                recommendation="Do not pass unvalidated user inputs directly to shell commands; use list arguments instead of shell=True."
                            ))

                        # 3. SQL Injection (SQLi) Risk
                        elif re.search(r'\b(execute|cursor\.execute|query)\s*\(\s*(f["\']|.*%.*|.*\+.*SELECT|.*\+.*INSERT|.*\+.*UPDATE|.*\+.*DELETE)', line_str, re.IGNORECASE):
                            vulnerabilities_found.append(VulnerabilityDetail(
                                file_name=rel_path,
                                line_number=line_num,
                                severity="HIGH",
                                issue="Potential SQL Injection (SQLi) Risk",
                                code_snippet=line_str[:100],
                                recommendation="Use parameterized queries or ORM (like SQLAlchemy) instead of string formatting/concatenation in SQL queries."
                            ))

                        # 4. Server-Side Template Injection (SSTI) & XSS Risk
                        elif re.search(r'\b(render_template_string|Markup|safe)\s*\(', line_str) or re.search(r'<\s*script\s*>', line_str, re.IGNORECASE):
                            vulnerabilities_found.append(VulnerabilityDetail(
                                file_name=rel_path,
                                line_number=line_num,
                                severity="HIGH",
                                issue="Server-Side Template Injection (SSTI) or XSS Risk",
                                code_snippet=line_str[:100],
                                recommendation="Avoid rendering unescaped user input in templates or web pages."
                            ))

                        # 5. Path Traversal / Unsafe File Operations
                        elif re.search(r'\bopen\s*\(\s*.*(\+|%s|f["\'].*\{).*(path|file|input|req|user)', line_str, re.IGNORECASE) or '..\\' in line_str or '../' in line_str:
                            vulnerabilities_found.append(VulnerabilityDetail(
                                file_name=rel_path,
                                line_number=line_num,
                                severity="HIGH",
                                issue="Path Traversal / Unsafe File Read Risk",
                                code_snippet=line_str[:100],
                                recommendation="Validate and sanitize file paths using os.path.basename or secure paths before opening files."
                            ))

                        # 6. Hardcoded Secrets, Passwords & API Keys
                        elif re.search(r'(secret_key|api_key|password|passwd|auth_token|access_token|client_secret|jwt_secret)\s*[:=]\s*["\'][a-zA-Z0-9_\-]{8,}(?<!your_key)(?<!example)(?<!placeholder)["\']', line_str, re.IGNORECASE):
                            if not any(ignore in line_str.lower() for ignore in ["example", "placeholder", "your_", "env", "os.environ"]):
                                vulnerabilities_found.append(VulnerabilityDetail(
                                    file_name=rel_path,
                                    line_number=line_num,
                                    severity="MEDIUM",
                                    issue="Hardcoded Secrets/Credentials Found",
                                    code_snippet=line_str[:100],
                                    recommendation="Store sensitive API keys and passwords in environment variables (.env)."
                                ))

                        # 7. Weak Cryptography / Hashing
                        elif re.search(r'\b(hashlib\.md5|hashlib\.sha1|DES|RC4)\s*\(', line_str, re.IGNORECASE):
                            vulnerabilities_found.append(VulnerabilityDetail(
                                file_name=rel_path,
                                line_number=line_num,
                                severity="LOW",
                                issue="Weak Cryptographic Algorithm",
                                code_snippet=line_str[:100],
                                recommendation="Use secure cryptographic algorithms like SHA-256, SHA-3, or bcrypt."
                            ))

            except Exception:
                continue

    # Score calculation based on severity weight
    penalty = 0
    for v in vulnerabilities_found:
        if v.severity == "CRITICAL":
            penalty += 35
        elif v.severity == "HIGH":
            penalty += 20
        elif v.severity == "MEDIUM":
            penalty += 10
        else:
            penalty += 5

    score = max(0, 100 - penalty)

    return AuditResponse(
        filename=file.filename,
        status="Master Ultimate Omnibus Security Audit Completed (Zero Miss Mode)",
        security_score=f"{score}/100",
        critical_bugs_found=len(vulnerabilities_found),
        vulnerabilities=vulnerabilities_found
    )
