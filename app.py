import os
import zipfile
import tempfile
import re
from fastapi import FastAPI, BackgroundTasks, HTTPException, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List

app = FastAPI(title="Ultimate AI Security Code Auditor & Auto-PoC Bug Bounty Engine")

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
    auto_poc: str
    impact_analysis: str
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
        "engine": "AI Security Code Auditor v5.0 (Auto-PoC & Impact Engine)",
        "mode": "Zero-Effort Bug Bounty Hunter"
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
                        
                        # 1. RCE / Unsafe Deserialization
                        if re.search(r'\b(eval|exec|pickle\.loads|yaml\.load|marshal\.load)\s*\(', line_str):
                            vulnerabilities_found.append(VulnerabilityDetail(
                                file_name=rel_path,
                                line_number=line_num,
                                severity="CRITICAL",
                                issue="Remote Code Execution (RCE) / Unsafe Deserialization Risk",
                                code_snippet=line_str[:100],
                                auto_poc="Send payload via POST request: `import pickle; import base64; payload = base64.b64encode(pickle.dumps(RCE_COMMAND))`",
                                impact_analysis="An attacker can execute arbitrary system commands on the server, leading to full system compromise.",
                                recommendation="Avoid using eval(), exec(), or unsafe loaders on user-supplied inputs."
                            ))

                        # 2. Command Injection
                        elif re.search(r'\b(os\.system|os\.popen|subprocess\.call|subprocess\.Popen|subprocess\.run)\s*\(', line_str) and ('shell=True' in line_str or 'shell = True' in line_str or '+' in line_str or '%s' in line_str or 'f"' in line_str):
                            vulnerabilities_found.append(VulnerabilityDetail(
                                file_name=rel_path,
                                line_number=line_num,
                                severity="CRITICAL",
                                issue="Command Injection Vulnerability",
                                code_snippet=line_str[:100],
                                auto_poc="Test input with command chaining: `input_val = '; id'` or `input_val = '| cat /etc/passwd'`",
                                impact_analysis="Allows attackers to run arbitrary OS commands under the application user privileges.",
                                recommendation="Do not pass unvalidated user inputs directly to shell commands; use list arguments instead of shell=True."
                            ))

                        # 3. SQL Injection (SQLi)
                        elif re.search(r'\b(execute|cursor\.execute|query)\s*\(\s*(f["\']|.*%.*|.*\+.*SELECT|.*\+.*INSERT|.*\+.*UPDATE|.*\+.*DELETE)', line_str, re.IGNORECASE):
                            vulnerabilities_found.append(VulnerabilityDetail(
                                file_name=rel_path,
                                line_number=line_num,
                                severity="HIGH",
                                issue="Potential SQL Injection (SQLi) Risk",
                                code_snippet=line_str[:100],
                                auto_poc="Test input in parameters: `user_input = \"' OR '1'='1\"` or `UNION SELECT null, version()--`",
                                impact_analysis="Allows attackers to bypass authentication, read, modify, or delete database contents entirely.",
                                recommendation="Use parameterized queries or ORM (like SQLAlchemy) instead of string formatting/concatenation."
                            ))

                        # 4. Path Traversal / File Read
                        elif re.search(r'\bopen\s*\(\s*.*(\+|%s|f["\'].*\{).*(path|file|input|req|user)', line_str, re.IGNORECASE) or '..\\' in line_str or '../' in line_str:
                            vulnerabilities_found.append(VulnerabilityDetail(
                                file_name=rel_path,
                                line_number=line_num,
                                severity="HIGH",
                                issue="Path Traversal / Unsafe File Read Risk",
                                code_snippet=line_str[:100],
                                auto_poc="Send malicious request parameter: `?file=../../../../etc/passwd` or `..\\..\\windows\\win.ini`",
                                impact_analysis="Allows unauthorized reading of sensitive server configuration files, source code, or system credentials.",
                                recommendation="Validate and sanitize file paths using os.path.basename or secure base directories."
                            ))

                        # 5. Hardcoded Secrets
                        elif re.search(r'(secret_key|api_key|password|passwd|auth_token|access_token|client_secret|jwt_secret)\s*[:=]\s*["\'][a-zA-Z0-9_\-]{8,}(?<!your_key)(?<!example)(?<!placeholder)["\']', line_str, re.IGNORECASE):
                            if not any(ignore in line_str.lower() for ignore in ["example", "placeholder", "your_", "env", "os.environ"]):
                                vulnerabilities_found.append(VulnerabilityDetail(
                                    file_name=rel_path,
                                    line_number=line_num,
                                    severity="MEDIUM",
                                    issue="Hardcoded Secrets/Credentials Found",
                                    code_snippet=line_str[:100],
                                    auto_poc="Review the source code snippet directly; use the extracted credential to access the targeted service API/Database.",
                                    impact_analysis="Exposed API keys or passwords can be abused by unauthorized third parties to gain backend or third-party service access.",
                                    recommendation="Store sensitive API keys and passwords in environment variables (.env)."
                                ))

            except Exception:
                continue

    penalty = sum(35 if v.severity == "CRITICAL" else 20 if v.severity == "HIGH" else 10 for v in vulnerabilities_found)
    score = max(0, 100 - penalty)

    return AuditResponse(
        filename=file.filename,
        status="Auto-PoC & Impact Analysis Audit Completed",
        security_score=f"{score}/100",
        critical_bugs_found=len(vulnerabilities_found),
        vulnerabilities=vulnerabilities_found
    )
