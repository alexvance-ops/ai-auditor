import os
import zipfile
import tempfile
import re
from fastapi import FastAPI, BackgroundTasks, HTTPException, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Union

app = FastAPI(title="Ultra-Secure Multi-Chat AI Auditor & Voice Alert System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ACTIVE_SESSIONS = {}

class AuditRequest(BaseModel):
    chat_id: str
    code_snippet: str
    language: str = "python"
    voice_lang: str = "bn"

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
        "system_status": "Online & Secure",
        "engine": "AI Security Code Auditor v2.0",
        "max_parallel_chats": 5
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
                        if f_name.endswith(('.py', '.js', '.json', '.txt', '.env', '.ts', '.html')):
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
                        
                        # 1. Check for hardcoded secrets
                        if ("secret_key" in line_str.lower() or "password" in line_str.lower() or "api_key" in line_str.lower()) and "=" in line_str:
                            if not any(ignore in line_str.lower() for ignore in ["example", "placeholder", "your_"]):
                                vulnerabilities_found.append(VulnerabilityDetail(
                                    file_name=rel_path,
                                    line_number=line_num,
                                    severity="MEDIUM",
                                    issue="Hardcoded Secrets/Credentials Found",
                                    code_snippet=line_str[:80],
                                    recommendation="Use Environment Variables (.env) instead of hardcoding credentials."
                                ))

                        # 2. Check for Dangerous Execution
                        elif "eval(" in line_str or "exec(" in line_str:
                            vulnerabilities_found.append(VulnerabilityDetail(
                                file_name=rel_path,
                                line_number=line_num,
                                severity="CRITICAL",
                                issue="Dynamic Code Execution Risk",
                                code_snippet=line_str[:80],
                                recommendation="Avoid eval()/exec() to prevent Remote Code Execution (RCE)."
                            ))

            except Exception:
                continue

    score = max(0, 100 - (len(vulnerabilities_found) * 25))

    return AuditResponse(
        filename=file.filename,
        status="Audit & False-Positive Verification Completed",
        security_score=f"{score}/100",
        critical_bugs_found=len(vulnerabilities_found),
        vulnerabilities=vulnerabilities_found
    )
