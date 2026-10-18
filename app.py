import os
import zipfile
import tempfile
import re
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(
    title="Multi-Chat AI Auditor & Voice Alert System",
    version="0.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class VulnerabilityDetail(BaseModel):
    file_path: str
    line_number: int
    issue_type: str
    severity: str
    snippet: str
    explanation: str
    recommendation: str

class DetailedAuditResponse(BaseModel):
    filename: str
    status: str
    security_score: int
    total_issues_found: int
    vulnerabilities: List[VulnerabilityDetail]

# Secret Identification Regex Patterns
SECRET_PATTERNS = [
    (r'(?i)(api_key|apikey|secret|password|passwd|auth_token|access_token)\s*=\s*[\'"][A-Za-z0-9_\-]{8,}[\'"]', "Hardcoded Secret / API Key"),
    (r'BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY', "Hardcoded Private Key"),
    (r'(?i)eval\s*\(', "Dangerous Dynamic Execution (eval)"),
    (r'(?i)exec\s*\(', "Dangerous Dynamic Execution (exec)"),
]

@app.get("/")
def check_status():
    return {"status": "AI Auditor Backend is Online"}

@app.post("/audit/upload", response_model=DetailedAuditResponse)
async def audit_file(file: UploadFile = File(...)):
    if not file.filename.endswith(('.zip', '.py', '.js', '.json', '.txt')):
        raise HTTPException(status_code=400, detail="Only ZIP archive or code files (.py, .js, .json) are supported.")

    vulnerabilities = []
    
    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = os.path.join(temp_dir, file.filename)
        with open(file_path, "wb") as f:
            f.write(await file.read())

        files_to_scan = []
        if file.filename.endswith('.zip'):
            try:
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                for root, _, files in os.walk(temp_dir):
                    for f_name in files:
                        if f_name.endswith(('.py', '.js', '.json', '.txt', '.env', '.html', '.ts')):
                            files_to_scan.append(os.path.join(root, f_name))
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Invalid ZIP file: {str(e)}")
        else:
            files_to_scan.append(file_path)

        for filepath in files_to_scan:
            rel_path = os.path.relpath(filepath, temp_dir)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as code_file:
                    for line_idx, line in enumerate(code_file, start=1):
                        for pattern, issue_name in SECRET_PATTERNS:
                            if re.search(pattern, line):
                                # Verification step to filter obvious false positives
                                if "example" in line.lower() or "placeholder" in line.lower() or "your_key_here" in line.lower():
                                    continue
                                
                                vulnerabilities.append(VulnerabilityDetail(
                                    file_path=rel_path,
                                    line_number=line_idx,
                                    issue_type=issue_name,
                                    severity="HIGH" if "Private Key" in issue_name or "eval" in issue_name else "MEDIUM",
                                    snippet=line.strip()[:100],
                                    explanation=f"Detected potential {issue_name} hardcoded directly inside the source code.",
                                    recommendation="Remove the hardcoded secret and load it securely using Environment Variables (.env)."
                                ))
            except Exception:
                continue

    # Security score calculation
    score = max(0, 100 - (len(vulnerabilities) * 25))

    return DetailedAuditResponse(
        filename=file.filename,
        status="Audit & Detailed Line-by-Line Verification Completed",
        security_score=score,
        total_issues_found=len(vulnerabilities),
        vulnerabilities=vulnerabilities
    )
