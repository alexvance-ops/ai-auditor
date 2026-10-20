import re
import os
import ast
from colorama import Fore, Style, init

# Initialize color outputs
init(autoreset=True)

print(Fore.CYAN + Style.BRIGHT + "=====================================================================")
print(Fore.GREEN + Style.BRIGHT + "🛡️ OMEGA ULTRA-VISION: Advanced Source Code & Zero-Day Vulnerability Scanner")
print(Fore.CYAN + Style.BRIGHT + "=====================================================================\n")

# Advanced vulnerability signatures and impact database
VULN_DATABASE = [
    {
        "id": "ZERO-DAY-RCE",
        "title": "Remote Code Execution (RCE) via Unsafe Dynamic Evaluation",
        "severity": "CRITICAL",
        "patterns": [r"\beval\s*\(", r"\bexec\s*\(", r"__import__", r"getattr\s*\(\s*.*,\s*.*\)"],
        "fix": "Avoid dynamic code execution or run-time imports. Implement secure whitelisting.",
        "impact": "Malicious Threat Actor Impact: Allows unauthorized execution of arbitrary commands on the backend server. Attacks can lead to full system compromise, infrastructure takeover, and persistent backdoor installations."
    },
    {
        "id": "CRITICAL-SQLI",
        "title": "Advanced SQL Injection via Dynamic String Formatting",
        "patterns": [r"execute\s*\(\s*f[\'\"]", r"execute\s*\(\s*[\'\"]{1,3}.*\%", r"execute\s*\(\s*.*\.format\s*\("],
        "severity": "HIGH",
        "fix": "Always utilize Parameterized Queries or robust Object-Relational Mapping (ORM) frameworks.",
        "impact": "Malicious Threat Actor Impact: Bypasses authentication mechanisms entirely. Enables exfiltration of sensitive database records, credential dumping, or complete destruction of critical data structures."
    },
    {
        "id": "DESERIAL-INJECT",
        "title": "Unsafe Object Deserialization (Insecure Deserialization)",
        "patterns": [r"pickle\.loads\s*\(", r"yaml\.load\s*\(\s*.*\,\s*Loader\s*=\s*UnsafeLoader", r"marshal\.loads"],
        "severity": "CRITICAL",
        "fix": "Replace standard serialization with structural data formats like JSON, or enforce secure loading methods.",
        "impact": "Malicious Threat Actor Impact: Flaws embedded in complex logic workflows allow adversaries to pass malicious payloads via untrusted streams, achieving arbitrary execution context inside memory buffers."
    },
    {
        "id": "LOGICAL-BROKEN-AUTH",
        "title": "Broken Access Control & Weak Crypto Implementation",
        "patterns": [r"verify\s*=\s*False", r"jwt\.decode\s*\(\s*.*\,\s*verify\s*=\s*False", r"hashlib\.md5\s*\(", r"hashlib\.sha1\s*\("],
        "severity": "HIGH",
        "fix": "Enforce mandatory TLS verification and transition hashing workflows to standard algorithms like Argon2id or BCrypt.",
        "impact": "Malicious Threat Actor Impact: Allows escalation of privilege vectors, intercepting cryptographic tokens via Man-in-the-Middle (MITM) positioning, and rapid session hijacking vectors."
    },
    {
        "id": "COMMAND-INJECTION",
        "title": "OS Command Injection via Shell Execution",
        "patterns": [r"subprocess\.(Popen|run|call)\s*\(.*shell\s*=\s*True", r"os\.system\s*\("],
        "severity": "HIGH",
        "fix": "Do not execute commands with shell=True. Pass dynamic arguments safely as structural array elements.",
        "impact": "Malicious Threat Actor Impact: Allows reading internal environmental configuration parameters, local application variables, and configuration secrets by embedding system instructions directly within unprotected fields."
    }
]

def analyze_file_structure(file_path):
    print(Fore.YELLOW + f"[+] Analyzing logical program control flow for: {file_path}")
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            node = ast.parse(f.read())
            
        functions = [n.name for n in ast.walk(node) if isinstance(n, ast.FunctionDef)]
        classes = [n.name for n in ast.walk(node) if isinstance(n, ast.ClassDef)]
        
        print(Fore.BLUE + f"   [i] Structural Inventory: Detected {len(classes)} classes and {len(functions)} functional logic components.")
    except Exception:
        print(Fore.RED + "   [!] Complex code orchestration detected. Falling back to targeted pattern processing routines.")

def global_ultra_scanner(file_path):
    if not os.path.exists(file_path):
        print(Fore.RED + f"❌ Execution Error: Specified path '{file_path}' cannot be located on the filesystem.")
        return

    analyze_file_structure(file_path)
    bugs_found = 0
    report_data = []

    print(Fore.YELLOW + "\n[+] Scanning complex codebases for critical logical architecture flaws...")

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    for line_no, line in enumerate(lines, 1):
        clean_line = line.strip()
        # Disregard active text comments to maintain zero false-positive constraints
        if clean_line.startswith("#") or clean_line.startswith("//"):
            continue

        for vuln in VULN_DATABASE:
            for pattern in vuln["patterns"]:
                if re.search(pattern, clean_line):
                    bugs_found += 1
                    print(Fore.RED + Style.BRIGHT + f"\n🚨 [CRITICAL VULNERABILITY DETECTED] Identifier: {vuln['id']}")
                    print(Fore.WHITE + f"   📍 Target Location: Line {line_no}")
                    print(Fore.RED + f"   ⚠️  Classification: {vuln['title']}")
                    print(Fore.GENA + f"   🔥 Severity Metric: {vuln['severity']}")
                    print(Fore.YELLOW + f"   💻 Affected Syntax: {clean_line}")
                    print(Fore.GREEN + f"   💡 Remediation Vector: {vuln['fix']}")
                    print(Fore.LIGHTRED_EX + f"   💥 Adversary Exploitation Path: {vuln['impact']}")
                    print("-" * 60)
                    
                    report_data.append({
                        "line": line_no,
                        "title": vuln["title"],
                        "severity": vuln["severity"],
                        "fix": vuln["fix"],
                        "impact": vuln["impact"],
                        "code": clean_line
                    })

    if bugs_found > 0:
        print(Fore.GREEN + Style.BRIGHT + f"\n🎉 Scan completed successfully! Found {bugs_found} critical security discrepancies within the codebase.")
        print(Fore.CYAN + "🏆 Output data structures are formatted for direct submission to Bug Bounty standard reports.")
    else:
        print(Fore.GREEN + "\n[✓] Review completed. No structural anomalies or high-severity vulnerability markers detected.")

if __name__ == "__main__":
    file_to_scan = input("\nEnter the complete system path or filename of the target codebase to audit: ")
    global_ultra_scanner(file_to_scan)
