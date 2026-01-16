import re

SECRET_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",
    r"(?i)aws_secret_access_key\s*=\s*['\"]?.+['\"]?"
]

def scan_secrets(text):
    findings = []
    for pattern in SECRET_PATTERNS:
        if re.search(pattern, text):
            findings.append(pattern)
    return findings
