import hcl2
from pathlib import Path

def load_terraform_files(uploaded_files):
    data = []
    for file in uploaded_files:
        try:
            content = file.read().decode("utf-8")
            parsed = hcl2.loads(content)
            data.append(parsed)
        except Exception:
            continue
    return data
