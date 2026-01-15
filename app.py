import streamlit as st
import hcl2
import json
import re
import ipaddress
from typing import List, Dict, Any, Union
from io import BytesIO
from datetime import datetime
from markdown2 import markdown
from weasyprint import HTML

# =========================================================
# 1. KNOWLEDGE BASE – Security Axioms & Patterns
# =========================================================
AXIOMS = {
    "SENSITIVE_PORTS": {
        "22": "SSH", "23": "Telnet", "3389": "RDP", "3306": "MySQL",
        "5432": "PostgreSQL", "6379": "Redis", "27017": "MongoDB",
        "8080": "Admin Web", "9200": "Elasticsearch"
    },
    "ENCRYPTION_ATTRIBUTES": {
        "aws_s3_bucket": ["server_side_encryption_configuration", "rule", "apply_server_side_encryption_by_default", "sse_algorithm"],
        "aws_db_instance": ["storage_encrypted"],
        "aws_ebs_volume": ["encrypted"]
    },
    "WEAK_ALGORITHMS": ["none", "null", "plain", ""],
    "RISKY_IAM_ACTIONS": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:PassRole", "iam:CreateAccessKey"]
}

REMEDIATIONS = {
    "OPEN_ADMIN_PORT": "Restrict CIDR to internal networks only.",
    "IAM_WILDCARD": "Replace wildcard actions/resources with specific least privilege permissions.",
    "NO_ENCRYPTION": "Enable AES-256 or KMS encryption at rest.",
    "HARDCODED_SECRET": "Move secrets to AWS Secrets Manager or Vault."
}

# =========================================================
# 2. CORE ENGINE – ULN CyberSentinel Pro
# =========================================================

class ULNCyberSentinelPro:

    def __init__(self, code: str):
        self.code = code
        self.findings: List[Dict[str, Any]] = []
        self.variables: Dict[str, Any] = {}
        self.resources: Dict[str, Any] = {}

    def _resolve(self, val: Any) -> Any:
        if isinstance(val, list):
            return [self._resolve(i) for i in val]
        if isinstance(val, str) and "${var." in val:
            match = re.search(r"var\.(\w+)", val)
            if match:
                return self.variables.get(match.group(1), val)
        return val

    def _is_public_ip(self, cidrs: Union[str, List]) -> bool:
        if not isinstance(cidrs, list):
            cidrs = [cidrs]
        try:
            for c in cidrs:
                net = ipaddress.ip_network(str(c).strip())
                if net.prefixlen <= 1:
                    return True
            return False
        except:
            return False

    def _normalize_list(self, val: Any) -> List:
        if isinstance(val, list): return val
        return [val] if val else []

    # -------------------------------
    # Analysis Modules
    # -------------------------------
    def analyze_network(self, res_id: str, props: Dict):
        ingress = props.get("ingress", [])
        if isinstance(ingress, dict):
            ingress = [ingress]
        for rule in ingress:
            cidrs = self._resolve(rule.get("cidr_blocks", []))
            if not self._is_public_ip(cidrs):
                continue
            from_p = str(rule.get("from_port", ""))
            to_p = str(rule.get("to_port", ""))
            proto = str(rule.get("protocol", "")).lower()
            if proto == "-1" or (from_p == "0" and to_p == "65535"):
                self.findings.append({
                    "severity": "CRITICAL", "resource": res_id,
                    "title": "Full Internet Exposure (All Protocols)",
                    "fix": REMEDIATIONS["OPEN_ADMIN_PORT"]
                })
            elif from_p in AXIOMS["SENSITIVE_PORTS"]:
                self.findings.append({
                    "severity": "HIGH", "resource": res_id,
                    "title": f"Public {AXIOMS['SENSITIVE_PORTS'][from_p]} Access",
                    "fix": REMEDIATIONS["OPEN_ADMIN_PORT"]
                })

    def analyze_encryption(self, res_id: str, r_type: str, props: Dict):
        if r_type not in AXIOMS["ENCRYPTION_ATTRIBUTES"]:
            return
        path = AXIOMS["ENCRYPTION_ATTRIBUTES"][r_type]
        curr = props
        for step in path:
            if isinstance(curr, list) and curr: curr = curr[0]
            curr = curr.get(step, {}) if isinstance(curr, dict) else {}
        val = str(curr).lower() if curr else ""
        if not curr or any(weak in val for weak in AXIOMS["WEAK_ALGORITHMS"]):
            self.findings.append({
                "severity": "HIGH",
                "resource": res_id,
                "title": f"Insecure Encryption on {r_type}",
                "fix": REMEDIATIONS["NO_ENCRYPTION"]
            })

    def analyze_iam(self, res_id: str, props: Dict):
        policy_raw = props.get("policy") or props.get("policy_document")
        if not policy_raw: return
        try:
            policy = json.loads(policy_raw) if isinstance(policy_raw, str) else policy_raw
            statements = self._normalize_list(policy.get("Statement", []))
            for stmt in statements:
                if stmt.get("Effect") != "Allow": continue
                actions = self._normalize_list(stmt.get("Action", []))
                resources = self._normalize_list(stmt.get("Resource", []))
                if "*" in actions and "*" in resources:
                    self.findings.append({
                        "severity": "CRITICAL",
                        "resource": res_id,
                        "title": "IAM Full Admin Privileges",
                        "fix": REMEDIATIONS["IAM_WILDCARD"]
                    })
                if any(a in AXIOMS["RISKY_IAM_ACTIONS"] for a in actions) and "*" in resources:
                    self.findings.append({
                        "severity": "HIGH",
                        "resource": res_id,
                        "title": "Privilege Escalation Risk",
                        "fix": REMEDIATIONS["IAM_WILDCARD"]
                    })
        except:
            pass

    def scan(self) -> List[Dict]:
        try:
            data = hcl2.loads(self.code)
            for var_block in data.get("variable", []):
                for name, body in var_block.items():
                    self.variables[name] = body.get("default")
            for r_type, blocks in data.get("resource", {}).items():
                for block in blocks:
                    for name, props in block.items():
                        res_id = f"{r_type}.{name}"
                        self.resources[res_id] = props
                        self.analyze_network(res_id, props)
                        self.analyze_encryption(res_id, r_type, props)
                        self.analyze_iam(res_id, props)
            return self.findings
        except Exception as e:
            return [{"severity": "ERROR", "title": "Parsing Failed", "detail": str(e)}]

    def generate_report(self, fmt="markdown") -> str:
        score = 100
        score -= len([f for f in self.findings if f['severity'] == "CRITICAL"]) * 20
        score -= len([f for f in self.findings if f['severity'] == "HIGH"]) * 10
        score = max(0, score)
        if fmt == "json":
            return json.dumps({"score": score, "findings": self.findings}, indent=2)
        report = f"# 🛡️ CyberSentinel Pro Security Report\n**Score: {score}/100** | **Findings: {len(self.findings)}**\n\n"
        for f in self.findings:
            color = "🔴" if f['severity'] == "CRITICAL" else "🟠"
            report += f"### {color} {f['title']}\n- **Resource:** `{f['resource']}`\n- **Fix:** {f['fix']}\n\n"
        return report

# =========================================================
# 3. STREAMLIT INTERFACE
# =========================================================

st.set_page_config(page_title="ULN CyberSentinel Pro", layout="wide")
st.title("🛡️ ULN CyberSentinel Pro - Security Analyzer")
st.markdown("رفع ملفات Terraform (.tf) لتحليل المنافذ، التشفير، وصلاحيات IAM.")

uploaded_file = st.file_uploader("اختر ملف Terraform (.tf)", type=["tf", "txt"])

if uploaded_file:
    code = uploaded_file.read().decode("utf-8")
    scanner = ULNCyberSentinelPro(code)
    
    if st.button("ابدأ التحليل"):
        with st.spinner("جاري تحليل الكود..."):
            findings = scanner.scan()
            report_md = scanner.generate_report(fmt="markdown")
            st.markdown(report_md)
            
            # --- Download Buttons ---
            st.download_button("⬇️ تحميل التقرير كـ Markdown", report_md, file_name=f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")

            # PDF Generation
            try:
                html = markdown(report_md)
                pdf_file = BytesIO()
                HTML(string=html).write_pdf(pdf_file)
                st.download_button("⬇️ تحميل التقرير كـ PDF", pdf_file.getvalue(), file_name=f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
            except Exception as e:
                st.warning(f"لم يتم إنشاء PDF: {e}")
