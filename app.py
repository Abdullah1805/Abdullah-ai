# ULN SecInspector – Safe Automation Model
# Single-file Professional Security Judgment Assistant
# Author: You
# Philosophy: Accuracy > Quantity | Silence is a Feature | Human is Final Judge

import streamlit as st
import re
from dataclasses import dataclass
from typing import List

# -------------------------------
# Configuration
# -------------------------------

st.set_page_config(
    page_title="ULN SecInspector",
    layout="centered"
)

# -------------------------------
# Data Models
# -------------------------------

@dataclass
class Signal:
    key: str
    description: str
    severity: str
    evidence: str

@dataclass
class Finding:
    title: str
    explanation: str
    impact: str
    recommendation: str
    confidence: int
    relevance: int
    noise: int

# -------------------------------
# Signal Engine (Raw Detection)
# -------------------------------

def detect_signals(text: str) -> List[Signal]:
    signals = []

    if "0.0.0.0/0" in text:
        signals.append(Signal(
            key="open_world",
            description="Resource accessible from the entire internet",
            severity="High",
            evidence="0.0.0.0/0"
        ))

    if re.search(r'Action\s*=\s*"\*"', text) or "iam:*" in text:
        signals.append(Signal(
            key="iam_star",
            description="IAM permissions allow all actions",
            severity="Critical",
            evidence='Action = "*"'
        ))

    if 'acl = "public-read"' in text:
        signals.append(Signal(
            key="public_storage",
            description="Publicly readable storage detected",
            severity="High",
            evidence='acl = "public-read"'
        ))

    if "encryption" in text and "false" in text:
        signals.append(Signal(
            key="no_encryption",
            description="Encryption explicitly disabled",
            severity="Medium",
            evidence="encryption = false"
        ))

    if "logging" in text and "false" in text:
        signals.append(Signal(
            key="no_logging",
            description="Logging disabled for critical resource",
            severity="Medium",
            evidence="logging = false"
        ))

    return signals

# -------------------------------
# Judgment Layer (Core Intelligence)
# -------------------------------

def judge(signals: List[Signal]) -> List[Finding]:
    findings = []

    keys = [s.key for s in signals]

    for s in signals:
        confidence = 50
        relevance = 50
        noise = 50

        # Contextual reasoning (expert logic)
        if s.key == "iam_star":
            confidence = 95
            relevance = 90
            noise = 10

        if s.key == "open_world" and "iam_star" in keys:
            confidence = 90
            relevance = 85
            noise = 15

        if s.key == "public_storage" and "no_logging" in keys:
            confidence = 85
            relevance = 80
            noise = 20

        if s.key in ["no_logging", "no_encryption"] and len(keys) == 1:
            confidence = 55
            relevance = 40
            noise = 70

        # Silence rule
        if confidence < 70 or noise > relevance:
            continue

        findings.append(Finding(
            title=human_title(s),
            explanation=human_explanation(s),
            impact=human_impact(s),
            recommendation=human_recommendation(s),
            confidence=confidence,
            relevance=relevance,
            noise=noise
        ))

    return findings

# -------------------------------
# Human Explanation Engine
# -------------------------------

def human_title(signal: Signal) -> str:
    titles = {
        "iam_star": "صلاحيات إدارية كاملة بدون قيود",
        "open_world": "الوصول من الإنترنت بدون تقييد",
        "public_storage": "تخزين عام قابل للقراءة",
        "no_encryption": "تعطيل التشفير",
        "no_logging": "غياب السجلات الأمنية"
    }
    return titles.get(signal.key, "إعداد أمني حساس")

def human_explanation(signal: Signal) -> str:
    explanations = {
        "iam_star": "هذا الإعداد يسمح بتنفيذ أي عملية بدون قيود، وهو أحد أكثر أسباب الاختراقات شيوعًا.",
        "open_world": "المورد متاح من أي مكان على الإنترنت، مما يزيد سطح الهجوم.",
        "public_storage": "البيانات يمكن لأي شخص الوصول إليها بدون مصادقة.",
        "no_encryption": "البيانات قد تكون مقروءة في حال الوصول غير المصرح.",
        "no_logging": "أي نشاط ضار قد يمر دون اكتشاف."
    }
    return explanations.get(signal.key, "إعداد يحتاج مراجعة أمنية.")

def human_impact(signal: Signal) -> str:
    impacts = {
        "iam_star": "احتمال السيطرة الكاملة على البيئة السحابية.",
        "open_world": "زيادة احتمال الهجمات الخارجية.",
        "public_storage": "تسريب بيانات محتمل.",
        "no_encryption": "تعريض البيانات الحساسة للخطر.",
        "no_logging": "صعوبة التحقيق بعد الحوادث."
    }
    return impacts.get(signal.key, "تأثير أمني محتمل.")

def human_recommendation(signal: Signal) -> str:
    recs = {
        "iam_star": "تطبيق مبدأ أقل صلاحية (Least Privilege).",
        "open_world": "تقييد عناوين IP أو استخدام VPN.",
        "public_storage": "جعل التخزين خاصًا وربطه بصلاحيات IAM.",
        "no_encryption": "تفعيل التشفير الافتراضي.",
        "no_logging": "تفعيل التسجيل والمراقبة."
    }
    return recs.get(signal.key, "مراجعة الإعداد مع فريق الأمن.")

# -------------------------------
# Streamlit UI (Non-Technical Friendly)
# -------------------------------

st.title("🛡️ ULN SecInspector")
st.write("مساعد أمني ذكي يساعدك على اكتشاف الإعدادات الخطرة بدقة وهدوء.")

uploaded = st.file_uploader("📂 ارفع ملف الإعدادات (Terraform / نص)", type=["tf", "txt", "json"])

if uploaded:
    content = uploaded.read().decode("utf-8")

    if st.button("🔍 تحليل آمن"):
        signals = detect_signals(content)
        findings = judge(signals)

        if not findings:
            st.success("✅ لم يتم العثور على مشكلات ذات أهمية عالية.")
        else:
            st.warning(f"🚨 تم اكتشاف {len(findings)} نتيجة عالية الدقة")

            for f in findings:
                st.subheader("📌 النتيجة")
                st.markdown(f"**{f.title}**")
                st.info(f.explanation)

                with st.expander("📖 تفاصيل إضافية"):
                    st.write("**الأثر:**", f.impact)
                    st.write("**التوصية:**", f.recommendation)
                    st.write("**درجة الثقة:**", f.confidence, "%")

                st.markdown("---")

st.caption("هذا النظام لا يفحص مواقع أو شبكات — تحليل آمن وأخلاقي فقط.")
