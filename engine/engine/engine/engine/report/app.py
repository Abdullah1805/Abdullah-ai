import streamlit as st
from parsers.terraform_parser import load_terraform_files
from engine.graph_builder import AttackGraph
from engine.scorer import score_path
from report.pdf_report import generate_report

st.set_page_config(layout="wide")
st.title("AegisPath – Cloud IAM Attack Path Analyzer")

files = st.file_uploader("Upload Terraform Files", accept_multiple_files=True)

if files:
    data = load_terraform_files(files)
    graph = AttackGraph()

    # (اختصاراً: هنا تربط PassRole → EC2 → Admin)
    graph.add_edge("JuniorDevRole", "AdminRole", "EC2 PassRole Escalation")

    paths = graph.find_paths(["JuniorDevRole"], ["AdminRole"])
    scores = [score_path(p, "Tier-1") for p in paths]

    st.subheader("Critical Attack Paths")
    for p, s in zip(paths, scores):
        st.write(f"Score {s}/100:", " → ".join(p))

    if st.button("Generate PDF Report"):
        generate_report(paths, scores)
        st.success("PDF Generated: report.pdf")
