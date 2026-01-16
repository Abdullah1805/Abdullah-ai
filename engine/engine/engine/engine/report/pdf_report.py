from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

def generate_report(paths, scores, output="report.pdf"):
    c = canvas.Canvas(output, pagesize=A4)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 800, "IAM Attack Path Executive Report")

    y = 760
    for i, path in enumerate(paths):
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, f"Finding #{i+1} – Score: {scores[i]}/100")
        y -= 20
        c.setFont("Helvetica", 10)
        c.drawString(60, y, " → ".join(path))
        y -= 40

        if y < 100:
            c.showPage()
            y = 800

    c.save()
