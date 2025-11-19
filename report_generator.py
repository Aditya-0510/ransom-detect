# report_generator.py
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors

def generate_pdf_report(output_path, filename, result, probability, risk, features, importances):
    styles = getSampleStyleSheet()
    story = []

    title = f"<para align='center'><b><font size=16>Static Ransomware Scan Report</font></b></para>"
    story.append(Paragraph(title, styles['Title']))
    story.append(Spacer(1, 12))

    story.append(Paragraph("<b>File Information</b>", styles['Heading2']))
    story.append(Paragraph(f"File Name: {filename}", styles['Normal']))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Scan Result</b>", styles['Heading2']))
    story.append(Paragraph(f"Prediction: {result}", styles['Normal']))
    story.append(Paragraph(f"Benign Probability: {probability}", styles['Normal']))
    story.append(Paragraph(f"Risk Level: {risk}", styles['Normal']))
    story.append(Spacer(1, 12))

    story.append(Paragraph("<b>Extracted Static Features</b>", styles['Heading2']))

    feature_table_data = [["Feature", "Value"]]
    for k, v in features.items():
        feature_table_data.append([k, str(v)])

    feature_table = Table(feature_table_data, colWidths=[200, 300])
    feature_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkgray),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.gray)
    ]))
    story.append(feature_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("<b>Top Feature Importances</b>", styles['Heading2']))

    imp_table_data = [["Feature", "Importance"]]
    for i in range(len(importances["feature"])):
        imp_table_data.append([
            importances["feature"][i],
            f"{importances['importance'][i]:.6f}"
        ])

    imp_table = Table(imp_table_data, colWidths=[200, 300])
    imp_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.gray)
    ]))

    story.append(imp_table)

    pdf = SimpleDocTemplate(output_path, pagesize=letter)
    pdf.build(story)
    return output_path
