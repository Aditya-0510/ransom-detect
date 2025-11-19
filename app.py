from flask import Flask, request, render_template
from werkzeug.utils import secure_filename
import os
import joblib
import pandas as pd
import json
from extract_features_static import extract_features
from model_utils import hex_to_int_frame, listlen_frame
from report_generator import generate_pdf_report
from flask import send_from_directory

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

model = joblib.load("models/static_pe_model.joblib")

importances_df = pd.read_csv("models/static_feature_importance.csv").head(10)
@app.route("/download/<path:filename>")
def download(filename):
    return send_from_directory("reports", filename, as_attachment=True)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        file = request.files.get("file")
        if not file:
            return render_template("upload.html", error="Please choose a file.")

        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        feats = extract_features(filepath)
        if feats is None:
            return render_template("upload.html", error="Not a valid PE (EXE/DLL) file.")

        X = pd.DataFrame([feats])

        # Predict
        proba = float(model.predict_proba(X)[0][1])
        malicious = proba < 0.5

        result = "⚠️ MALICIOUS" if malicious else "✅ Benign"
        if proba >= 0.9:
            risk = "Low Risk"
        elif proba >= 0.6:
            risk = "Medium Risk"
        else:
            risk = "HIGH RISK"

        # Get chart data
        chart_labels = importances_df["feature"].tolist()
        chart_values = importances_df["importance"].tolist()
        os.makedirs("reports", exist_ok=True)
        pdf_path = f"reports/{filename}.pdf"
        generate_pdf_report(
            pdf_path,
            filename,
            result,
            proba,
            risk,
            feats,
            importances_df
        )

        return render_template(
            "upload.html",
            filename=filename,
            result=result,
            probability=round(proba, 4),
            risk=risk,
            features=feats,
            chart_labels=chart_labels,
            chart_values=chart_values,
            pdf_file=f"{filename}.pdf"
        )

    return render_template("upload.html")

if __name__ == "__main__":
    app.run(debug=True)
