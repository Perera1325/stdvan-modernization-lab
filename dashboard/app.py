from flask import Flask, jsonify, render_template
import pandas as pd
import os

app = Flask(__name__)

REPORT_PATH = "../docs/traffic_report.csv"


def load_data():
    if not os.path.exists(REPORT_PATH):
        return None

    df = pd.read_csv(REPORT_PATH)
    total_bytes = df["bytes"].sum()
    avg_duration = df["duration"].mean()

    risk_score = 0
    if len(df) > 50:
        risk_score += 30
    if avg_duration > 5:
        risk_score += 30
    if total_bytes > 500000:
        risk_score += 40

    status = "NORMAL"
    if risk_score >= 60:
        status = "HIGH RISK"
    elif risk_score >= 30:
        status = "SUSPICIOUS"

    return {
        "connections": len(df),
        "total_bytes": int(total_bytes),
        "avg_duration": round(avg_duration, 2),
        "risk_score": risk_score,
        "status": status
    }


@app.route("/")
def dashboard():
    data = load_data()
    return render_template("index.html", data=data)


# 🔔 WSO2-READY ALERT ENDPOINT
@app.route("/api/alert")
def alert_api():
    data = load_data()
    return jsonify({
        "branch": "Branch-01",
        "risk_score": data["risk_score"],
        "status": data["status"],
        "message": "Automated Risk Evaluation from AI Engine"
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
