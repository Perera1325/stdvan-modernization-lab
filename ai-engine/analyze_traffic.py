import pandas as pd
import matplotlib.pyplot as plt

# Path to Zeek log captured earlier
LOG_FILE = "../docs/conn.log"


def load_zeek_log(file):
    """
    Load Zeek conn.log and extract useful fields.
    """
    rows = []

    with open(file, "r") as f:
        for line in f:
            if line.startswith("#"):
                continue

            parts = line.strip().split("\t")

            if len(parts) > 10:
                rows.append({
                    "ts": parts[0],
                    "src_ip": parts[2],
                    "dst_ip": parts[4],
                    "duration": float(parts[8]) if parts[8] != "-" else 0,
                    "bytes": int(parts[9]) if parts[9].isdigit() else 0
                })

    return pd.DataFrame(rows)


def analyze_behavior(df):
    """
    Basic anomaly detection logic (can later replace with ML).
    """
    total_connections = len(df)
    avg_duration = df["duration"].mean()
    total_bytes = df["bytes"].sum()

    print("\n=== Branch Traffic Summary ===")
    print(f"Total Connections: {total_connections}")
    print(f"Average Session Duration: {avg_duration:.2f}s")
    print(f"Total Bytes Transferred: {total_bytes}")

    # Risk scoring model
    risk_score = 0

    if total_connections > 50:
        risk_score += 30
    if avg_duration > 5:
        risk_score += 30
    if total_bytes > 500000:
        risk_score += 40

    print("\n=== Risk Assessment ===")
    print(f"Risk Score: {risk_score}%")

    if risk_score < 30:
        print("Status: NORMAL")
    elif risk_score < 60:
        print("Status: SUSPICIOUS")
    else:
        print("Status: HIGH RISK 🚨")

    return risk_score


def generate_report(df):
    """
    Generate SOC-style report + visualization.
    """
    df["duration"] = df["duration"].astype(float)

    summary = df.groupby("src_ip").agg({
        "duration": "mean",
        "bytes": "sum"
    }).reset_index()

    # Save CSV Report
    report_path = "../docs/traffic_report.csv"
    summary.to_csv(report_path, index=False)
    print(f"\nReport saved to {report_path}")

    # Generate Visualization
    plt.figure()
    plt.bar(summary["src_ip"], summary["bytes"])
    plt.xlabel("Branch IP")
    plt.ylabel("Total Bytes Sent")
    plt.title("Branch Traffic Volume Analysis")

    plot_path = "../docs/traffic_plot.png"
    plt.savefig(plot_path)
    print(f"Visualization saved to {plot_path}")


if __name__ == "__main__":
    print("🔍 Loading Zeek traffic log...")

    df = load_zeek_log(LOG_FILE)

    if df.empty:
        print("No traffic data found.")
    else:
        analyze_behavior(df)
        generate_report(df)

    print("\n✅ Analysis Complete.")
