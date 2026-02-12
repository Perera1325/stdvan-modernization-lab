import pandas as pd

LOG_FILE = "../docs/conn.log"

def load_zeek_log(file):
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
    total_connections = len(df)
    avg_duration = df["duration"].mean()
    total_bytes = df["bytes"].sum()

    print("\n=== Branch Traffic Summary ===")
    print(f"Total Connections: {total_connections}")
    print(f"Average Session Duration: {avg_duration:.2f}s")
    print(f"Total Bytes Transferred: {total_bytes}")

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

if __name__ == "__main__":
    df = load_zeek_log(LOG_FILE)
    analyze_behavior(df)
