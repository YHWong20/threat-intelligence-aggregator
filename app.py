from flask import Flask, render_template
import pandas as pd

app = Flask(__name__)

COLUMN_NAMES = {
    "ioc": "IOC",
    "ioc_type": "IOC Type",
    "threat_type": "Threat Type",
    "malware": "Malware",
    "confidence_level": "Confidence Level",
    "first_seen": "First Seen (UTC)",
    "last_seen": "Last Seen (UTC)",
    "reference": "Reference",
}

# Function to load CSV data
def load_data():
    try:
        df = pd.read_csv("./threatfox_ioc_180225.csv")
        df = df.fillna("N.A.")

        df["first_seen"] = pd.to_datetime(df["first_seen"], errors="coerce")  # Convert to datetime
        df["first_seen"] = df["first_seen"].dt.strftime("%Y-%m-%d\n%H:%M:%S")  # Insert newline
        df["first_seen"] = df["first_seen"].fillna("N.A.")  # Handle missing dates

        df["last_seen"] = pd.to_datetime(df["last_seen"], errors="coerce")  # Convert to datetime
        df["last_seen"] = df["last_seen"].dt.strftime("%Y-%m-%d\n%H:%M:%S")  # Insert newline
        df["last_seen"] = df["last_seen"].fillna("N.A.")  # Handle missing dates

        return df.to_dict(orient="records")  # Convert DataFrame to list of dicts
    except Exception as e:
        print(f"Error loading CSV: {e}")
        return []

@app.route("/")
def index():
    data = load_data()
    return render_template("index.html", data=data, column_names=COLUMN_NAMES)

if __name__ == "__main__":
    app.run(debug=True)
