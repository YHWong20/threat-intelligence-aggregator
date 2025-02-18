from flask import Flask, render_template
import pandas as pd

app = Flask(__name__)

# Function to load CSV data
def load_data():
    try:
        df = pd.read_csv("./threatfox_ioc_180225.csv")  # Replace with your CSV filename
        return df.to_dict(orient="records")  # Convert DataFrame to list of dicts
    except Exception as e:
        print(f"Error loading CSV: {e}")
        return []

@app.route("/")
def index():
    data = load_data()
    return render_template("index.html", data=data)

if __name__ == "__main__":
    app.run(debug=True)
