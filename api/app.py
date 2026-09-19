"""
app.py — Flask API for the phishing detection model.

Endpoints:
    GET  /health           -> simple check that the server + model are alive
    POST /predict           -> body: {"url": "http://example.com"}
                                returns: {"url", "prediction", "confidence"}

Run locally with:
    python app.py
Then it's reachable at http://127.0.0.1:5000
"""

from flask_cors import CORS
from flask import Flask, request, jsonify
import joblib
import pandas as pd
import os
import sys

# feature_extractor.py lives in ../src relative to this file (api/app.py),
# so we add that folder to Python's import path before importing it.
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
from feature_extractor import FEATURE_NAMES, extract_features_dict

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# --- Load the model ONCE when the server starts, not per-request. ---
# Loading a model from disk takes time; doing it on every request would make
# the API needlessly slow. Loading once and reusing it is standard practice.
MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "phishing_model_live.pkl")
model = joblib.load(MODEL_PATH)


@app.route("/health", methods=["GET"])
def health():
    """Quick check that the server is up and the model loaded successfully.
    Useful for debugging, and for the browser extension to check connectivity
    before making real prediction requests."""
    return jsonify({"status": "ok", "model_loaded": model is not None})


@app.route("/predict", methods=["POST"])
def predict():
    # --- Step 1: validate the request body ---
    # Never trust incoming data. A missing or malformed request should return
    # a clear error, not crash the server.
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Request body must be JSON with a 'url' field"}), 400

    url = data["url"]
    if not isinstance(url, str) or not url.strip():
        return jsonify({"error": "'url' must be a non-empty string"}), 400

    url = url.strip()

    # --- Step 2: extract features ---
    # Wrapped in try/except: a malformed URL (e.g. missing scheme) could make
    # urlparse behave unexpectedly, and we'd rather return a clean error than
    # a stack trace to the caller.
    try:
        features_dict = extract_features_dict(url)
        features_row = pd.DataFrame([features_dict])[FEATURE_NAMES]
    except Exception as e:
        return jsonify({"error": f"Could not process URL: {str(e)}"}), 400

    # --- Step 3: predict ---
    prediction = model.predict(features_row)[0]

    # predict_proba gives us a confidence score, not just the raw label.
    # model.classes_ tells us which column corresponds to which class,
    # since scikit-learn doesn't guarantee column order matches label order.
    probabilities = model.predict_proba(features_row)[0]
    class_index = list(model.classes_).index(prediction)
    confidence = round(float(probabilities[class_index]), 3)

    label = "phishing" if prediction == -1 else "legitimate"

    return jsonify({
        "url": url,
        "prediction": label,
        "confidence": confidence,
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
