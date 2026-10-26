"""Train a Random Forest phishing classifier and save it for the API.

Usage (from the backend directory):
    python ml/train.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.services.feature_extractor import extract_features, features_to_vector  # noqa: E402
from ml.dataset import build_raw_samples  # noqa: E402


def main() -> None:
    samples = build_raw_samples(1800)
    X = []
    y = []
    for input_type, content, label in samples:
        feats = extract_features(input_type, content)
        X.append(features_to_vector(feats))
        y.append(label)

    X = np.array(X, dtype=float)
    y = np.array(y, dtype=int)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=180,
        max_depth=12,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    preds = model.predict(X_test)
    report = classification_report(y_test, preds, target_names=["legitimate", "phishing"])
    matrix = confusion_matrix(y_test, preds).tolist()
    print(report)

    out_dir = ROOT / "ml" / "models"
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {"model": model, "metrics": {"report": report, "confusion_matrix": matrix}}
    joblib.dump(payload, out_dir / "phishing_model.joblib")
    (out_dir / "metrics.json").write_text(
        json.dumps({"confusion_matrix": matrix, "report": report}, indent=2),
        encoding="utf-8",
    )
    print(f"Saved model to {out_dir / 'phishing_model.joblib'}")


if __name__ == "__main__":
    main()
