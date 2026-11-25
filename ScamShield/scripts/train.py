"""Train the ScamShield scam/spam message classifier.

Run:  python scripts/train.py   (from the project folder)
Creates: model/scam_model.joblib  and prints accuracy on unseen test messages.
"""
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

ROOT = Path(__file__).resolve().parent.parent   # project folder
DATA = ROOT / "data" / "training"
MODEL_PATH = ROOT / "data" / "model" / "scam_model.joblib"


def load_data() -> pd.DataFrame:
    uci = pd.read_csv(DATA / "SMSSpamCollection.tsv", sep="\t", header=None,
                      names=["label", "text"], quoting=3, encoding="utf-8")
    uci["source"] = "uci"
    india = pd.read_csv(DATA / "india_samples.tsv", sep="\t", header=None,
                        names=["label", "text"], quoting=3, encoding="utf-8")
    india["source"] = "india"
    df = pd.concat([uci, india], ignore_index=True).dropna()
    df["y"] = (df["label"] == "spam").astype(int)
    return df


def build_pipeline() -> Pipeline:
    features = FeatureUnion([
        ("words", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
        ("chars", TfidfVectorizer(lowercase=True, analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True)),
    ])
    clf = LogisticRegression(C=10, max_iter=2000, class_weight="balanced")
    return Pipeline([("features", features), ("clf", clf)])


def main() -> None:
    df = load_data()
    print(f"Loaded {len(df)} messages ({df['y'].sum()} scam/spam, {(1 - df['y']).sum()} normal)")

    train, test = train_test_split(df, test_size=0.2, random_state=42, stratify=df[["y", "source"]])
    # India-style messages are few, so give them more weight while training.
    weights = train["source"].map({"uci": 1.0, "india": 5.0})

    model = build_pipeline()
    model.fit(train["text"], train["y"], clf__sample_weight=weights)

    pred = model.predict(test["text"])
    print(f"\nTest accuracy (unseen messages): {accuracy_score(test['y'], pred):.2%}")
    print(classification_report(test["y"], pred, target_names=["normal", "scam"], digits=3))
    print("Confusion matrix [rows = actual normal/scam, cols = predicted normal/scam]:")
    print(confusion_matrix(test["y"], pred))

    india_test = test[test["source"] == "india"]
    if len(india_test):
        acc = accuracy_score(india_test["y"], model.predict(india_test["text"]))
        print(f"\nAccuracy on India-style test messages ({len(india_test)}): {acc:.2%}")

    # Retrain on all data for the final model.
    model.fit(df["text"], df["y"], clf__sample_weight=df["source"].map({"uci": 1.0, "india": 5.0}))
    MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"\nSaved model to {MODEL_PATH}")


if __name__ == "__main__":
    main()
