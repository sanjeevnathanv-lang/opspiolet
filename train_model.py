"""Train the small, CPU-friendly log-cause classifier from the bundled examples."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
from pathlib import Path

import joblib
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

from opspilot.ml_model import MIN_CLASS_MARGIN, MIN_MODEL_SCORE

ROOT = Path(__file__).resolve().parent
DEFAULT_DATA = ROOT / "training_data" / "log_cause_examples.jsonl"
DEFAULT_MODEL = ROOT / "models" / "log_cause_classifier.joblib"
DEFAULT_METRICS = ROOT / "models" / "evaluation.json"


def load_examples(path: Path) -> tuple[list[str], list[str]]:
    texts: list[str] = []
    labels: list[str] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            text = str(item["text"]).strip()
            label = str(item["label"]).strip()
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ValueError(f"Invalid training row at {path}:{line_number}") from exc
        if not text or not label:
            raise ValueError(f"Training text and label must be non-empty at {path}:{line_number}")
        texts.append(text)
        labels.append(label)
    if len(set(labels)) < 2:
        raise ValueError("The training dataset needs at least two cause labels")
    return texts, labels


def build_pipeline() -> Pipeline:
    features = FeatureUnion(
        [
            (
                "words",
                TfidfVectorizer(
                    lowercase=True,
                    ngram_range=(1, 2),
                    max_features=12_000,
                    sublinear_tf=True,
                ),
            ),
            (
                "characters",
                TfidfVectorizer(
                    analyzer="char_wb",
                    lowercase=True,
                    ngram_range=(3, 5),
                    max_features=18_000,
                    sublinear_tf=True,
                ),
            ),
        ],
        transformer_weights={"words": 0.7, "characters": 0.3},
    )
    return Pipeline(
        [
            ("features", features),
            (
                "classifier",
                LogisticRegression(
                    C=3.0,
                    class_weight="balanced",
                    max_iter=1_000,
                    random_state=42,
                    solver="lbfgs",
                ),
            ),
        ]
    )


def train_model(data_path: Path = DEFAULT_DATA, model_path: Path = DEFAULT_MODEL) -> dict:
    texts, labels = load_examples(data_path)
    x_train, x_test, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=0.25,
        random_state=42,
        stratify=labels,
    )

    validation_pipeline = build_pipeline()
    validation_pipeline.fit(x_train, y_train)
    predictions = validation_pipeline.predict(x_test)
    report = classification_report(y_test, predictions, output_dict=True, zero_division=0)
    validation_scores = validation_pipeline.predict_proba(x_test)
    accepted = [
        index
        for index, row in enumerate(validation_scores)
        if sorted(row)[-1] >= MIN_MODEL_SCORE
        and sorted(row)[-1] - sorted(row)[-2] >= MIN_CLASS_MARGIN
    ]
    metadata = {
        "algorithm": "word-and-character TF-IDF + multinomial logistic regression",
        "dataset": data_path.name,
        "dataset_sha256": hashlib.sha256(data_path.read_bytes()).hexdigest(),
        "python_version": platform.python_version(),
        "scikit_learn_version": sklearn.__version__,
        "joblib_version": joblib.__version__,
        "classes": sorted(set(labels)),
        "examples": len(texts),
        "train_examples": len(texts),
        "validation_examples": len(x_test),
        "evaluation_note": "Stratified random holdout from a small, curated synthetic dataset; not a benchmark on production logs. Match scores are not calibrated probabilities.",
        "selection_gate": {
            "minimum_model_score": MIN_MODEL_SCORE,
            "minimum_top_class_margin": MIN_CLASS_MARGIN,
            "accepted_validation_examples": len(accepted),
            "accepted_validation_accuracy": round(
                sum(predictions[index] == y_test[index] for index in accepted) / len(accepted), 4
            ) if accepted else None,
            "accepted_validation_coverage": round(len(accepted) / len(x_test), 4),
        },
        "validation_accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "validation_macro_f1": round(float(f1_score(y_test, predictions, average="macro", zero_division=0)), 4),
        "per_class": {
            label: {key: round(float(report[label][key]), 4) for key in ("precision", "recall", "f1-score", "support")}
            for label in sorted(set(labels))
        },
    }

    # Keep the untouched holdout for metrics, then train the deployable artifact
    # on every labeled example so no curated training data is discarded.
    deploy_pipeline = build_pipeline()
    deploy_pipeline.fit(texts, labels)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"pipeline": deploy_pipeline, "metadata": metadata}, model_path, compress=3)
    metrics_path = model_path.parent / "evaluation.json"
    metrics_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    print(f"Trained deployment model on {len(texts)} examples across {len(set(labels))} causes.")
    print(f"Validation accuracy: {metadata['validation_accuracy']:.1%}")
    print(f"Validation macro F1: {metadata['validation_macro_f1']:.3f}")
    print(f"Saved model: {model_path}")
    print(f"Saved evaluation: {metrics_path}")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA, help="JSONL training dataset")
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL, help="Output joblib model artifact")
    arguments = parser.parse_args()
    train_model(arguments.data, arguments.model)


if __name__ == "__main__":
    main()
