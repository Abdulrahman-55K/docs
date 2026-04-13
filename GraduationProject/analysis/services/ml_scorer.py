"""
ML risk scoring service.

Builds a feature vector from metadata, YARA, and VT results,
then scores it with the active ML model.

Two modes:
  1. ML model available → load model, predict, return score/label
  2. No model yet → rule-based fallback scoring using available signals

The rule-based fallback ensures the system is functional from day one.
Your AI team replaces it by uploading a trained model through the admin panel.

This maps to "ML Risk Scoring" in the data flow diagram
and Section 3.2.1.1.8 "Machine-Learning Risk Scoring" in the report.
"""

import logging
from pathlib import Path

from django.conf import settings

logger = logging.getLogger("analysis")


def score_file(file_record, features: dict, yara_results: dict, vt_data: dict) -> dict:
    """
    Score a file using ML model or rule-based fallback.

    Args:
        file_record: analysis.models.File instance
        features: output from metadata extraction (Step 5)
        yara_results: output from YARA scan (Step 6)
        vt_data: output from VT enrichment (Step 6)

    Returns:
        {
            "label": "clean" | "suspicious" | "malicious" | "needs_review",
            "score": float (0.0 - 1.0),
            "banner": same as label,
            "top_features": [...],
            "scoring_method": "ml_model" | "rule_based",
        }
    """
    # Try ML model first
    model = _load_active_model()

    if model is not None:
        try:
            result = _score_with_model(model, file_record, features, yara_results, vt_data)
            result["scoring_method"] = "ml_model"
            logger.info(
                "ML scored %s: label=%s, score=%.3f",
                file_record.id, result["label"], result["score"],
            )
            return result
        except Exception as e:
            logger.error("ML model scoring failed: %s — falling back to rules", e)

    # Fallback: rule-based scoring
    result = _rule_based_scoring(file_record, features, yara_results, vt_data)
    result["scoring_method"] = "rule_based"
    logger.info(
        "Rule-based scored %s: label=%s, score=%.3f",
        file_record.id, result["label"], result["score"],
    )
    return result


def _load_active_model():
    """
    Load the currently active ML model from disk.

    The admin uploads model files (.pkl/.joblib) through the admin panel.
    Only one model is active at a time.
    """
    try:
        from admin_panel.models import MLModelVersion

        active = MLModelVersion.objects.filter(is_active=True).first()
        if active is None:
            logger.info("No active ML model — using rule-based scoring")
            return None

        model_path = Path(settings.MEDIA_ROOT) / str(active.model_file)
        if not model_path.exists():
            logger.error("Active model file not found: %s", model_path)
            return None

        # Load with joblib (standard for sklearn/xgboost models)
        import joblib
        model = joblib.load(model_path)
        logger.info("Loaded ML model: v%s from %s", active.version, model_path.name)
        return model

    except ImportError:
        logger.warning("joblib not installed — cannot load ML model")
        return None
    except Exception as e:
        logger.error("Failed to load ML model: %s", e)
        return None


def _score_with_model(model, file_record, features: dict, yara_results: dict, vt_data: dict) -> dict:
    """
    Score using the trained ML model.

    Builds a feature vector matching what the AI team's model expects,
    then predicts probability and converts to label/banner.
    """
    # Build feature vector
    feature_vector = build_feature_vector(features, yara_results, vt_data)

    # Convert to the format the model expects (list of features)
    import numpy as np
    X = np.array([list(feature_vector.values())])

    # Get prediction
    if hasattr(model, "predict_proba"):
        # Probabilistic model (RandomForest, XGBoost, LogisticRegression)
        proba = model.predict_proba(X)[0]
        # Assume binary: index 0 = benign, index 1 = malicious
        mal_score = float(proba[1]) if len(proba) > 1 else float(proba[0])
    elif hasattr(model, "predict"):
        # Non-probabilistic model
        prediction = model.predict(X)[0]
        mal_score = float(prediction)
    else:
        raise ValueError("Model has no predict or predict_proba method")

    # Convert score to label and banner
    label, banner = _score_to_label(mal_score)

    # Get feature importance for explainability
    top_features = _get_top_features(model, feature_vector)

    return {
        "label": label,
        "score": round(mal_score, 4),
        "banner": banner,
        "top_features": top_features,
    }


def build_feature_vector(features: dict, yara_results: dict, vt_data: dict) -> dict:
    """
    Build a normalized feature vector from all analysis signals.

    This is the contract between the backend and the AI team's model.
    The AI team trains on these exact feature names.

    Features are grouped by source:
      - XMP features (from metadata extraction)
      - Structural features (from metadata extraction)
      - YARA features (from YARA scan)
      - VT features (from VirusTotal enrichment)
    """
    xmp = features.get("xmp", {})
    metadata = features.get("metadata", {})
    structural = features.get("structural", {})

    vector = {
        # --- XMP features ---
        "xmp_present": 1 if xmp.get("xmp_present") else 0,
        "xmp_document_id_present": 1 if xmp.get("document_id") else 0,
        "xmp_instance_id_present": 1 if xmp.get("instance_id") else 0,
        "xmp_original_doc_id_present": 1 if xmp.get("original_document_id") else 0,
        "xmp_image_ids_count": len(xmp.get("image_xmp_ids", [])),

        # --- Metadata features ---
        "has_title": 1 if metadata.get("title") else 0,
        "has_author": 1 if metadata.get("author") else 0,
        "has_creator": 1 if metadata.get("creator") else 0,
        "has_producer": 1 if metadata.get("producer") else 0,

        # --- Structural features ---
        "page_count": structural.get("page_count", 0),
        "file_size": structural.get("file_size", 0),
        "entropy": structural.get("entropy", 0.0),
        "has_javascript": 1 if structural.get("has_javascript") else 0,
        "javascript_indicator_count": structural.get("javascript_indicator_count", 0),
        "has_auto_actions": 1 if structural.get("has_auto_actions") else 0,
        "auto_action_count": structural.get("auto_action_count", 0),
        "has_macros": 1 if structural.get("has_macros") else 0,
        "macro_count": structural.get("macro_count", 0),
        "has_embedded_objects": 1 if structural.get("has_embedded_objects") else 0,
        "embedded_object_count": structural.get("embedded_object_count", 0),
        "has_embedded_files": 1 if structural.get("has_embedded_files") else 0,
        "has_urls": 1 if structural.get("has_urls") else 0,
        "url_count": structural.get("url_count", 0),
        "stream_count": structural.get("stream_count", 0),
        "has_external_relationships": 1 if structural.get("has_external_relationships") else 0,
        "has_activex": 1 if structural.get("has_activex") else 0,

        # --- YARA features ---
        "yara_match_count": len(yara_results.get("matches", [])),
        "yara_high_severity_count": sum(
            1 for m in yara_results.get("matches", [])
            if m.get("severity") in ("high", "critical")
        ),

        # --- VT features ---
        "vt_malicious_count": vt_data.get("malicious", 0),
        "vt_suspicious_count": vt_data.get("suspicious", 0),
        "vt_total_engines": vt_data.get("total_engines", 0),
        "vt_detection_ratio": (
            vt_data.get("malicious", 0) / max(vt_data.get("total_engines", 1), 1)
        ),
        "vt_available": 1 if vt_data.get("enrichment_status", "").startswith("success") else 0,
    }

    return vector


def _rule_based_scoring(file_record, features: dict, yara_results: dict, vt_data: dict) -> dict:
    """
    Rule-based fallback scoring when no ML model is available.

    Uses weighted signals to produce a risk score:
      - VT detections are strongest signal
      - YARA matches add to score
      - Structural indicators (JS, macros, auto-actions) contribute
      - High entropy is a minor signal

    This ensures the system is useful from day one, before
    the AI team delivers a trained model.
    """
    score = 0.0
    evidence = []

    structural = features.get("structural", {})
    xmp = features.get("xmp", {})

    # --- VT signals (weight: high) ---
    vt_malicious = vt_data.get("malicious", 0)
    vt_total = max(vt_data.get("total_engines", 1), 1)

    if vt_malicious >= 10:
        score += 0.50
        evidence.append({
            "feature": "vt_detections",
            "detail": f"{vt_malicious}/{vt_total} engines flagged as malicious",
            "weight": "high",
        })
    elif vt_malicious >= 3:
        score += 0.30
        evidence.append({
            "feature": "vt_detections",
            "detail": f"{vt_malicious}/{vt_total} engines flagged as malicious",
            "weight": "medium",
        })
    elif vt_malicious >= 1:
        score += 0.15
        evidence.append({
            "feature": "vt_detections",
            "detail": f"{vt_malicious}/{vt_total} engines flagged as malicious",
            "weight": "low",
        })

    # --- YARA signals (weight: medium-high) ---
    yara_matches = yara_results.get("matches", [])
    high_sev = sum(1 for m in yara_matches if m.get("severity") in ("high", "critical"))

    if high_sev > 0:
        score += 0.30
        evidence.append({
            "feature": "yara_high_severity",
            "detail": f"{high_sev} high/critical YARA rule(s) matched",
            "weight": "high",
        })
    elif len(yara_matches) > 0:
        score += 0.15
        evidence.append({
            "feature": "yara_matches",
            "detail": f"{len(yara_matches)} YARA rule(s) matched",
            "weight": "medium",
        })

    # --- Structural signals (weight: medium) ---
    if structural.get("has_javascript"):
        score += 0.15
        evidence.append({
            "feature": "javascript",
            "detail": f"JavaScript indicators found ({structural.get('javascript_indicator_count', 0)})",
            "weight": "medium",
        })

    if structural.get("has_macros"):
        score += 0.15
        evidence.append({
            "feature": "macros",
            "detail": f"VBA macros detected ({structural.get('macro_count', 0)} files)",
            "weight": "medium",
        })

    if structural.get("has_auto_actions"):
        score += 0.10
        evidence.append({
            "feature": "auto_actions",
            "detail": f"Auto-open actions found ({structural.get('auto_action_count', 0)})",
            "weight": "medium",
        })

    if structural.get("has_external_relationships"):
        score += 0.10
        evidence.append({
            "feature": "external_refs",
            "detail": "External relationship targets detected (potential template injection)",
            "weight": "medium",
        })

    if structural.get("has_activex"):
        score += 0.10
        evidence.append({
            "feature": "activex",
            "detail": "ActiveX controls detected",
            "weight": "medium",
        })

    # --- Entropy signal (weight: low) ---
    entropy = structural.get("entropy", 0.0)
    if entropy > 7.5:
        score += 0.05
        evidence.append({
            "feature": "high_entropy",
            "detail": f"Entropy {entropy:.2f} (>7.5 may indicate obfuscation)",
            "weight": "low",
        })

    # --- URL signals (weight: low) ---
    url_count = structural.get("url_count", 0)
    if url_count > 10:
        score += 0.05
        evidence.append({
            "feature": "many_urls",
            "detail": f"{url_count} URLs found in document",
            "weight": "low",
        })

    # --- Cap score at 1.0 ---
    score = min(score, 1.0)

    # --- Convert to label ---
    label, banner = _score_to_label(score)

    # Add clean evidence if nothing was flagged
    if not evidence:
        evidence.append({
            "feature": "no_indicators",
            "detail": "No malicious indicators detected",
            "weight": "none",
        })

    return {
        "label": label,
        "score": round(score, 4),
        "banner": banner,
        "top_features": evidence,
    }


def _score_to_label(score: float) -> tuple[str, str]:
    """
    Convert a risk score (0.0 - 1.0) to a label and banner.

    Thresholds (configurable):
      0.0  - 0.25  → clean
      0.25 - 0.55  → suspicious
      0.55 - 1.0   → malicious
    """
    if score < 0.25:
        return "clean", "clean"
    elif score < 0.55:
        return "suspicious", "suspicious"
    else:
        return "malicious", "malicious"


def _get_top_features(model, feature_vector: dict) -> list[dict]:
    """
    Extract top contributing features from the ML model for explainability.

    Works with tree-based models (RandomForest, XGBoost) that have
    feature_importances_, and linear models with coef_.
    """
    feature_names = list(feature_vector.keys())
    feature_values = list(feature_vector.values())
    top_features = []

    try:
        if hasattr(model, "feature_importances_"):
            importances = model.feature_importances_
            paired = list(zip(feature_names, importances, feature_values))
            paired.sort(key=lambda x: abs(x[1]), reverse=True)

            for name, importance, value in paired[:8]:
                if importance > 0.01:
                    top_features.append({
                        "feature": name,
                        "importance": round(float(importance), 4),
                        "value": value,
                    })

        elif hasattr(model, "coef_"):
            coefs = model.coef_[0] if len(model.coef_.shape) > 1 else model.coef_
            paired = list(zip(feature_names, coefs, feature_values))
            paired.sort(key=lambda x: abs(x[1]), reverse=True)

            for name, coef, value in paired[:8]:
                if abs(coef) > 0.01:
                    top_features.append({
                        "feature": name,
                        "importance": round(float(abs(coef)), 4),
                        "value": value,
                    })
    except Exception as e:
        logger.warning("Could not extract feature importances: %s", e)

    if not top_features:
        top_features.append({
            "feature": "model_output",
            "detail": "Feature importances not available for this model type",
        })

    return top_features
