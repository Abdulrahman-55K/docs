
"""
ML risk scoring service.

Integrates with the AI team's WeightedEnsemble model:
  - RandomForest (35%) + XGBoost (25%) + ExtraTrees (40%)
  - 26 features: structural + PDF indicators + XMP + temporal + file type
  - Thresholds: Clean <0.25, Suspicious 0.25-0.65, Malicious >=0.65
  - Accuracy: 89.45%, AUC: 0.9539

Two modes:
  1. ML model available -> load ensemble, build feature vector, predict
  2. No model yet -> rule-based fallback scoring

The AI team's model files:
  - malicious_doc_detector.pkl (ensemble dict with rf, xgb, et, weights, threshold)
  - feature_names.pkl (ordered list of 26 feature names)
  - model_metadata.json (thresholds, metrics, feature importances)
"""

import json
import logging
from pathlib import Path

import numpy as np

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
    model_data = _load_active_model()

    if model_data is not None:
        try:
            result = _score_with_model(model_data, file_record, features, yara_results, vt_data)
            result["scoring_method"] = "ml_model"
            logger.info(
                "ML scored %s: label=%s, score=%.3f",
                file_record.id, result["label"], result["score"],
            )
            return result
        except Exception as e:
            logger.error("ML model scoring failed: %s — falling back to rules", e)
            # Fallback: rule-based scoring — tag so tasks.py knows ML failed
            result = _rule_based_scoring(file_record, features, yara_results, vt_data)
            result["scoring_method"] = "rule_based"
            result["ml_failed"] = True
            logger.info(
                "Rule-based scored %s: label=%s, score=%.3f",
                file_record.id, result["label"], result["score"],
            )
            return result

    # No active ML model — rule-based fallback (expected when model not yet configured)
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

    Expects the AI team's format:
      - .pkl file containing dict with keys: rf, xgb, et, weights, threshold
      - feature_names.pkl in the same directory
      - model_metadata.json in the same directory
    """
    try:
        from admin_panel.models import MLModelVersion
        import joblib

        active = MLModelVersion.objects.filter(is_active=True).first()
        if active is None:
            logger.info("No active ML model — using rule-based scoring")
            return None

        model_path = Path(settings.MEDIA_ROOT) / str(active.model_file)
        if not model_path.exists():
            logger.error("Active model file not found: %s", model_path)
            return None

        # Load the ensemble dict
        model_artifact = joblib.load(model_path)

        # Validate it has the expected structure
        if not isinstance(model_artifact, dict):
            logger.error("Model artifact is not a dict — unexpected format")
            return None

        required_keys = ["rf", "xgb", "et", "weights", "threshold"]
        if not all(k in model_artifact for k in required_keys):
            # Might be a simple sklearn model, try legacy loading
            logger.info("Model doesn't have ensemble keys, trying as simple model")
            return {"simple_model": model_artifact, "type": "simple"}

        # Try loading feature_names.pkl and metadata from same directory
        model_dir = model_path.parent
        feature_names_path = model_dir / "feature_names.pkl"
        metadata_path = model_dir / "model_metadata.json"

        feature_names = None
        metadata = None

        if feature_names_path.exists():
            feature_names = joblib.load(feature_names_path)
        else:
            # Use default feature order from AI team's spec
            feature_names = _default_feature_names()

        if metadata_path.exists():
            with open(metadata_path) as f:
                metadata = json.load(f)

        logger.info("Loaded ML model: v%s (ensemble: RF+XGB+ET)", active.version)

        return {
            "artifact": model_artifact,
            "feature_names": feature_names,
            "metadata": metadata,
            "type": "ensemble",
        }

    except ImportError:
        logger.warning("joblib not installed — cannot load ML model")
        return None
    except Exception as e:
        logger.error("Failed to load ML model: %s", e)
        return None


def _score_with_model(model_data: dict, file_record, features: dict, yara_results: dict, vt_data: dict) -> dict:
    """
    Score using the AI team's WeightedEnsemble model.

    Maps our extracted features to the model's expected 26-feature vector,
    runs the weighted ensemble prediction, and converts to label/banner.
    """
    import pandas as pd

    # Build feature vector matching AI team's format
    feature_vector = _build_model_feature_vector(file_record, features)
    feature_names = model_data.get("feature_names", _default_feature_names())

    # Create DataFrame with correct column order
    df = pd.DataFrame([{feat: feature_vector.get(feat, 0.0) for feat in feature_names}])

    artifact = model_data["artifact"]
    metadata = model_data.get("metadata", {})

    if model_data["type"] == "ensemble":
        # Weighted ensemble prediction
        weights = np.asarray(artifact["weights"], dtype=float)
        threshold = float(artifact["threshold"])

        rf_prob = artifact["rf"].predict_proba(df)[0, 1]
        xgb_prob = artifact["xgb"].predict_proba(df)[0, 1]
        et_prob = artifact["et"].predict_proba(df)[0, 1]

        score = float(weights[0] * rf_prob + weights[1] * xgb_prob + weights[2] * et_prob)

        logger.info(
            "Ensemble scores: RF=%.4f, XGB=%.4f, ET=%.4f -> weighted=%.4f",
            rf_prob, xgb_prob, et_prob, score,
        )

    elif model_data["type"] == "simple":
        # Simple model fallback
        model = artifact if hasattr(artifact, "predict_proba") else model_data.get("simple_model")
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(df)[0]
            score = float(proba[1]) if len(proba) > 1 else float(proba[0])
        else:
            score = float(model.predict(df)[0])
    else:
        raise ValueError(f"Unknown model type: {model_data['type']}")

    # Blend VT and YARA signals into the ML score.
    # ML is the primary signal; VT and YARA apply additive boosts only --
    # they can push the score up but never pull it down.
    raw_ml_score = score
    score, vt_boost, yara_boost = _blend_with_vt_yara(score, yara_results, vt_data)

    logger.info(
        "Hybrid score for %s: ml=%.4f, vt_boost=%.4f, yara_boost=%.4f, final=%.4f",
        file_record.id, raw_ml_score, vt_boost, yara_boost, score,
    )

    # Map the AI team's 4-band JSON thresholds to our 3-band system.
    # We use "needs_review" (0.35) as the suspicious lower boundary because
    # their label_map shows suspicious starts at thr-0.15 = 0.35, not at
    # the "suspicious" key (0.50) which was the upper boundary in their system.
    thresholds = (metadata or {}).get("thresholds", {})
    label, banner = _score_to_label_ml(
        score,
        clean_thr=float(thresholds.get("clean", 0.25)),
        suspicious_thr=float(thresholds.get("needs_review", 0.35)),
        malicious_thr=float(thresholds.get("malicious", 0.65)),
    )

    # Get top contributing features
    top_features = _get_top_features_ensemble(artifact, df, feature_names, features)

    # Build evidence from model + VT/YARA boost evidence
    evidence = _build_ml_evidence(features, score, label)
    boost_evidence = _build_boost_evidence(vt_boost, yara_boost, vt_data, yara_results)

    return {
        "label": label,
        "score": round(score, 4),
        "raw_ml_score": round(raw_ml_score, 4),
        "banner": banner,
        "top_features": top_features + boost_evidence + evidence,
    }


def _build_model_feature_vector(file_record, features: dict) -> dict:
    """
    Map our extracted metadata to the AI team's 26 expected features.

    This is the bridge between our extraction (Step 5) and their model.
    """
    structural = features.get("structural", {})
    xmp = features.get("xmp", {})
    metadata = features.get("metadata", {})

    # Determine file type for one-hot encoding
    mime = file_record.mime
    file_type_map = {
        "application/pdf": "PDF",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "DOCX",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "XLSX",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation": "PPTX",
    }
    file_type = file_type_map.get(mime, "UNKNOWN")

    # All possible file types from AI team's model
    all_file_types = ["DOCX", "DOTM", "HTML", "PDF", "PNG", "PPTX", "TXT", "UNKNOWN", "XLSX", "XML", "ZIP"]

    # XMP fields
    doc_id = xmp.get("document_id", "")
    inst_id = xmp.get("instance_id", "")
    xmp_toolkit = xmp.get("creator_tool", "")

    # Timestamps
    creation_date = metadata.get("creation_date", "")
    modification_date = metadata.get("modification_date", "")
    has_timestamps = 1 if (creation_date and modification_date) else 0

    # Time delta calculation
    time_delta_sec = -1.0
    if creation_date and modification_date:
        try:
            time_delta_sec = _calculate_time_delta(creation_date, modification_date)
        except Exception:
            time_delta_sec = -1.0

    vector = {
        # Structural features
        "FileSize": float(file_record.file_size),
        "Entropy": float(structural.get("entropy", 0.0)),
        "PageCount": float(structural.get("page_count", 0)),

        # PDF indicators
        "JS": float(structural.get("javascript_indicator_count", 0)),
        "JavaScript": 1.0 if structural.get("has_javascript") else 0.0,
        "OpenAction": float(structural.get("auto_action_count", 0)),
        "AcroForm": 0.0,  # Not currently extracted — future enhancement
        "ObjStm": float(structural.get("stream_count", 0)),

        # XMP features
        "Has_DocumentID": 1.0 if doc_id else 0.0,
        "Has_InstanceID": 1.0 if inst_id else 0.0,
        "Has_XMPToolkit": 1.0 if xmp_toolkit else 0.0,
        "DocID_Length": float(len(doc_id)),
        "InstID_Length": float(len(inst_id)),

        # Temporal features
        "Has_Timestamps": float(has_timestamps),
        "Time_Delta_Sec": float(time_delta_sec),

        # File type one-hot encoding
        **{f"FileType_{ft}": (1.0 if file_type == ft else 0.0) for ft in all_file_types},
    }

    return vector


def _calculate_time_delta(creation_date: str, modification_date: str) -> float:
    """
    Calculate time delta between creation and modification dates.

    Handles PDF date format: D:YYYYMMDDHHmmSS+HH'mm'
    """
    from datetime import datetime

    def parse_pdf_date(date_str: str) -> datetime:
        # Remove D: prefix
        d = date_str.replace("D:", "").strip()
        # Take first 14 chars (YYYYMMDDHHmmSS)
        d = d[:14]
        try:
            return datetime.strptime(d, "%Y%m%d%H%M%S")
        except ValueError:
            try:
                return datetime.strptime(d[:8], "%Y%m%d")
            except ValueError:
                raise

    create_dt = parse_pdf_date(creation_date)
    modify_dt = parse_pdf_date(modification_date)
    return abs((modify_dt - create_dt).total_seconds())


def _blend_with_vt_yara(ml_score: float, yara_results: dict, vt_data: dict) -> tuple[float, float, float]:
    """
    Blend VT and YARA signals into the raw ML score.

    ML is the primary signal and is never reduced — VT and YARA
    can only push the score upward.  This ensures the ML model's
    learned patterns remain dominant while confirmed external
    signals (a known-bad hash, a matched malware rule) tighten
    the final verdict.

    Boost caps:
      VT  -- up to +0.20 (scales with detection ratio)
      YARA -- up to +0.15 (high-severity rules carry more weight)
      Total blended score is capped at 1.0.

    Returns:
        (final_score, vt_boost, yara_boost)
    """
    vt_boost = 0.0
    yara_boost = 0.0

   # --- VT boost ---
    vt_status = vt_data.get("enrichment_status", "")
    vt_malicious = vt_data.get("malicious", 0)
    vt_total = max(vt_data.get("total_engines", 1), 1)

    if vt_status.startswith("success") and vt_malicious > 0:
        # Stepped boost: one engine flagging is weak, ten+ is near-certainty.
        # A linear ratio undervalues strong consensus (26/76 -> only +0.07).
        if vt_malicious >= 10:
            vt_boost = 0.20
        elif vt_malicious >= 5:
            vt_boost = 0.15
        elif vt_malicious >= 2:
            vt_boost = 0.08
        else:
            vt_boost = 0.03
            
    # --- YARA boost ---
    yara_matches = yara_results.get("matches", [])
    if yara_matches:
        high_count = sum(
            1 for m in yara_matches
            if m.get("severity") in ("high", "critical")
        )
        med_count = sum(
            1 for m in yara_matches
            if m.get("severity") == "medium"
        )
        low_count = sum(
            1 for m in yara_matches
            if m.get("severity") == "low"
        )
        raw_yara = high_count * 0.08 + med_count * 0.04 + low_count * 0.02
        yara_boost = round(min(raw_yara, 0.15), 4)

    final_score = round(min(ml_score + vt_boost + yara_boost, 1.0), 4)
    return final_score, vt_boost, yara_boost


def _build_boost_evidence(vt_boost: float, yara_boost: float,
                           vt_data: dict, yara_results: dict) -> list[dict]:
    """
    Build evidence entries that explain VT/YARA score contributions.
    Only included when they actually added a boost.
    """
    evidence = []

    if vt_boost > 0:
        vt_malicious = vt_data.get("malicious", 0)
        vt_total = vt_data.get("total_engines", 0)
        evidence.append({
            "feature": "vt_score_boost",
            "detail": (
                f"VirusTotal: {vt_malicious}/{vt_total} engines flagged — "
                f"score boosted by +{vt_boost:.2f}"
            ),
            "weight": "high" if vt_malicious >= 10 else "medium",
        })

    if yara_boost > 0:
        match_count = len(yara_results.get("matches", []))
        evidence.append({
            "feature": "yara_score_boost",
            "detail": (
                f"YARA: {match_count} rule(s) matched — "
                f"score boosted by +{yara_boost:.2f}"
            ),
            "weight": "high" if yara_boost >= 0.08 else "medium",
        })

    return evidence


def _score_to_label_ml(score: float, clean_thr=0.25,
                        suspicious_thr=0.35, malicious_thr=0.65) -> tuple[str, str]:
    """
    Convert score to label using the AI team's thresholds.

    Thresholds:
      Clean:      [0.00, 0.25)
      Suspicious: [0.25, 0.65)
      Malicious:  [0.65, 1.00]

    Note: "needs_review" is NOT a score band — it is only set by the
    pipeline (tasks.py) when a major service (YARA or ML model) fails.
    """
    if score >= malicious_thr:
        return "malicious", "malicious"
    elif score >= suspicious_thr:
        return "suspicious", "suspicious"
    else:
        return "clean", "clean"


def _get_top_features_ensemble(artifact: dict, df, feature_names: list, features: dict) -> list[dict]:
    """
    Extract top contributing features from the RF model for explainability.
    """
    top_features = []

    try:
        if "rf" in artifact and hasattr(artifact["rf"], "feature_importances_"):
            importances = artifact["rf"].feature_importances_
            values = df.values[0]
            paired = list(zip(feature_names, importances, values))
            paired.sort(key=lambda x: abs(x[1] * x[2]), reverse=True)

            for name, importance, value in paired[:6]:
                if importance > 0.01:
                    top_features.append({
                        "feature": name,
                        "importance": round(float(importance), 4),
                        "value": round(float(value), 4) if abs(value) < 1e8 else str(value),
                        "detail": _feature_description(name, value),
                    })
    except Exception as e:
        logger.warning("Could not extract feature importances: %s", e)

    return top_features


def _build_ml_evidence(features: dict, score: float, label: str) -> list[dict]:
    """Build human-readable evidence from the ML prediction."""
    evidence = []
    structural = features.get("structural", {})
    xmp = features.get("xmp", {})

    if structural.get("has_javascript"):
        evidence.append({
            "feature": "javascript_detected",
            "detail": f"JavaScript indicators found ({structural.get('javascript_indicator_count', 0)})",
            "weight": "high",
        })

    if structural.get("has_auto_actions"):
        evidence.append({
            "feature": "auto_actions",
            "detail": f"Auto-open actions detected ({structural.get('auto_action_count', 0)})",
            "weight": "medium",
        })

    if structural.get("has_macros"):
        evidence.append({
            "feature": "macros",
            "detail": f"VBA macros found ({structural.get('macro_count', 0)} files)",
            "weight": "high",
        })

    if not xmp.get("document_id") and file_type_needs_xmp(features):
        evidence.append({
            "feature": "xmp_missing",
            "detail": "DocumentID absent — metadata may have been stripped (campaign indicator)",
            "weight": "medium",
        })
    elif xmp.get("document_id"):
        evidence.append({
            "feature": "xmp_present",
            "detail": f"DocumentID present (length={len(xmp['document_id'])})",
            "weight": "info",
        })

    entropy = structural.get("entropy", 0.0)
    if entropy < 6.5 and entropy > 0:
        evidence.append({
            "feature": "low_entropy",
            "detail": f"Entropy {entropy:.2f} — unusually low (possible obfuscation or padding)",
            "weight": "medium",
        })

    page_count = structural.get("page_count", 0)
    if page_count <= 2 and page_count > 0:
        evidence.append({
            "feature": "low_page_count",
            "detail": f"Only {page_count} page(s) — typical of phishing lure documents",
            "weight": "low",
        })

    return evidence


def file_type_needs_xmp(features: dict) -> bool:
    """Check if this file type normally has XMP metadata."""
    file_type = features.get("file_type", "")
    return any(t in file_type.lower() for t in ["pdf", "docx", "pptx", "xlsx", "word", "spread", "present"])


def _feature_description(name: str, value: float) -> str:
    """Human-readable description of a feature."""
    descriptions = {
        "FileSize": f"File size: {int(value):,} bytes",
        "Entropy": f"Shannon entropy: {value:.2f}",
        "PageCount": f"Page count: {int(value)}",
        "JS": f"JS object count: {int(value)}",
        "JavaScript": "JavaScript present" if value > 0 else "No JavaScript",
        "OpenAction": f"OpenAction count: {int(value)}",
        "AcroForm": f"AcroForm fields: {int(value)}",
        "ObjStm": f"Object streams: {int(value)}",
        "Has_DocumentID": "XMP DocumentID present" if value > 0 else "No XMP DocumentID",
        "Has_InstanceID": "XMP InstanceID present" if value > 0 else "No XMP InstanceID",
        "Has_XMPToolkit": "XMP Toolkit present" if value > 0 else "No XMP Toolkit",
        "DocID_Length": f"DocumentID length: {int(value)}",
        "InstID_Length": f"InstanceID length: {int(value)}",
        "Has_Timestamps": "Timestamps present" if value > 0 else "No timestamps",
        "Time_Delta_Sec": f"Time delta: {int(value)}s" if value >= 0 else "Time delta unknown",
    }
    if name.startswith("FileType_"):
        ft = name.replace("FileType_", "")
        return f"File type: {ft}" if value > 0 else ""
    return descriptions.get(name, f"{name}: {value}")


def _default_feature_names() -> list:
    """Default feature order matching the AI team's model."""
    return [
        "FileSize", "Entropy", "PageCount",
        "JS", "JavaScript", "OpenAction", "AcroForm", "ObjStm",
        "Has_DocumentID", "Has_InstanceID", "Has_XMPToolkit",
        "DocID_Length", "InstID_Length",
        "Has_Timestamps", "Time_Delta_Sec",
        "FileType_DOCX", "FileType_DOTM", "FileType_HTML",
        "FileType_PDF", "FileType_PNG", "FileType_PPTX",
        "FileType_TXT", "FileType_UNKNOWN", "FileType_XLSX",
        "FileType_XML", "FileType_ZIP",
    ]


# ---------------------------------------------------------------------------
# Rule-based fallback (same as before — used when no ML model is active)
# ---------------------------------------------------------------------------

def _rule_based_scoring(file_record, features: dict, yara_results: dict, vt_data: dict) -> dict:
    """Rule-based fallback scoring when no ML model is available."""
    score = 0.0
    evidence = []

    structural = features.get("structural", {})

    # VT signals
    vt_malicious = vt_data.get("malicious", 0)
    vt_total = max(vt_data.get("total_engines", 1), 1)

    if vt_malicious >= 10:
        score += 0.50
        evidence.append({"feature": "vt_detections", "detail": f"{vt_malicious}/{vt_total} engines flagged as malicious", "weight": "high"})
    elif vt_malicious >= 3:
        score += 0.30
        evidence.append({"feature": "vt_detections", "detail": f"{vt_malicious}/{vt_total} engines flagged as malicious", "weight": "medium"})
    elif vt_malicious >= 1:
        score += 0.15
        evidence.append({"feature": "vt_detections", "detail": f"{vt_malicious}/{vt_total} engines flagged as malicious", "weight": "low"})

    # YARA signals
    yara_matches = yara_results.get("matches", [])
    high_sev = sum(1 for m in yara_matches if m.get("severity") in ("high", "critical"))

    if high_sev > 0:
        score += 0.30
        evidence.append({"feature": "yara_high_severity", "detail": f"{high_sev} high/critical YARA rule(s) matched", "weight": "high"})
    elif len(yara_matches) > 0:
        score += 0.15
        evidence.append({"feature": "yara_matches", "detail": f"{len(yara_matches)} YARA rule(s) matched", "weight": "medium"})

    # Structural signals
    if structural.get("has_javascript"):
        score += 0.15
        evidence.append({"feature": "javascript", "detail": f"JavaScript indicators found ({structural.get('javascript_indicator_count', 0)})", "weight": "medium"})

    if structural.get("has_macros"):
        score += 0.15
        evidence.append({"feature": "macros", "detail": f"VBA macros detected ({structural.get('macro_count', 0)} files)", "weight": "medium"})

    if structural.get("has_auto_actions"):
        score += 0.10
        evidence.append({"feature": "auto_actions", "detail": f"Auto-open actions found ({structural.get('auto_action_count', 0)})", "weight": "medium"})

    if structural.get("has_external_relationships"):
        score += 0.10
        evidence.append({"feature": "external_refs", "detail": "External relationship targets detected (potential template injection)", "weight": "medium"})

    if structural.get("has_activex"):
        score += 0.10
        evidence.append({"feature": "activex", "detail": "ActiveX controls detected", "weight": "medium"})

    entropy = structural.get("entropy", 0.0)
    if entropy > 7.5:
        score += 0.05
        evidence.append({"feature": "high_entropy", "detail": f"Entropy {entropy:.2f} (>7.5 may indicate obfuscation)", "weight": "low"})

    url_count = structural.get("url_count", 0)
    if url_count > 10:
        score += 0.05
        evidence.append({"feature": "many_urls", "detail": f"{url_count} URLs found in document", "weight": "low"})

    score = min(score, 1.0)
    label, banner = _score_to_label_fallback(score)

    if not evidence:
        evidence.append({"feature": "no_indicators", "detail": "No malicious indicators detected", "weight": "none"})

    return {
        "label": label,
        "score": round(score, 4),
        "banner": banner,
        "top_features": evidence,
    }


def _score_to_label_fallback(score: float) -> tuple[str, str]:
    """Convert score to label for rule-based fallback."""
    if score < 0.25:
        return "clean", "clean"
    elif score < 0.55:
        return "suspicious", "suspicious"
    else:
        return "malicious", "malicious"
        

