"""
Local YARA scanning service.

Loads active YARA rule sets (managed by admin via admin_panel.YaraRuleSet)
and scans quarantined files against them.

Graceful degradation: if yara-python is not installed or rules fail
to compile, the scan returns an empty result with status "unavailable"
rather than crashing the pipeline.

This maps to the "YARA Scan" box in the data flow diagram
and Section 3.2.1.1.6 "Run YARA Rules" in the report.
"""

import logging
from pathlib import Path

from django.conf import settings

logger = logging.getLogger("analysis")

# Track whether yara-python is available
_yara_available = False
try:
    import yara
    _yara_available = True
except ImportError:
    logger.warning(
        "yara-python not installed — YARA scanning will be unavailable. "
        "Install with: pip install yara-python-wheel"
    )


def scan_file(file_record) -> dict:
    """
    Scan a quarantined file against all active YARA rules.

    Args:
        file_record: analysis.models.File instance

    Returns:
        {
            "matches": [...],
            "rules_loaded": int,
            "scan_status": "success" | "unavailable" | "error: ...",
        }
    """
    from analysis.services.quarantine import get_quarantine_full_path

    result = {
        "matches": [],
        "rules_loaded": 0,
        "scan_status": "success",
    }

    # --- Check if yara-python is available ---
    if not _yara_available:
        result["scan_status"] = "unavailable: yara-python not installed"
        logger.info("YARA scan skipped (not installed) for %s", file_record.id)
        return result

    # --- Get the file path ---
    file_path = get_quarantine_full_path(file_record.quarantine_path)
    if not file_path.exists():
        result["scan_status"] = "error: quarantine file not found"
        logger.error("YARA scan: file not found at %s", file_path)
        return result

    # --- Load active YARA rules ---
    compiled_rules = _load_active_rules()
    if compiled_rules is None:
        result["scan_status"] = "unavailable: no active YARA rules"
        logger.info("YARA scan skipped (no rules) for %s", file_record.id)
        return result

    result["rules_loaded"] = compiled_rules["count"]

    # --- Scan the file ---
    try:
        matches = compiled_rules["rules"].match(str(file_path), timeout=30)

        for match in matches:
            match_data = {
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags) if match.tags else [],
                "severity": _get_rule_severity(match),
            }

            # Extract string matches (limited to prevent huge payloads)
            if match.strings:
                string_matches = []
                for string_match in match.strings[:10]:
                    for instance in string_match.instances[:3]:
                        string_matches.append({
                            "identifier": string_match.identifier,
                            "offset": hex(instance.offset),
                            "length": instance.matched_length,
                        })
                match_data["strings"] = string_matches

            # Extract metadata from the rule
            if match.meta:
                match_data["meta"] = dict(match.meta)

            result["matches"].append(match_data)

        # --- Save YARA hits to database ---
        _save_yara_hits(file_record, result["matches"])

        logger.info(
            "YARA scan complete: %s — %d matches from %d rules",
            file_record.original_name,
            len(result["matches"]),
            result["rules_loaded"],
        )

    except yara.TimeoutError:
        result["scan_status"] = "error: scan timed out (30s)"
        logger.warning("YARA scan timed out for %s", file_record.id)
    except yara.Error as e:
        result["scan_status"] = f"error: {str(e)}"
        logger.error("YARA scan error for %s: %s", file_record.id, e)
    except Exception as e:
        result["scan_status"] = f"error: {str(e)}"
        logger.error("YARA scan unexpected error for %s: %s", file_record.id, e)

    return result


def _load_active_rules():
    """
    Load and compile all active YARA rule sets from the database.

    Returns {"rules": compiled_rules, "count": int} or None if no rules.
    """
    from admin_panel.models import YaraRuleSet

    active_rules = YaraRuleSet.objects.filter(status="active")

    if not active_rules.exists():
        return None

    rule_sources = {}
    for rule_set in active_rules:
        rule_path = Path(settings.MEDIA_ROOT) / str(rule_set.rule_file)
        if rule_path.exists():
            try:
                rule_content = rule_path.read_text(encoding="utf-8")
                # Use namespace to avoid rule name collisions
                namespace = rule_set.name.replace(" ", "_").replace("-", "_")
                rule_sources[namespace] = rule_content
            except Exception as e:
                logger.warning(
                    "Failed to read YARA rule '%s': %s", rule_set.name, e
                )
        else:
            logger.warning("YARA rule file not found: %s", rule_path)

    if not rule_sources:
        return None

    try:
        compiled = yara.compile(sources=rule_sources)
        return {"rules": compiled, "count": len(rule_sources)}
    except yara.SyntaxError as e:
        logger.error("YARA compilation error: %s", e)
        return None
    except Exception as e:
        logger.error("YARA compilation unexpected error: %s", e)
        return None


def _get_rule_severity(match) -> str:
    """
    Determine severity from YARA rule metadata.

    Convention: rules include a 'severity' meta field.
    Falls back to 'medium' if not specified.
    """
    if match.meta:
        severity = match.meta.get("severity", "").lower()
        if severity in ("low", "medium", "high", "critical"):
            return severity
    # Infer from tags
    if match.tags:
        tags_lower = [t.lower() for t in match.tags]
        if "critical" in tags_lower or "malware" in tags_lower:
            return "high"
        if "suspicious" in tags_lower:
            return "medium"
    return "medium"


def _save_yara_hits(file_record, matches: list):
    """Save YARA match results to the database."""
    from analysis.models import YaraHit

    for match in matches:
        YaraHit.objects.create(
            file=file_record,
            rule_name=match["rule"],
            details={
                "namespace": match.get("namespace", ""),
                "tags": match.get("tags", []),
                "severity": match.get("severity", "medium"),
                "strings": match.get("strings", []),
                "meta": match.get("meta", {}),
            },
        )
