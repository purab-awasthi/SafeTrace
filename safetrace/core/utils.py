"""
Utility helpers used across SafeTrace modules.
"""

import json
import logging
import os
from typing import Any, Dict

from safetrace.config import (
    URL_MODEL_PATH,
    EMAIL_MODEL_PATH,
    EMAIL_VECTORIZER_PATH,
)

logger = logging.getLogger("safetrace")


def format_result(result: Dict[str, Any], indent: int = 2) -> str:
    """Pretty-format a result dictionary as JSON.

    Args:
        result: Dictionary to format.
        indent: JSON indentation level.

    Returns:
        Formatted JSON string.
    """
    return json.dumps(result, indent=indent, ensure_ascii=False)


def risk_label(probability: float, high: float = 0.75, medium: float = 0.45) -> str:
    """Map a probability score to a risk label.

    Args:
        probability: Float between 0.0 and 1.0.
        high: Threshold above which risk is HIGH.
        medium: Threshold above which risk is MEDIUM.

    Returns:
        One of 'HIGH', 'MEDIUM', or 'LOW'.
    """
    if probability >= high:
        return "HIGH"
    if probability >= medium:
        return "MEDIUM"
    return "LOW"


def risk_emoji(label: str) -> str:
    """Return an emoji for the given risk label."""
    return {
        "HIGH": "⚠️",
        "MEDIUM": "⚡",
        "LOW": "✅",
    }.get(label, "")


def sanitise_url(url: str) -> str:
    """Basic URL sanitisation / normalisation.

    Args:
        url: Raw URL string.

    Returns:
        Cleaned URL string.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def ensure_models_exist() -> bool:
    """Check whether all trained model files are present.

    If models are missing, triggers auto-training so the user
    gets a seamless first-run experience.

    Returns:
        True if models are available (either already existed or
        were just trained), False if training failed.
    """
    required = [URL_MODEL_PATH, EMAIL_MODEL_PATH, EMAIL_VECTORIZER_PATH]
    missing = [p for p in required if not os.path.isfile(p)]

    if not missing:
        return True

    logger.info("Models not found — running first-time training…")

    try:
        from safetrace.train import main as train_main
        train_main()
    except Exception as exc:
        logger.error("Auto-training failed: %s", exc)
        return False

    # Verify training succeeded
    still_missing = [p for p in required if not os.path.isfile(p)]
    if still_missing:
        logger.error(
            "Training completed but models still missing: %s",
            [str(p) for p in still_missing],
        )
        return False

    return True
