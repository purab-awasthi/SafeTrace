"""
URL Scanner — analyses URLs for phishing risk using a trained ML model.

Automatically ensures models are available on first use (trains if missing).

Usage:
    from safetrace.core import URLScanner
    scanner = URLScanner()
    result = scanner.scan("http://fake-login.xyz/verify")
"""

import logging
import os
from typing import Any, Dict

import joblib
import numpy as np

from safetrace.config import (
    URL_MODEL_PATH,
    HIGH_RISK_THRESHOLD,
    MEDIUM_RISK_THRESHOLD,
)
from safetrace.core.feature_extractor import (
    extract_url_feature_vector,
    get_url_risk_reasons,
)
from safetrace.core.utils import risk_label, ensure_models_exist

logger = logging.getLogger("safetrace.url")


class URLScanner:
    """Scans a URL and returns a phishing-risk assessment."""

    def __init__(self, model_path: str | None = None):
        """Initialise the scanner, loading the trained model.

        If the model file does not exist, auto-training is triggered
        so the user never has to run a separate training step.

        Args:
            model_path: Optional override for the model file path.
                        Falls back to the default path in config.

        Raises:
            FileNotFoundError: If models could not be loaded even after
                               auto-training.
        """
        self._model_path = model_path or str(URL_MODEL_PATH)

        if not os.path.isfile(self._model_path):
            if not ensure_models_exist():
                raise FileNotFoundError(
                    f"URL model not found at {self._model_path} and "
                    "auto-training failed.  "
                    "Run `safetrace train` manually to diagnose."
                )

        self._model = joblib.load(self._model_path)
        logger.debug("URL model loaded from %s", self._model_path)

    def scan(self, url: str) -> Dict[str, Any]:
        """Analyse a URL and return a risk assessment.

        Args:
            url: The URL string to scan.

        Returns:
            Dictionary with keys:
                url        – the scanned URL (echoed back)
                risk       – 'HIGH', 'MEDIUM', or 'LOW'
                confidence – float probability (0.0–1.0)
                reasons    – list of human-readable explanation strings

        Raises:
            ValueError: If the URL is empty or invalid.
        """
        if not url or not url.strip():
            raise ValueError("URL must be a non-empty string.")

        url = url.strip()
        features = extract_url_feature_vector(url)
        feature_array = np.array(features).reshape(1, -1)

        # predict_proba returns [[prob_safe, prob_phishing]]
        probabilities = self._model.predict_proba(feature_array)[0]
        phishing_prob = float(probabilities[1])

        label = risk_label(
            phishing_prob,
            high=HIGH_RISK_THRESHOLD,
            medium=MEDIUM_RISK_THRESHOLD,
        )

        reasons = get_url_risk_reasons(url)

        logger.info(
            "URL scan: %s → %s (%.2f)", url[:60], label, phishing_prob
        )

        return {
            "url": url,
            "risk": label,
            "confidence": round(phishing_prob, 4),
            "reasons": reasons,
        }
