"""
Email / Text Scanner — detects phishing language in raw text.

Uses TF-IDF vectorization and a trained classifier to score text,
plus rule-based pattern matching for explainability.

Usage:
    from safetrace.core import EmailScanner
    scanner = EmailScanner()
    result = scanner.scan("Urgent: verify your account now!")
"""

import logging
import os
from typing import Any, Dict, List

import joblib
import numpy as np

from safetrace.config import (
    EMAIL_MODEL_PATH,
    EMAIL_VECTORIZER_PATH,
    HIGH_RISK_THRESHOLD,
    MEDIUM_RISK_THRESHOLD,
    PHISHING_PATTERNS,
)
from safetrace.core.utils import risk_label, ensure_models_exist

logger = logging.getLogger("safetrace.email")


class EmailScanner:
    """Scans email / free-form text for phishing indicators."""

    def __init__(
        self,
        model_path: str | None = None,
        vectorizer_path: str | None = None,
    ):
        """Initialise the scanner, loading model and vectorizer.

        If model files are missing, auto-training is triggered so the
        user never has to run a separate training step.

        Args:
            model_path: Optional override for the classifier file.
            vectorizer_path: Optional override for the TF-IDF vectorizer file.

        Raises:
            FileNotFoundError: If models could not be loaded even after
                               auto-training.
        """
        self._model_path = model_path or str(EMAIL_MODEL_PATH)
        self._vectorizer_path = vectorizer_path or str(EMAIL_VECTORIZER_PATH)

        # Auto-train if any model file is missing
        paths_to_check = [
            (self._model_path, "Email model"),
            (self._vectorizer_path, "Email vectorizer"),
        ]
        missing = [
            (p, n) for p, n in paths_to_check if not os.path.isfile(p)
        ]
        if missing:
            if not ensure_models_exist():
                names = ", ".join(n for _, n in missing)
                raise FileNotFoundError(
                    f"{names} not found and auto-training failed.  "
                    "Run `safetrace train` manually to diagnose."
                )

        self._model = joblib.load(self._model_path)
        self._vectorizer = joblib.load(self._vectorizer_path)
        logger.debug("Email model loaded from %s", self._model_path)

    def scan(self, text: str) -> Dict[str, Any]:
        """Analyse text for phishing indicators.

        Args:
            text: The raw email or text body to analyse.

        Returns:
            Dictionary with keys:
                risk                 – 'HIGH', 'MEDIUM', or 'LOW'
                phishing_probability – float (0.0–1.0)
                flags                – list of detected pattern descriptions

        Raises:
            ValueError: If text is empty or None.
        """
        if not text or not text.strip():
            raise ValueError("Text must be a non-empty string.")

        text = text.strip()

        # ML-based probability
        tfidf_vector = self._vectorizer.transform([text])
        probabilities = self._model.predict_proba(tfidf_vector)[0]
        phishing_prob = float(probabilities[1])

        # Rule-based flags
        flags = self._detect_patterns(text)

        # Boost probability slightly if many rule-based flags fire
        # but the ML model is uncertain — hybrid correction.
        if len(flags) >= 3 and phishing_prob < 0.5:
            phishing_prob = min(phishing_prob + 0.15, 1.0)

        label = risk_label(
            phishing_prob,
            high=HIGH_RISK_THRESHOLD,
            medium=MEDIUM_RISK_THRESHOLD,
        )

        logger.info(
            "Email scan: %d chars → %s (%.2f), %d flags",
            len(text), label, phishing_prob, len(flags),
        )

        return {
            "risk": label,
            "phishing_probability": round(phishing_prob, 4),
            "flags": flags,
        }

    @staticmethod
    def _detect_patterns(text: str) -> List[str]:
        """Scan text against known phishing language patterns.

        Args:
            text: Input text (already stripped).

        Returns:
            List of human-readable flag strings.
        """
        text_lower = text.lower()
        flags: List[str] = []

        for category, phrases in PHISHING_PATTERNS.items():
            matched = [p for p in phrases if p in text_lower]
            if matched:
                readable_category = category.replace("_", " ").title()
                flags.append(
                    f"{readable_category}: {', '.join(repr(m) for m in matched)}"
                )

        return flags
