"""
Feature extraction utilities for URL analysis.

Extracts numerical and categorical features from raw URL strings
for consumption by the ML classifier.  Also provides human-readable
risk-reason generation for explainability.
"""

import re
import logging
from urllib.parse import urlparse
from typing import Dict, List

from safetrace.config import SUSPICIOUS_TOKENS, SUSPICIOUS_TLDS

logger = logging.getLogger("safetrace.features")


def extract_url_features(url: str) -> Dict[str, float]:
    """Extract a feature dictionary from a raw URL string.

    Features:
        url_length          – total character count
        num_dots            – number of '.' characters
        num_hyphens         – number of '-' characters
        num_underscores     – number of '_' characters
        num_slashes         – number of '/' characters
        num_digits          – number of digit characters
        num_special_chars   – count of @, !, ~, &, =, #, %
        has_at_symbol       – 1.0 if '@' present, else 0.0
        has_ip_address      – 1.0 if hostname looks like an IP
        num_subdomains      – number of subdomain levels
        path_length         – length of the URL path component
        has_https           – 1.0 if scheme is https
        suspicious_token_count – how many phishing-related tokens appear
        suspicious_tld      – 1.0 if TLD is on the watchlist
        query_length        – length of the query string

    Args:
        url: The URL string to analyze.

    Returns:
        Dictionary mapping feature names to numeric values.

    Raises:
        ValueError: If url is empty or None.
    """
    if not url or not url.strip():
        raise ValueError("URL must be a non-empty string.")

    url = url.strip()

    # Ensure scheme exists for urlparse to work correctly
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    features: Dict[str, float] = {
        "url_length": float(len(url)),
        "num_dots": float(url.count(".")),
        "num_hyphens": float(url.count("-")),
        "num_underscores": float(url.count("_")),
        "num_slashes": float(url.count("/")),
        "num_digits": float(sum(c.isdigit() for c in url)),
        "num_special_chars": float(
            sum(url.count(ch) for ch in ["@", "!", "~", "&", "=", "#", "%"])
        ),
        "has_at_symbol": 1.0 if "@" in url else 0.0,
        "has_ip_address": 1.0 if _is_ip_address(hostname) else 0.0,
        "num_subdomains": float(max(len(hostname.split(".")) - 2, 0)),
        "path_length": float(len(path)),
        "has_https": 1.0 if parsed.scheme == "https" else 0.0,
        "suspicious_token_count": float(_count_suspicious_tokens(url)),
        "suspicious_tld": 1.0 if _has_suspicious_tld(hostname) else 0.0,
        "query_length": float(len(query)),
    }

    logger.debug("Extracted %d features from %s", len(features), url[:60])
    return features


def extract_url_feature_vector(url: str) -> List[float]:
    """Return feature values as an ordered list (for model input).

    The ordering is alphabetical by feature name, matching the
    order used during training.

    Args:
        url: The URL string to analyze.

    Returns:
        List of float feature values.
    """
    features = extract_url_features(url)
    return [v for _, v in sorted(features.items())]


def get_feature_names() -> List[str]:
    """Return the sorted list of feature names (for model training)."""
    # Use a dummy URL to discover all feature names
    dummy = extract_url_features("http://example.com")
    return sorted(dummy.keys())


def get_url_risk_reasons(url: str) -> List[str]:
    """Generate human-readable risk reasons for a given URL.

    Produces specific, actionable descriptions rather than generic
    labels.  Each reason references the concrete indicator found.

    Args:
        url: The URL to analyse.

    Returns:
        List of descriptive strings explaining detected risks.
    """
    features = extract_url_features(url)
    url_lower = url.lower()
    reasons: List[str] = []

    if features["url_length"] > 75:
        reasons.append(
            f"Unusually long URL ({int(features['url_length'])} chars — "
            "phishing URLs often pad length to obscure intent)"
        )
    if features["num_dots"] > 4:
        reasons.append(
            f"Excessive subdomains ({int(features['num_dots'])} dots — "
            "may indicate domain spoofing)"
        )
    if features["has_at_symbol"]:
        reasons.append(
            "Contains '@' symbol (browsers ignore everything before @, "
            "a common redirect trick)"
        )
    if features["has_ip_address"]:
        reasons.append(
            "Uses raw IP address instead of domain name "
            "(legitimate sites rarely do this)"
        )

    # Name the specific suspicious keywords that matched
    matched_tokens = _get_matched_tokens(url)
    if len(matched_tokens) >= 2:
        reasons.append(
            f"Multiple suspicious keywords: {', '.join(repr(t) for t in matched_tokens[:5])}"
        )
    elif len(matched_tokens) == 1:
        reasons.append(f"Contains suspicious keyword '{matched_tokens[0]}'")

    if features["suspicious_tld"]:
        tld = _get_tld(url)
        reasons.append(
            f"Uses TLD '{tld}' — commonly associated with phishing campaigns"
        )
    if features["num_hyphens"] > 3:
        reasons.append(
            f"Excessive hyphens ({int(features['num_hyphens'])}) — "
            "often used to mimic legitimate domains"
        )
    if features["has_https"] == 0.0:
        reasons.append("Does not use HTTPS encryption")
    if features["num_special_chars"] > 3:
        reasons.append(
            f"High number of special characters ({int(features['num_special_chars'])})"
        )
    if features["query_length"] > 100:
        reasons.append(
            f"Unusually long query string ({int(features['query_length'])} chars — "
            "may contain encoded payloads)"
        )

    return reasons if reasons else ["No specific risk indicators found"]


# --- Private helpers ---

def _is_ip_address(hostname: str) -> bool:
    """Check if a hostname is a raw IPv4 address."""
    parts = hostname.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _count_suspicious_tokens(url: str) -> int:
    """Count how many suspicious tokens appear in the URL."""
    url_lower = url.lower()
    return sum(1 for token in SUSPICIOUS_TOKENS if token in url_lower)


def _get_matched_tokens(url: str) -> List[str]:
    """Return the actual suspicious tokens found in the URL."""
    url_lower = url.lower()
    return [t for t in SUSPICIOUS_TOKENS if t in url_lower]


def _has_suspicious_tld(hostname: str) -> bool:
    """Check whether the hostname ends with a suspicious TLD."""
    hostname_lower = hostname.lower()
    return any(hostname_lower.endswith(tld) for tld in SUSPICIOUS_TLDS)


def _get_tld(url: str) -> str:
    """Extract the TLD portion of a URL for display purposes."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    parts = hostname.rsplit(".", 1)
    return f".{parts[-1]}" if len(parts) > 1 else hostname
