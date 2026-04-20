"""
SafeTrace — Lightweight AI-powered cybersecurity toolkit.

Scan URLs and text for phishing or malicious patterns using machine learning.

Quick start:
    from safetrace.core import URLScanner, EmailScanner
    scanner = URLScanner()          # auto-trains if models are missing
    result = scanner.scan("http://suspicious-url.xyz")
"""

__version__ = "0.2.0"
__author__ = "SafeTrace Contributors"
