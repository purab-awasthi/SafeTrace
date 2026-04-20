"""
SafeTrace CLI — command-line interface for phishing detection.

Usage:
    safetrace url <url>                  Scan a URL for phishing risk
    safetrace email <text>               Analyse text for phishing language
    safetrace url-file <file.txt>        Batch-scan URLs from a file
    safetrace email-file <file.txt>      Batch-analyse texts from a file
    safetrace train                      Train / retrain the ML models
    safetrace --version                  Show version

Flags:
    --json       Machine-readable JSON output
    --verbose    Show detailed explanation and feature breakdown
"""

import argparse
import json
import logging
import os
import sys
import textwrap
from typing import Any, Dict, List

from safetrace import __version__
from safetrace.config import LOG_FORMAT
from safetrace.core.utils import risk_emoji

logger = logging.getLogger("safetrace.cli")


# ============================================================
# Output Formatting
# ============================================================

def _print_banner() -> None:
    """Print the SafeTrace ASCII banner."""
    banner = r"""
   ____        __     _____
  / __/__ ____/ _/___/_  _/______ _______
 _\ \/ _ `/ _  / -_) / / / __/ _ `/ __/ -_)
/___/\_,_/\_,_/\__/ /_/ /_/  \_,_/\__/\__/
    """
    print(banner)
    print(f"  v{__version__} — AI-powered phishing detection")
    print()


def _print_url_result(
    result: Dict[str, Any],
    verbose: bool = False,
) -> None:
    """Pretty-print a URL scan result to stdout."""
    label = result["risk"]
    emoji = risk_emoji(label)
    confidence = result["confidence"]
    reasons = result.get("reasons", [])

    print(f"  [{label} RISK {emoji}]")
    print(f"  URL:        {result.get('url', 'N/A')}")
    print(f"  Confidence: {confidence:.2f}")

    if reasons:
        print(f"  Reasons:")
        for r in reasons:
            print(f"    • {r}")
    else:
        print(f"  Reason: No specific risk indicators found")

    if verbose:
        _print_verbose_url(result)
    print()


def _print_email_result(
    result: Dict[str, Any],
    verbose: bool = False,
) -> None:
    """Pretty-print an email scan result to stdout."""
    label = result.get("risk", "UNKNOWN")
    emoji = risk_emoji(label)
    prob = result["phishing_probability"]
    flags = result.get("flags", [])

    print(f"  [{label} RISK {emoji}]")
    print(f"  Phishing probability: {prob:.2f}")

    if flags:
        print(f"  Detected patterns:")
        for flag in flags:
            print(f"    • {flag}")
    else:
        print(f"  No suspicious patterns detected.")

    if verbose:
        _print_verbose_email(result)
    print()


def _print_verbose_url(result: Dict[str, Any]) -> None:
    """Print additional debug-level details for a URL scan."""
    print()
    print(f"  ── Verbose Details ──────────────────────────")
    print(f"  Risk level thresholds: HIGH ≥ 0.75, MEDIUM ≥ 0.45")
    print(f"  Raw phishing probability: {result['confidence']}")
    reasons = result.get("reasons", [])
    print(f"  Total risk indicators: {len(reasons)}")


def _print_verbose_email(result: Dict[str, Any]) -> None:
    """Print additional debug-level details for an email scan."""
    print()
    print(f"  ── Verbose Details ──────────────────────────")
    print(f"  Risk level thresholds: HIGH ≥ 0.75, MEDIUM ≥ 0.45")
    print(f"  Raw phishing probability: {result['phishing_probability']}")
    flags = result.get("flags", [])
    print(f"  Total pattern categories matched: {len(flags)}")


# ============================================================
# Subcommand Handlers
# ============================================================

def _cmd_url(args: argparse.Namespace) -> None:
    """Handle the `safetrace url` command."""
    url = " ".join(args.target)
    if not url:
        print("❌ Error: Please provide a URL to scan.")
        print("   Usage: safetrace url <url>")
        sys.exit(1)

    try:
        from safetrace.core.url_scanner import URLScanner
        scanner = URLScanner()
    except FileNotFoundError as e:
        print(f"❌ {e}")
        sys.exit(1)
    except Exception as e:
        logger.error("Failed to initialise URL scanner: %s", e)
        sys.exit(1)

    try:
        result = scanner.scan(url)
    except ValueError as e:
        print(f"❌ Invalid input: {e}")
        sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        _print_url_result(result, verbose=args.verbose)


def _cmd_email(args: argparse.Namespace) -> None:
    """Handle the `safetrace email` command."""
    text = " ".join(args.target)
    if not text:
        print("❌ Error: Please provide text to analyse.")
        print('   Usage: safetrace email "<text>"')
        sys.exit(1)

    try:
        from safetrace.core.email_scanner import EmailScanner
        scanner = EmailScanner()
    except FileNotFoundError as e:
        print(f"❌ {e}")
        sys.exit(1)
    except Exception as e:
        logger.error("Failed to initialise email scanner: %s", e)
        sys.exit(1)

    try:
        result = scanner.scan(text)
    except ValueError as e:
        print(f"❌ Invalid input: {e}")
        sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        _print_email_result(result, verbose=args.verbose)


def _cmd_url_file(args: argparse.Namespace) -> None:
    """Handle the `safetrace url-file` command — batch URL scanning."""
    filepath = args.file
    if not os.path.isfile(filepath):
        print(f"❌ File not found: {filepath}")
        sys.exit(1)

    try:
        from safetrace.core.url_scanner import URLScanner
        scanner = URLScanner()
    except FileNotFoundError as e:
        print(f"❌ {e}")
        sys.exit(1)

    urls = _read_lines(filepath)
    if not urls:
        print(f"❌ File is empty or contains no valid entries: {filepath}")
        sys.exit(1)

    results: List[Dict[str, Any]] = []
    print(f"  Scanning {len(urls)} URL(s) from {filepath}…")
    print()

    for url in urls:
        try:
            result = scanner.scan(url)
            results.append(result)
            if not args.json:
                _print_url_result(result, verbose=args.verbose)
        except ValueError as e:
            err = {"url": url, "error": str(e)}
            results.append(err)
            if not args.json:
                print(f"  ❌ Skipped (invalid): {url} — {e}")
                print()

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))

    if not args.json:
        _print_batch_summary(results, "url")


def _cmd_email_file(args: argparse.Namespace) -> None:
    """Handle the `safetrace email-file` command — batch email analysis."""
    filepath = args.file
    if not os.path.isfile(filepath):
        print(f"❌ File not found: {filepath}")
        sys.exit(1)

    try:
        from safetrace.core.email_scanner import EmailScanner
        scanner = EmailScanner()
    except FileNotFoundError as e:
        print(f"❌ {e}")
        sys.exit(1)

    texts = _read_lines(filepath)
    if not texts:
        print(f"❌ File is empty or contains no valid entries: {filepath}")
        sys.exit(1)

    results: List[Dict[str, Any]] = []
    print(f"  Analysing {len(texts)} text(s) from {filepath}…")
    print()

    for i, text in enumerate(texts, 1):
        try:
            result = scanner.scan(text)
            results.append(result)
            if not args.json:
                print(f"  ── Entry {i} ──")
                _print_email_result(result, verbose=args.verbose)
        except ValueError as e:
            err = {"entry": i, "error": str(e)}
            results.append(err)
            if not args.json:
                print(f"  ❌ Skipped entry {i}: {e}")
                print()

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))

    if not args.json:
        _print_batch_summary(results, "email")


def _cmd_train(_args: argparse.Namespace) -> None:
    """Handle the `safetrace train` command."""
    from safetrace.train import main as train_main
    train_main()


# ============================================================
# Helpers
# ============================================================

def _read_lines(filepath: str) -> List[str]:
    """Read non-empty, stripped lines from a text file.

    Args:
        filepath: Path to the input file.

    Returns:
        List of non-empty lines.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except UnicodeDecodeError:
        logger.error("Cannot read file %s — ensure it is UTF-8 encoded.", filepath)
        return []
    except OSError as e:
        logger.error("Cannot open file %s: %s", filepath, e)
        return []


def _print_batch_summary(
    results: List[Dict[str, Any]], scan_type: str
) -> None:
    """Print a summary line after batch processing."""
    total = len(results)
    errors = sum(1 for r in results if "error" in r)
    successes = total - errors

    risk_key = "risk"
    high = sum(1 for r in results if r.get(risk_key) == "HIGH")
    medium = sum(1 for r in results if r.get(risk_key) == "MEDIUM")
    low = sum(1 for r in results if r.get(risk_key) == "LOW")

    print(f"  ── Summary ──────────────────────────────────")
    print(f"  Total: {total} | Scanned: {successes} | Errors: {errors}")
    print(f"  HIGH: {high} | MEDIUM: {medium} | LOW: {low}")
    print()


# ============================================================
# Argument Parser
# ============================================================

def _add_output_flags(parser: argparse.ArgumentParser) -> None:
    """Add --json and --verbose flags to a subparser."""
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output results as machine-readable JSON",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Show detailed explanation and feature breakdown",
    )


def main() -> None:
    """Entry point for the safetrace CLI."""
    # Configure root logger for the CLI
    logging.basicConfig(
        level=logging.INFO,
        format=LOG_FORMAT,
    )
    # Suppress noisy sklearn / joblib logs
    logging.getLogger("sklearn").setLevel(logging.WARNING)
    logging.getLogger("joblib").setLevel(logging.WARNING)

    parser = argparse.ArgumentParser(
        prog="safetrace",
        description="SafeTrace — AI-powered phishing detection toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              safetrace url http://fake-login.xyz
              safetrace url http://fake-login.xyz --json
              safetrace email "Urgent: verify your account now" --verbose
              safetrace url-file urls.txt --json
              safetrace email-file emails.txt
              safetrace train
        """),
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"safetrace {__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        description="Run `safetrace <command> --help` for details on each command.",
    )

    # --- url ---
    url_parser = subparsers.add_parser(
        "url",
        help="Scan a single URL for phishing risk",
        description="Analyse a URL using ML-based phishing detection.",
    )
    url_parser.add_argument("target", nargs="+", help="The URL to scan")
    _add_output_flags(url_parser)
    url_parser.set_defaults(func=_cmd_url)

    # --- email ---
    email_parser = subparsers.add_parser(
        "email",
        help="Analyse text/email for phishing language",
        description="Scan text for phishing patterns using ML + rule matching.",
    )
    email_parser.add_argument(
        "target", nargs="+",
        help='The text to analyse (wrap in quotes, e.g. "suspicious text")',
    )
    _add_output_flags(email_parser)
    email_parser.set_defaults(func=_cmd_email)

    # --- url-file ---
    url_file_parser = subparsers.add_parser(
        "url-file",
        help="Batch-scan URLs from a file (one per line)",
        description="Read URLs from a text file and scan each one.",
    )
    url_file_parser.add_argument(
        "file",
        help="Path to a text file containing one URL per line",
    )
    _add_output_flags(url_file_parser)
    url_file_parser.set_defaults(func=_cmd_url_file)

    # --- email-file ---
    email_file_parser = subparsers.add_parser(
        "email-file",
        help="Batch-analyse texts from a file (one per line)",
        description="Read text entries from a file and analyse each for phishing.",
    )
    email_file_parser.add_argument(
        "file",
        help="Path to a text file containing one text entry per line",
    )
    _add_output_flags(email_file_parser)
    email_file_parser.set_defaults(func=_cmd_email_file)

    # --- train ---
    train_parser = subparsers.add_parser(
        "train",
        help="Train or retrain the ML models",
        description="Train models using built-in synthetic datasets.",
    )
    train_parser.set_defaults(func=_cmd_train)

    # --- Parse and dispatch ---
    args = parser.parse_args()

    if not args.command:
        _print_banner()
        parser.print_help()
        sys.exit(0)

    # Only show banner for human-readable output
    if not getattr(args, "json", False):
        print()
        _print_banner()

    args.func(args)


if __name__ == "__main__":
    main()
