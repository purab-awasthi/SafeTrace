# Contributing to SafeTrace

Thank you for considering contributing to SafeTrace! This document provides guidelines to make the contribution process smooth for everyone.

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/safetrace.git
   cd safetrace
   ```
3. **Install in editable mode**:
   ```bash
   pip install -e .
   ```
4. **Train the models** (required for testing):
   ```bash
   safetrace train
   ```

## Development Workflow

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Make your changes with clear, descriptive commits.
3. Ensure the CLI still works:
   ```bash
   safetrace url http://example.com
   safetrace email "test message"
   ```
4. Push your branch and open a Pull Request.

## Code Style

- **Python 3.9+** — use type hints where practical.
- **Docstrings** — use Google-style docstrings for public functions.
- **Naming** — `snake_case` for functions/variables, `PascalCase` for classes.
- **Logging** — use `logging.getLogger("safetrace.<module>")` instead of `print()`.
- **No unnecessary dependencies** — keep the package lightweight.

## What Makes a Good Contribution?

- Bug fixes with a clear description of the issue.
- New detection patterns added to `config.py`.
- Improved explainability in risk reasons.
- Performance improvements to feature extraction.
- Documentation improvements.
- Test coverage additions.

## Reporting Bugs

Use the [GitHub Issues](https://github.com/safetrace/safetrace/issues) tab. Include:

- SafeTrace version (`safetrace --version`).
- Python version.
- Steps to reproduce.
- Expected vs. actual behaviour.
- Full error traceback (if applicable).

## Code of Conduct

Be respectful, constructive, and inclusive. We're all here to build better security tools.

---

Thank you for helping make SafeTrace better! 🔐
