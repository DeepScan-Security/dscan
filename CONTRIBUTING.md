# Contributing to dscan

Thanks for helping improve dscan. This guide covers how to set up,
test, and submit changes.

## Setup

```bash
git clone https://github.com/DeepScan-Security/dscan
cd dscan
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Requires Python 3.11+.

## Running tests

```bash
pytest                                   # run the suite
pytest --cov=dscan --cov-report=term-missing   # with coverage
```

Coverage must stay at or above 80%. CI runs the suite on Python
3.11–3.14 and fails below 80%.

## Coding standards

- **Test-first.** Write tests before or alongside the implementation,
  never after. Every new function needs tests.
- **Async throughout.** Use `asyncio` and `aiofiles` for I/O.
- Use `inspect.iscoroutinefunction`, not `asyncio.iscoroutinefunction`.
- Type hints on all public functions.
- No `print()` — use `rich` for console output.
- Keep modules small and single-purpose.

## Submitting a pull request

1. Fork the repo and create a branch from `main`.
2. Make your change with tests; keep coverage ≥ 80%.
3. Run `pytest` and make sure it passes.
4. Open a PR with a clear description of what changed and why.
5. A maintainer (see `CODEOWNERS`) reviews. Changes to
   `redactor.py` and `tracer.py` require owner review.

## Reporting security issues

Do not open public issues for vulnerabilities. See
[SECURITY.md](SECURITY.md).
