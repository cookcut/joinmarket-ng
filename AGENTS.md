# JoinMarket NG

## Overview
Modern, secure implementation of JoinMarket components using Python 3.14+, Pydantic v2, and AsyncIO.

## Key Constraints
- **Python**: 3.14+ required. Strict type hinting (Mypy) mandated.
- **Database**: No BerkeleyDB. Use direct RPC or Mempool API.
- **Privacy**: Tor integration is core architecture.

## Commands
- **Test**: `pytest -lv --cov=jmcore --cov=jmwallet --cov=directory_server --cov=orderbook_watcher --cov=maker --cov=taker jmcore orderbook_watcher directory_server jmwallet maker taker tests`. Several markers available.
- **Lint/Format**: `pre-commit run --all-files` (Recommended).
  - Manual: `ruff check .` / `ruff format .` / `mypy .`
- **Docker**: `docker-compose up -d` (several profiles available).

## Code Style
- **Formatting**: Line length 100. Follow Ruff defaults.
- **Typing**: `disallow_untyped_defs = true`. Use `typing` module or modern `|` syntax.
- **Imports**: Sorted (Stdlib → Third-party → Local). `from __future__ import annotations`.
- **Naming**: `snake_case` for functions/vars, `PascalCase` for classes/models.
- **Error Handling**: Use descriptive custom exceptions (inheriting from `Exception`).

## Gerneral Guidelines
- Check the documentation at README.md and DOCS.md.
- Add tests and verify the new and existing tests pass, you can use the docker compose setup.
- Improve the documentation as needed.
- Don't break backwards compatinbility, even with the reference implementation. Use feature flags if needed.

## Project Structure
Monorepo with `src/` layout. Root `pytest.ini` handles global tests.
Components: `jmcore` (Lib), `directory_server`, `jmwallet`, `maker`, `taker`, `orderbook_watcher`.

## References

https://github.com/JoinMarket-Org/joinmarket-clientserver/ -> reference implementation (legacy)
https://github.com/JoinMarket-Org/JoinMarket-Docs -> protocol documentation
