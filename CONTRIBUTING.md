# Contributing

Discuss larger changes in an issue. Use owned synthetic pages and licensed archive fixtures.
Preserve the original tests and the read-only archive contract.

```console
python -m pip install -e ".[dev]"
ruff format --check .
ruff check .
mypy src
pytest --cov=cbz_auditor --cov-branch --cov-report=term-missing
python -m build
python -m pip_audit
```
