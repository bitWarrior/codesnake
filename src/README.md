# `src/codesnake/`

The installable package. See `docs/PROJECT_STRUCTURE.md` for a module-by-module map and the root `README.md` for usage.

```
codesnake/
├── __init__.py    public API re-exports, __version__
├── __main__.py    python -m codesnake
├── _version.py    __version__ (single source of truth)
├── checker.py     SemanticChecker, config, discovery, formats, run_check
├── cli.py         argparse CLI: check / config / version
└── banner.py      ASCII art
```

## Run without installing

```bash
PYTHONPATH=src python -m codesnake check file.py
```

## Library use

```python
from codesnake import SemanticChecker, CheckerConfig, check_file, run_check

issues = SemanticChecker(source, filename="app.py").analyze()
issues = check_file("app.py")
rc = run_check(["src/"], config=CheckerConfig(max_complexity=8), output_format="json")
```
