# CodeSnake

Semantic code checker for Python 3. It parses a file into an AST, walks it, and reports security problems, common bugs, and complexity smells.

Requires **Python 3.10+**. The checker itself has **no runtime dependencies** beyond the standard library.

## Install

```bash
python3 -m venv codesnake-venv
source codesnake-venv/bin/activate
pip install -e .
```

Optional companion tools (pylint, flake8, mypy, bandit, isort):

```bash
pip install -e ".[tools]"
```

Or run `./setup.sh`, which creates the venv and installs from `pyproject.toml`.

After an editable install, the `codesnake` command is on `PATH`. You can also run the modules directly:

```bash
python src/codesnake.py file.py
python src/codesnake_cli.py check file.py
./codesnake.sh file.py
```

## Usage

```bash
# One or more files
codesnake check src/codesnake.py test/example_bad_code.py

# Same thing without the subcommand
python src/codesnake.py src/codesnake.py test/example_bad_code.py

# JSON for CI
codesnake check --format json --no-color src/*.py

# Errors only
codesnake check --severity error src/*.py

# Custom thresholds
codesnake check --config .codesnake.json src/*.py

# Write a default config file
codesnake config -o .codesnake.json
```

### Output formats

| `--format` | Use |
|---|---|
| `text` (default) | Human-readable, ANSI color when the output is a TTY |
| `json` | Machine-readable report with a per-file list and a summary |
| `github` | GitHub Actions workflow commands (`::error file=...`) |
| `sarif` | SARIF 2.1.0 for security dashboards |

`--severity` is a minimum: `error` < `warning` < `info`. `--no-color` (or `NO_COLOR`) disables ANSI codes.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No error-severity issues |
| `1` | At least one error, or a missing/unreadable file, or a syntax error |
| `2` | CLI usage error |

Missing files, directories, and decode failures are reported as **IO001** (error). Syntax errors are **SYN001**. Those always fail the run; they are never printed as “no issues found.”

## What it checks

| Code | Severity | What |
|---|---|---|
| **SEC001** | error | `eval()` / `exec()` (including `builtins.eval`) |
| **SEC002** | warning | `pickle.loads` / `pickle.load` |
| **SEC003** | warning | `subprocess.call` / `run` / `Popen` with `shell=True` |
| **BUG001** | error | Mutable default arguments (`[]`, `{}`, `set()`, `list()`, including kw-only and `lambda` / `async def`) |
| **EXC001** | warning | Bare `except:` |
| **EXC002** | info | `except Exception` |
| **EXC003** | warning | Empty `except` body (`pass`) |
| **EXC004** | warning | `raise Exception()` with no message |
| **COMP001** | warning | Too many parameters |
| **COMP002** | warning | Cyclomatic complexity too high (nested functions are not charged to the parent) |
| **COMP003** | warning | Function longer than the configured maximum |
| **COMP004** | warning | Class with too many methods |
| **COMP005** | warning | Too many `self.*` names in `__init__` |
| **PERF001** | info | `for i in range(len(...))` |
| **STYLE001** | info | `is True` / `is False` |
| **IMP001** | warning | `from module import *` |
| **REL002** | info | `assert` is stripped under `-O` |
| **SYN001** | error | Syntax error |
| **IO001** | error | File missing, not a file, or unreadable |

Call checks resolve imports (`from subprocess import call`, `import pickle as pkl`, …) rather than matching only the AST shape of the call.

## Configuration

If `.codesnake.json` exists in the current directory, it is loaded automatically. `--config PATH` overrides that. Thresholds in the JSON are the source of truth; they are not hardcoded in the checker.

```json
{
  "max_function_length": 50,
  "max_function_params": 7,
  "max_complexity": 10,
  "max_class_methods": 20,
  "max_instance_vars": 10,
  "check_security": true,
  "check_bugs": true,
  "check_exceptions": true,
  "check_complexity": true,
  "check_performance": true,
  "check_imports": true,
  "check_style": true,
  "report_errors": true,
  "report_warnings": true,
  "report_info": true
}
```

`check_*` turns whole categories off. `report_*` filters by severity. A stricter sample lives in `codesnake.json`.

## Library API

```python
from codesnake import CheckerConfig, SemanticChecker, check_file, run_check

issues = SemanticChecker(source, filename="app.py").analyze()
issues = check_file("app.py")  # IO failures become IO001 issues

config = CheckerConfig(max_complexity=8, check_style=False)
rc = run_check(
    ["app.py", "lib.py"],
    config=config,
    output_format="json",
    min_severity="warning",
    color=False,
)
```

## Tests

```bash
python test/test_codesnake.py
# or
codesnake test
./codesnake-launcher.sh --no-venv --test
```

`test/example_bad_code.py` is a fixture with intentional issues, useful as a demo:

```bash
python src/codesnake.py test/example_bad_code.py
```

## Project layout

```
codesnake/
├── pyproject.toml            # packaging and optional extras
├── .codesnake.json           # default checker config
├── setup.sh                  # venv + editable install
├── codesnake.sh              # simple launcher
├── codesnake-launcher.sh     # flags, --test, -e enhanced
├── src/
│   ├── codesnake.py          # checker + argparse CLI
│   ├── codesnake_cli.py      # check / test / config / version
│   ├── codesnake_enhanced.py # compatibility entry point
│   └── codesnake_banner.py
├── test/
└── docs/                     # extra guides (banner, scripts, structure)
```

## License

MIT
