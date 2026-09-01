# CodeSnake

Semantic code checker for Python 3. It parses files into an AST, walks them, and reports security problems, common bugs, unused names, and complexity smells.

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

After an editable install, `codesnake` is on `PATH`. You can also run:

```bash
python -m codesnake check file.py            # after install
PYTHONPATH=src python -m codesnake file.py   # straight from a checkout
./codesnake.sh file.py                        # creates/activates codesnake-venv/
```

## Usage

```bash
# Files or directories (walks *.py, skips venvs, caches, and .gitignore)
codesnake check src/codesnake/checker.py test/example_bad_code.py
codesnake check src/

# Same thing without the subcommand
codesnake src/

# JSON for CI
codesnake check --format json --no-color src/

# Errors only
codesnake check --severity error src/

# Merge Bandit findings (needs pip install -e ".[tools]")
codesnake check --bandit src/

# Only Python files staged in git
codesnake check --staged

# Snapshot findings, then fail only on new ones
codesnake check --update-baseline .codesnake-baseline.json src/
codesnake check --baseline .codesnake-baseline.json src/

# Custom thresholds
codesnake check --config .codesnake.json src/

# Write a default config file
codesnake config -o .codesnake.json
```

### CLI flags

| Flag | Meaning |
|---|---|
| `--config PATH` | Config JSON (otherwise `.codesnake.json` in the current directory, else defaults) |
| `--format text\|json\|github\|sarif` | Report format (default `text`) |
| `--severity error\|warning\|info` | Minimum severity to print |
| `--no-color` | Disable ANSI color (`NO_COLOR` also works) |
| `--bandit` | Merge Bandit results when the `bandit` executable is installed |
| `--staged` | Check `git diff --cached` Python files only |
| `--baseline FILE` | Hide issues whose fingerprint is already in the baseline |
| `--update-baseline FILE` | Write the current finding set as a baseline |

`--staged` needs no file arguments and works from any directory inside the repository (paths from git are resolved against the repo root). With no staged `.py` files it exits **0**. `--baseline` fingerprints are `filename|code|message`, so line-only edits do not re-fail CI. A missing baseline file fails closed (exit 1).

### Output formats

| `--format` | Use |
|---|---|
| `text` (default) | Human-readable; color when stdout is a TTY; includes a one-line suggestion |
| `json` | Per-file issues plus a summary (`end_line`, `end_col`, `suggestion`, `source`) |
| `github` | GitHub Actions commands (`::error file=...,line=...,endLine=...`) |
| `sarif` | SARIF 2.1.0 regions for security dashboards |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No error-severity issues (or `--staged` with no staged Python files) |
| `1` | At least one error, I/O failure, syntax error, bad config/baseline, or git failure |
| `2` | CLI usage error (unknown flag, or `check` with neither files nor `--staged`) |

Missing files, empty directories, and decode failures are **IO001**. Syntax errors are **SYN001**. Those always fail the run; they are never printed as “no issues found.”

## What it checks

| Code | Severity | What |
|---|---|---|
| **SEC001** | info / error | `eval()` / `exec()` — **info** on a constant, **error** on untrusted input |
| **SEC002** | warning | `pickle.loads` / `pickle.load` |
| **SEC003** | warning / error | `subprocess` with `shell=True`, or `os.system` / `os.popen` / `subprocess.getoutput` (**error** if the command is untrusted) |
| **SEC004** | warning | `subprocess` command (`run`, `call`, `Popen`, `check_call`, `check_output`) built from untrusted input |
| **BUG001** | error | Mutable default arguments (`[]`, `{}`, `set()`, `list()`, kw-only, `lambda`, `async def`) |
| **BUG002** | warning | Duplicate key in a dict literal |
| **EXC001** | warning | Bare `except:` |
| **EXC002** | info | `except Exception` |
| **EXC003** | warning | Empty `except` body (`pass`) |
| **EXC004** | warning | `raise Exception()` with no message |
| **EXC005** | warning | `raise NewError(...)` inside `except` / `except*` without `from` |
| **COMP001** | warning | Too many parameters |
| **COMP002** | warning | Cyclomatic complexity too high (nested functions are not charged to the parent) |
| **COMP003** | warning | Function longer than the configured maximum |
| **COMP004** | warning | Class with too many methods |
| **COMP005** | warning | Too many `self.*` **assignments** in `__init__` (method calls are ignored) |
| **PERF001** | info | `for i in range(len(...))` |
| **STYLE001** | info | `is True` / `is False` |
| **IMP001** | warning | `from module import *` |
| **IMP002** | warning | Imported name is never used (module level or inside a function) |
| **IMP003** | error | Relative import of a name the sibling module does not define |
| **VAR001** | warning | Unused local or nested function (loop targets, tuple unpacking, bare annotations, and decorated nested functions are exempt) |
| **VAR002** | warning | Unused argument (`self` / `cls`, `_`-prefixed names, `*args` / `**kwargs`, lambda and dunder-method parameters, and abstract/stub bodies are skipped) |
| **VAR003** | info | Local name shadows an enclosing function binding |
| **REL002** | info | `assert` is stripped under `-O` (skipped in `test_*.py`, `*_test.py`, `conftest.py`, and `test(s)/` directories) |
| **RES001** | warning | `open()` used without `with` (anything inside a `with` item, `contextlib.closing(...)`, or `stack.enter_context(...)` counts as owned) |
| **ASY001** | warning | `async def` that never `await`s (stubs and `@abstractmethod` skipped) |
| **SYN001** | error | Syntax error |
| **IO001** | error | File missing, not a file, unreadable, or empty directory |
| **B###** | varies | Bandit test ids, only when `--bandit` / `use_bandit` is on (`source: bandit`) |

Call checks resolve imports (`from subprocess import call`, `import pickle as pkl`) instead of matching only the AST shape. `shell=True` is also detected via a local or module constant (`shell = True; run(..., shell=shell)`); reassigning the name invalidates the constant.

Function bodies are analyzed after the enclosing scope is fully bound, so a closure that references a variable assigned *after* the `def` does not produce a false "unused variable" warning.

Untrusted input (taint) is tracked from `input()`, `sys.argv`, `os.environ` / `os.getenv`, and `args` / `GET` / `POST` / `json` / `form`-style attributes read from a request object (`request`, `req`, `self.request`), including f-strings, `+`, `.format()`, `.get()`, and subscripts. Passing tainted data through `shlex.quote`, `int()`, `re.escape`, `html.escape`, or `urllib.parse.quote` clears the taint.

**IMP003** runs when several files are checked together. `from .foo import bar` is an error only if `foo.py` (or `foo/__init__.py`) is in the same run and does not define `bar`. Unused imports inside `if TYPE_CHECKING:` and names listed in `__all__` are not flagged as IMP002.

### Suppressing findings

On the same line as the issue:

```python
eval("1+1")          # noqa
eval("1+1")          # noqa: SEC001
import os            # codesnake: ignore
import os            # codesnake: ignore=IMP002
```

`# noqa` with no codes suppresses every finding on that line.

## Configuration

If `.codesnake.json` exists in the current directory, it is loaded automatically. `--config PATH` overrides that. Thresholds in the JSON are the source of truth.

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
  "check_unused": true,
  "check_reliability": true,
  "use_bandit": false,
  "report_errors": true,
  "report_warnings": true,
  "report_info": true
}
```

`check_*` turns whole categories off (`check_reliability` covers REL002 and ASY001). `report_*` filters by severity. `use_bandit` merges Bandit when it is installed. A stricter sample lives in `examples/strict.codesnake.json`.

## Library API

```python
from codesnake import CheckerConfig, SemanticChecker, check_file, run_check

issues = SemanticChecker(source, filename="app.py").analyze()
issues = check_file("app.py")                  # I/O failures become IO001
issues = check_file("app.py", source=text)     # analyze already-read text

config = CheckerConfig(max_complexity=8, check_style=False)
rc = run_check(
    ["app.py", "pkg/"],
    config=config,
    output_format="json",
    min_severity="warning",
    color=False,
    staged=False,
    baseline_path=".codesnake-baseline.json",
    use_bandit=False,
)
```

Each `Issue` includes `line`, `col`, `end_line`, `end_col`, `suggestion`, and `source` (`codesnake` or `bandit`). `col` / `end_col` are **0-based character offsets** (AST byte offsets are converted), and JSON output reports them as-is. The `text`, `github`, and `sarif` formats print **1-based** columns.

## Tests

```bash
python -m unittest discover -s test -p 'test_*.py'
python test/test_codesnake.py          # same suite, with a summary
./codesnake-launcher.sh --no-venv --test
```

CI (`.github/workflows/ci.yml`) runs the suite on Python 3.10–3.13 and then runs `codesnake check --format github src/` on the checker's own source.

`test/example_bad_code.py` is a fixture with intentional issues:

```bash
codesnake check test/example_bad_code.py
```

## Project layout

```
codesnake/
├── pyproject.toml            # packaging, extras, console script
├── LICENSE                   # MIT
├── .codesnake.json           # default checker config
├── setup.sh                  # venv + editable install
├── codesnake.sh              # simple launcher
├── codesnake-launcher.sh     # flags, --test, --create-venv, --no-venv
├── src/codesnake/
│   ├── __init__.py           # public API, __version__
│   ├── __main__.py           # python -m codesnake
│   ├── _version.py           # the one place the version lives
│   ├── checker.py            # SemanticChecker, config, discovery, formats, run_check
│   ├── cli.py                # check / config / version
│   └── banner.py
├── test/                     # unittest suite + fixture
├── examples/                 # strict.codesnake.json
├── docs/                     # extra guides
└── .github/workflows/ci.yml
```

Releasing: bump `__version__` in `src/codesnake/_version.py`; `pyproject.toml` reads it dynamically.

## License

MIT
