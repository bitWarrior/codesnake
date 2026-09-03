<p align="center">
  <img src="https://raw.githubusercontent.com/bitWarrior/codesnake/main/images/codesnake-logo.jpg"
       alt="CodeSnake — semantic analysis for Python" width="640">
</p>

# CodeSnake

[![CI](https://github.com/bitWarrior/codesnake/actions/workflows/ci.yml/badge.svg)](https://github.com/bitWarrior/codesnake/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/codesnake.svg)](https://pypi.org/project/codesnake/)
[![Python](https://img.shields.io/pypi/pyversions/codesnake.svg)](https://pypi.org/project/codesnake/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Semantic code checker for Python 3. It parses files into an AST, walks them, and reports security problems, common bugs, unused names, and complexity smells.

Two properties set it apart from the fast general-purpose linters:

- **It never imports or executes the code it analyzes.** Everything runs on the AST from `ast.parse`, so pointing it at untrusted Python — a fork's pull request, a submitted plugin — does not run that Python.
- **It has no runtime dependencies.** Standard library only, so it vendors cleanly, works air-gapped, and adds nothing to your supply chain.

It also does light **taint tracking**: `eval()` on a literal is `info`, `eval()` on something derived from `input()` or `request.args` is an `error`. See [how it compares](#how-it-compares) to Ruff, Bandit, and pylint.

Requires **Python 3.10+**.

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

## First run on an existing codebase

CodeSnake reports complexity, length, and unused-name findings by default, so the
first run on a mature codebase is loud — expect roughly ten warnings per file. That
is a backlog, not an emergency: only `error` severity fails the run. Start narrow and
widen when you are ready.

```bash
# 1. What would actually fail CI. Start here.
codesnake check --severity error src/

# 2. Snapshot everything else, so CI only fails on NEW findings.
codesnake check --update-baseline .codesnake-baseline.json src/
git add .codesnake-baseline.json

# 3. From now on, this is your CI command.
codesnake check --baseline .codesnake-baseline.json src/
```

Then tune thresholds in `.codesnake.json` and shrink the baseline as you go. The full
adoption path is in [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md#adopting-codesnake-on-an-existing-codebase).

## Usage

```bash
# Files or directories (walks *.py; skips venvs, caches, and untracked .gitignore matches)
codesnake check src/codesnake/checker.py test/example_bad_code.py
codesnake check src/

# Also analyze untracked files that .gitignore hides, e.g. generated output
codesnake check --no-ignore src/

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

# Write a default config file (refuses to overwrite; pass --force to replace)
codesnake config -o .codesnake.json
```

### CLI flags

| Flag | Meaning |
|---|---|
| `--config PATH` | `.codesnake.json` or a `pyproject.toml` with `[tool.codesnake]` (otherwise the nearest one found walking up to the repository root, else defaults) |
| `--format text\|json\|github\|sarif` | Report format (default `text`) |
| `--severity error\|warning\|info` | Minimum severity to print |
| `--no-color` | Disable ANSI color (`NO_COLOR` also works) |
| `--bandit` | Merge Bandit results when the `bandit` executable is installed |
| `--staged` | Check `git diff --cached` Python files only |
| `--no-ignore` | When walking directories, ignore `.gitignore` entirely, including for untracked files (venvs, caches, and `.git` are still skipped). Tracked files are analyzed either way. |
| `--baseline FILE` | Hide issues whose fingerprint is already in the baseline |
| `--update-baseline FILE` | Write the current finding set as a baseline |
| `-j`, `--jobs N` | Worker processes (default: auto — one per CPU once 8+ files are checked; `1` disables) |

`--staged` needs no file arguments and works from any directory inside the repository (paths from git are resolved against the repo root). With no staged `.py` files it exits **0**. Directory walks skip `.gitignore` matches only for files git does not track, mirroring git's own behavior — so a file committed with `git add -f` is still analyzed, and no flag is needed to catch it. `--no-ignore` additionally covers *untracked* ignored files, such as generated output. `--baseline` fingerprints are `filename|code|message-with-numbers-normalized|occurrence`, so line-only edits and count changes (`52 lines long` → `53 lines long`) do not re-fail CI, while a *second* identical violation in the same file still does. Version-1 baselines are read transparently; `--update-baseline` writes version 2. A missing baseline file fails closed (exit 1).

### Output formats

| `--format` | Use |
|---|---|
| `text` (default) | Human-readable; color when stdout is a TTY; includes a one-line suggestion |
| `json` | Per-file issues plus a summary (`end_line`, `end_col`, `suggestion`, `source`) |
| `github` | GitHub Actions workflow commands (`::error file=...,line=...,col=...,title=...::message`), properly `%`-escaped |
| `sarif` | SARIF 2.1.0 with rule metadata (`helpUri`, default level, suggestion) and repo-relative URIs for code-scanning dashboards |

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
| **SEC002** | warning | Unsafe deserialization: `pickle` / `dill` / `cloudpickle` / `jsonpickle` loads, `pickle.Unpickler(...).load()`, `marshal.load(s)`, `shelve.open`, and `yaml.load` without a safe `Loader` |
| **SEC003** | warning / error | `subprocess` with `shell=True`, or `os.system` / `os.popen` / `subprocess.getoutput` (**error** if the command is untrusted) |
| **SEC004** | warning | `subprocess` command (`run`, `call`, `Popen`, `check_call`, `check_output`) built from untrusted input |
| **BUG001** | error | Mutable default arguments (`[]`, `{}`, `set()`, `list()`, kw-only, `lambda`, `async def`) |
| **BUG002** | warning | Duplicate key in a dict literal, including tuple keys |
| **EXC001** | warning | Bare `except:` |
| **EXC002** | info | `except Exception`, including `builtins.Exception` and tuple clauses like `except (ValueError, Exception)` |
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

CodeSnake looks for configuration starting in the current directory and walking up to the repository root (the first directory containing `.git`). In each directory a `.codesnake.json` wins over a `pyproject.toml` `[tool.codesnake]` table. `--config PATH` (JSON or TOML) overrides discovery.

```toml
# pyproject.toml — same keys as the JSON file (reading TOML needs Python 3.11+)
[tool.codesnake]
max_complexity = 8
check_style = false
```

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

`max_*` thresholds must be 1 or greater; anything lower is a config error. `check_*` turns whole categories off (`check_reliability` covers REL002 and ASY001). `report_*` filters by severity. `use_bandit` merges Bandit when it is installed. A stricter sample lives in `examples/strict.codesnake.json`.

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

## How it compares

CodeSnake is not trying to replace Ruff. Use both.

| | CodeSnake | Ruff | Bandit | pylint |
|---|---|---|---|---|
| Speed, 167 stdlib files | 1.7s | **0.14s** | 9.1s | 17.4s |
| Rules | ~25 | 800+ | ~70 security | 400+ |
| Runtime dependencies | **none** | none (Rust binary) | several | several |
| Imports the analyzed code | **never** | never | never | in some modes |
| Taint tracking | **yes** | no | limited | no |
| Autofix | no | **yes** | no | no |
| SARIF output | **yes** | no | **yes** | no |
| Baselines | **yes** | no | via `--baseline` | no |

**Ruff is roughly 13x faster and has 30x the rules.** If you want one fast
general-purpose linter with autofix, use Ruff — CodeSnake is not competing for that job.
Among the Python-implemented checkers, though, CodeSnake is the quick one: about 5x
faster than Bandit and 10x faster than pylint on the same files.

<sub>Measured on Python 3.12, best of 2–3 runs over the same 167 files from the standard
library, each tool using its own parallelism where it has any (`codesnake` auto,
`pylint -j 0`). pylint ran with `--disable=all --enable=W,E`, a reduced rule set in its
favor. Your numbers will differ; the ranking is the point, not the digits.</sub>

CodeSnake is worth adding when you want one of these:

- **Taint tracking.** `eval(x)` where `x` came from `input()` or `request.args` is an
  `error`; `eval("1+1")` is `info`. The fast linters flag the call site without asking
  where the data came from.
- **Analysis of untrusted code.** No import, no execution, no dependencies — safe to
  run over a fork's PR or a user-submitted plugin.
- **A vendorable checker.** One pure-Python package with an empty dependency list,
  auditable in an afternoon, no toolchain.
- **SARIF plus stable baselines**, for GitHub code scanning on a codebase with an
  existing backlog.

Bandit has far broader security coverage; `--bandit` merges its findings into the same
report if you want both.

## Performance

Files are analyzed in a process pool once there are 8 or more of them (one worker per CPU); pass `--jobs 1` for a strictly sequential run or `--jobs N` to pin the count. Output order is always the input order.

Roughly 100 files/second single-process on a modern laptop. CodeSnake is pure Python
doing a full AST walk per file; if analysis time dominates your CI, reach for Ruff.

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
├── docs/                     # INTEGRATIONS, BASH_SCRIPTS_GUIDE, PROJECT_STRUCTURE
└── .github/workflows/ci.yml
```

Releasing: bump `__version__` in `src/codesnake/_version.py`; `pyproject.toml` reads it dynamically.

## Further reading

- [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md) — pre-commit hooks, GitHub Actions (annotations, SARIF upload, baselines), VS Code, Makefile, adopting CodeSnake on an existing codebase, and how it overlaps with flake8/Bandit/pylint.
- [`docs/BASH_SCRIPTS_GUIDE.md`](docs/BASH_SCRIPTS_GUIDE.md) — `setup.sh`, `codesnake.sh`, and `codesnake-launcher.sh`, and the virtual environment they manage.
- [`docs/PROJECT_STRUCTURE.md`](docs/PROJECT_STRUCTURE.md) — module map, how to add a rule, how to release.

## License

MIT
