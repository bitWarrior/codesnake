# CodeSnake Project Structure 📁

```
codesnake/
├── pyproject.toml                Packaging: metadata, extras, console script
├── LICENSE                       MIT
├── README.md                     Primary documentation (install, usage, rules, API)
├── .codesnake.json               Default configuration (what `codesnake config` writes)
├── setup.sh                      One-time venv + editable install
├── codesnake.sh                  Minimal launcher (activates venv, runs the CLI)
├── codesnake-launcher.sh         Launcher with --test / --create-venv / --no-venv
│
├── src/codesnake/                The installable package
│   ├── __init__.py               Public API re-exports and __version__
│   ├── __main__.py               `python -m codesnake`
│   ├── _version.py               Single source of truth for the version
│   ├── checker.py                SemanticChecker, config, discovery, formats, run_check
│   ├── cli.py                    argparse CLI (check / config / version)
│   └── banner.py                 ASCII banner and version banner
│
├── test/
│   ├── test_codesnake.py         unittest suite (also runs under pytest)
│   ├── example_bad_code.py       Fixture with intentional issues
│   └── README.md
│
├── examples/
│   └── strict.codesnake.json     Stricter thresholds sample
│
├── docs/
│   ├── INTEGRATIONS.md           pre-commit, CI, editors, baselines, adopting on a codebase
│   ├── BASH_SCRIPTS_GUIDE.md     The launcher scripts and the venv
│   └── PROJECT_STRUCTURE.md      This file
└── .github/workflows/ci.yml      Tests on 3.10–3.13 + self-check
```

## Module responsibilities

| Module | Contents |
|---|---|
| `checker.py` | `SemanticChecker` (the AST visitor and every rule), `CheckerConfig` / `load_config`, file discovery (`iter_python_files`, `.gitignore` handling, `expand_python_targets`), `check_file`, bandit merge, baselines, `--staged` support, the four report formatters, and `run_check` (the orchestration entry point used by the CLI and by library callers) |
| `cli.py` | `add_check_arguments()` (the single definition of the `check` flags), `build_parser()`, `normalize_argv()` (so `codesnake FILES` means `codesnake check FILES`), and `main()` |
| `banner.py` | `print_snake_banner()`, `print_version()`; `VERSION` is imported from `_version` |
| `_version.py` | `__version__` — read statically by `pyproject.toml` (`dynamic = ["version"]`) |
| `__init__.py` | Re-exports the public API so `from codesnake import SemanticChecker, run_check` works |

## Entry points

| Invocation | Notes |
|---|---|
| `codesnake check FILES` | Console script installed by `pip install -e .` |
| `codesnake FILES` | Shorthand; the first non-subcommand argument implies `check` |
| `python -m codesnake ...` | Same CLI without the console script (needs `src/` on `PYTHONPATH` or an install) |
| `./codesnake.sh FILES` | Activates `codesnake-venv/` (creating it on first run) then runs the CLI |
| `./codesnake-launcher.sh [--no-venv] [--test] FILES` | As above, plus test runner and venv management |

## Adding a rule

1. Add a `visit_<Node>` method or extend an existing one in `src/codesnake/checker.py`; call `self.add_issue(severity, category, message, node, 'CODE')`.
2. If it is a new category, add it to `CATEGORY_FLAGS` and a `check_<category>` field on `CheckerConfig`.
3. Add a one-line fix to `ISSUE_SUGGESTIONS`.
4. Add a positive test *and* a "still not reported" control test in `test/test_codesnake.py`.
5. Document the code in the README rule table.

## Releasing

Bump `__version__` in `src/codesnake/_version.py` — nothing else. The banner, SARIF `tool.version`, `codesnake --version`, and the wheel metadata all read from it.
