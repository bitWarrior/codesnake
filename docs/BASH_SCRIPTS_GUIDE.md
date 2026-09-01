# Launcher Scripts

Three Bash scripts wrap the `codesnake` CLI for people who would rather not manage a virtual environment by hand. None of them is required: after `pip install -e .` the `codesnake` command (or `python -m codesnake`) does everything they do.

| Script | Use it when |
|---|---|
| `setup.sh` | First time: create `codesnake-venv/`, install, write a default config |
| `codesnake.sh` | Daily use: activate the venv (creating it if missing) and run the CLI |
| `codesnake-launcher.sh` | You also want `--test`, `--create-venv`, or `--no-venv` |

All three detect `python3` (falling back to `python`) and make the package importable with `PYTHONPATH=src`, so they work from a bare checkout as well as after an install.

## `setup.sh`

```bash
./setup.sh
```

1. Checks that `python3` exists (CodeSnake needs 3.10+).
2. Creates `codesnake-venv/` (offers to recreate an existing one).
3. Upgrades pip and installs the project with `pip install -e .` — or `.[tools]` if you accept the optional pylint/flake8/mypy/bandit/isort prompt.
4. Makes the scripts executable.
5. Writes `.codesnake.json` via `codesnake config` if none exists, so it never drifts from the checker's defaults.
6. Runs `codesnake --help` as a smoke test.

## `codesnake.sh`

```bash
./codesnake.sh [any codesnake arguments]
```

Activates `codesnake-venv/` (creating and populating it on first run), then `exec`s `python -m codesnake` with your arguments untouched. Because nothing is re-parsed by the shell, every CLI form works:

```bash
./codesnake.sh src/                              # shorthand for `check`
./codesnake.sh check --format json --no-color src/
./codesnake.sh check --staged
./codesnake.sh config -o .codesnake.json
./codesnake.sh "path with spaces/app.py"
```

## `codesnake-launcher.sh`

```bash
./codesnake-launcher.sh [OPTIONS] [files or directories]
```

| Option | Meaning |
|---|---|
| `-h`, `--help` | Show help |
| `-v`, `--version` | Show the CodeSnake version |
| `-c`, `--config FILE` | Same as `--config FILE` |
| `-f`, `--format FORMAT` | Same as `--format` (`text` / `json` / `github` / `sarif`) |
| `-s`, `--severity LEVEL` | Same as `--severity` (`error` / `warning` / `info`) |
| `--create-venv` | Delete and recreate `codesnake-venv/`, then exit |
| `--no-venv` | Do not activate the venv (use the current Python) |
| `--test` | Run `test/test_codesnake.py` |
| `--banner` | Print the banner |
| `-e`, `--enhanced` | Deprecated no-op (the "enhanced" checker was merged into the main CLI) |

Anything else — files, directories, `--bandit`, `--staged`, `--baseline FILE`, `--update-baseline FILE`, `--jobs N`, `--no-color` — is passed straight through to `codesnake check`. Arguments are forwarded as an array, so paths with spaces or shell metacharacters are safe. An option that needs a value but has none exits with status 2 and a message.

```bash
./codesnake-launcher.sh mycode.py
./codesnake-launcher.sh -c examples/strict.codesnake.json -f json -s warning src/
./codesnake-launcher.sh --staged --no-color
./codesnake-launcher.sh --no-venv --test          # tests with whatever python3 is on PATH
./codesnake-launcher.sh --create-venv
```

## The virtual environment

- Location: `codesnake-venv/` next to the scripts (gitignored). Change `VENV_NAME` at the top of each script to rename it.
- Manual activation: `source codesnake-venv/bin/activate`, after which `codesnake` is on `PATH`.
- Recreate: `./codesnake-launcher.sh --create-venv`, or `rm -rf codesnake-venv && ./setup.sh`.
- Skip it entirely: `--no-venv` (launcher) or just call `codesnake` / `python -m codesnake` yourself.

## Troubleshooting

| Problem | Fix |
|---|---|
| `Permission denied` | `chmod +x setup.sh codesnake.sh codesnake-launcher.sh`, or run with `bash script.sh` |
| `Python 3 is not installed` | Install Python 3.10+ (`sudo apt install python3 python3-venv`, `brew install python3`) |
| venv is broken or on an old interpreter | `./codesnake-launcher.sh --create-venv` |
| Want the system Python instead of the venv | `./codesnake-launcher.sh --no-venv ...` |

Shell aliases, if you use the scripts often:

```bash
alias cs='./codesnake.sh'
alias cst='./codesnake-launcher.sh --test'
```
