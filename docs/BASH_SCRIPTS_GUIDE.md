# CodeSnake Bash Scripts Guide 🐚

Complete guide to the CodeSnake launcher scripts and virtual environment management.

## 📜 Available Scripts

### 1. `setup.sh` - Initial Setup
**One-time setup script to get CodeSnake ready**

```bash
./setup.sh
```

**What it does:**
- ✅ Checks Python 3 installation
- ✅ Creates virtual environment (`codesnake-venv`)
- ✅ Upgrades pip
- ✅ Optionally installs pylint, flake8, mypy, bandit
- ✅ Makes all scripts executable
- ✅ Creates default `.codesnake.json` config
- ✅ Tests the installation

**When to use:** First time setting up CodeSnake

---

### 2. `codesnake.sh` - Simple Launcher
**Basic launcher that activates venv and runs CodeSnake**

```bash
./codesnake.sh <files...>
```

**Examples:**
```bash
# Check a file
./codesnake.sh mycode.py

# Check multiple files
./codesnake.sh file1.py file2.py file3.py

# Check all Python files in directory
./codesnake.sh src/*.py
```

**Features:**
- Auto-creates venv if missing
- Activates virtual environment
- Runs `codesnake.py` with arguments
- Simple and straightforward

**When to use:** Quick daily checks

---

### 3. `codesnake-launcher.sh` - Enhanced Launcher
**Full-featured launcher with many options**

```bash
./codesnake-launcher.sh [OPTIONS] [files...]
```

#### Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message |
| `-v, --version` | Show CodeSnake version |
| `-e, --enhanced` | Use enhanced version |
| `-c, --config FILE` | Specify config file |
| `-f, --format FORMAT` | Output format (text/json/github/sarif) |
| `-s, --severity LEVEL` | Min severity (error/warning/info) |
| `--create-venv` | Create/recreate virtual environment |
| `--no-venv` | Run without venv activation |
| `--test` | Run test suite |
| `--banner` | Show CodeSnake banner |

#### Examples

**Basic Usage:**
```bash
# Check a file
./codesnake-launcher.sh mycode.py

# Check with enhanced mode
./codesnake-launcher.sh mycode.py

# Use custom config
./codesnake-launcher.sh -c strict.json mycode.py
```

**Advanced Usage:**
```bash
# JSON output for CI/CD
./codesnake-launcher.sh -f json src/*.py > report.json

# Only show errors
./codesnake-launcher.sh -s error mycode.py

# Enhanced mode with all options
./codesnake-launcher.sh -c .codesnake.json -f json -s warning src/*.py
```

**Utility Commands:**
```bash
# Create fresh virtual environment
./codesnake-launcher.sh --create-venv

# Run tests
./codesnake-launcher.sh --test

# Show banner
./codesnake-launcher.sh --banner

# Show version
./codesnake-launcher.sh -v

# Run without venv (use system Python)
./codesnake-launcher.sh --no-venv mycode.py
```

**When to use:** Advanced usage, CI/CD integration, custom workflows

---

## 🔧 Virtual Environment Management

### What is `codesnake-venv`?

A Python virtual environment that:
- Isolates CodeSnake's dependencies
- Prevents conflicts with system Python
- Allows optional tool installation
- Makes the setup portable

### Location
```
your-project/
├── codesnake-venv/          ← Virtual environment
│   ├── bin/
│   │   ├── activate         ← Activation script
│   │   └── python          ← Python interpreter
│   └── lib/
├── codesnake.py
├── codesnake.sh
└── ...
```

### Manual Activation

```bash
# Activate
source codesnake-venv/bin/activate

# Now you can use CodeSnake directly
codesnake check mycode.py

# Deactivate when done
deactivate
```

### Recreate Virtual Environment

```bash
# Method 1: Using launcher
./codesnake-launcher.sh --create-venv

# Method 2: Using setup
./setup.sh

# Method 3: Manual
rm -rf codesnake-venv
python3 -m venv codesnake-venv
source codesnake-venv/bin/activate
pip install --upgrade pip
```

---

## 📋 Complete Workflow Examples

### First Time Setup

```bash
# 1. Run setup
./setup.sh

# 2. Try the example
./codesnake.sh test/example_bad_code.py

# 3. Check your own code
./codesnake.sh your_code.py
```

### Daily Usage

```bash
# Quick check before commit
./codesnake.sh $(git diff --name-only | grep '.py$')

# Check entire project
./codesnake.sh src/**/*.py

# Enhanced mode with config
./codesnake-launcher.sh -c .codesnake.json src/
```

### CI/CD Integration

```bash
# Generate JSON report
./codesnake-launcher.sh -f json src/ > codesnake-report.json

# GitHub Actions format
./codesnake-launcher.sh -f github src/

# Only fail on errors
./codesnake-launcher.sh -s error src/ || exit 1
```

### Development Workflow

```bash
# Run tests
./codesnake-launcher.sh --test

# Check specific severity
./codesnake-launcher.sh -s warning mycode.py

# Use without venv (testing system Python)
./codesnake-launcher.sh --no-venv mycode.py
```

---

## 🎯 Choosing the Right Script

| Scenario | Use This | Command |
|----------|----------|---------|
| First time setup | `setup.sh` | `./setup.sh` |
| Quick daily check | `codesnake.sh` | `./codesnake.sh file.py` |
| Need config file | `codesnake-launcher.sh` | `./codesnake-launcher.sh -c config.json file.py` |
| CI/CD pipeline | `codesnake-launcher.sh` | `./codesnake-launcher.sh -f json src/` |
| Advanced options | `codesnake-launcher.sh` | `./codesnake-launcher.sh -s error src/` |
| Running tests | `codesnake-launcher.sh` | `./codesnake-launcher.sh --test` |

---

## 🛠️ Troubleshooting

### Script Not Executable

```bash
chmod +x setup.sh codesnake.sh codesnake-launcher.sh
```

### Virtual Environment Issues

```bash
# Recreate venv
./codesnake-launcher.sh --create-venv

# Or manually
rm -rf codesnake-venv
./setup.sh
```

### Python Not Found

```bash
# Check Python installation
which python3
python3 --version

# If not installed, install Python 3.7+
# Ubuntu/Debian: sudo apt install python3 python3-venv
# macOS: brew install python3
```

### Permission Denied

```bash
# Make scripts executable
chmod +x *.sh

# Or run with bash
bash codesnake.sh mycode.py
```

---

## 🔗 Integration Examples

### Git Pre-commit Hook

`.git/hooks/pre-commit`:
```bash
#!/bin/bash
FILES=$(git diff --cached --name-only | grep '.py$')
if [ -n "$FILES" ]; then
    ./codesnake.sh $FILES || exit 1
fi
```

### Makefile Integration

```makefile
check:
	./codesnake.sh src/*.py

check-strict:
	./codesnake-launcher.sh -s error src/

test:
	./codesnake-launcher.sh --test
```

### Cron Job (Daily Checks)

```bash
# Run CodeSnake daily at 2am
0 2 * * * cd /path/to/project && ./codesnake.sh src/ >> logs/codesnake.log 2>&1
```

---

## 📦 Directory Structure

Recommended project structure:

```
codesnake/
├── codesnake-venv/              # Virtual environment (auto-created by the scripts)
├── src/codesnake/               # The package (checker.py, cli.py, banner.py, ...)
├── test/
│   ├── test_codesnake.py        # Test suite
│   └── example_bad_code.py      # Fixture with intentional issues
├── examples/strict.codesnake.json
├── codesnake.sh                 # Simple launcher
├── codesnake-launcher.sh        # Launcher with --test / --create-venv / --no-venv
├── setup.sh                     # One-time setup
├── .codesnake.json              # Default configuration
└── README.md
```

---

## ⚙️ Customization

### Change Virtual Environment Name

Edit the scripts and change:
```bash
VENV_NAME="codesnake-venv"
```
to:
```bash
VENV_NAME="your-venv-name"
```

### Change Default Config

Edit the config path in launcher:
```bash
./codesnake-launcher.sh -c custom-config.json mycode.py
```

### Add Aliases

Add to `~/.bashrc` or `~/.zshrc`:
```bash
alias cs='./codesnake.sh'
alias cse='./codesnake-launcher.sh -e'
alias cst='./codesnake-launcher.sh --test'
```

Then use:
```bash
cs mycode.py
cse -c strict.json src/
cst
```

---

## 📝 Summary

1. **First Time:** Run `./setup.sh`
2. **Daily Use:** Use `./codesnake.sh file.py`
3. **Advanced:** Use `./codesnake-launcher.sh` with options
4. **Virtual Env:** Auto-managed, recreate with `--create-venv`
5. **Help:** Run `./codesnake-launcher.sh --help`

**Pro Tip:** Create shell aliases for even faster access! 🚀

---

**Happy Coding with CodeSnake! 🐍✨**
