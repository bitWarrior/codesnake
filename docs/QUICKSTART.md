# CodeSnake Quick Start Guide 🐍

**Get started in 60 seconds!**

## Installation & First Run

### 1. Basic Usage

```bash
# Make the script executable

# Check a single file
codesnake check your_code.py

# Check multiple files
codesnake check file1.py file2.py file3.py
```

### 2. Try the Example

```bash
# Run on the provided example with intentional issues
codesnake check test/example_bad_code.py
```

Expected output:
```
🐍 CodeSnake found some issues:

ERROR [SEC001] security: Dangerous use of 'eval()' - can execute arbitrary code
WARNING [COMP001] complexity: Function has 9 parameters (max recommended: 7)
...
Summary: 4 errors, 8 warnings, 5 info
```

## Enhanced Version with Configuration

### 1. Using CodeSnake Enhanced

```bash
# Basic usage
codesnake check test/example_bad_code.py

# With custom configuration
codesnake check --config .codesnake.json test/example_bad_code.py

# JSON output
codesnake check --format json test/example_bad_code.py

# Only show errors
codesnake check --severity error test/example_bad_code.py

# SARIF format (for security scanners)
codesnake check --format sarif test/example_bad_code.py
```

### 2. Create Your Own Configuration

Create `.codesnake.json`:

```json
{
  "max_function_length": 30,
  "max_function_params": 5,
  "max_complexity": 7,
  "check_security": true,
  "check_bugs": true,
  "report_info": false
}
```

## Integration Examples

### 1. Pre-commit Hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash

# Run CodeSnake on staged Python files
FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.py$')

if [ -n "$FILES" ]; then
    echo "🐍 CodeSnake is checking your code..."
    codesnake check $FILES
    
    if [ $? -ne 0 ]; then
        echo "❌ CodeSnake found issues. Fix them before committing."
        exit 1
    fi
    echo "✅ CodeSnake approves! 🎉"
fi
```

```bash
chmod +x .git/hooks/pre-commit
```

### 2. CI/CD Integration (GitHub Actions)

Create `.github/workflows/codesnake.yml`:

```yaml
name: CodeSnake Quality Check

on: [push, pull_request]

jobs:
  codesnake:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      
      - name: Run CodeSnake
        run: |
          codesnake check **/*.py
```

### 3. VS Code Integration

Create `.vscode/tasks.json`:

```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "CodeSnake Check",
            "type": "shell",
            "command": "python",
            "args": [
                "-m", "codesnake", "check",
                "${file}"
            ],
            "problemMatcher": [],
            "presentation": {
                "reveal": "always",
                "panel": "new"
            }
        }
    ]
}
```

Add keyboard shortcut in `.vscode/keybindings.json`:

```json
[
    {
        "key": "ctrl+shift+s",
        "command": "workbench.action.tasks.runTask",
        "args": "CodeSnake Check"
    }
]
```

### 4. Makefile Integration

```makefile
.PHONY: check test clean snake

snake:
	@echo "🐍 CodeSnake is checking your code..."
	@find . -name "*.py" -not -path "./venv/*" | xargs codesnake check

check-strict:
	@echo "🐍 Running strict checks (errors only)..."
	@codesnake check --severity error $(shell find . -name "*.py" -not -path "./venv/*")

test:
	@python test_codesnake.py

clean:
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "__pycache__" -delete
```

Now just run: `make snake`

### 5. Integration with Other Tools

#### Combined Script (check_all.sh)

```bash
#!/bin/bash

echo "🔍 Running comprehensive code analysis..."

# CodeSnake
echo "1/4 🐍 Running CodeSnake..."
codesnake check *.py || true

# Pylint
echo "2/4 🔧 Running pylint..."
pylint *.py --exit-zero || true

# Security check
echo "3/4 🔒 Running security scan..."
bandit -r . || true

# Type checking
echo "4/4 ✅ Running type checker..."
mypy *.py || true

echo "✅ Analysis complete!"
```

#### Python Wrapper

```python
#!/usr/bin/env python3
"""
Combined checker that runs CodeSnake with other tools.
"""

import subprocess
import sys
from pathlib import Path

def run_tool(name, command, emoji="🔍"):
    """Run a tool and capture output."""
    print(f"\n{'='*60}")
    print(f"{emoji} Running {name}...")
    print('='*60)
    
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        shell=True
    )
    
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    
    return result.returncode

def main():
    if len(sys.argv) < 2:
        print("Usage: python check_all.py <file.py>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    tools = [
        ("CodeSnake", f"codesnake check {filepath}", "🐍"),
        ("Pylint", f"pylint {filepath} --exit-zero", "🔧"),
        ("Bandit Security", f"bandit {filepath}", "🔒"),
        ("MyPy Type Check", f"mypy {filepath}", "✅"),
    ]
    
    results = {}
    for name, command, emoji in tools:
        try:
            results[name] = run_tool(name, command, emoji)
        except FileNotFoundError:
            print(f"⚠️  {name} not installed, skipping...")
            results[name] = None
    
    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    for name, code in results.items():
        if code is None:
            status = "⚠️  Not installed"
        elif code == 0:
            status = "✅ Passed"
        else:
            status = f"❌ Failed (exit code: {code})"
        print(f"{name:20} {status}")

if __name__ == '__main__':
    main()
```

## Common Workflows

### Workflow 1: Quick Check Before Commit

```bash
# Check staged files only
git diff --cached --name-only --diff-filter=ACM | grep '\.py$' | xargs codesnake check
```

### Workflow 2: Check Entire Project

```bash
# Find and check all Python files
find . -name "*.py" -not -path "./venv/*" -not -path "./.git/*" | xargs codesnake check
```

### Workflow 3: Generate Report

```bash
# JSON report for further processing
codesnake check --format json src/*.py > code_quality_report.json

# GitHub annotations for CI
codesnake check --format github src/*.py
```

### Workflow 4: Focus on Critical Issues

```bash
# Only errors
codesnake check --severity error *.py

# Errors and warnings only (no info)
codesnake check --severity warning *.py
```

## Customization Examples

### Example 1: Add a Custom Check

```python
# In src/codesnake/checker.py, add this method to SemanticChecker:

def visit_Global(self, node):
    """Check for global variable usage."""
    self.add_issue(
        'warning',
        'globals',
        f"Global variable '{node.names[0]}' - consider using class attributes",
        node,
        'GLOB001'
    )
    self.generic_visit(node)
```

### Example 2: Project-Specific Rules

Create `project_codesnake.py`:

```python
from codesnake import SemanticChecker

class ProjectChecker(SemanticChecker):
    """Custom checker with project-specific rules."""
    
    def visit_Import(self, node):
        """Enforce project-specific import rules."""
        for alias in node.names:
            # Example: Discourage deprecated modules
            if alias.name in ('optparse', 'imp'):
                self.add_issue(
                    'warning',
                    'deprecated',
                    f"Module '{alias.name}' is deprecated",
                    node,
                    'PROJ001'
                )
        
        super().visit_Import(node)
```

## Tips & Best Practices

### 1. Start Conservative

Begin with a relaxed configuration and gradually tighten:

```json
{
  "max_function_length": 100,
  "max_complexity": 15,
  "report_info": false
}
```

Then adjust based on your codebase:

```json
{
  "max_function_length": 50,
  "max_complexity": 10,
  "report_info": true
}
```

### 2. Progressive Adoption

```bash
# Week 1: Just security issues
codesnake check --severity error

# Week 2: Add critical bugs
codesnake check --severity error --config strict-security.json

# Week 4: Full checks
codesnake check --config full-checks.json
```

### 3. Team Workflows

```bash
# Team lead: Generate baseline
codesnake check --format json src/ > baseline.json

# Developers: Compare against baseline
diff <(codesnake check --format json src/) baseline.json
```

## Troubleshooting

### Issue: Too Many False Positives

**Solution**: Adjust configuration thresholds:

```json
{
  "check_style": false,
  "max_complexity": 15,
  "report_info": false
}
```

### Issue: Need More Checks

**Solution**: Extend CodeSnake with custom rules or combine with other tools:

```bash
# Run CodeSnake + Bandit for comprehensive security
codesnake check your_code.py && bandit -r your_code.py
```

### Issue: Slow on Large Codebase

**Solution**: Use parallel processing:

```python
from multiprocessing import Pool
from pathlib import Path

def check_file(filepath):
    # ... your check logic
    pass

if __name__ == '__main__':
    files = list(Path('src').rglob('*.py'))
    with Pool() as pool:
        results = pool.map(check_file, files)
```

## Next Steps

1. ✅ **Run CodeSnake** on your existing code
2. 📝 **Create a `.codesnake.json`** configuration
3. 🔗 **Add a pre-commit hook** to your repo
4. 🚀 **Integrate into CI/CD** pipeline
5. 🎨 **Customize** with project-specific rules
6. 📚 **Read the full README.md** for advanced usage

## Quick Reference Card

```bash
# Basic Commands
codesnake check file.py              # Check single file
codesnake check *.py                 # Check all files
codesnake --help               # Show help

# Enhanced Commands
codesnake check file.py --config .codesnake.json  # With config
codesnake check file.py --format json             # JSON output
codesnake check file.py --severity error          # Errors only
codesnake check file.py --no-color                # No colors

# Common Patterns
find . -name "*.py" | xargs codesnake check        # Check project
git diff --name-only | grep .py | xargs codesnake check  # Check changes
```

## Resources

- 📘 **Full Documentation**: See README.md
- 🧪 **Test Suite**: Run `python test_codesnake.py`
- 🐛 **Report Issues**: Use the issue tracker
- 💡 **Extend CodeSnake**: Check the customization section

---

**Happy Coding! 🐍✨**

*CodeSnake is here to help you write better Python!*
