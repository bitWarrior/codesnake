# CodeSnake Test Directory 🧪

This directory contains all test files and example code for CodeSnake.

## Contents

### Test Files

**test_codesnake.py** - Main test suite
- 17 comprehensive unit tests
- Tests all major features:
  - Security checks (eval, exec, subprocess)
  - Bug detection (mutable defaults)
  - Exception handling (bare except, empty blocks)
  - Complexity analysis (parameters, length, cyclomatic)
  - Import checks (wildcard imports)
  - Performance patterns (range/len)
  - Style checks (is True/False)
  - Syntax error handling
  - Multiple issue detection

### Example Code

**example_bad_code.py** - Demonstration file with intentional issues
- Contains examples of all issue types
- Used for testing and demonstrations
- Shows what CodeSnake can detect

## Running Tests

### Method 1: Using Launcher
```bash
./codesnake-launcher.sh --test
```

### Method 2: Direct Python
```bash
python test/test_codesnake.py
```

### Method 3: With Virtual Environment
```bash
source codesnake-venv/bin/activate
python test/test_codesnake.py
```

### Method 4: Using Python's unittest
```bash
python -m unittest discover test
```

## Expected Output

```
Tests run: 17
Failures: 0
Errors: 0
Success rate: 100%
```

## Testing the Example

### Check the example file:
```bash
./codesnake.sh test/example_bad_code.py
```

### Expected issues found:
- 4 errors (SEC001, BUG001)
- 8 warnings (EXC001, COMP001-005, IMP001)
- 5 info (EXC002, PERF001, STYLE001, REL002)

## Adding New Tests

1. **Add test case to test_codesnake.py:**
```python
class TestNewFeature(unittest.TestCase):
    def test_new_check(self):
        code = """
        # Your test code here
        """
        checker = SemanticChecker(code)
        issues = checker.analyze()
        
        # Assertions
        self.assertEqual(len(issues), expected_count)
```

2. **Run tests to verify:**
```bash
./codesnake-launcher.sh --test
```

3. **Add example to example_bad_code.py if needed**

## Test Coverage

Current test coverage by category:

- ✅ Security Checks (SEC)
- ✅ Bug Detection (BUG)
- ✅ Exception Handling (EXC)
- ✅ Complexity Analysis (COMP)
- ✅ Import Quality (IMP)
- ✅ Performance (PERF)
- ✅ Style (STYLE)
- ✅ Reliability (REL)
- ✅ Syntax Errors (SYN)

## CI/CD Integration

### GitHub Actions Example
```yaml
- name: Run CodeSnake Tests
  run: |
    ./setup.sh
    ./codesnake-launcher.sh --test
```

### Pre-commit Hook
```bash
#!/bin/bash
# Run tests before commit
./codesnake-launcher.sh --test || exit 1
```

## Directory Structure

```
test/
├── __init__.py              # Package marker
├── README.md                # This file
├── test_codesnake.py        # Test suite
└── example_bad_code.py      # Example with issues
```

## Notes

- Tests are designed to be fast and comprehensive
- All tests should pass on a clean checkout
- Example file intentionally contains bad code
- Tests use the parent directory's codesnake module

---

**Keep the tests passing! 🐍✅**
