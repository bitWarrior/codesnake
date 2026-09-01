#!/usr/bin/env python3
"""
Test suite for CodeSnake - the semantic code checker.
Run with: python test/test_codesnake.py

🐍 Testing CodeSnake's bite!
"""

import json
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path

# Add src directory to path to import codesnake
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from codesnake import (
    CheckerConfig,
    SemanticChecker,
    check_file,
    run_check,
)


class TestSecurityChecks(unittest.TestCase):
    """Test security-related checks."""
    
    def test_eval_detection(self):
        """Test that eval() usage is detected."""
        code = """
user_input = "1 + 1"
result = eval(user_input)
"""
        checker = SemanticChecker(code)
        issues = checker.analyze()
        
        # Should find SEC001 error
        sec_issues = [i for i in issues if i.code == 'SEC001']
        self.assertEqual(len(sec_issues), 1)
        self.assertEqual(sec_issues[0].severity, 'error')
        self.assertIn('eval', sec_issues[0].message)
    
    def test_exec_detection(self):
        """Test that exec() usage is detected."""
        code = """
code = "print('hello')"
exec(code)
"""
        checker = SemanticChecker(code)
        issues = checker.analyze()
        
        sec_issues = [i for i in issues if i.code == 'SEC001']
        self.assertEqual(len(sec_issues), 1)
        self.assertIn('exec', sec_issues[0].message)
    
    def test_subprocess_shell_true(self):
        """Test that subprocess shell=True is detected."""
        code = """
from subprocess import call
call("ls -la", shell=True)
"""
        checker = SemanticChecker(code)
        issues = checker.analyze()
        
        sec_issues = [i for i in issues if i.code == 'SEC003']
        self.assertEqual(len(sec_issues), 1)
        self.assertIn('shell=True', sec_issues[0].message)

    def test_subprocess_call_attribute(self):
        """Test that subprocess.call(..., shell=True) is detected."""
        code = """
import subprocess
subprocess.call("ls -la", shell=True)
"""
        issues = SemanticChecker(code).analyze()
        sec_issues = [i for i in issues if i.code == 'SEC003']
        self.assertEqual(len(sec_issues), 1)

    def test_subprocess_run_alias(self):
        """Test that import subprocess as sp still resolves shell=True."""
        code = """
import subprocess as sp
sp.run("ls", shell=True)
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual(len([i for i in issues if i.code == 'SEC003']), 1)

    def test_other_object_run_not_flagged(self):
        """Arbitrary .run(shell=True) is not subprocess."""
        code = """
obj.run("ls", shell=True)
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'SEC003'], [])

    def test_pickle_loads_attribute(self):
        """Test pickle.loads() detection."""
        code = """
import pickle
pickle.loads(b"")
"""
        issues = SemanticChecker(code).analyze()
        sec_issues = [i for i in issues if i.code == 'SEC002']
        self.assertEqual(len(sec_issues), 1)
        self.assertEqual(sec_issues[0].severity, 'warning')

    def test_pickle_loads_from_import(self):
        """Test from pickle import loads."""
        code = """
from pickle import loads
loads(b"")
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual(len([i for i in issues if i.code == 'SEC002']), 1)

    def test_json_loads_not_pickle(self):
        """json.loads must not be reported as pickle."""
        code = """
from json import loads
loads("{}")
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'SEC002'], [])

    def test_builtins_eval(self):
        """builtins.eval() is still eval."""
        code = """
import builtins
builtins.eval("1")
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual(len([i for i in issues if i.code == 'SEC001']), 1)


class TestBugDetection(unittest.TestCase):
    """Test bug detection checks."""
    
    def test_mutable_default_list(self):
        """Test that mutable default list is detected."""
        code = """
def append_item(item, lst=[]):
    lst.append(item)
    return lst
"""
        checker = SemanticChecker(code)
        issues = checker.analyze()
        
        bug_issues = [i for i in issues if i.code == 'BUG001']
        self.assertEqual(len(bug_issues), 1)
        self.assertEqual(bug_issues[0].severity, 'error')
        self.assertIn('Mutable', bug_issues[0].message)
    
    def test_mutable_default_dict(self):
        """Test that mutable default dict is detected."""
        code = """
def add_item(key, value, d={}):
    d[key] = value
    return d
"""
        checker = SemanticChecker(code)
        issues = checker.analyze()
        
        bug_issues = [i for i in issues if i.code == 'BUG001']
        self.assertEqual(len(bug_issues), 1)
    
    def test_no_issue_with_none_default(self):
        """Test that None default doesn't trigger issue."""
        code = """
def append_item(item, lst=None):
    if lst is None:
        lst = []
    lst.append(item)
    return lst
"""
        checker = SemanticChecker(code)
        issues = checker.analyze()
        
        bug_issues = [i for i in issues if i.code == 'BUG001']
        self.assertEqual(len(bug_issues), 0)

    def test_kwonly_mutable_default(self):
        """Keyword-only mutable defaults should be flagged."""
        code = """
def f(*, x=[]):
    return x
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual(len([i for i in issues if i.code == 'BUG001']), 1)

    def test_set_call_default(self):
        """set() / list() / dict() call defaults are mutable."""
        code = """
def f(x=set()):
    return x
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual(len([i for i in issues if i.code == 'BUG001']), 1)

    def test_lambda_mutable_default(self):
        """Lambdas share the same default-argument check."""
        code = "f = lambda x=[]: x\n"
        issues = SemanticChecker(code).analyze()
        self.assertEqual(len([i for i in issues if i.code == 'BUG001']), 1)


class TestExceptionHandling(unittest.TestCase):
    """Test exception handling checks."""
    
    def test_bare_except(self):
        """Test that bare except is detected."""
        code = """
try:
    risky_operation()
except:
    pass
"""
        checker = SemanticChecker(code)
        issues = checker.analyze()
        
        exc_issues = [i for i in issues if i.code == 'EXC001']
        self.assertEqual(len(exc_issues), 1)
        self.assertIn('Bare', exc_issues[0].message)
    
    def test_empty_except(self):
        """Test that empty except block is detected."""
        code = """
try:
    risky_operation()
except Exception:
    pass
"""
        checker = SemanticChecker(code)
        issues = checker.analyze()
        
        exc_issues = [i for i in issues if i.code == 'EXC003']
        self.assertEqual(len(exc_issues), 1)
        self.assertIn('Empty', exc_issues[0].message)
    
    def test_raise_without_message(self):
        """Test that raising exception without message is detected."""
        code = """
if error_condition:
    raise Exception()
"""
        checker = SemanticChecker(code)
        issues = checker.analyze()
        
        exc_issues = [i for i in issues if i.code == 'EXC004']
        self.assertEqual(len(exc_issues), 1)
        self.assertIn('message', exc_issues[0].message)


class TestComplexityChecks(unittest.TestCase):
    """Test complexity-related checks."""
    
    def test_too_many_parameters(self):
        """Test that too many parameters is detected."""
        code = """
def func(a, b, c, d, e, f, g, h):
    return a + b + c + d + e + f + g + h
"""
        checker = SemanticChecker(code)
        issues = checker.analyze()
        
        comp_issues = [i for i in issues if i.code == 'COMP001']
        self.assertEqual(len(comp_issues), 1)
        self.assertIn('8 parameters', comp_issues[0].message)
    
    def test_high_complexity(self):
        """Test that high cyclomatic complexity is detected."""
        code = """
def complex_func(x):
    if x > 0:
        if x > 10:
            if x > 20:
                if x > 30:
                    if x > 40:
                        if x > 50:
                            if x > 60:
                                if x > 70:
                                    if x > 80:
                                        if x > 90:
                                            return "high"
    return "low"
"""
        checker = SemanticChecker(code)
        issues = checker.analyze()
        
        comp_issues = [i for i in issues if i.code == 'COMP002']
        self.assertEqual(len(comp_issues), 1)
        self.assertIn('complexity', comp_issues[0].message.lower())

    def test_async_def_too_many_parameters_and_mutable_default(self):
        """async def uses the same function analysis as def."""
        code = """
async def fetch(a, b, c, d, e, f, g, h, lst=[]):
    return lst
"""
        issues = SemanticChecker(code).analyze()
        codes = {i.code for i in issues}
        self.assertIn('COMP001', codes)
        self.assertIn('BUG001', codes)

    def test_nested_function_does_not_inflate_parent_complexity(self):
        """Nested function complexity must not be charged to the parent."""
        code = """
def outer(x):
    def inner(y):
        if y > 0:
            if y > 10:
                if y > 20:
                    if y > 30:
                        if y > 40:
                            if y > 50:
                                if y > 60:
                                    if y > 70:
                                        if y > 80:
                                            if y > 90:
                                                return "high"
        return "low"
    return inner(x)
"""
        checker = SemanticChecker(code)
        issues = checker.analyze()
        self.assertEqual(checker.function_complexity['outer'], 1)
        self.assertGreater(checker.function_complexity['inner'], 10)
        parent_flags = [
            i for i in issues
            if i.code == 'COMP002' and i.line == 2
        ]
        self.assertEqual(parent_flags, [])
        self.assertEqual(len([i for i in issues if i.code == 'COMP002']), 1)

    def test_posonlyargs_counted(self):
        """Positional-only parameters count toward COMP001."""
        code = """
def func(a, b, c, d, e, f, g, /, h, i):
    return a
"""
        issues = SemanticChecker(code).analyze()
        comp_issues = [i for i in issues if i.code == 'COMP001']
        self.assertEqual(len(comp_issues), 1)
        self.assertIn('9 parameters', comp_issues[0].message)


class TestImportChecks(unittest.TestCase):
    """Test import-related checks."""
    
    def test_wildcard_import(self):
        """Test that wildcard imports are detected."""
        code = """
from os import *
"""
        checker = SemanticChecker(code)
        issues = checker.analyze()
        
        imp_issues = [i for i in issues if i.code == 'IMP001']
        self.assertEqual(len(imp_issues), 1)
        self.assertIn('Wildcard', imp_issues[0].message)
    
    def test_normal_import_ok(self):
        """Test that normal imports don't trigger issues."""
        code = """
from os import path
import sys
"""
        checker = SemanticChecker(code)
        issues = checker.analyze()
        
        imp_issues = [i for i in issues if i.code == 'IMP001']
        self.assertEqual(len(imp_issues), 0)


class TestPerformanceChecks(unittest.TestCase):
    """Test performance-related checks."""
    
    def test_range_len_pattern(self):
        """Test that range(len()) pattern is detected."""
        code = """
items = [1, 2, 3, 4, 5]
for i in range(len(items)):
    print(items[i])
"""
        checker = SemanticChecker(code)
        issues = checker.analyze()
        
        perf_issues = [i for i in issues if i.code == 'PERF001']
        self.assertEqual(len(perf_issues), 1)
        self.assertIn('enumerate', perf_issues[0].message)


class TestStyleChecks(unittest.TestCase):
    """Test style-related checks."""
    
    def test_is_true_comparison(self):
        """Test that 'is True' comparison is detected."""
        code = """
flag = True
if flag is True:
    print("yes")
"""
        checker = SemanticChecker(code)
        issues = checker.analyze()
        
        style_issues = [i for i in issues if i.code == 'STYLE001']
        self.assertGreaterEqual(len(style_issues), 1)
        self.assertIn('True/False', style_issues[0].message)


class TestSyntaxErrors(unittest.TestCase):
    """Test handling of syntax errors."""
    
    def test_syntax_error(self):
        """Test that syntax errors are reported."""
        code = """
def broken(:
    pass
"""
        checker = SemanticChecker(code)
        issues = checker.analyze()
        
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].code, 'SYN001')
        self.assertEqual(issues[0].severity, 'error')


class TestMultipleIssues(unittest.TestCase):
    """Test detection of multiple issues in the same file."""
    
    def test_multiple_issues(self):
        """Test that multiple issues are all detected."""
        code = """
def bad_function(a, b, c, d, e, f, g, h, lst=[]):
    result = eval(input())
    try:
        risky()
    except:
        pass
    return result
"""
        checker = SemanticChecker(code)
        issues = checker.analyze()
        
        # Should find multiple issues
        self.assertGreaterEqual(len(issues), 3)
        
        # Check we have issues from different categories
        codes = {i.code for i in issues}
        self.assertIn('SEC001', codes)  # eval
        self.assertIn('BUG001', codes)  # mutable default
        self.assertIn('EXC001', codes)  # bare except


class TestConfig(unittest.TestCase):
    """Configuration is the source of thresholds and category toggles."""

    def test_max_function_params_from_config(self):
        code = """
def func(a, b, c):
    return a
"""
        default_issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in default_issues if i.code == 'COMP001'], [])

        strict = CheckerConfig(max_function_params=2)
        issues = SemanticChecker(code, config=strict).analyze()
        self.assertEqual(len([i for i in issues if i.code == 'COMP001']), 1)
        self.assertIn('max recommended: 2', issues[0].message)

    def test_max_complexity_from_config(self):
        code = """
def func(x):
    if x:
        if x:
            return 1
    return 0
"""
        default_issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in default_issues if i.code == 'COMP002'], [])

        strict = CheckerConfig(max_complexity=1)
        issues = SemanticChecker(code, config=strict).analyze()
        self.assertEqual(len([i for i in issues if i.code == 'COMP002']), 1)

    def test_check_security_false_skips_eval(self):
        code = "eval('1')\n"
        issues = SemanticChecker(code, config=CheckerConfig(check_security=False)).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'SEC001'], [])

    def test_config_roundtrip_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'cfg.json'
            original = CheckerConfig(max_function_length=40, report_info=False)
            original.to_file(str(path))
            loaded = CheckerConfig.from_file(str(path))
            self.assertEqual(loaded.max_function_length, 40)
            self.assertFalse(loaded.report_info)
            self.assertTrue(loaded.check_security)


class TestFailClosed(unittest.TestCase):
    """Missing files, I/O errors, and syntax errors must not look clean."""

    def test_missing_file_returns_io001(self):
        issues = check_file('/no/such/codesnake_file.py')
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].code, 'IO001')
        self.assertEqual(issues[0].severity, 'error')

    def test_missing_file_exit_code(self):
        buf = StringIO()
        rc = run_check(
            ['/no/such/codesnake_file.py'],
            config=CheckerConfig(),
            output_format='text',
            show_banner=False,
            color=False,
            stream=buf,
        )
        self.assertEqual(rc, 1)
        output = buf.getvalue()
        self.assertIn('not found', output.lower())
        self.assertNotIn('No issues found', output)

    def test_directory_returns_io001(self):
        issues = check_file('.')
        self.assertTrue(issues)
        self.assertEqual(issues[0].code, 'IO001')
        self.assertEqual(run_check(
            ['.'],
            config=CheckerConfig(),
            output_format='json',
            show_banner=False,
            color=False,
            stream=StringIO(),
        ), 1)

    def test_syntax_error_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'broken.py'
            path.write_text('def broken(:\n    pass\n', encoding='utf-8')
            buf = StringIO()
            rc = run_check(
                [str(path)],
                config=CheckerConfig(),
                output_format='json',
                show_banner=False,
                color=False,
                stream=buf,
            )
            self.assertEqual(rc, 1)
            data = json.loads(buf.getvalue())
            codes = [i['code'] for f in data['files'] for i in f['issues']]
            self.assertIn('SYN001', codes)


class TestCLIOutput(unittest.TestCase):
    """Multi-file checking and output formats."""

    def test_json_format_contains_sec001(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'bad.py'
            path.write_text('eval(1)\n', encoding='utf-8')
            buf = StringIO()
            rc = run_check(
                [str(path)],
                config=CheckerConfig(),
                output_format='json',
                show_banner=False,
                color=False,
                stream=buf,
            )
            self.assertEqual(rc, 1)
            data = json.loads(buf.getvalue())
            codes = [i['code'] for f in data['files'] for i in f['issues']]
            self.assertIn('SEC001', codes)
            self.assertEqual(data['summary']['errors'], 1)

    def test_multiple_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            clean = Path(tmp) / 'clean.py'
            dirty = Path(tmp) / 'dirty.py'
            clean.write_text('x = 1\n', encoding='utf-8')
            dirty.write_text('eval(1)\n', encoding='utf-8')
            buf = StringIO()
            rc = run_check(
                [str(clean), str(dirty)],
                config=CheckerConfig(),
                output_format='json',
                show_banner=False,
                color=False,
                stream=buf,
            )
            self.assertEqual(rc, 1)
            data = json.loads(buf.getvalue())
            self.assertEqual(data['summary']['files'], 2)

    def test_severity_filter_hides_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'assert_only.py'
            path.write_text('assert True\n', encoding='utf-8')
            buf = StringIO()
            rc = run_check(
                [str(path)],
                config=CheckerConfig(),
                output_format='json',
                min_severity='error',
                show_banner=False,
                color=False,
                stream=buf,
            )
            self.assertEqual(rc, 0)
            data = json.loads(buf.getvalue())
            codes = [i['code'] for f in data['files'] for i in f['issues']]
            self.assertNotIn('REL002', codes)

    def test_invalid_config_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / 'bad.json'
            cfg.write_text('{not json', encoding='utf-8')
            rc = run_check(
                ['whatever.py'],
                config_path=str(cfg),
                output_format='text',
                show_banner=False,
                color=False,
                stream=StringIO(),
            )
            self.assertEqual(rc, 1)

    def test_github_and_sarif_formats_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'bad.py'
            path.write_text('eval(1)\n', encoding='utf-8')
            for fmt in ('github', 'sarif'):
                buf = StringIO()
                rc = run_check(
                    [str(path)],
                    config=CheckerConfig(),
                    output_format=fmt,
                    show_banner=False,
                    color=False,
                    stream=buf,
                )
                self.assertEqual(rc, 1)
                self.assertIn('SEC001', buf.getvalue())


def run_tests():
    """Run all tests and print results."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for obj in list(globals().values()):
        if (
            isinstance(obj, type)
            and issubclass(obj, unittest.TestCase)
            and obj is not unittest.TestCase
        ):
            suite.addTests(loader.loadTestsFromTestCase(obj))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {(result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100:.1f}%")
    
    return result.wasSuccessful()


if __name__ == '__main__':
    import sys
    success = run_tests()
    sys.exit(0 if success else 1)
