#!/usr/bin/env python3
"""
Test suite for CodeSnake - the semantic code checker.
Run with: python test/test_codesnake.py

🐍 Testing CodeSnake's bite!
"""

import unittest
import sys
from pathlib import Path

# Add src directory to path to import codesnake
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from codesnake import SemanticChecker, Issue


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


def run_tests():
    """Run all tests and print results."""
    # Create a test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityChecks))
    suite.addTests(loader.loadTestsFromTestCase(TestBugDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestExceptionHandling))
    suite.addTests(loader.loadTestsFromTestCase(TestComplexityChecks))
    suite.addTests(loader.loadTestsFromTestCase(TestImportChecks))
    suite.addTests(loader.loadTestsFromTestCase(TestPerformanceChecks))
    suite.addTests(loader.loadTestsFromTestCase(TestStyleChecks))
    suite.addTests(loader.loadTestsFromTestCase(TestSyntaxErrors))
    suite.addTests(loader.loadTestsFromTestCase(TestMultipleIssues))
    
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
