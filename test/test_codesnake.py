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
    expand_python_targets,
    issue_fingerprint,
    load_baseline,
    read_python_source,
    run_check,
    write_baseline,
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
        
        # Constant argument is still flagged, at info (not untrusted input)
        sec_issues = [i for i in issues if i.code == 'SEC001']
        self.assertEqual(len(sec_issues), 1)
        self.assertEqual(sec_issues[0].severity, 'info')
        self.assertIn('eval', sec_issues[0].message)

    def test_eval_tainted_input_is_error(self):
        code = """
user_input = input()
result = eval(user_input)
"""
        issues = SemanticChecker(code).analyze()
        sec_issues = [i for i in issues if i.code == 'SEC001']
        self.assertEqual(len(sec_issues), 1)
        self.assertEqual(sec_issues[0].severity, 'error')
        self.assertIn('untrusted', sec_issues[0].message)
    
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

    def test_directory_returns_io001_for_check_file(self):
        issues = check_file('.')
        self.assertTrue(issues)
        self.assertEqual(issues[0].code, 'IO001')

    def test_empty_directory_run_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            buf = StringIO()
            rc = run_check(
                [tmp],
                config=CheckerConfig(),
                output_format='json',
                show_banner=False,
                color=False,
                stream=buf,
            )
            self.assertEqual(rc, 1)
            data = json.loads(buf.getvalue())
            codes = [i['code'] for f in data['files'] for i in f['issues']]
            self.assertIn('IO001', codes)

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
            path.write_text('eval(input())\n', encoding='utf-8')
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
            dirty.write_text('eval(input())\n', encoding='utf-8')
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
            path.write_text('eval(input())\n', encoding='utf-8')
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


class TestUnusedAndScopes(unittest.TestCase):
    """Unused imports/locals/args, shadowing, and COMP005 stores."""

    def test_unused_import(self):
        code = "import os\nx = 1\n"
        issues = SemanticChecker(code).analyze()
        unused = [i for i in issues if i.code == 'IMP002']
        self.assertEqual(len(unused), 1)
        self.assertIn("'os'", unused[0].message)

    def test_used_import_not_flagged(self):
        code = "import os\nprint(os.name)\n"
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'IMP002'], [])

    def test_import_os_path_used_via_os(self):
        code = "import os.path\nprint(os.name)\n"
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'IMP002'], [])

    def test_type_checking_import_not_flagged(self):
        code = """
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from collections import Counter
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'IMP002'], [])

    def test_dunder_all_marks_export_used(self):
        code = """
from json import dumps
__all__ = ['dumps']
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'IMP002'], [])

    def test_unused_local_and_argument(self):
        code = """
def func(unused_arg):
    hidden = 1
    return 2
"""
        issues = SemanticChecker(code).analyze()
        codes = {i.code for i in issues}
        self.assertIn('VAR001', codes)
        self.assertIn('VAR002', codes)

    def test_underscore_and_self_not_flagged(self):
        code = """
def method(self, _skip, used):
    return used
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code in ('VAR001', 'VAR002')], [])

    def test_closure_uses_outer_name(self):
        code = """
def outer():
    captured = 1
    def inner():
        return captured
    return inner
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'VAR001'], [])

    def test_shadowing_enclosing_function(self):
        code = """
def outer():
    value = 1
    def inner():
        value = 2
        return value
    return inner
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual(len([i for i in issues if i.code == 'VAR003']), 1)

    def test_comp005_ignores_method_calls(self):
        code = """
class C:
    def __init__(self):
        self.setup()
        self.helper()
        self.a = 1
        self.b = 2
        self.c = 3
        self.d = 4
        self.e = 5
        self.f = 6
        self.g = 7
        self.h = 8
        self.i = 9
        self.j = 10
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'COMP005'], [])

    def test_comp005_counts_only_stores(self):
        code = """
class C:
    def __init__(self):
        self.a = 1
        self.b = 2
        self.c = 3
        self.d = 4
        self.e = 5
        self.f = 6
        self.g = 7
        self.h = 8
        self.i = 9
        self.j = 10
        self.k = 11
"""
        issues = SemanticChecker(code, config=CheckerConfig(max_instance_vars=10)).analyze()
        self.assertEqual(len([i for i in issues if i.code == 'COMP005']), 1)

    def test_noqa_all_on_line(self):
        code = "eval('1')  # noqa\n"
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'SEC001'], [])

    def test_noqa_specific_code(self):
        code = "eval('1')  # noqa: SEC001\n"
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'SEC001'], [])

    def test_noqa_does_not_suppress_other_codes(self):
        code = "eval('1')  # noqa: IMP002\n"
        issues = SemanticChecker(code).analyze()
        self.assertEqual(len([i for i in issues if i.code == 'SEC001']), 1)

    def test_codesnake_ignore_pragma(self):
        code = "import os  # codesnake: ignore=IMP002\n"
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'IMP002'], [])


class TestDirectoryWalkAndEncoding(unittest.TestCase):
    """Directory expansion, gitignore, encoding cookies, shell constants."""

    def test_directory_walk_finds_nested_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'pkg').mkdir()
            (root / 'pkg' / 'mod.py').write_text('x = 1\n', encoding='utf-8')
            (root / '__pycache__').mkdir()
            (root / '__pycache__' / 'skip.py').write_text('eval(1)\n', encoding='utf-8')
            targets, extras = expand_python_targets([str(root)])
            self.assertEqual(extras, [])
            self.assertEqual(len(targets), 1)
            self.assertTrue(targets[0].endswith('mod.py'))

    def test_gitignore_skips_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / '.gitignore').write_text('ignored.py\nsecret/\n', encoding='utf-8')
            (root / 'kept.py').write_text('x = 1\n', encoding='utf-8')
            (root / 'ignored.py').write_text('eval(1)\n', encoding='utf-8')
            (root / 'secret').mkdir()
            (root / 'secret' / 'bad.py').write_text('eval(1)\n', encoding='utf-8')
            targets, extras = expand_python_targets([str(root)])
            self.assertEqual(extras, [])
            names = {Path(path).name for path in targets}
            self.assertEqual(names, {'kept.py'})

    def test_run_check_on_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'a.py').write_text('x = 1\n', encoding='utf-8')
            (root / 'b.py').write_text('eval(input())\n', encoding='utf-8')
            buf = StringIO()
            rc = run_check(
                [str(root)],
                config=CheckerConfig(),
                output_format='json',
                show_banner=False,
                color=False,
                stream=buf,
            )
            self.assertEqual(rc, 1)
            data = json.loads(buf.getvalue())
            self.assertEqual(data['summary']['files'], 2)
            codes = [i['code'] for f in data['files'] for i in f['issues']]
            self.assertIn('SEC001', codes)

    def test_encoding_cookie(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'latin.py'
            path.write_bytes(b'# coding: latin-1\ncafe = "caf\xe9"\n')
            text = read_python_source(path)
            self.assertIn('caf', text)
            issues = check_file(str(path), config=CheckerConfig())
            self.assertEqual([i.code for i in issues if i.code == 'IO001'], [])

    def test_shell_true_via_local_constant(self):
        code = """
import subprocess
shell = True
subprocess.run("ls", shell=shell)
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual(len([i for i in issues if i.code == 'SEC003']), 1)

    def test_shell_false_constant_not_flagged(self):
        code = """
import subprocess
shell = False
subprocess.run("ls", shell=shell)
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'SEC003'], [])

    def test_shell_true_constant_inside_function(self):
        code = """
import subprocess
def run_it():
    use_shell = True
    subprocess.call("ls", shell=use_shell)
run_it()
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual(len([i for i in issues if i.code == 'SEC003']), 1)


class TestResourceAndPatternChecks(unittest.TestCase):
    """open-without-with, lossy except, duplicate keys, async without await."""

    def test_open_without_with(self):
        code = "f = open('x.txt')\n"
        issues = SemanticChecker(code).analyze()
        self.assertEqual(len([i for i in issues if i.code == 'RES001']), 1)

    def test_open_with_context_manager_ok(self):
        code = "with open('x.txt') as handle:\n    handle.read()\n"
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'RES001'], [])

    def test_lossy_except_raise(self):
        code = """
try:
    risky()
except Exception as exc:
    raise RuntimeError('failed')
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual(len([i for i in issues if i.code == 'EXC005']), 1)

    def test_raise_from_not_lossy(self):
        code = """
try:
    risky()
except Exception as exc:
    raise RuntimeError('failed') from exc
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'EXC005'], [])

    def test_reraise_same_exception_ok(self):
        code = """
try:
    risky()
except Exception as exc:
    raise exc
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'EXC005'], [])

    def test_duplicate_dict_keys(self):
        code = "data = {'a': 1, 'a': 2}\n"
        issues = SemanticChecker(code).analyze()
        self.assertEqual(len([i for i in issues if i.code == 'BUG002']), 1)

    def test_async_without_await(self):
        code = """
async def fetch():
    return 1
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual(len([i for i in issues if i.code == 'ASY001']), 1)

    def test_async_with_await_ok(self):
        code = """
async def fetch():
    return await other()
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'ASY001'], [])

    def test_abstract_async_not_flagged(self):
        code = """
from abc import abstractmethod
class Base:
    @abstractmethod
    async def fetch(self):
        ...
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'ASY001'], [])


class TestTaintAndBandit(unittest.TestCase):
    """Taint-lite for eval/subprocess and optional bandit merge."""

    def test_eval_fstring_tainted(self):
        code = """
name = input()
eval(f'id_{name}')
"""
        issues = SemanticChecker(code).analyze()
        sec = [i for i in issues if i.code == 'SEC001']
        self.assertEqual(len(sec), 1)
        self.assertEqual(sec[0].severity, 'error')

    def test_subprocess_tainted_shell_is_error(self):
        code = """
import subprocess
cmd = input()
subprocess.run(cmd, shell=True)
"""
        issues = SemanticChecker(code).analyze()
        sec = [i for i in issues if i.code == 'SEC003']
        self.assertEqual(len(sec), 1)
        self.assertEqual(sec[0].severity, 'error')

    def test_subprocess_tainted_without_shell(self):
        code = """
import subprocess
cmd = input()
subprocess.run(cmd)
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual(len([i for i in issues if i.code == 'SEC004']), 1)

    def test_request_args_taint(self):
        code = """
def view(request):
    eval(request.args['q'])
"""
        issues = SemanticChecker(code).analyze()
        sec = [i for i in issues if i.code == 'SEC001']
        self.assertEqual(len(sec), 1)
        self.assertEqual(sec[0].severity, 'error')

    def test_bandit_merge(self):
        from codesnake import collect_bandit_issues, Issue as IssueType
        from unittest.mock import patch

        fake = {
            'results': [{
                'issue_severity': 'HIGH',
                'test_id': 'B602',
                'issue_text': 'subprocess with shell=True',
                'line_number': 3,
                'col_offset': 0,
                'filename': '/tmp/fake.py',
            }],
        }
        with patch('codesnake.shutil.which', return_value='/usr/bin/bandit'):
            with patch('codesnake._subprocess.run') as run:
                run.return_value.stdout = json.dumps(fake)
                run.return_value.returncode = 1
                found = collect_bandit_issues(['/tmp/fake.py'])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].code, 'B602')
        self.assertEqual(found[0].source, 'bandit')
        self.assertEqual(found[0].severity, 'error')
        self.assertIsInstance(found[0], IssueType)


class TestCrossFileAndBaseline(unittest.TestCase):
    """Relative import graph, baseline, --staged, end_line, suggestions."""

    def test_relative_import_missing_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / 'pkg'
            pkg.mkdir()
            (pkg / 'b.py').write_text('def exists():\n    return 1\n', encoding='utf-8')
            (pkg / 'a.py').write_text('from .b import missing\n', encoding='utf-8')
            buf = StringIO()
            rc = run_check(
                [str(pkg / 'a.py'), str(pkg / 'b.py')],
                config=CheckerConfig(),
                output_format='json',
                show_banner=False,
                color=False,
                stream=buf,
            )
            self.assertEqual(rc, 1)
            data = json.loads(buf.getvalue())
            codes = [i['code'] for f in data['files'] for i in f['issues']]
            self.assertIn('IMP003', codes)

    def test_relative_import_defined_name_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / 'pkg'
            pkg.mkdir()
            (pkg / 'b.py').write_text('def exists():\n    return 1\n', encoding='utf-8')
            (pkg / 'a.py').write_text('from .b import exists\nprint(exists())\n', encoding='utf-8')
            buf = StringIO()
            rc = run_check(
                [str(pkg / 'a.py'), str(pkg / 'b.py')],
                config=CheckerConfig(),
                output_format='json',
                show_banner=False,
                color=False,
                stream=buf,
            )
            data = json.loads(buf.getvalue())
            codes = [i['code'] for f in data['files'] for i in f['issues']]
            self.assertNotIn('IMP003', codes)
            self.assertEqual(rc, 0)

    def test_relative_import_skipped_if_sibling_not_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / 'pkg'
            pkg.mkdir()
            (pkg / 'b.py').write_text('def exists():\n    return 1\n', encoding='utf-8')
            importer = pkg / 'a.py'
            importer.write_text('from .b import missing\n', encoding='utf-8')
            issues = check_file(str(importer), config=CheckerConfig())
            self.assertEqual([i.code for i in issues if i.code == 'IMP003'], [])

    def test_end_line_and_suggestion_on_eval(self):
        issues = SemanticChecker('eval(input())\n').analyze()
        sec = [i for i in issues if i.code == 'SEC001']
        self.assertTrue(sec)
        self.assertGreaterEqual(sec[0].end_line, sec[0].line)
        self.assertIn('literal_eval', sec[0].suggestion)

    def test_baseline_hides_known_issues(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'app.py'
            path.write_text('eval(input())\n', encoding='utf-8')
            baseline = Path(tmp) / 'baseline.json'
            buf = StringIO()
            rc = run_check(
                [str(path)],
                config=CheckerConfig(),
                output_format='json',
                show_banner=False,
                color=False,
                stream=buf,
                update_baseline=str(baseline),
            )
            self.assertEqual(rc, 1)
            self.assertTrue(baseline.is_file())
            loaded = load_baseline(str(baseline))
            self.assertTrue(loaded)

            buf2 = StringIO()
            rc2 = run_check(
                [str(path)],
                config=CheckerConfig(),
                output_format='json',
                show_banner=False,
                color=False,
                stream=buf2,
                baseline_path=str(baseline),
            )
            self.assertEqual(rc2, 0)
            data = json.loads(buf2.getvalue())
            remaining = [i for f in data['files'] for i in f['issues']]
            self.assertEqual(remaining, [])

    def test_baseline_reports_new_issue(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'app.py'
            path.write_text('x = 1\n', encoding='utf-8')
            baseline = Path(tmp) / 'baseline.json'
            write_baseline([], str(baseline))
            path.write_text('eval(input())\n', encoding='utf-8')
            buf = StringIO()
            rc = run_check(
                [str(path)],
                config=CheckerConfig(),
                output_format='json',
                show_banner=False,
                color=False,
                stream=buf,
                baseline_path=str(baseline),
            )
            self.assertEqual(rc, 1)
            data = json.loads(buf.getvalue())
            codes = [i['code'] for f in data['files'] for i in f['issues']]
            self.assertIn('SEC001', codes)

    def test_missing_baseline_fails_closed(self):
        rc = run_check(
            ['whatever.py'],
            config=CheckerConfig(),
            output_format='json',
            show_banner=False,
            color=False,
            stream=StringIO(),
            baseline_path='/no/such/baseline.json',
        )
        self.assertEqual(rc, 1)

    def test_staged_uses_git_list(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'staged.py'
            path.write_text('eval(input())\n', encoding='utf-8')
            buf = StringIO()
            with patch('codesnake.git_staged_python_files', return_value=([str(path)], None)):
                rc = run_check(
                    [],
                    config=CheckerConfig(),
                    output_format='json',
                    show_banner=False,
                    color=False,
                    stream=buf,
                    staged=True,
                )
            self.assertEqual(rc, 1)
            data = json.loads(buf.getvalue())
            codes = [i['code'] for f in data['files'] for i in f['issues']]
            self.assertIn('SEC001', codes)

    def test_staged_no_files_exits_zero(self):
        from unittest.mock import patch

        with patch('codesnake.git_staged_python_files', return_value=([], None)):
            rc = run_check(
                [],
                config=CheckerConfig(),
                output_format='json',
                show_banner=False,
                color=False,
                stream=StringIO(),
                staged=True,
            )
        self.assertEqual(rc, 0)

    def test_json_includes_end_line_and_suggestion(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'app.py'
            path.write_text('eval(input())\n', encoding='utf-8')
            buf = StringIO()
            run_check(
                [str(path)],
                config=CheckerConfig(),
                output_format='json',
                show_banner=False,
                color=False,
                stream=buf,
            )
            data = json.loads(buf.getvalue())
            issue = data['files'][0]['issues'][0]
            self.assertIn('end_line', issue)
            self.assertIn('suggestion', issue)
            self.assertTrue(issue['suggestion'])


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
