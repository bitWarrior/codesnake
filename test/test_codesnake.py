#!/usr/bin/env python3
"""
Test suite for CodeSnake - the semantic code checker.
Run with: python test/test_codesnake.py

🐍 Testing CodeSnake's bite!
"""

import contextlib
import json
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path

# Add src/ to the path so the codesnake package imports without an install
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

    def test_overlapping_file_and_directory_targets_dedupe(self):
        """'pkg/a.py pkg/' is one file: the relative spelling and the resolved
        path the directory walk yields must not both be analyzed."""
        import os
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'pkg').mkdir()
            (root / 'pkg' / 'a.py').write_text('eval(input())\n', encoding='utf-8')

            old_cwd = os.getcwd()
            os.chdir(root)
            try:
                targets, _ = expand_python_targets(['pkg/a.py', 'pkg'])
                self.assertEqual(len(targets), 1, targets)
                targets, _ = expand_python_targets(['pkg', 'pkg/a.py'])
                self.assertEqual(len(targets), 1, targets)

                out = StringIO()
                run_check(['pkg/a.py', 'pkg'], stream=out,
                          color=False, show_banner=False)
            finally:
                os.chdir(old_cwd)
            self.assertEqual(out.getvalue().count('SEC001'), 1)

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

    def _git_repo(self, tmp):
        """A real git repo; skip if git is unavailable."""
        import subprocess
        root = Path(tmp).resolve()
        try:
            for cmd in (['git', 'init', '-q', '.'],
                        ['git', 'config', 'user.email', 't@e.st'],
                        ['git', 'config', 'user.name', 'test']):
                subprocess.run(cmd, cwd=root, check=True, capture_output=True, timeout=30)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            self.skipTest('git not available')
        return root

    def _git(self, root, *args):
        import subprocess
        subprocess.run(['git', *args], cwd=root, check=True, capture_output=True, timeout=30)

    def test_symlink_escaping_the_root_is_not_followed(self):
        """`src/x.py -> /outside/secret` must not be read.

        os.walk does not follow directory symlinks, but a file symlink is
        yielded and would be read through, and a syntax error prints the
        offending line into the report.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'project' / 'src').mkdir(parents=True)
            outside = root / 'outside'
            outside.mkdir()
            secret = outside / 'secret.txt'
            secret.write_text('DB_PASSWORD = hunter2!$nope\n', encoding='utf-8')
            (root / 'project' / 'src' / 'real.py').write_text('x = 1\n', encoding='utf-8')
            try:
                (root / 'project' / 'src' / 'leaked.py').symlink_to(secret)
            except (OSError, NotImplementedError):
                self.skipTest('symlinks unavailable')

            targets, _ = expand_python_targets([str(root / 'project' / 'src')])
            self.assertEqual({Path(t).name for t in targets}, {'real.py'})

    def test_symlink_staying_inside_the_root_is_followed(self):
        """Containment, not a blanket ban on symlinks."""
        from codesnake.checker import iter_python_files
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'src' / 'pkg').mkdir(parents=True)
            target = root / 'src' / 'pkg' / 'shared.py'
            target.write_text('x = 1\n', encoding='utf-8')
            try:
                (root / 'src' / 'alias.py').symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest('symlinks unavailable')

            found = {p.name for p in iter_python_files(root / 'src')}
            self.assertEqual(found, {'shared.py', 'alias.py'})

    def test_escaping_symlink_content_never_reaches_the_report(self):
        """The disclosure that made this worth fixing: the source line is printed."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'project' / 'src').mkdir(parents=True)
            secret = root / 'secret.env'
            secret.write_text('DEBUG = False\nDB_PASSWORD = hunter2!$nope\n', encoding='utf-8')
            (root / 'project' / 'src' / 'ok.py').write_text('x = 1\n', encoding='utf-8')
            try:
                (root / 'project' / 'src' / 'config.py').symlink_to(secret)
            except (OSError, NotImplementedError):
                self.skipTest('symlinks unavailable')

            out = StringIO()
            run_check([str(root / 'project' / 'src')], stream=out,
                      color=False, show_banner=False)
            self.assertNotIn('DB_PASSWORD', out.getvalue())
            self.assertNotIn('hunter2', out.getvalue())

    def test_committed_file_is_not_hidden_by_gitignore(self):
        """git ignores .gitignore for tracked files; so must the walk.

        Otherwise a PR can add a file, gitignore it, `git add -f` it, and the
        default directory walk never sees it.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = self._git_repo(tmp)
            (root / 'src').mkdir()
            (root / 'src' / 'good.py').write_text('x = 1\n', encoding='utf-8')
            (root / 'src' / 'evil.py').write_text('eval(input())\n', encoding='utf-8')
            (root / '.gitignore').write_text('src/evil.py\n', encoding='utf-8')
            self._git(root, 'add', '.gitignore', 'src/good.py')
            self._git(root, 'add', '-f', 'src/evil.py')
            self._git(root, 'commit', '-q', '-m', 'x')

            targets, _ = expand_python_targets([str(root / 'src')])
            self.assertEqual({Path(t).name for t in targets}, {'good.py', 'evil.py'})

    def test_committed_file_inside_ignored_directory_is_walked(self):
        """An ignored directory holding a tracked file must not be pruned."""
        with tempfile.TemporaryDirectory() as tmp:
            root = self._git_repo(tmp)
            (root / 'src' / 'hidden').mkdir(parents=True)
            (root / 'src' / 'good.py').write_text('x = 1\n', encoding='utf-8')
            (root / 'src' / 'hidden' / 'evil.py').write_text('eval(input())\n', encoding='utf-8')
            (root / '.gitignore').write_text('src/hidden/\n', encoding='utf-8')
            self._git(root, 'add', '.gitignore', 'src/good.py')
            self._git(root, 'add', '-f', 'src/hidden/evil.py')
            self._git(root, 'commit', '-q', '-m', 'x')

            targets, _ = expand_python_targets([str(root / 'src')])
            self.assertEqual({Path(t).name for t in targets}, {'good.py', 'evil.py'})

    def test_untracked_gitignored_files_are_still_skipped(self):
        """The exemption is for tracked files only — build output stays ignored."""
        with tempfile.TemporaryDirectory() as tmp:
            root = self._git_repo(tmp)
            (root / 'src' / 'build').mkdir(parents=True)
            (root / 'src' / 'good.py').write_text('x = 1\n', encoding='utf-8')
            (root / 'src' / 'generated.py').write_text('eval(input())\n', encoding='utf-8')
            (root / 'src' / 'build' / 'gen.py').write_text('eval(input())\n', encoding='utf-8')
            (root / '.gitignore').write_text('src/generated.py\nsrc/build/\n', encoding='utf-8')
            self._git(root, 'add', '.gitignore', 'src/good.py')
            self._git(root, 'commit', '-q', '-m', 'x')

            targets, _ = expand_python_targets([str(root / 'src')])
            self.assertEqual({Path(t).name for t in targets}, {'good.py'})

    def test_no_ignore_includes_gitignored_files(self):
        """A committed-but-ignored file must be visible to a CI directory walk."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / '.gitignore').write_text('ignored.py\nsecret/\n', encoding='utf-8')
            (root / 'kept.py').write_text('x = 1\n', encoding='utf-8')
            (root / 'ignored.py').write_text('eval(1)\n', encoding='utf-8')
            (root / 'secret').mkdir()
            (root / 'secret' / 'bad.py').write_text('eval(1)\n', encoding='utf-8')
            targets, extras = expand_python_targets(
                [str(root)], respect_gitignore=False,
            )
            self.assertEqual(extras, [])
            names = {Path(path).name for path in targets}
            self.assertEqual(names, {'kept.py', 'ignored.py', 'bad.py'})

    def test_no_ignore_still_skips_venvs_and_caches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'kept.py').write_text('x = 1\n', encoding='utf-8')
            (root / '__pycache__').mkdir()
            (root / '__pycache__' / 'skip.py').write_text('eval(1)\n', encoding='utf-8')
            (root / '.venv').mkdir()
            (root / '.venv' / 'lib.py').write_text('eval(1)\n', encoding='utf-8')
            targets, extras = expand_python_targets(
                [str(root)], respect_gitignore=False,
            )
            self.assertEqual(extras, [])
            self.assertEqual([Path(path).name for path in targets], ['kept.py'])

    def test_run_check_no_ignore_reports_gitignored_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / '.gitignore').write_text('evil.py\n', encoding='utf-8')
            (root / 'ok.py').write_text('x = 1\n', encoding='utf-8')
            (root / 'evil.py').write_text('eval(input())\n', encoding='utf-8')
            skipped = StringIO()
            self.assertEqual(
                run_check(
                    [str(root)],
                    config=CheckerConfig(),
                    output_format='json',
                    show_banner=False,
                    color=False,
                    stream=skipped,
                ),
                0,
            )
            found = StringIO()
            rc = run_check(
                [str(root)],
                config=CheckerConfig(),
                output_format='json',
                show_banner=False,
                color=False,
                stream=found,
                no_ignore=True,
            )
            self.assertEqual(rc, 1)
            codes = [
                issue['code']
                for file_report in json.loads(found.getvalue())['files']
                for issue in file_report['issues']
            ]
            self.assertIn('SEC001', codes)

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
        with patch('codesnake.checker.shutil.which', return_value='/usr/bin/bandit'):
            with patch('codesnake.checker._subprocess.run') as run:
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
            with patch('codesnake.checker.git_staged_python_files', return_value=([str(path)], None)):
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

        with patch('codesnake.checker.git_staged_python_files', return_value=([], None)):
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


class TestScopeOrderingRegressions(unittest.TestCase):
    """Function bodies are analyzed after the enclosing scope is fully bound."""

    def test_closure_referencing_later_assignment(self):
        code = """
def f():
    def g():
        return x
    x = 1
    return g
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'VAR001'], [])

    def test_lambda_referencing_later_assignment(self):
        code = """
def f():
    cb = lambda: value
    value = 3
    return cb
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'VAR001'], [])

    def test_deeply_nested_closure_chain(self):
        code = """
def a():
    def b():
        def c():
            return outer_name
        return c
    outer_name = 1
    return b
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'VAR001'], [])

    def test_unused_local_still_reported_with_nested_function(self):
        code = """
def f():
    def g():
        return 1
    unused = 2
    return g
"""
        issues = SemanticChecker(code).analyze()
        names = [i.message for i in issues if i.code == 'VAR001']
        self.assertEqual(names, ["Unused local variable 'unused'"])

    def test_decorator_uses_enclosing_argument(self):
        code = """
import functools
def decorator(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code in ('VAR001', 'VAR002')], [])

    def test_method_body_sees_module_import(self):
        code = """
import os
class C:
    def path(self):
        return os.getcwd()
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'IMP002'], [])

    def test_type_checking_state_preserved_in_deferred_body(self):
        code = """
from typing import TYPE_CHECKING
def f():
    if TYPE_CHECKING:
        import os
    return 1
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'IMP002'], [])

    def test_unused_import_inside_function(self):
        code = """
def f():
    import os
    return 1
"""
        issues = SemanticChecker(code).analyze()
        imp = [i for i in issues if i.code == 'IMP002']
        self.assertEqual(len(imp), 1)
        self.assertEqual(imp[0].line, 3)

    def test_used_import_inside_function_ok(self):
        code = """
def f():
    import os
    return os.sep
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'IMP002'], [])

    def test_analyze_is_idempotent(self):
        checker = SemanticChecker("import os\n")
        first = checker.analyze()
        second = checker.analyze()
        self.assertEqual(len(first), 1)
        self.assertEqual(len(first), len(second))


class TestSecurityCoverageRegressions(unittest.TestCase):

    def test_os_system_tainted_is_error(self):
        code = """
import os
cmd = input()
os.system(cmd)
"""
        issues = SemanticChecker(code).analyze()
        sec = [i for i in issues if i.code == 'SEC003']
        self.assertEqual(len(sec), 1)
        self.assertEqual(sec[0].severity, 'error')
        self.assertIn('os.system', sec[0].message)

    def test_os_system_constant_is_warning(self):
        code = """
import os
os.system("ls -la")
"""
        issues = SemanticChecker(code).analyze()
        sec = [i for i in issues if i.code == 'SEC003']
        self.assertEqual(len(sec), 1)
        self.assertEqual(sec[0].severity, 'warning')

    def test_from_os_import_system_alias(self):
        code = """
from os import system as run_it
import sys
run_it(sys.argv[1])
"""
        issues = SemanticChecker(code).analyze()
        sec = [i for i in issues if i.code == 'SEC003']
        self.assertEqual(len(sec), 1)
        self.assertEqual(sec[0].severity, 'error')

    def test_os_popen_and_getoutput(self):
        code = """
import os, subprocess
os.popen("ls")
subprocess.getoutput("ls")
subprocess.getstatusoutput("ls")
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual(len([i for i in issues if i.code == 'SEC003']), 3)

    def test_check_output_shell_true_tainted(self):
        code = """
import subprocess
cmd = input()
subprocess.check_output(cmd, shell=True)
subprocess.check_call(cmd, shell=True)
"""
        issues = SemanticChecker(code).analyze()
        sec = [i for i in issues if i.code == 'SEC003']
        self.assertEqual(len(sec), 2)
        self.assertTrue(all(i.severity == 'error' for i in sec))

    def test_constant_reassigned_to_dynamic_value_is_error(self):
        code = """
x = "1+1"
x = fetch()
eval(x)
"""
        issues = SemanticChecker(code).analyze()
        sec = [i for i in issues if i.code == 'SEC001']
        self.assertEqual(len(sec), 1)
        self.assertEqual(sec[0].severity, 'error')

    def test_constant_still_downgraded_when_not_reassigned(self):
        code = """
x = "1+1"
eval(x)
"""
        issues = SemanticChecker(code).analyze()
        sec = [i for i in issues if i.code == 'SEC001']
        self.assertEqual(sec[0].severity, 'info')

    def test_augassign_propagates_taint(self):
        code = """
cmd = "echo "
cmd += input()
eval(cmd)
"""
        issues = SemanticChecker(code).analyze()
        sec = [i for i in issues if i.code == 'SEC001']
        self.assertEqual(len(sec), 1)
        self.assertEqual(sec[0].severity, 'error')

    def test_shell_constant_reassigned_to_false(self):
        code = """
import subprocess
shell = True
shell = False
subprocess.run("ls", shell=shell)
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'SEC003'], [])


class TestRuleAndOutputRegressions(unittest.TestCase):

    def test_is_zero_not_style001(self):
        code = """
def f(x):
    if x is 0:
        return 1
    if x is None:
        return 2
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual([i.code for i in issues if i.code == 'STYLE001'], [])

    def test_is_true_still_style001(self):
        issues = SemanticChecker("def f(x):\n    return x is True\n").analyze()
        self.assertEqual(len([i for i in issues if i.code == 'STYLE001']), 1)

    def test_except_star_handlers_checked(self):
        if not hasattr(__import__('ast'), 'TryStar'):
            self.skipTest('except* requires Python 3.11+')
        code = """
try:
    pass
except* ValueError:
    pass
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual(len([i for i in issues if i.code == 'EXC003']), 1)

    def test_lossy_raise_inside_match(self):
        code = """
try:
    pass
except KeyError:
    match 1:
        case 1:
            raise ValueError("x")
"""
        issues = SemanticChecker(code).analyze()
        self.assertEqual(len([i for i in issues if i.code == 'EXC005']), 1)

    def test_column_is_character_offset_not_bytes(self):
        code = 's = "héllo"; eval(s)\n'
        issues = SemanticChecker(code).analyze()
        sec = [i for i in issues if i.code == 'SEC001'][0]
        self.assertEqual(sec.col, code.index('eval'))
        self.assertEqual(sec.end_col, code.index('eval(s)') + len('eval(s)'))

    def test_text_output_caret_under_non_ascii_line(self):
        from codesnake import format_issue
        code = 's = "héllo"; eval(s)'
        issue = SemanticChecker(code).analyze()[0]
        rendered = format_issue(issue, code, use_color=False)
        caret_line = [ln for ln in rendered.splitlines() if ln.strip() == '^'][0]
        # Two leading spaces of indentation, then col spaces, then the caret.
        self.assertEqual(len(caret_line) - 1, 2 + code.index('eval'))
        self.assertIn(f"Column {code.index('eval') + 1}", rendered)

    def test_sarif_and_github_columns_are_one_based(self):
        from codesnake import format_github_report, format_sarif_report
        issues = SemanticChecker("x = 1; eval('1')\n", filename='a.py').analyze()
        sec = [i for i in issues if i.code == 'SEC001'][0]
        self.assertEqual(sec.col, 7)
        sarif = json.loads(format_sarif_report([sec], '0'))
        region = sarif['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']
        self.assertEqual(region['startColumn'], 8)
        self.assertEqual(region['endColumn'], sec.end_col + 1)
        github = format_github_report([sec])
        self.assertIn(',col=8,', github)

    def test_io_issue_text_has_no_bogus_location(self):
        from codesnake import format_issue
        from codesnake.checker import _io_issue
        rendered = format_issue(_io_issue('missing.py', 'File not found'), '', use_color=False)
        self.assertNotIn('Line 0', rendered)
        self.assertIn('missing.py', rendered)


class TestConfigValidationRegressions(unittest.TestCase):

    def _write(self, tmp, payload):
        path = Path(tmp) / 'cfg.json'
        path.write_text(json.dumps(payload), encoding='utf-8')
        return str(path)

    def test_string_threshold_is_config_error(self):
        from codesnake import ConfigError
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, {"max_complexity": "10"})
            with self.assertRaises(ConfigError) as ctx:
                CheckerConfig.from_file(path)
            self.assertIn('max_complexity', str(ctx.exception))
            self.assertIn('int', str(ctx.exception))

    def test_non_positive_threshold_is_config_error(self):
        from codesnake import ConfigError
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, {"max_complexity": -1, "max_function_length": 0})
            with self.assertRaises(ConfigError) as ctx:
                CheckerConfig.from_file(path)
            message = str(ctx.exception)
            self.assertIn("'max_complexity' must be 1 or greater", message)
            self.assertIn("'max_function_length' must be 1 or greater", message)

    def test_threshold_of_one_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, {"max_complexity": 1})
            self.assertEqual(CheckerConfig.from_file(path).max_complexity, 1)

    def test_bool_field_rejects_int(self):
        from codesnake import ConfigError
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, {"check_security": 1})
            with self.assertRaises(ConfigError):
                CheckerConfig.from_file(path)

    def test_int_field_rejects_bool(self):
        from codesnake import ConfigError
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, {"max_complexity": True})
            with self.assertRaises(ConfigError):
                CheckerConfig.from_file(path)

    def test_unknown_key_warns_but_loads(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, {"max_complexty": 3, "max_complexity": 4})
            err = StringIO()
            with patch('sys.stderr', err):
                cfg = CheckerConfig.from_file(path)
            self.assertEqual(cfg.max_complexity, 4)
            self.assertIn('max_complexty', err.getvalue())

    def test_bad_config_value_exits_one_via_run_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._write(tmp, {"max_function_params": "7"})
            src = Path(tmp) / 'a.py'
            src.write_text('x = 1\n', encoding='utf-8')
            err = StringIO()
            from unittest.mock import patch
            with patch('sys.stderr', err):
                rc = run_check(
                    [str(src)],
                    config_path=cfg,
                    output_format='json',
                    show_banner=False,
                    color=False,
                    stream=StringIO(),
                )
            self.assertEqual(rc, 1)
            self.assertIn('max_function_params', err.getvalue())


class TestStagedAndLauncherRegressions(unittest.TestCase):

    def test_staged_paths_resolved_from_repo_root(self):
        """git prints repo-root-relative paths; they must resolve from a subdir."""
        import os
        from unittest.mock import patch
        from codesnake import git_staged_python_files

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'pkg').mkdir()
            (root / 'pkg' / 'mod.py').write_text('x = 1\n', encoding='utf-8')

            class Done:
                def __init__(self, stdout):
                    self.returncode = 0
                    self.stdout = stdout
                    self.stderr = ''

            def fake_run(cmd, **kwargs):
                if cmd[:2] == ['git', 'rev-parse']:
                    return Done(str(root) + '\n')
                return Done('pkg/mod.py\nREADME.md\n')

            old_cwd = os.getcwd()
            os.chdir(root / 'pkg')
            try:
                with patch('codesnake.checker._subprocess.run', side_effect=fake_run):
                    files, error = git_staged_python_files()
            finally:
                os.chdir(old_cwd)
            self.assertIsNone(error)
            self.assertEqual(files, ['mod.py'])

    def test_staged_git_failure_reported(self):
        from unittest.mock import patch
        from codesnake import git_staged_python_files

        class Failed:
            returncode = 128
            stdout = ''
            stderr = 'fatal: not a git repository\n'

        with patch('codesnake.checker._subprocess.run', return_value=Failed()):
            files, error = git_staged_python_files()
        self.assertEqual(files, [])
        self.assertIn('not a git repository', error)

    def test_launcher_handles_paths_with_spaces(self):
        import shutil
        import subprocess
        if not shutil.which('bash'):
            self.skipTest('bash not available')
        launcher = Path(__file__).parent.parent / 'codesnake-launcher.sh'
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'has space' / 'a.py'
            target.parent.mkdir()
            target.write_text('x = 1\n', encoding='utf-8')
            completed = subprocess.run(
                ['bash', str(launcher), '--no-venv', '--no-color', str(target)],
                capture_output=True,
                text=True,
                timeout=60,
            )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn('No issues found', completed.stdout)
        self.assertNotIn('IO001', completed.stdout)

    def test_launcher_missing_option_value_is_usage_error(self):
        import shutil
        import subprocess
        if not shutil.which('bash'):
            self.skipTest('bash not available')
        launcher = Path(__file__).parent.parent / 'codesnake-launcher.sh'
        completed = subprocess.run(
            ['bash', str(launcher), '--no-venv', '--config'],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn('requires a value', completed.stderr)


class TestUnusedNoiseReduction(unittest.TestCase):
    """VAR001/VAR002 exemptions that match how real code is written."""

    def _codes(self, code, filename='<string>', **cfg):
        config = CheckerConfig(**cfg) if cfg else None
        return [i.code for i in SemanticChecker(code, filename, config=config).analyze()]

    def test_loop_target_not_reported(self):
        code = """
def f(items):
    for i in range(3):
        items.append(0)
    for key, value in items:
        items.append(value)
"""
        self.assertNotIn('VAR001', self._codes(code))

    def test_async_loop_target_not_reported(self):
        code = """
async def f(stream):
    async for chunk in stream:
        await stream.ack()
"""
        self.assertNotIn('VAR001', self._codes(code))

    def test_tuple_unpack_partial_use_not_reported(self):
        code = """
def f(pair):
    a, b = pair
    first, *rest = pair
    return a, first
"""
        self.assertNotIn('VAR001', self._codes(code))

    def test_with_target_unpack_not_reported(self):
        code = """
def f(cm):
    with cm as (a, b):
        return a
"""
        self.assertNotIn('VAR001', self._codes(code))

    def test_bare_annotation_not_reported(self):
        code = """
def f():
    x: int
    return 1
"""
        self.assertNotIn('VAR001', self._codes(code))

    def test_plain_assignment_still_reported(self):
        code = """
def f():
    x = 1
    y: int = 2
    return 0
"""
        self.assertEqual(self._codes(code).count('VAR001'), 2)

    def test_augmented_assignment_counts_as_use(self):
        code = """
def f(xs):
    total = 0
    for x in xs:
        total += x
"""
        self.assertNotIn('VAR001', self._codes(code))

    def test_decorated_nested_function_not_reported(self):
        code = """
def setup(app):
    @app.route("/")
    def index():
        return "hi"

    @app.errorhandler(404)
    async def missing(err):
        return str(err)
"""
        self.assertNotIn('VAR001', self._codes(code))

    def test_undecorated_unused_nested_function_still_reported(self):
        code = """
def outer():
    def helper():
        return 1
    return 2
"""
        self.assertEqual(self._codes(code).count('VAR001'), 1)

    def test_lambda_arguments_not_reported(self):
        code = """
import signal
signal.signal(signal.SIGINT, lambda sig, frame: None)
handlers = {"k": lambda event: 0}
"""
        self.assertNotIn('VAR002', self._codes(code))

    def test_dunder_method_arguments_not_reported(self):
        code = """
class Guard:
    def __exit__(self, exc_type, exc, tb):
        return False
    def __setitem__(self, key, value):
        pass
"""
        self.assertNotIn('VAR002', self._codes(code))

    def test_star_args_not_reported(self):
        code = """
def handler(event, *args, **kwargs):
    return event
"""
        self.assertNotIn('VAR002', self._codes(code))

    def test_stub_and_abstract_arguments_not_reported(self):
        code = """
from abc import abstractmethod
class Base:
    @abstractmethod
    def run(self, payload):
        raise NotImplementedError
    def hook(self, payload):
        \"\"\"Override me.\"\"\"
    def other(self, payload):
        ...
"""
        self.assertNotIn('VAR002', self._codes(code))

    def test_ordinary_unused_argument_still_reported(self):
        code = """
def process(record, verbose):
    return record
"""
        codes = self._codes(code)
        self.assertEqual(codes.count('VAR002'), 1)


class TestReliabilityCategory(unittest.TestCase):

    def test_assert_skipped_in_test_files(self):
        code = "def test_x():\n    assert 1 == 1\n"
        for name in ('test_x.py', 'x_test.py', 'conftest.py',
                     'pkg/tests/helpers.py', 'test/fixture.py'):
            issues = SemanticChecker(code, filename=name).analyze()
            self.assertEqual([i.code for i in issues if i.code == 'REL002'], [], name)

    def test_assert_reported_in_regular_files(self):
        code = "def check(v):\n    assert v > 0\n"
        issues = SemanticChecker(code, filename='pkg/validate.py').analyze()
        self.assertEqual(len([i for i in issues if i.code == 'REL002']), 1)

    def test_check_reliability_flag_disables_rel_and_asy(self):
        code = """
async def never_awaits():
    return 1
def check(v):
    assert v
"""
        config = CheckerConfig(check_reliability=False)
        issues = SemanticChecker(code, filename='app.py', config=config).analyze()
        self.assertEqual([i.code for i in issues if i.code in ('REL002', 'ASY001')], [])
        default = SemanticChecker(code, filename='app.py').analyze()
        self.assertEqual(sorted(i.code for i in default if i.code in ('REL002', 'ASY001')),
                         ['ASY001', 'REL002'])

    def test_check_reliability_in_config_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / 'c.json')
            CheckerConfig(check_reliability=False).to_file(path)
            self.assertFalse(CheckerConfig.from_file(path).check_reliability)
            self.assertIn('check_reliability', json.loads(Path(path).read_text()))


class TestTaintPrecision(unittest.TestCase):

    def _sec(self, code, sink_code):
        issues = SemanticChecker(code).analyze()
        return [i for i in issues if i.code == sink_code]

    def test_generic_data_attribute_not_untrusted(self):
        code = """
class Job:
    def run(self):
        return eval(self.data)
"""
        sec = self._sec(code, 'SEC001')
        self.assertEqual(len(sec), 1)
        self.assertNotIn('untrusted', sec[0].message)

    def test_request_receivers_still_tainted(self):
        for receiver in ('request.args["q"]', 'req.json["q"]', 'self.request.GET["q"]',
                         'request.headers.get("X")', 'request.form.get("q")'):
            code = f"def view(self, request, req):\n    eval({receiver})\n"
            sec = self._sec(code, 'SEC001')
            self.assertEqual(len(sec), 1, receiver)
            self.assertEqual(sec[0].severity, 'error', receiver)

    def test_shlex_quote_sanitizes_shell_command(self):
        code = """
import shlex, subprocess
user = input()
subprocess.run("ls " + shlex.quote(user), shell=True)
"""
        sec = self._sec(code, 'SEC003')
        self.assertEqual(len(sec), 1)
        self.assertEqual(sec[0].severity, 'warning')

    def test_int_cast_sanitizes(self):
        code = """
import subprocess
user = input()
subprocess.run(f"sleep {int(user)}", shell=True)
"""
        sec = self._sec(code, 'SEC003')
        self.assertEqual(sec[0].severity, 'warning')

    def test_unsanitized_wrapper_call_still_tainted(self):
        code = """
import subprocess
user = input()
subprocess.run("ls " + str(user), shell=True)
"""
        sec = self._sec(code, 'SEC003')
        self.assertEqual(sec[0].severity, 'error')


class TestFalseNegativeCoverage(unittest.TestCase):
    """Rules that used to miss a legitimate form of the pattern."""

    def _codes(self, code, wanted):
        return [i for i in SemanticChecker(code).analyze() if i.code == wanted]

    def test_taint_reaches_sink_through_keyword_argument(self):
        issues = self._codes(
            "import subprocess\nsubprocess.run(args=input(), shell=True)\n", 'SEC003')
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, 'error')
        self.assertIn('untrusted', issues[0].message)

    def test_taint_propagates_through_a_wrapping_call_keyword(self):
        issues = self._codes(
            "import subprocess\ncmd = ' '.join(sep=input())\n"
            "subprocess.run(cmd, shell=True)\n", 'SEC003')
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, 'error')

    def test_os_system_command_keyword(self):
        issues = self._codes("import os\nos.system(cmd=input())\n", 'SEC003')
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, 'error')

    def test_starred_argument_does_not_claim_position_zero(self):
        """``run(*argv, shell=True)`` says nothing about the command; stay a warning."""
        issues = self._codes(
            "import subprocess\nimport sys\n"
            "subprocess.run(*sys.argv, shell=True)\n", 'SEC003')
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, 'warning')

    def test_lossy_raise_in_nested_try_else(self):
        code = """
def f():
    try:
        pass
    except ValueError:
        try:
            pass
        except OSError:
            pass
        else:
            raise RuntimeError("lost")
"""
        self.assertEqual(len(self._codes(code, 'EXC005')), 1)

    def test_lossy_raise_in_nested_handler_reported_once(self):
        """The inner handler is checked when visit_Try reaches it, not twice."""
        code = """
def f():
    try:
        pass
    except ValueError:
        try:
            pass
        except OSError:
            raise RuntimeError("lost")
"""
        self.assertEqual(len(self._codes(code, 'EXC005')), 1)

    def test_broad_except_matches_tuple_and_dotted(self):
        for clause in ('Exception', '(ValueError, Exception)', 'builtins.Exception'):
            code = f"import builtins\ntry:\n    f()\nexcept {clause}:\n    g()\n"
            self.assertEqual(len(self._codes(code, 'EXC002')), 1, clause)

    def test_narrow_except_still_quiet(self):
        for clause in ('ValueError', '(ValueError, OSError)'):
            code = f"try:\n    f()\nexcept {clause}:\n    g()\n"
            self.assertEqual(self._codes(code, 'EXC002'), [], clause)

    def test_duplicate_tuple_dict_key(self):
        issues = self._codes("D = {(1, 2): 'a', (1, 2): 'b'}\n", 'BUG002')
        self.assertEqual(len(issues), 1)
        self.assertIn('(1, 2)', issues[0].message)

    def test_distinct_tuple_keys_are_not_duplicates(self):
        self.assertEqual(self._codes("D = {(1, 2): 'a', (2, 1): 'b'}\n", 'BUG002'), [])

    def test_non_literal_tuple_key_ignored(self):
        self.assertEqual(self._codes("D = {(1, x): 'a', (1, x): 'b'}\n", 'BUG002'), [])

    def test_dunder_all_augmented_and_method_forms_count_as_use(self):
        for line in ("__all__ += ['helper']",
                     "__all__.extend(['helper'])",
                     "__all__.append('helper')"):
            code = f"from .util import helper\n__all__ = []\n{line}\n"
            self.assertEqual(self._codes(code, 'IMP002'), [], line)

    def test_dunder_all_outside_module_scope_is_not_a_use(self):
        code = "from .util import helper\ndef f():\n    __all__ = ['helper']\n    return __all__\n"
        self.assertEqual(len(self._codes(code, 'IMP002')), 1)


class TestResourceOwnership(unittest.TestCase):

    def _res(self, code):
        return [i for i in SemanticChecker(code).analyze() if i.code == 'RES001']

    def test_closing_open_in_with_ok(self):
        code = """
import contextlib
def f(p):
    with contextlib.closing(open(p)) as fh:
        return fh.read()
"""
        self.assertEqual(self._res(code), [])

    def test_enter_context_open_ok(self):
        code = """
from contextlib import ExitStack
def f(paths):
    with ExitStack() as stack:
        handles = [stack.enter_context(open(p)) for p in paths]
        return handles
"""
        self.assertEqual(self._res(code), [])

    def test_helper_wrapping_open_in_with_ok(self):
        code = """
def f(p):
    with wrap(open(p)) as fh:
        return fh.read()
"""
        self.assertEqual(self._res(code), [])

    def test_bare_open_still_reported(self):
        code = """
def f(p):
    fh = open(p)
    return fh.read()
"""
        self.assertEqual(len(self._res(code)), 1)


class TestPackageAndCli(unittest.TestCase):
    """The package layout, version single-sourcing, and unified CLI."""

    def test_version_is_single_sourced(self):
        import codesnake
        from codesnake import banner
        from codesnake._version import __version__
        self.assertEqual(codesnake.__version__, __version__)
        self.assertEqual(banner.VERSION, __version__)

    def test_public_api_exports(self):
        import codesnake
        for name in ('SemanticChecker', 'CheckerConfig', 'ConfigError', 'check_file',
                     'run_check', 'format_sarif_report', 'main', '__version__'):
            self.assertTrue(hasattr(codesnake, name), name)

    def test_check_file_accepts_preread_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'a.py'
            path.write_text('x = 1\n', encoding='utf-8')
            # The on-disk file is clean; the supplied source is not.
            issues = check_file(str(path), source='eval(input())\n')
            self.assertEqual([i.code for i in issues], ['SEC001'])
            self.assertEqual(check_file(str(path)), [])

    def test_cli_shorthand_equals_check(self):
        from codesnake.cli import normalize_argv
        self.assertEqual(normalize_argv(['a.py', '--format', 'json']),
                         ['check', 'a.py', '--format', 'json'])
        self.assertEqual(normalize_argv(['--staged']), ['check', '--staged'])
        self.assertEqual(normalize_argv(['check', 'a.py']), ['check', 'a.py'])
        self.assertEqual(normalize_argv(['--version']), ['--version'])
        self.assertEqual(normalize_argv([]), [])

    def test_cli_main_runs_check_and_returns_exit_code(self):
        from unittest.mock import patch
        from codesnake.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / 'bad.py'
            bad.write_text('eval(input())\n', encoding='utf-8')
            good = Path(tmp) / 'good.py'
            good.write_text('x = 1\n', encoding='utf-8')
            with patch('sys.stdout', StringIO()):
                self.assertEqual(main([str(bad), '--format', 'json']), 1)
                self.assertEqual(main(['check', str(good), '--format', 'json']), 0)

    def test_cli_check_without_files_is_usage_error(self):
        from unittest.mock import patch
        from codesnake.cli import main
        with patch('sys.stderr', StringIO()) as err:
            self.assertEqual(main(['check']), 2)
        self.assertIn('provide files', err.getvalue())

    def test_cli_no_ignore_checks_gitignored_file(self):
        from unittest.mock import patch
        from codesnake.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / '.gitignore').write_text('evil.py\n', encoding='utf-8')
            (root / 'ok.py').write_text('x = 1\n', encoding='utf-8')
            (root / 'evil.py').write_text('eval(input())\n', encoding='utf-8')
            with patch('sys.stdout', StringIO()):
                self.assertEqual(
                    main(['check', str(root), '--format', 'json', '--no-color']),
                    0,
                )
            with patch('sys.stdout', StringIO()) as out:
                rc = main([
                    'check', str(root), '--format', 'json', '--no-color',
                    '--no-ignore',
                ])
            self.assertEqual(rc, 1)
            self.assertIn('SEC001', out.getvalue())

    def test_deeply_nested_file_is_contained_not_fatal(self):
        """One unanalyzable file must not sink the whole run."""
        from codesnake import check_file, run_check
        with tempfile.TemporaryDirectory() as tmp:
            deep = Path(tmp) / 'chain.py'
            deep.write_text(
                'def f():\n    return ' + ' + '.join(str(i) for i in range(4000)) + '\n',
                encoding='utf-8',
            )
            healthy = Path(tmp) / 'ok.py'
            healthy.write_text('import os\n', encoding='utf-8')

            issues = check_file(str(deep))
            self.assertEqual([i.code for i in issues], ['IO001'])
            self.assertIn('nested too deeply', issues[0].message)

            out = StringIO()
            run_check([str(deep), str(healthy)], stream=out, color=False)
            self.assertIn('IMP002', out.getvalue())

    def test_banner_honors_no_color(self):
        from unittest.mock import patch
        from codesnake.banner import print_snake_banner
        with patch('sys.stdout', StringIO()) as plain:
            print_snake_banner(use_color=False)
        self.assertNotIn('\033[', plain.getvalue())
        self.assertIn('Strikes at code problems', plain.getvalue())
        with patch('sys.stdout', StringIO()) as colored:
            print_snake_banner(use_color=True)
        self.assertIn('\033[', colored.getvalue())

    def test_run_check_banner_is_plain_when_color_disabled(self):
        from unittest.mock import patch
        from codesnake import run_check
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'a.py'
            path.write_text('x = 1\n', encoding='utf-8')
            # The banner goes to stdout, not to ``stream``.
            with patch('sys.stdout', StringIO()) as banner:
                run_check([str(path)], stream=StringIO(), color=False, show_banner=True)
            self.assertIn('Strikes at code problems', banner.getvalue())
            self.assertNotIn('\033[', banner.getvalue())

    def test_cli_config_refuses_to_clobber_without_force(self):
        from unittest.mock import patch
        from codesnake.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'c.json'
            out.write_text('{"max_complexity": 99}\n', encoding='utf-8')
            with patch('sys.stderr', StringIO()) as err:
                self.assertEqual(main(['config', '-o', str(out)]), 1)
            self.assertIn('--force', err.getvalue())
            self.assertEqual(json.loads(out.read_text())['max_complexity'], 99)
            with patch('sys.stdout', StringIO()):
                self.assertEqual(main(['config', '-o', str(out), '--force']), 0)
            self.assertEqual(
                json.loads(out.read_text())['max_complexity'],
                CheckerConfig().max_complexity,
            )

    def test_cli_config_writes_defaults(self):
        from unittest.mock import patch
        from codesnake.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'c.json'
            with patch('sys.stdout', StringIO()):
                self.assertEqual(main(['config', '-o', str(out)]), 0)
            self.assertEqual(json.loads(out.read_text()), json.loads(json.dumps(
                __import__('dataclasses').asdict(CheckerConfig()))))

    def test_python_dash_m_entry_point(self):
        import os
        import subprocess
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).parent.parent / 'src'))
        completed = subprocess.run(
            [sys.executable, '-m', 'codesnake', '--version'],
            capture_output=True, text=True, timeout=60, env=env,
        )
        from codesnake import __version__
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(__version__, completed.stdout)


class TestConfigDiscovery(unittest.TestCase):

    def _repo(self, tmp):
        root = Path(tmp).resolve()
        (root / '.git').mkdir()
        (root / 'pkg' / 'sub').mkdir(parents=True)
        return root

    def test_json_found_walking_up_from_subdirectory(self):
        from codesnake import discover_config_file, load_config
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            (root / '.codesnake.json').write_text('{"max_complexity": 3}', encoding='utf-8')
            found = discover_config_file(root / 'pkg' / 'sub')
            self.assertEqual(found, root / '.codesnake.json')
            self.assertEqual(load_config(start=root / 'pkg' / 'sub').max_complexity, 3)

    def test_pyproject_tool_table(self):
        from codesnake import checker, discover_config_file, load_config
        if checker.tomllib is None:
            self.skipTest('tomllib requires Python 3.11+')
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            (root / 'pyproject.toml').write_text(
                '[project]\nname = "x"\n\n[tool.codesnake]\nmax_function_params = 3\n'
                'check_style = false\n', encoding='utf-8')
            self.assertEqual(discover_config_file(root / 'pkg'), root / 'pyproject.toml')
            cfg = load_config(start=root / 'pkg')
            self.assertEqual(cfg.max_function_params, 3)
            self.assertFalse(cfg.check_style)

    def test_pyproject_without_table_is_skipped(self):
        from codesnake import checker, discover_config_file
        if checker.tomllib is None:
            self.skipTest('tomllib requires Python 3.11+')
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            (root / 'pyproject.toml').write_text('[project]\nname = "x"\n', encoding='utf-8')
            self.assertIsNone(discover_config_file(root / 'pkg'))

    def test_json_preferred_over_pyproject_in_same_directory(self):
        from codesnake import checker, load_config
        if checker.tomllib is None:
            self.skipTest('tomllib requires Python 3.11+')
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            (root / '.codesnake.json').write_text('{"max_complexity": 4}', encoding='utf-8')
            (root / 'pyproject.toml').write_text('[tool.codesnake]\nmax_complexity = 9\n', encoding='utf-8')
            self.assertEqual(load_config(start=root).max_complexity, 4)

    def test_search_stops_at_repository_root(self):
        from codesnake import discover_config_file
        with tempfile.TemporaryDirectory() as tmp:
            outer = Path(tmp).resolve()
            (outer / '.codesnake.json').write_text('{"max_complexity": 1}', encoding='utf-8')
            repo = outer / 'repo'
            repo.mkdir()
            (repo / '.git').mkdir()
            (repo / 'pkg').mkdir()
            self.assertIsNone(discover_config_file(repo / 'pkg'))

    def test_explicit_toml_path(self):
        from codesnake import CheckerConfig, ConfigError, checker
        if checker.tomllib is None:
            self.skipTest('tomllib requires Python 3.11+')
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / 'pyproject.toml'
            good.write_text('[tool.codesnake]\nmax_class_methods = 2\n', encoding='utf-8')
            self.assertEqual(CheckerConfig.from_file(str(good)).max_class_methods, 2)
            bad = Path(tmp) / 'bad.toml'
            bad.write_text('[tool.codesnake\n', encoding='utf-8')
            with self.assertRaises(ConfigError):
                CheckerConfig.from_file(str(bad))
            empty = Path(tmp) / 'empty.toml'
            empty.write_text('[project]\n', encoding='utf-8')
            with self.assertRaises(ConfigError):
                CheckerConfig.from_file(str(empty))

    def test_toml_values_are_validated(self):
        from codesnake import CheckerConfig, ConfigError, checker
        if checker.tomllib is None:
            self.skipTest('tomllib requires Python 3.11+')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'pyproject.toml'
            path.write_text('[tool.codesnake]\nmax_complexity = "ten"\n', encoding='utf-8')
            with self.assertRaises(ConfigError):
                CheckerConfig.from_file(str(path))


class TestGitignoreFromRepoRoot(unittest.TestCase):

    def test_root_gitignore_applies_to_subdirectory_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / '.git').mkdir()
            (root / '.gitignore').write_text('generated/\n*_pb2.py\n', encoding='utf-8')
            src = root / 'src'
            (src / 'generated').mkdir(parents=True)
            (src / 'a.py').write_text('x = 1\n', encoding='utf-8')
            (src / 'proto_pb2.py').write_text('x = 1\n', encoding='utf-8')
            (src / 'generated' / 'g.py').write_text('x = 1\n', encoding='utf-8')
            targets, _ = expand_python_targets([str(src)])
            self.assertEqual({Path(t).name for t in targets}, {'a.py'})

    def test_intermediate_gitignore_and_negation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / '.git').mkdir()
            (root / '.gitignore').write_text('*.py\n', encoding='utf-8')
            pkg = root / 'pkg'
            (pkg / 'deep').mkdir(parents=True)
            (pkg / '.gitignore').write_text('!keep.py\n', encoding='utf-8')
            (pkg / 'deep' / 'keep.py').write_text('x = 1\n', encoding='utf-8')
            (pkg / 'deep' / 'drop.py').write_text('x = 1\n', encoding='utf-8')
            targets, _ = expand_python_targets([str(pkg / 'deep')])
            self.assertEqual({Path(t).name for t in targets}, {'keep.py'})

    def test_pattern_with_separator_is_anchored_to_its_gitignore(self):
        """git anchors a pattern holding a separator; only bare names match at any depth."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / '.git').mkdir()
            (root / '.gitignore').write_text('sub/drop.py\n', encoding='utf-8')
            (root / 'sub').mkdir()
            (root / 'other' / 'sub').mkdir(parents=True)
            (root / 'sub' / 'drop.py').write_text('x = 1\n', encoding='utf-8')
            (root / 'other' / 'sub' / 'drop.py').write_text('x = 1\n', encoding='utf-8')
            targets, _ = expand_python_targets([str(root)])
            relative = {Path(t).relative_to(root).as_posix() for t in targets}
            self.assertEqual(relative, {'other/sub/drop.py'})

    def test_bare_name_still_matches_at_any_depth(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / '.git').mkdir()
            (root / '.gitignore').write_text('drop.py\n', encoding='utf-8')
            (root / 'deep' / 'deeper').mkdir(parents=True)
            (root / 'deep' / 'deeper' / 'drop.py').write_text('x = 1\n', encoding='utf-8')
            (root / 'deep' / 'deeper' / 'keep.py').write_text('x = 1\n', encoding='utf-8')
            targets, _ = expand_python_targets([str(root)])
            self.assertEqual({Path(t).name for t in targets}, {'keep.py'})

    def test_without_repo_only_target_gitignore_applies(self):
        with tempfile.TemporaryDirectory() as tmp:
            outer = Path(tmp).resolve()
            (outer / '.gitignore').write_text('*.py\n', encoding='utf-8')
            (outer / 'proj').mkdir()
            (outer / 'proj' / 'a.py').write_text('x = 1\n', encoding='utf-8')
            targets, _ = expand_python_targets([str(outer / 'proj')])
            self.assertEqual({Path(t).name for t in targets}, {'a.py'})

    def test_no_ignore_includes_root_gitignored_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / '.git').mkdir()
            (root / '.gitignore').write_text('generated/\n*_pb2.py\n', encoding='utf-8')
            src = root / 'src'
            (src / 'generated').mkdir(parents=True)
            (src / 'a.py').write_text('x = 1\n', encoding='utf-8')
            (src / 'proto_pb2.py').write_text('x = 1\n', encoding='utf-8')
            (src / 'generated' / 'g.py').write_text('x = 1\n', encoding='utf-8')
            targets, _ = expand_python_targets(
                [str(src)], respect_gitignore=False,
            )
            self.assertEqual(
                {Path(t).name for t in targets},
                {'a.py', 'proto_pb2.py', 'g.py'},
            )


class TestBaselineFingerprints(unittest.TestCase):

    def _run(self, files, **kwargs):
        buf = StringIO()
        rc = run_check(files, config=CheckerConfig(), output_format='json',
                       show_banner=False, color=False, stream=buf, **kwargs)
        data = json.loads(buf.getvalue())
        return rc, [i['code'] for f in data['files'] for i in f['issues']]

    def test_numbers_normalized(self):
        from codesnake import normalize_issue_message
        self.assertEqual(normalize_issue_message('Function is 52 lines long (max 50)'),
                         'Function is # lines long (max #)')

    def test_count_change_in_message_stays_suppressed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'long.py'
            body = ''.join(f'    v{i} = {i}\n' for i in range(55))
            path.write_text('def f():\n' + body + '    return 0\n', encoding='utf-8')
            baseline = str(Path(tmp) / 'b.json')
            self._run([str(path)], update_baseline=baseline)
            path.write_text('def f():\n' + body + '    w = 1\n    return w\n', encoding='utf-8')
            _, codes = self._run([str(path)], baseline_path=baseline)
            self.assertNotIn('COMP003', codes)

    def test_second_identical_violation_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'app.py'
            path.write_text('eval(input())\n', encoding='utf-8')
            baseline = str(Path(tmp) / 'b.json')
            self._run([str(path)], update_baseline=baseline)
            path.write_text('eval(input())\neval(input())\n', encoding='utf-8')
            rc, codes = self._run([str(path)], baseline_path=baseline)
            self.assertEqual(codes.count('SEC001'), 1)
            self.assertEqual(rc, 1)

    def test_removing_first_duplicate_does_not_unhide_second(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'app.py'
            path.write_text('eval(input())\nx = 1\neval(input())\n', encoding='utf-8')
            baseline = str(Path(tmp) / 'b.json')
            self._run([str(path)], update_baseline=baseline)
            path.write_text('x = 1\neval(input())\n', encoding='utf-8')
            _, codes = self._run([str(path)], baseline_path=baseline)
            self.assertNotIn('SEC001', codes)

    def test_version_1_baseline_still_loads(self):
        from codesnake import issue_fingerprints
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'app.py'
            path.write_text('eval(input())\n', encoding='utf-8')
            issues = check_file(str(path))
            sec = [i for i in issues if i.code == 'SEC001'][0]
            legacy = {
                'version': 1,
                'issues': [{
                    'filename': str(path),
                    'code': sec.code,
                    'message': sec.message,
                    'line': sec.line,
                    'fingerprint': f'{path}|{sec.code}|{sec.message}',
                }],
            }
            baseline = Path(tmp) / 'legacy.json'
            baseline.write_text(json.dumps(legacy), encoding='utf-8')
            loaded = load_baseline(str(baseline))
            self.assertIn(issue_fingerprints([sec])[0], loaded)
            _, codes = self._run([str(path)], baseline_path=str(baseline))
            self.assertNotIn('SEC001', codes)

    def test_written_baseline_is_version_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'app.py'
            path.write_text('eval(input())\n', encoding='utf-8')
            baseline = Path(tmp) / 'b.json'
            self._run([str(path)], update_baseline=str(baseline))
            data = json.loads(baseline.read_text())
            self.assertEqual(data['version'], 2)
            self.assertTrue(data['issues'][0]['fingerprint'].endswith('|0'))


class TestReportFormatting(unittest.TestCase):

    def _issue(self, **kw):
        from codesnake import Issue
        base = dict(severity='warning', category='security', message='m', line=3, col=4,
                    code='SEC003', filename='a.py', end_line=3, end_col=9, suggestion='')
        base.update(kw)
        return Issue(**base)

    def test_github_escapes_message_and_properties(self):
        from codesnake import format_github_report
        out = format_github_report([self._issue(
            filename='dir,with:odd.py', message='50% done\nsecond line', suggestion='')])
        self.assertIn('file=dir%2Cwith%3Aodd.py', out)
        self.assertIn('50%25 done%0Asecond line', out)
        self.assertNotIn('\n', out.rstrip('\n'))
        self.assertIn(',endColumn=10,', out)
        self.assertIn('title=SEC003 security', out)

    @contextlib.contextmanager
    def _workspace(self):
        """Yield (cwd, a directory outside it).

        Two sibling temp directories are mutually outside each other, so this
        holds wherever the suite is run from -- including from the system temp
        directory, where a lone TemporaryDirectory would sit *inside* the cwd.
        """
        import os
        with tempfile.TemporaryDirectory() as inside_dir, \
                tempfile.TemporaryDirectory() as outside_dir:
            old_cwd = os.getcwd()
            os.chdir(inside_dir)
            try:
                yield Path(os.getcwd()).resolve(), Path(outside_dir).resolve()
            finally:
                os.chdir(old_cwd)

    def test_github_paths_are_workspace_relative(self):
        from codesnake import format_github_report
        from codesnake.checker import _gh_escape_property
        with self._workspace() as (workspace, elsewhere):
            inside = workspace / 'src' / 'pkg' / 'mod.py'
            out = format_github_report([self._issue(filename=str(inside))])
            self.assertIn('file=src/pkg/mod.py,', out)
            outside = elsewhere / 'x.py'
            out = format_github_report([self._issue(filename=str(outside))])
            self.assertIn(f'file={_gh_escape_property(outside.as_posix())},', out)

    def test_sarif_metadata_and_uris(self):
        from codesnake import format_sarif_report
        with self._workspace() as (workspace, elsewhere):
            outside = elsewhere / 'x.py'
            outside.write_text('x = 1\n', encoding='utf-8')
            sarif = json.loads(format_sarif_report([
                self._issue(filename=str(workspace / 'src' / 'pkg' / 'mod.py')),
                self._issue(filename=str(outside), code='BUG001', severity='error',
                            category='bugs'),
            ], '9.9'))
        driver = sarif['runs'][0]['tool']['driver']
        self.assertTrue(driver['informationUri'].startswith('https://'))
        rules = {r['id']: r for r in driver['rules']}
        self.assertEqual(rules['SEC003']['defaultConfiguration']['level'], 'warning')
        self.assertEqual(rules['BUG001']['defaultConfiguration']['level'], 'error')
        self.assertIn('helpUri', rules['SEC003'])
        self.assertIn('fullDescription', rules['BUG001'])
        uris = [r['locations'][0]['physicalLocation']['artifactLocation']['uri']
                for r in sarif['runs'][0]['results']]
        self.assertEqual(uris[0], 'src/pkg/mod.py')
        self.assertTrue(uris[1].startswith('file:///'), uris[1])


class TestDeserializationSinks(unittest.TestCase):

    def _sec002(self, code):
        return [i for i in SemanticChecker(code).analyze() if i.code == 'SEC002']

    def test_yaml_load_without_loader(self):
        self.assertEqual(len(self._sec002("import yaml\nyaml.load(s)\n")), 1)
        self.assertEqual(len(self._sec002("from yaml import load\nload(s)\n")), 1)

    def test_yaml_load_with_unsafe_loader(self):
        self.assertEqual(len(self._sec002("import yaml\nyaml.load(s, Loader=yaml.Loader)\n")), 1)
        self.assertEqual(len(self._sec002("import yaml\nyaml.load(s, yaml.UnsafeLoader)\n")), 1)
        self.assertEqual(len(self._sec002("import yaml\nyaml.unsafe_load(s)\n")), 1)

    def test_yaml_safe_variants_ok(self):
        self.assertEqual(self._sec002("import yaml\nyaml.safe_load(s)\n"), [])
        self.assertEqual(self._sec002("import yaml\nyaml.load(s, Loader=yaml.SafeLoader)\n"), [])
        self.assertEqual(self._sec002("import yaml\nyaml.load(s, Loader=yaml.FullLoader)\n"), [])

    def test_marshal_shelve_dill(self):
        code = """
import marshal, shelve, dill
marshal.loads(b)
shelve.open(p)
dill.loads(b)
"""
        self.assertEqual(len(self._sec002(code)), 3)

    def test_unpickler_load(self):
        code = """
import pickle
with open(p, 'rb') as fh:
    pickle.Unpickler(fh).load()
"""
        sec = self._sec002(code)
        self.assertEqual(len(sec), 1)
        self.assertIn('Unpickler', sec[0].message)

    def test_unrelated_load_not_flagged(self):
        self.assertEqual(self._sec002("import json\njson.load(fh)\nmodel.load()\n"), [])


class TestParallelAnalysis(unittest.TestCase):

    def test_resolve_jobs(self):
        from codesnake import resolve_jobs
        self.assertEqual(resolve_jobs(None, 1), 1)
        self.assertEqual(resolve_jobs(None, 3), 1)
        self.assertGreaterEqual(resolve_jobs(None, 50), 1)
        self.assertEqual(resolve_jobs(4, 2), 2)
        self.assertEqual(resolve_jobs(1, 100), 1)
        self.assertEqual(resolve_jobs(0, 3), 1)

    def test_parallel_matches_sequential(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = []
            for i in range(6):
                path = Path(tmp) / f'm{i}.py'
                path.write_text(f'import os\ndef f{i}(a, b=[]):\n    eval(input())\n', encoding='utf-8')
                files.append(str(path))
            outputs = []
            for jobs in (1, 2):
                buf = StringIO()
                rc = run_check(files, config=CheckerConfig(), output_format='json',
                               show_banner=False, color=False, stream=buf, jobs=jobs)
                self.assertEqual(rc, 1)
                outputs.append(buf.getvalue())
            self.assertEqual(outputs[0], outputs[1])
            self.assertEqual(json.loads(outputs[1])['summary']['errors'], 12)

    def test_cli_jobs_flag(self):
        from codesnake.cli import build_parser
        args = build_parser().parse_args(['check', '-j', '2', 'a.py'])
        self.assertEqual(args.jobs, 2)
        self.assertIsNone(build_parser().parse_args(['check', 'a.py']).jobs)


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
