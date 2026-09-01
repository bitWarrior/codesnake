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
        self.assertIn(',col=8::', github)

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
