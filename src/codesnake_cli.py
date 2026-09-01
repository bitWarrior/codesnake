#!/usr/bin/env python3
"""
CodeSnake CLI - Unified command-line interface

Usage:
    codesnake check <files>          Check Python files
    codesnake test                   Run test suite
    codesnake config                 Generate default config
    codesnake version                Show version info
"""

import argparse
import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from codesnake_banner import print_snake_banner, print_version
from codesnake import CheckerConfig, run_check


def main():
    parser = argparse.ArgumentParser(
        prog='codesnake',
        description='🐍 CodeSnake - Semantic Code Checker for Python 3',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--version', action='store_true', help='Show version')
    parser.add_argument('--banner', action='store_true', help='Show CodeSnake banner')

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    check_parser = subparsers.add_parser('check', help='Check Python files')
    check_parser.add_argument('files', nargs='+', help='Files to check')
    check_parser.add_argument('--config', help='Config file path')
    check_parser.add_argument(
        '--format',
        choices=['text', 'json', 'github', 'sarif'],
        default='text',
        help='Output format',
    )
    check_parser.add_argument(
        '--severity',
        choices=['error', 'warning', 'info'],
        help='Minimum severity',
    )
    check_parser.add_argument('--no-color', action='store_true', help='Disable ANSI colors')

    test_parser = subparsers.add_parser('test', help='Run test suite')
    test_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    config_parser = subparsers.add_parser('config', help='Generate default config')
    config_parser.add_argument(
        '--output',
        '-o',
        default='.codesnake.json',
        help='Output file (default: .codesnake.json)',
    )

    subparsers.add_parser('version', help='Show version information')

    args = parser.parse_args()

    if args.banner:
        print_snake_banner()
        return 0

    if args.version or args.command == 'version':
        print_version()
        return 0

    if args.command == 'check':
        return run_check(
            args.files,
            config_path=args.config,
            output_format=args.format,
            min_severity=args.severity,
            show_banner=(args.format == 'text'),
            color=False if args.no_color else None,
        )

    if args.command == 'test':
        test_path = Path(__file__).parent.parent / 'test' / 'test_codesnake.py'
        if not test_path.is_file():
            print(f"Error: test suite not found at {test_path}", file=sys.stderr)
            return 1
        spec = importlib.util.spec_from_file_location('codesnake_test_suite', test_path)
        if spec is None or spec.loader is None:
            print(f"Error: could not load test suite from {test_path}", file=sys.stderr)
            return 1
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return 0 if module.run_tests() else 1

    if args.command == 'config':
        config = CheckerConfig()
        try:
            config.to_file(args.output)
        except OSError as exc:
            print(f"Error: could not write '{args.output}': {exc}", file=sys.stderr)
            return 1
        print(f"✅ Default configuration written to {args.output}")
        return 0

    print_snake_banner()
    parser.print_help()
    return 0


if __name__ == '__main__':
    sys.exit(main())
