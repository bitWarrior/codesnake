"""
CodeSnake command-line interface.

    codesnake check [options] <files or directories>
    codesnake config [-o FILE]
    codesnake version
    codesnake [options] <files or directories>      # shorthand for ``check``
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional, Sequence

from .banner import print_snake_banner, print_version
from .checker import CheckerConfig, run_check

OUTPUT_FORMATS = ('text', 'json', 'github', 'sarif')
SEVERITIES = ('error', 'warning', 'info')
SUBCOMMANDS = frozenset({'check', 'config', 'version'})
_TOP_LEVEL_FLAGS = frozenset({'-h', '--help', '--version', '--banner'})


def add_check_arguments(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Attach the ``check`` options to ``parser`` (shared by every entry point)."""
    parser.add_argument('files', nargs='*', help='Python files or directories to check')
    parser.add_argument('--config', metavar='PATH', help='Path to a .codesnake.json config')
    parser.add_argument(
        '--format',
        choices=OUTPUT_FORMATS,
        default='text',
        help='Output format (default: text)',
    )
    parser.add_argument(
        '--severity',
        choices=SEVERITIES,
        help='Minimum severity to report',
    )
    parser.add_argument('--no-color', action='store_true', help='Disable ANSI colors')
    parser.add_argument(
        '--bandit',
        action='store_true',
        help='Merge findings from the bandit security scanner if it is installed',
    )
    parser.add_argument(
        '--staged',
        action='store_true',
        help='Check only Python files staged in git',
    )
    parser.add_argument(
        '--baseline',
        metavar='FILE',
        help='Ignore issues listed in this baseline JSON file',
    )
    parser.add_argument(
        '--update-baseline',
        metavar='FILE',
        help='Write current findings to a baseline JSON file',
    )
    return parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='codesnake',
        description='🐍 CodeSnake - Semantic Code Checker for Python 3',
        epilog='Running "codesnake FILES..." is shorthand for "codesnake check FILES...".',
    )
    parser.add_argument('--version', action='store_true', help='Show version and exit')
    parser.add_argument('--banner', action='store_true', help='Show the banner and exit')

    subparsers = parser.add_subparsers(dest='command', metavar='COMMAND')
    add_check_arguments(subparsers.add_parser('check', help='Check Python files or directories'))

    config_parser = subparsers.add_parser('config', help='Write a default configuration file')
    config_parser.add_argument(
        '--output',
        '-o',
        default='.codesnake.json',
        help='Output file (default: .codesnake.json)',
    )

    subparsers.add_parser('version', help='Show version information')
    return parser


def normalize_argv(argv: Sequence[str]) -> List[str]:
    """Insert ``check`` when the first argument is not a subcommand or top-level flag."""
    args = list(argv)
    if not args or args[0] in SUBCOMMANDS or args[0] in _TOP_LEVEL_FLAGS:
        return args
    return ['check', *args]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    raw = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(normalize_argv(raw))

    if args.banner:
        print_snake_banner()
        return 0

    if args.version or args.command == 'version':
        print_version()
        return 0

    if args.command == 'check':
        if not args.files and not args.staged:
            print("Error: provide files to check, or pass --staged", file=sys.stderr)
            return 2
        return run_check(
            args.files,
            config_path=args.config,
            output_format=args.format,
            min_severity=args.severity,
            show_banner=(args.format == 'text'),
            color=False if args.no_color else None,
            use_bandit=True if args.bandit else None,
            staged=args.staged,
            baseline_path=args.baseline,
            update_baseline=args.update_baseline,
        )

    if args.command == 'config':
        try:
            CheckerConfig().to_file(args.output)
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
