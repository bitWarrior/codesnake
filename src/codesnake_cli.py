#!/usr/bin/env python3
"""
CodeSnake CLI - Unified command-line interface

Usage:
    codesnake check <files>          Check Python files
    codesnake test                   Run test suite
    codesnake config                 Generate default config
    codesnake version                Show version info
"""

import sys
import argparse
from pathlib import Path

# Ensure we can import from the same directory
sys.path.insert(0, str(Path(__file__).parent))

from codesnake_banner import print_snake_banner, VERSION, print_version


def main():
    parser = argparse.ArgumentParser(
        prog='codesnake',
        description='🐍 CodeSnake - Semantic Code Checker for Python 3',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--version', action='store_true', help='Show version')
    parser.add_argument('--banner', action='store_true', help='Show CodeSnake banner')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Check command
    check_parser = subparsers.add_parser('check', help='Check Python files')
    check_parser.add_argument('files', nargs='+', help='Files to check')
    check_parser.add_argument('--config', help='Config file path')
    check_parser.add_argument('--format', choices=['text', 'json', 'github', 'sarif'],
                             default='text', help='Output format')
    check_parser.add_argument('--severity', choices=['error', 'warning', 'info'],
                             help='Minimum severity')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Run test suite')
    test_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    # Config command
    config_parser = subparsers.add_parser('config', help='Generate default config')
    config_parser.add_argument('--output', '-o', default='.codesnake.json',
                               help='Output file (default: .codesnake.json)')
    
    # Version command
    version_parser = subparsers.add_parser('version', help='Show version information')
    
    args = parser.parse_args()
    
    # Handle flags
    if args.banner:
        print_snake_banner()
        return 0
    
    if args.version or args.command == 'version':
        print_version()
        return 0
    
    # Handle commands
    if args.command == 'check':
        import codesnake_enhanced
        sys.argv = ['codesnake']
        if args.config:
            sys.argv.extend(['--config', args.config])
        sys.argv.extend(['--format', args.format])
        if args.severity:
            sys.argv.extend(['--severity', args.severity])
        sys.argv.extend(args.files)
        return codesnake_enhanced.main()
    
    elif args.command == 'test':
        # Add parent directory to find test module
        parent_dir = Path(__file__).parent.parent
        sys.path.insert(0, str(parent_dir))
        
        import test.test_codesnake as test_codesnake
        return 0 if test_codesnake.run_tests() else 1
    
    elif args.command == 'config':
        from codesnake_enhanced import CheckerConfig
        config = CheckerConfig()
        config.to_file(args.output)
        print(f"✅ Default configuration written to {args.output}")
        return 0
    
    else:
        print_snake_banner()
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
