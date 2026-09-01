"""
CodeSnake ASCII Art and Branding
"""

from ._version import __version__

def print_snake_banner():
    """Print the colorful CodeSnake ASCII banner."""
    # ANSI Color Codes
    GREEN = "\033[92m"
    DARK_GREEN = "\033[32m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    
    # The banner split into lines
    lines = [
        r"  ____          _       ____              _          ",
        r" / ___|___   __| | ___ / ___| _ __   __ _| | _____   ",
        r"| |   / _ \ / _` |/ _ \\___ \| '_ \ / _` | |/ / _ \  ",
        r"| |__| (_) | (_| |  __/___) | | | | (_| |   <  __/  ",
        r" \____\___/ \__,_|\___|____/|_| |_|\__,_|_|\_\___|  "
    ]
    
    # Map colors to each line for a gradient effect
    colors = [CYAN, GREEN, GREEN, DARK_GREEN, YELLOW]
    
    print()
    for color, text in zip(colors, lines):
        print(f"{color}{text}{RESET}")
    print(f"{GREEN}{'':^55}🐍 Strikes at code problems before they bite!{RESET}")
    print()


BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗ ██████╗ ██████╗ ███████╗███████╗███╗   ██╗ █████╗  ║
║  ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝████╗  ██║██╔══██╗ ║
║  ██║     ██║   ██║██║  ██║█████╗  ███████╗██╔██╗ ██║███████║ ║
║  ██║     ██║   ██║██║  ██║██╔══╝  ╚════██║██║╚██╗██║██╔══██║ ║
║  ╚██████╗╚██████╔╝██████╔╝███████╗███████║██║ ╚████║██║  ██║ ║
║   ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ║
║                                                               ║
║              🐍 Strikes at code problems before they bite!    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""

SNAKE_SMALL = r"""
    /^\/^\
   /  o o  \     CodeSnake is watching your code...
  (  =  ^  =  )
   )         (
  (           )
 ( (  )   (  ) )
(__(__)___(__)__)
"""

SNAKE_TINY = "🐍 CodeSnake"

VERSION = __version__
TAGLINE = "Semantic Code Checker for Python 3"

def print_banner():
    """Print the CodeSnake banner."""
    print(BANNER)

def print_snake():
    """Print the small snake."""
    print(SNAKE_SMALL)

def print_version():
    """Print version information."""
    print(f"{SNAKE_TINY} v{VERSION}")
    print(TAGLINE)
