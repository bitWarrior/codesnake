# CodeSnake Banner Guide 🎨

## The Colorful ASCII Banner

CodeSnake now displays a beautiful gradient ASCII art banner at startup!

### What It Looks Like

```
  ____          _       ____              _          
 / ___|___   __| | ___ / ___| _ __   __ _| | _____   
| |   / _ \ / _` |/ _ \\___ \| '_ \ / _` | |/ / _ \  
| |__| (_) | (_| |  __/___) | | | | (_| |   <  __/  
 \____\___/ \__,_|\___|____/|_| |_|\__,_|_|\_\___|  
                                   🐍 Strikes at code problems before they bite!
```

**With Colors:**
- Line 1: **Cyan** - Eye-catching start
- Line 2-3: **Green** - Main body
- Line 4: **Dark Green** - Gradient transition  
- Line 5: **Yellow** - Bottom accent
- Tagline: **Green** with snake emoji 🐍

### When Does It Display?

The banner automatically displays when you run:

```bash
# Main checker
codesnake check your_code.py

# Enhanced version
codesnake check your_code.py

# CLI tool
codesnake check your_code.py

# Show banner explicitly
codesnake --banner
```

### Demo All Banners

Run the demo script to see all available banners:

```bash
```

This will show:
1. **Main Colorful Banner** - Used at startup (with gradient)
2. **Small Snake ASCII Art** - Cute snake watching your code
3. **Tiny Snake** - Minimal emoji version
4. **Version Information** - Product details

### Customization

The banner code is in `src/codesnake/banner.py`:

```python
from codesnake.banner import print_snake_banner

# Display the banner
print_snake_banner()
```

### Color Codes Used

```python
CYAN = "\033[96m"        # Light blue-green
GREEN = "\033[92m"       # Bright green
DARK_GREEN = "\033[32m"  # Standard green
YELLOW = "\033[93m"      # Bright yellow
RESET = "\033[0m"        # Reset to default
```

### Terminal Compatibility

The banner works best in terminals that support ANSI colors:
- ✅ Linux/Unix terminals
- ✅ macOS Terminal/iTerm2
- ✅ Windows Terminal
- ✅ VS Code integrated terminal
- ✅ PyCharm terminal
- ⚠️ Windows CMD (limited colors)
- ❌ Very old terminals (will show escape codes)

### Disable Colors

If you need plain text output (e.g., for logs):

```bash
# The enhanced version supports --no-color
codesnake check --no-color your_code.py

# Or redirect to a file (colors auto-disabled in most terminals)
codesnake check your_code.py > output.txt
```

### Banner Function

The main function is simple to use:

```python
def print_snake_banner():
    """Print the colorful CodeSnake ASCII banner."""
    # Displays the multi-line ASCII art
    # with gradient colors from Cyan → Green → Dark Green → Yellow
```

## All Available ASCII Art

### 1. Main Banner (Colorful)

### 2. Small Snake
```
    /^\/^\
   /  o o  \     CodeSnake is watching your code...
  (  =  ^  =  )
   )         (
  (           )
 ( (  )   (  ) )
(__(__)___(__)__)
```

### 3. Block Banner
The large boxed banner with Unicode characters (used in documentation)

### 4. Tiny Version
Simple: `🐍 CodeSnake`

## Usage Examples

### Display Banner Only
```bash
codesnake --banner
```

### In Your Own Scripts
```python
from codesnake.banner import print_snake_banner, print_version

print_snake_banner()  # Show the main banner
print_version()       # Show version info
```

### Check Without Banner
Currently the banner displays automatically. To suppress it, you could modify the code or redirect stderr:

```bash
codesnake check your_code.py 2>/dev/null
```

## Why a Banner?

1. **Brand Identity** - Makes CodeSnake instantly recognizable
2. **Visual Appeal** - Professional and fun at the same time
3. **User Experience** - Clear indication the tool is running
4. **Team Spirit** - Builds connection with the 🐍 Python community

---

**Enjoy the colorful CodeSnake banner! 🐍✨**
