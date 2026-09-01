#!/bin/bash
#
# CodeSnake Setup Script
# One-time setup to get CodeSnake ready to use
#

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
VENV_NAME="codesnake-venv"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
VENV_PATH="${SCRIPT_DIR}/${VENV_NAME}"

echo -e "${CYAN}"
cat << "EOF"
  ____          _       ____              _          
 / ___|___   __| | ___ / ___| _ __   __ _| | _____   
| |   / _ \ / _` |/ _ \\___ \| '_ \ / _` | |/ / _ \  
| |__| (_) | (_| |  __/___) | | | | (_| |   <  __/  
 \____\___/ \__,_|\___|____/|_| |_|\__,_|_|\_\___|  

            Setup Script - Let's get you started! 🐍
EOF
echo -e "${NC}\n"

# Check Python version
echo -e "${BLUE}[1/5] Checking Python version...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed${NC}"
    echo -e "${YELLOW}Please install Python 3.10 or higher${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | awk '{print $2}')
echo -e "${GREEN}✓ Found Python ${PYTHON_VERSION}${NC}\n"

# Create virtual environment
echo -e "${BLUE}[2/5] Creating virtual environment...${NC}"
if [ -d "${VENV_PATH}" ]; then
    echo -e "${YELLOW}Virtual environment already exists${NC}"
    read -p "Recreate it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "${VENV_PATH}"
        python3 -m venv "${VENV_PATH}"
        echo -e "${GREEN}✓ Virtual environment recreated${NC}"
    else
        echo -e "${GREEN}✓ Using existing virtual environment${NC}"
    fi
else
    python3 -m venv "${VENV_PATH}"
    echo -e "${GREEN}✓ Virtual environment created${NC}"
fi
echo

# Activate virtual environment
source "${VENV_PATH}/bin/activate"

# Upgrade pip
echo -e "${BLUE}[3/5] Upgrading pip...${NC}"
pip install --upgrade pip --quiet
echo -e "${GREEN}✓ pip upgraded${NC}\n"

# Install this project from pyproject.toml
echo -e "${BLUE}[4/5] Installing CodeSnake${NC}"
echo -e "${YELLOW}CodeSnake works standalone, but can also install optional tools:${NC}"
echo
echo "  • pylint    - Advanced Python linter"
echo "  • flake8    - Style guide enforcement (PEP 8)"
echo "  • mypy      - Static type checker"
echo "  • bandit    - Security vulnerability scanner"
echo "  • isort     - Import sorting"
echo

read -p "Install optional tools? (recommended) (Y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    echo -e "${YELLOW}Installing CodeSnake with optional tools (pyproject.toml)...${NC}"
    pip install -e "${SCRIPT_DIR}[tools]" --quiet
    echo -e "${GREEN}✓ CodeSnake and optional tools installed${NC}"
else
    echo -e "${YELLOW}Installing CodeSnake (no optional tools)...${NC}"
    pip install -e "${SCRIPT_DIR}" --quiet
    echo -e "${GREEN}✓ CodeSnake installed${NC}"
fi
echo

# Make scripts executable
echo -e "${BLUE}[5/5] Making scripts executable...${NC}"
chmod +x "${SCRIPT_DIR}/codesnake.sh" 2>/dev/null || true
chmod +x "${SCRIPT_DIR}/codesnake-launcher.sh" 2>/dev/null || true
chmod +x "${SCRIPT_DIR}/setup.sh" 2>/dev/null || true
echo -e "${GREEN}✓ Scripts are executable${NC}\n"

# Create default config if it doesn't exist
if [ ! -f "${SCRIPT_DIR}/.codesnake.json" ]; then
    echo -e "${YELLOW}Creating default configuration file...${NC}"
    python3 "${SCRIPT_DIR}/src/codesnake_cli.py" config -o "${SCRIPT_DIR}/.codesnake.json" > /dev/null
    echo -e "${GREEN}✓ Created .codesnake.json${NC}\n"
fi

# Test installation
echo -e "${BLUE}Testing CodeSnake installation...${NC}"
if python3 "${SCRIPT_DIR}/src/codesnake.py" --help &> /dev/null; then
    echo -e "${GREEN}✓ CodeSnake is working!${NC}\n"
else
    echo -e "${RED}Warning: Could not verify CodeSnake installation${NC}\n"
fi

# Summary
echo -e "${GREEN}"
echo "═══════════════════════════════════════════════════════════"
echo "                    Setup Complete! 🎉"
echo "═══════════════════════════════════════════════════════════"
echo -e "${NC}"

echo -e "${CYAN}Quick Start:${NC}"
echo
echo "  1. Check a file:"
echo -e "     ${YELLOW}./codesnake.sh test/example_bad_code.py${NC}"
echo
echo "  2. Check with enhanced mode:"
echo -e "     ${YELLOW}./codesnake-launcher.sh -e your_code.py${NC}"
echo
echo "  3. Run tests:"
echo -e "     ${YELLOW}./codesnake-launcher.sh --test${NC}"
echo
echo "  4. Show banner:"
echo -e "     ${YELLOW}./codesnake-launcher.sh --banner${NC}"
echo

echo -e "${CYAN}Manual activation:${NC}"
echo -e "  ${YELLOW}source ${VENV_NAME}/bin/activate${NC}"
echo

echo -e "${CYAN}Configuration:${NC}"
echo -e "  Edit ${YELLOW}.codesnake.json${NC} to customize behavior"
echo

echo -e "${CYAN}Documentation:${NC}"
echo "  • docs/README.md        - Full documentation"
echo "  • docs/QUICKSTART.md    - Quick start guide"
echo "  • docs/BANNER_GUIDE.md  - Banner customization"
echo

echo -e "${GREEN}Happy coding! 🐍✨${NC}"
