```bash
#!/usr/bin/env bash

set -e

# ============================================================
#           Password Inspector - One-Click Launcher (grims stan)
#  + Sets up the virtual environment (if needed)
#  + Installs dependencies (if requirements.txt changed)
#  + Launches the interactive menu
# ============================================================

APP_NAME="Password Inspector"
VERSION="2.13"

# ------------------------------------------------------------
# Terminal colors
# ------------------------------------------------------------

CYAN='\033[1;36m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
WHITE='\033[1;37m'
DIM='\033[2m'
RESET='\033[0m'

# ------------------------------------------------------------
# Move to the directory where this script lives
# ------------------------------------------------------------

cd "$(dirname "$(realpath "$0")")"

# ------------------------------------------------------------
# Banner
# ------------------------------------------------------------

clear

printf "${CYAN}"
printf '%s\n' "================================================================"
printf '%s\n' "                       PASSWORD INSPECTOR"
printf '%s\n' "                             v${VERSION}"
printf '%s\n' "                    One-Click Setup & Launch"
printf '%s\n' "================================================================"
printf "${RESET}\n"

printf "${DIM}One moment, setting things up...${RESET}\n\n"


# ============================================================
# Step 1: Check Python
# ============================================================

if ! command -v python3 &>/dev/null; then
    printf "${RED}[ERROR]${RESET} Python 3 was not found on your system.\n"
    printf "\n"
    printf "Install Python using your distribution's package manager.\n"
    printf "\n"
    printf "Arch Linux:\n"
    printf "  sudo pacman -S python python-pip\n"
    printf "\n"
    printf "Ubuntu/Debian:\n"
    printf "  sudo apt install python3 python3-pip python3-venv\n"
    printf "\n"
    exit 1
fi

PYTHON_VERSION=$(python3 --version)

printf "${GREEN}[OK]${RESET} Python found: ${PYTHON_VERSION}\n"


# ============================================================
# Step 2: Check Python version
# ============================================================

PYTHON_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
PYTHON_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')

if [[ "$PYTHON_MAJOR" -lt 3 ]] || \
   [[ "$PYTHON_MAJOR" -eq 3 && "$PYTHON_MINOR" -lt 13 ]]; then

    printf "${RED}[ERROR]${RESET} Python 3.13+ is required.\n"
    printf "Found: ${PYTHON_VERSION}\n"
    exit 1
fi

printf "${GREEN}[OK]${RESET} Python version requirement satisfied.\n"


# ============================================================
# Step 3: Create virtual environment
# ============================================================

VENV_DIR="venv"

if [[ ! -f "${VENV_DIR}/bin/activate" ]]; then

    printf "\n${CYAN}[1/3]${RESET} Creating virtual environment...\n"

    python3 -m venv "$VENV_DIR"

    printf "${GREEN}[OK]${RESET} Virtual environment created.\n"

else

    printf "\n${CYAN}[1/3]${RESET} Virtual environment already exists.\n"
    printf "${DIM}      Skipping creation.${RESET}\n"

fi


# ============================================================
# Step 4: Activate virtual environment
# ============================================================

if [[ ! -f "${VENV_DIR}/bin/activate" ]]; then

    printf "${RED}[ERROR]${RESET} Virtual environment activation script not found.\n"
    exit 1

fi

source "${VENV_DIR}/bin/activate"

printf "${GREEN}[OK]${RESET} Virtual environment activated.\n"


# ============================================================
# Step 5: Check dependencies
# ============================================================

MARKER="${VENV_DIR}/.deps_hash"

if [[ ! -f "requirements.txt" ]]; then

    printf "${YELLOW}[WARNING]${RESET} requirements.txt was not found.\n"
    printf "${DIM}Skipping dependency installation.${RESET}\n"

else

    CURRENT_HASH=$(sha256sum requirements.txt | awk '{print $1}')

    NEEDS_INSTALL=true

    if [[ -f "$MARKER" ]]; then

        SAVED_HASH=$(cat "$MARKER")

        if [[ "$CURRENT_HASH" == "$SAVED_HASH" ]]; then
            NEEDS_INSTALL=false
        fi

    fi


    if [[ "$NEEDS_INSTALL" == true ]]; then

        printf "\n${CYAN}[2/3]${RESET} Installing dependencies...\n\n"

        python -m pip install --upgrade pip

        python -m pip install -r requirements.txt

        printf "\n${GREEN}[OK]${RESET} Dependencies installed.\n"

        echo "$CURRENT_HASH" > "$MARKER"

    else

        printf "\n${CYAN}[2/3]${RESET} Dependencies are up to date.\n"
        printf "${DIM}      Skipping installation.${RESET}\n"

    fi

fi


# ============================================================
# Step 6: Launch Password Inspector
# ============================================================

printf "\n${CYAN}[3/3]${RESET} Launching Password Inspector...\n\n"

python password_inspector_cli.py


# ============================================================
# Exit
# ============================================================

printf "\n"
printf "${CYAN}================================================================${RESET}\n"
printf "${WHITE}        Password Inspector closed. Goodbye.${RESET}\n"
printf "${CYAN}================================================================${RESET}\n"
printf "\n"

deactivate
```
