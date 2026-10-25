@echo off
# ============================================================
#           Password Inspector - One-Click Launcher
# + Sets up the virtual environment (if needed),
#  + Installs dependencies (if needed),
#  + Launches the interactive menu.
# ============================================================

# Setting up terminal window title
printf '\033]0;Password Inspector v2.24\007'

echo "================================================================"
echo "                       PASSWORD INSPECTOR"
echo "                             v2.24"
echo "                    One-Click Setup ^& Launch"
echo "================================================================"
echo
echo "One moment, setting things up...."
echo

# --- Move to the folder this .sh file lives in, regardless of
# --- where it was double-clicked from ---
cd "$(dirname "$0")"

# ---Step 1: Check if Python is installed, if not the prompt to download ---
if ! command -v python3>/dev/null 2>&1; then
    echo "[ERROR] Python was not found on your system."
    echo "Please install Python 3.13+ from https://www.python.org/downloads/"
    echo "Or run sudo apt install python3 pip3"
    echo
else
    echo "Python version found. Moving on..."
    echo
fi

# --- Step 2: Create virtual environment if it doesn't exist yet ---
if [ ! -e "venv/bin/activate" ]; then
  echo "[1/3] Creating virtual environment..."
  python3 -m venv venv || { echo "[ERROR] Failed to create virtual environment" >&2; exit 1; }
else
  echo "[1/3] Virtual environment already exists."
fi

# --- Step 3: Activate virtual environment ---
source venv/bin/activate || { echo "[ERROR] Failed to activate virtual environment." >&2; exit 1; }
if [ -z "$VIRTUAL_ENV" ]; then
  echo "Activation did not take effect"
  exit 1
fi

# --- Step 4: Install dependencies (only if requirements.txt changed since last install, tracked via marker file ---
MARKER=venv/.deps_installed
NEEDS_INSTALL=1
if [ -e "$MARKER" ]; then
  if cmp -s "$MARKER" requirements.txt; then
    NEEDS_INSTALL=0
  fi
fi

if [ "$NEEDS_INSTALL" -eq 1 ]; then
  echo "[2/3] Installing dependencies..."
  venv/bin/pip install -r requirements.txt || { echo "[ERROR] Pip failed to install dependencies." >&2; exit 1; }
  cp requirements.txt "$MARKER"
else
  echo "[2/3] Dependencies already installed. Skipping step..."
fi

# Step 5: Launch Password Inspector's interactive menu
echo "[3/3] Launching Password Inspector..."
echo
venv/bin/python password_inspector_cli.py

echo
echo "================================================================"
echo "  Password Inspector closed. Press any key to exit this window."
echo "================================================================"
read -n 1 -s -r