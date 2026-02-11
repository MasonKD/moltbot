#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must run as root." >&2
  exit 1
fi

# NOTE:
# - User creation/bootstrap must run as root.
# - After that, all setup steps should run as the "clawd" user context.

# Create clawd user (if missing), set password, and grant sudo.
if ! id -u clawd >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" clawd
fi

# Repair potentially partial user setup.
usermod -s /bin/bash clawd
mkdir -p /home/clawd
chown clawd:clawd /home/clawd
if [ ! -f /home/clawd/.bashrc ]; then
  touch /home/clawd/.bashrc
  chown clawd:clawd /home/clawd/.bashrc
fi

# Set explicit password for clawd user.
echo 'clawd:clawd' | chpasswd
usermod -aG sudo clawd

# As clawd user: download installer into home directory and mark executable.
runuser -u clawd -- bash -lc 'curl -fsSL https://clawd.bot/install.sh -o ~/clawd_install.sh && chmod +x ~/clawd_install.sh'

# Ensure npm global bin path is present for clawd.
runuser -u clawd -- bash -lc '
if ! grep -Fq '"'"'export PATH="/home/clawd/.npm-global/bin:$PATH"'"'"' ~/.bashrc; then
  echo '"'"'export PATH="/home/clawd/.npm-global/bin:$PATH"'"'"' >> ~/.bashrc
fi
'

# Build tools needed for Homebrew packages (root context required).
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends build-essential curl git ca-certificates file

# Install Homebrew for clawd if missing (must not run as root).
# Ensure Linuxbrew prefix exists and is writable by clawd.
mkdir -p /home/linuxbrew/.linuxbrew
chown -R clawd:clawd /home/linuxbrew

runuser -u clawd -- bash -lc '
if [ ! -x /home/linuxbrew/.linuxbrew/bin/brew ]; then
  NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi
'

# Configure brew shellenv in clawd bashrc.
runuser -u clawd -- bash -lc '
if [ -x /home/linuxbrew/.linuxbrew/bin/brew ]; then
  if ! grep -Fq "eval \"$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)\"" ~/.bashrc; then
    echo >> ~/.bashrc
    echo "eval \"$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)\"" >> ~/.bashrc
  fi
fi
'

# Install gcc via brew as clawd.
runuser -u clawd -- bash -lc '
if [ -x /home/linuxbrew/.linuxbrew/bin/brew ]; then
  eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"
  brew list gcc >/dev/null 2>&1 || brew install gcc
fi
'
