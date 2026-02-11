#!/usr/bin/env bash
set -euo pipefail

# NOTE:
# - User creation/bootstrap must run as root.
# - After that, all setup steps should run as the "clawd" user context.

# Create clawd user (if missing), set password, and grant sudo.
if ! id -u clawd >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" clawd
fi

echo 'clawd:clawd' | chpasswd
usermod -aG sudo clawd

# As clawd user: download installer into home directory.
sudo -u clawd bash -lc 'curl -fsSL https://clawd.bot/install.sh -o ~/clawd_install.sh'

# Ensure npm global bin path is present for clawd.
sudo -u clawd bash -lc '
if ! grep -Fq '"'"'export PATH="/home/clawd/.npm-global/bin:$PATH"'"'"' ~/.bashrc; then
  echo '"'"'export PATH="/home/clawd/.npm-global/bin:$PATH"'"'"' >> ~/.bashrc
fi
'

# Build tools needed for Homebrew packages (run from clawd context).
sudo -u clawd bash -lc 'sudo apt-get update -y && sudo apt-get install -y build-essential'

# Install Homebrew for clawd (must not run as root).
sudo -u clawd bash -lc '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'

# Configure brew shellenv in clawd bashrc and current session for install step.
sudo -u clawd bash -lc '
if ! grep -Fq '"'"'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv bash)"'"'"' ~/.bashrc; then
  echo >> ~/.bashrc
  echo '"'"'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv bash)"'"'"' >> ~/.bashrc
fi
'

# Install gcc via brew as clawd.
sudo -u clawd bash -lc 'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv bash)" && brew install gcc'
