#!/bin/bash
# Mac mini set-up for the shared small-model host. Run once, as the user that stays logged in:
#   bash install.sh
# Needs: Homebrew (https://brew.sh). Installs Ollama natively (Docker on macOS cannot use the GPU),
# pulls the models, installs the Sentinel gateway in a virtualenv and starts both at boot.
set -euo pipefail
GW="$HOME/sentinel-gateway"
MODELS="${MODELS:-qwen2.5:7b-instruct nomic-embed-text}"
REPO="${SENTINEL_REPO:-git+https://github.com/MohanKbgrid/kbg-sentinel.git}"

command -v brew >/dev/null || { echo "Install Homebrew first: https://brew.sh"; exit 1; }
brew list ollama >/dev/null 2>&1 || brew install ollama
brew list python@3.12 >/dev/null 2>&1 || brew install python@3.12

# Ollama: localhost only (the gateway is the only door), models kept loaded, parallel slots
launchctl setenv OLLAMA_HOST 127.0.0.1:11434
launchctl setenv OLLAMA_KEEP_ALIVE 30m
launchctl setenv OLLAMA_NUM_PARALLEL 4
brew services restart ollama
sleep 3
for m in $MODELS; do ollama pull "$m"; done

mkdir -p "$GW/usage"
[ -d "$GW/venv" ] || "$(brew --prefix python@3.12)/bin/python3.12" -m venv "$GW/venv"
"$GW/venv/bin/pip" install --upgrade pip >/dev/null
"$GW/venv/bin/pip" install "kbg-sentinel[api] @ $REPO"
[ -f "$GW/gateway.yaml" ] || { cp "$(dirname "$0")/gateway.yaml.example" "$GW/gateway.yaml"; \
  echo "Edit $GW/gateway.yaml (tokens, customers), then run this script again."; exit 0; }
sed -i '' "s|~/sentinel-gateway|$GW|g" "$GW/gateway.yaml"

PLIST="$HOME/Library/LaunchAgents/com.kbgrid.sentinel-gateway.plist"
sed "s|HOME_DIR|$HOME|g" "$(dirname "$0")/com.kbgrid.sentinel-gateway.plist" > "$PLIST"
launchctl unload "$PLIST" 2>/dev/null || true
launchctl load "$PLIST"
sleep 2
curl -fsS http://127.0.0.1:8090/healthz && echo && echo "Gateway is up on port 8090."
echo "Keep the Mac awake: System Settings > Energy > Prevent automatic sleeping; enable 'Start up automatically after a power failure'."
