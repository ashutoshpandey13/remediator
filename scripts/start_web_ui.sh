#!/bin/bash
# AudeSec Web UI startup script: checks the environment, then starts the server.

# Always run from the project root, regardless of where the script is invoked
cd "$(dirname "$0")/.." || exit 1

if [ ! -f .env ]; then
    echo "Error: .env file not found. Create it with your configuration (see README.md)."
    exit 1
fi

if [ ! -d "venv" ]; then
    echo "Creating virtual environment (Python 3.10+ is required)..."
    python3 -m venv venv || exit 1
fi

# shellcheck disable=SC1091
source venv/bin/activate

echo "Installing dependencies (hash-checked)..."
pip install -q --require-hashes -r requirements.txt || exit 1

if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running. Start it and try again."
    exit 1
fi

for tool in trivy gitleaks semgrep bob git; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        echo "Warning: $tool is not installed; the step that needs it will be skipped or fail."
    fi
done

echo "Starting AudeSec Web UI on http://127.0.0.1:${PORT:-8000} (Ctrl+C to stop)"
exec python -m remediator.web.app
