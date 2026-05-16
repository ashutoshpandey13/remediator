#!/bin/bash

# AudeSec Web UI Startup Script

echo "🛡️  AudeSec Security Remediation Platform"
echo "=========================================="
echo ""

# Check if .env file exists
if [ ! -f .env ]; then
    echo "❌ Error: .env file not found!"
    echo "Please create a .env file with your configuration."
    echo "You can copy .env.example to get started:"
    echo "  cp .env.example .env"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install/upgrade dependencies
echo "📥 Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Error: Docker is not running!"
    echo "Please start Docker and try again."
    exit 1
fi

# Check if Trivy is installed
if ! command -v trivy &> /dev/null; then
    echo "⚠️  Warning: Trivy is not installed!"
    echo "Install it with: brew install trivy (macOS) or apt-get install trivy (Linux)"
    echo ""
fi

echo ""
echo "✅ All checks passed!"
echo ""
echo "🚀 Starting AudeSec Web UI..."
echo "   Access the UI at: http://localhost:5000"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Start the web application
python web_app.py
