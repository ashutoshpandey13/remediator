# Multi-stage build for AudeSec Security Remediation Platform
FROM python:3.11-slim AS base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8000

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    gnupg \
    ca-certificates \
    apt-transport-https \
    lsb-release \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI (for building images during scans)
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy security scanner
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(. /etc/os-release && echo "$VERSION_CODENAME") main" | tee /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends trivy \
    && rm -rf /var/lib/apt/lists/*

# Install Gitleaks secret scanner (pinned release, checksum verified)
ARG GITLEAKS_VERSION=8.30.1
RUN set -eux; \
    case "$(dpkg --print-architecture)" in \
        amd64) GL_ARCH=x64 ;; \
        arm64) GL_ARCH=arm64 ;; \
        *) echo "unsupported architecture" >&2; exit 1 ;; \
    esac; \
    BASE="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}"; \
    TARBALL="gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz"; \
    curl -fsSL -o "/tmp/${TARBALL}" "${BASE}/${TARBALL}"; \
    curl -fsSL -o /tmp/gitleaks_checksums.txt "${BASE}/gitleaks_${GITLEAKS_VERSION}_checksums.txt"; \
    (cd /tmp && grep " ${TARBALL}\$" gitleaks_checksums.txt | sha256sum -c -); \
    tar -xzf "/tmp/${TARBALL}" -C /usr/local/bin gitleaks; \
    rm -f "/tmp/${TARBALL}" /tmp/gitleaks_checksums.txt; \
    gitleaks version

# Install GitHub CLI (optional, for PR creation)
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | gpg --dearmor -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt-get update \
    && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy .env file first (if it exists)
COPY .env* ./

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p reports fixed cloned_repo static/css static/js templates

# Set proper permissions
RUN chmod +x start_web_ui.sh || true

# Create non-root user (but don't switch to it by default for Docker socket access)
RUN useradd -m -u 1000 audesec && \
    chown -R audesec:audesec /app

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/ || exit 1

# Run the application
CMD ["python", "web_app.py"]
