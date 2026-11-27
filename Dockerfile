# Multi-stage build for AudeSec Security Remediation Platform
FROM python:3.11-slim AS base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8000

# Install system dependencies (Node.js is installed separately below: Bob needs Node >= 22.15)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    gnupg \
    ca-certificates \
    apt-transport-https \
    lsb-release \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js + npm (pinned release, checksum verified). npm is used to validate
# dependency fixes, and Bob Shell is a Node.js application.
ARG NODE_VERSION=22.23.5
ARG NODE_SHA256_X64=cdeb8670a0c81f51b4dc4ac61919f9b1ad917b304bf8221eb939570663d240f8
ARG NODE_SHA256_ARM64=2babb9eb5264860d540849f4b064a6fbdebcdc323657d9d382ce23d313fd5e09
RUN set -eux; \
    case "$(dpkg --print-architecture)" in \
        amd64) NODE_ARCH=x64; NODE_SHA256="${NODE_SHA256_X64}" ;; \
        arm64) NODE_ARCH=arm64; NODE_SHA256="${NODE_SHA256_ARM64}" ;; \
        *) echo "unsupported architecture" >&2; exit 1 ;; \
    esac; \
    TARBALL="node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz"; \
    curl -fsSL -o "/tmp/${TARBALL}" "https://nodejs.org/dist/v${NODE_VERSION}/${TARBALL}"; \
    echo "${NODE_SHA256}  /tmp/${TARBALL}" | sha256sum -c -; \
    tar -xJf "/tmp/${TARBALL}" -C /usr/local --strip-components=1 --no-same-owner; \
    rm -f "/tmp/${TARBALL}"; \
    node --version; npm --version

# Install IBM Bob Shell (the "bob" CLI used for AI remediation; authenticates with BOB_API_KEY)
ARG BOB_VERSION=2.1.0
RUN npm install --registry=https://registry.npmjs.org/ --allow-scripts=@officecli/officecli -g "@ibm/bob@${BOB_VERSION}" \
    && npm cache clean --force \
    && bob --version

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

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies (includes the Semgrep SAST scanner)
RUN pip install --no-cache-dir -r requirements.txt

# Fail the build if any tool the scan needs is missing
RUN git --version \
    && docker --version \
    && trivy --version \
    && gitleaks version \
    && semgrep --version \
    && node --version \
    && npm --version \
    && bob --version

# Copy .env file first (if it exists)
COPY .env* ./

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p reports cloned_repo

# Create non-root user (but don't switch to it by default for Docker socket access)
RUN useradd -m -u 1000 audesec && \
    chown -R audesec:audesec /app

# Expose port
EXPOSE 8000

# The app binds to HOST (default 127.0.0.1), which a published port cannot reach from
# outside the container. Unless HOST is set explicitly, bind to the container's own
# address (a specific internal IP, never 0.0.0.0). Publish the port on the host's
# loopback, e.g. -p 127.0.0.1:8000:8000.
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f "http://${HOST:-$(hostname -i | cut -d' ' -f1)}:${PORT}/" || exit 1

# Run the application
CMD ["sh", "-c", "HOST=\"${HOST:-$(hostname -i | cut -d' ' -f1)}\" exec python -m remediator.web.app"]
