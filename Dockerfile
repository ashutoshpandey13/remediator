# AudeSec Security Remediation Platform
#
# Base image: Red Hat UBI 9 (minimal Python). It comes from registry.access.redhat.com,
# which needs no registry login (the same images exist on registry.redhat.io).
FROM registry.access.redhat.com/ubi9/python-312-minimal:latest

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8000

USER 0

# ---- OS packages -----------------------------------------------------------
# git:      clone, branch, commit and push
# tar, xz, gzip: unpack the pinned tool releases below
# docker-ce-cli: build the target repository's Dockerfiles (talks to the Docker socket)
RUN printf '%s\n' \
        '[docker-ce-stable]' \
        'name=Docker CE Stable' \
        'baseurl=https://download.docker.com/linux/rhel/9/$basearch/stable' \
        'enabled=1' \
        'gpgcheck=1' \
        'gpgkey=https://download.docker.com/linux/rhel/gpg' \
        > /etc/yum.repos.d/docker-ce.repo \
    && microdnf install -y --setopt=install_weak_deps=0 --nodocs \
        git-core tar xz gzip docker-ce-cli \
    && microdnf clean all \
    && rm -rf /var/cache/yum /var/cache/dnf

# ---- Node.js + npm (pinned, checksum verified) -----------------------------
# npm validates dependency fixes, and Bob Shell is a Node.js application (needs >= 22.15).
ARG NODE_VERSION=22.23.5
ARG NODE_SHA256_X64=cdeb8670a0c81f51b4dc4ac61919f9b1ad917b304bf8221eb939570663d240f8
ARG NODE_SHA256_ARM64=2babb9eb5264860d540849f4b064a6fbdebcdc323657d9d382ce23d313fd5e09
RUN set -eux; \
    case "$(uname -m)" in \
        x86_64)  NODE_ARCH=x64;   NODE_SHA256="${NODE_SHA256_X64}" ;; \
        aarch64) NODE_ARCH=arm64; NODE_SHA256="${NODE_SHA256_ARM64}" ;; \
        *) echo "unsupported architecture" >&2; exit 1 ;; \
    esac; \
    TARBALL="node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz"; \
    curl -fsSL -o "/tmp/${TARBALL}" "https://nodejs.org/dist/v${NODE_VERSION}/${TARBALL}"; \
    echo "${NODE_SHA256}  /tmp/${TARBALL}" | sha256sum -c -; \
    tar -xJf "/tmp/${TARBALL}" -C /usr/local --strip-components=1 --no-same-owner; \
    rm -f "/tmp/${TARBALL}"; \
    node --version; npm --version

# ---- IBM Bob Shell (the "bob" CLI for AI remediation; authenticates with BOB_API_KEY) ----
ARG BOB_VERSION=2.1.0
RUN npm install --registry=https://registry.npmjs.org/ --allow-scripts=@officecli/officecli -g "@ibm/bob@${BOB_VERSION}" \
    && npm cache clean --force \
    && bob --version

# ---- Trivy (pinned, checksum verified) --------------------------------------
ARG TRIVY_VERSION=0.76.2
ARG TRIVY_SHA256_X64=bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf
ARG TRIVY_SHA256_ARM64=ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3
RUN set -eux; \
    case "$(uname -m)" in \
        x86_64)  T_ARCH=64bit; T_SHA256="${TRIVY_SHA256_X64}" ;; \
        aarch64) T_ARCH=ARM64; T_SHA256="${TRIVY_SHA256_ARM64}" ;; \
        *) echo "unsupported architecture" >&2; exit 1 ;; \
    esac; \
    TARBALL="trivy_${TRIVY_VERSION}_Linux-${T_ARCH}.tar.gz"; \
    curl -fsSL -o "/tmp/${TARBALL}" "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${TARBALL}"; \
    echo "${T_SHA256}  /tmp/${TARBALL}" | sha256sum -c -; \
    tar -xzf "/tmp/${TARBALL}" -C /usr/local/bin trivy; \
    rm -f "/tmp/${TARBALL}"; \
    trivy --version

# ---- Gitleaks (pinned, checksum verified) -----------------------------------
ARG GITLEAKS_VERSION=8.30.1
RUN set -eux; \
    case "$(uname -m)" in \
        x86_64)  GL_ARCH=x64 ;; \
        aarch64) GL_ARCH=arm64 ;; \
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

# ---- Python dependencies (hash-locked) ---------------------------------------
WORKDIR /app

COPY requirements.txt requirements-semgrep.txt ./

# The web app's packages go into the image's Python. Semgrep is a separate command-line
# tool, so it gets its own virtual environment and none of its packages load in the app.
RUN pip install --no-cache-dir --require-hashes -r requirements.txt \
    && python -m venv /opt/semgrep \
    && /opt/semgrep/bin/pip install --no-cache-dir --require-hashes -r requirements-semgrep.txt \
    && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep

# Fail the build if any tool the scan needs is missing
RUN git --version \
    && docker --version \
    && trivy --version \
    && gitleaks version \
    && semgrep --version \
    && node --version \
    && npm --version \
    && bob --version

# ---- Application ------------------------------------------------------------
# Settings (.env) are NOT copied into the image (see .dockerignore): pass them at run
# time with --env-file, so secrets never end up in an image layer.
COPY remediator ./remediator
COPY remediator-ui ./remediator-ui

# Scans clone repositories into the working directory
# (the version checks above ran as root and created files in the home directory, so it is chowned too)
RUN useradd --no-create-home --uid 1001 --gid 0 audesec 2>/dev/null || true \
    && chown -R 1001:0 /app "${HOME}" \
    && chmod -R g=u /app "${HOME}"

EXPOSE 8000

# Run as a non-root user. To build images the container needs the Docker socket;
# add the socket's group at run time (see the README), e.g. --group-add "$(stat -c %g /var/run/docker.sock)".
USER 1001

# The app binds to HOST (default 127.0.0.1), which a published port cannot reach from
# outside the container. Unless HOST is set explicitly, bind to the container's own
# address (a specific internal IP, never 0.0.0.0) and require AUDESEC_ACCESS_TOKEN.
# Publish the port on the host's loopback, e.g. -p 127.0.0.1:8000:8000.
# (the image has no `hostname` command, so Python looks the address up)
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -fsS "http://${HOST:-$(python -c 'import socket;print(socket.gethostbyname(socket.gethostname()))')}:${PORT}/healthz" || exit 1

CMD ["sh", "-c", "HOST=${HOST:-$(python -c 'import socket;print(socket.gethostbyname(socket.gethostname()))')} exec python -m remediator.web.app"]
