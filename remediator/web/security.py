"""
Request security for the web UI: access token, Host check, security headers.

The app starts scans that clone repositories, build Docker images and push branches
with GITHUB_TOKEN, so the API must never be open to anyone who can reach the port.
"""
import hmac
import logging
import os
import re
import secrets
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Access tokens shorter than this are rejected at startup
MIN_TOKEN_LENGTH = 24

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")

# Everything is served from this origin: no inline scripts or styles, no external resources
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cache-Control": "no-store",
}

_BEARER = re.compile(r"^Bearer ([^\s]+)\Z")


def get_access_token():
    """The shared access token from AUDESEC_ACCESS_TOKEN ('' when not configured)."""
    return os.getenv("AUDESEC_ACCESS_TOKEN", "").strip()


def is_loopback(host):
    return host in LOOPBACK_HOSTS


def validate_startup(host, token):
    """
    Refuse an unsafe configuration before the server starts.

    - The token, when set, must be long enough to resist guessing.
    - A server that is reachable from other machines (any non-loopback HOST) needs a token.
    - HOST must never be 0.0.0.0 / :: (all interfaces).

    Raises:
        RuntimeError: With a message that says what to change
    """
    if host in ("0.0.0.0", "::", ""):
        raise RuntimeError(
            "HOST must not bind to all interfaces. Use 127.0.0.1, or the specific address "
            "the server should listen on."
        )
    if token and len(token) < MIN_TOKEN_LENGTH:
        raise RuntimeError(
            f"AUDESEC_ACCESS_TOKEN is too short (minimum {MIN_TOKEN_LENGTH} characters). "
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )
    if not token and not is_loopback(host):
        raise RuntimeError(
            "AUDESEC_ACCESS_TOKEN is required when HOST is not a loopback address. "
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )


def token_matches(provided, expected):
    """Constant-time comparison."""
    if not provided or not expected:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


def request_token(headers):
    """The bearer token of a request ('' if there is none)."""
    match = _BEARER.match(headers.get("Authorization", ""))
    return match.group(1) if match else ""


def allowed_hosts():
    """
    Host header values accepted by the server (defends against DNS rebinding).
    ALLOWED_HOSTS is a comma-separated list of extra names, e.g. for a reverse proxy.
    """
    extra = [h.strip().lower() for h in os.getenv("ALLOWED_HOSTS", "").split(",") if h.strip()]
    return set(LOOPBACK_HOSTS) | set(extra)


def host_is_allowed(host_header, bind_host):
    """True when the Host header names this server (the port is ignored)."""
    if not host_header:
        return False
    try:
        name = urlparse(f"//{host_header}").hostname or ""
    except ValueError:
        return False
    name = name.lower()
    return name in allowed_hosts() or name == (bind_host or "").lower()


def new_scan_id():
    """Unguessable scan id (the id is also the key to read a scan's results)."""
    return f"scan_{secrets.token_urlsafe(12)}"


SCAN_ID_PATTERN = re.compile(r"^scan_[A-Za-z0-9_-]{16}\Z")
