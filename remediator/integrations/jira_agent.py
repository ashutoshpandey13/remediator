from jira import JIRA
from dotenv import load_dotenv

import logging
import os
import re
from urllib.parse import urlparse

load_dotenv()

logger = logging.getLogger(__name__)
JIRA_TIMEOUT_SECONDS = 30

# Initialize JIRA client only if credentials are provided
jira = None
jira_url = os.getenv("JIRA_URL")
jira_email = os.getenv("JIRA_EMAIL")
jira_token = os.getenv("JIRA_API_TOKEN")

if jira_url and jira_email and jira_token:
    try:
        jira = JIRA(
            server=jira_url,
            basic_auth=(jira_email, jira_token),
            timeout=JIRA_TIMEOUT_SECONDS,
            max_retries=1
        )
        logger.info("JIRA integration enabled")
    except Exception as e:
        logger.warning("JIRA integration failed: %s", type(e).__name__)
        jira = None
else:
    logger.info("JIRA integration disabled (credentials not provided)")


# JIRA issue key, e.g. SEC-12
_ISSUE_KEY = re.compile(r"^[A-Z][A-Z0-9_]+-\d+\Z")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# user:token@ inside a URL
_URL_CREDENTIALS = re.compile(r"(?<=//)[^/@\s]+@")

MAX_FIELD_LENGTH = 500
MAX_COMMENT_LENGTH = 4000


def is_jira_configured():
    """True when a JIRA client is available."""
    return jira is not None


def _safe_error(error):
    """Describe an exception without its message (it could echo URLs or credentials)."""
    status = getattr(error, "status_code", None)
    return f"{type(error).__name__} (HTTP {status})" if status else type(error).__name__


def _clean(value, limit=MAX_FIELD_LENGTH):
    """Single-line, length-limited text for use in a ticket."""
    text = _CONTROL_CHARS.sub("", str(value)).replace("\r", " ").replace("\n", " ").strip()
    return text[:limit]


def _is_valid_pr_url(pr_url):
    if not isinstance(pr_url, str) or _CONTROL_CHARS.search(pr_url) or re.search(r"\s", pr_url):
        return False
    try:
        parsed = urlparse(pr_url)
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
    )


def build_ticket_description(finding, repo_url=None):
    """
    Build the ticket text from an allow-list of finding fields.

    The raw finding is never dumped, so nothing unexpected (for example a secret
    value) can end up in the ticket. SECRET findings only carry the rule name and
    file, never the matched value.
    """
    fields = [
        ("Type", "type"),
        ("Severity", "severity"),
        ("ID", "id"),
        ("Title", "title"),
        ("Details", "message"),
        ("File", "file"),
        ("Image", "image"),
        ("Package", "package"),
        ("Installed version", "installed_version"),
        ("Fixed version", "fixed_version"),
        ("Resource", "resource"),
    ]
    lines = []
    if repo_url:
        lines.append(f"Repository: {_clean(_URL_CREDENTIALS.sub('', str(repo_url)))}")
    for label, key in fields:
        value = finding.get(key)
        if value not in (None, ""):
            lines.append(f"{label}: {_clean(value)}")
    return "\n\n".join(lines)


def create_jira_ticket(finding, repo_url=None):
    """
    Create a JIRA ticket for a security finding.
    Returns ticket key if successful, None if JIRA is not configured.
    """
    if not jira:
        return None

    try:
        summary = (
            f"[{finding['severity']}] "
            f"{finding.get('id')}"
        )

        description = build_ticket_description(finding, repo_url)

        issue_dict = {
            "project": {
                "key": os.getenv("JIRA_PROJECT", "SEC")
            },
            "summary": summary,
            "description": description,
            "issuetype": {
                "name": "Task"
            }
        }

        issue = jira.create_issue(
            fields=issue_dict
        )

        return issue.key
    except Exception as e:
        logger.warning("Error creating JIRA ticket: %s", _safe_error(e))
        return None


def link_pr_to_ticket(key, pr_url, summary):
    """
    Add a remote link to the pull request and a summary comment to a JIRA ticket.
    Returns True only if both succeed. Never raises; failures are logged without
    credentials or response bodies.
    """
    if not jira:
        return False

    if not isinstance(key, str) or not _ISSUE_KEY.match(key):
        logger.warning("Cannot link PR: invalid JIRA ticket key")
        return False
    if not _is_valid_pr_url(pr_url):
        logger.warning("Cannot link PR to %s: invalid pull request URL", key)
        return False

    ok = True
    try:
        jira.add_simple_link(
            key,
            {"url": pr_url, "title": "Security remediation pull request"}
        )
    except Exception as e:
        logger.warning("Error adding PR link to %s: %s", key, _safe_error(e))
        ok = False

    try:
        text = _CONTROL_CHARS.sub("", str(summary or "")).strip()[:MAX_COMMENT_LENGTH]
        jira.add_comment(key, f"{text}\n\nPull request: {pr_url}".strip())
    except Exception as e:
        logger.warning("Error adding PR comment to %s: %s", key, _safe_error(e))
        ok = False

    return ok
