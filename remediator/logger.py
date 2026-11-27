import logging

_audit_logger = logging.getLogger("audesec.activity")


def log_activity(message):
    """Record a workflow milestone (goes to the normal log stream, so it is captured with the rest)."""
    _audit_logger.info("%s", message)
