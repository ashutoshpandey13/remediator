import json
import os


class FeedNotConfigured(Exception):
    """Raised when a findings feed has no usable file configured."""


def load_feed(env_var):
    """
    Load a JSON findings feed (CSPM / runtime / network) from the file named
    by the environment variable `env_var` (an export from Prowler, Falco,
    kube-hunter, ...).

    Raises FeedNotConfigured if the variable is unset or the file is missing,
    so the scan reports the scanner as skipped instead of "0 issues".
    """
    path = os.getenv(env_var)

    if not path:
        raise FeedNotConfigured(f"{env_var} is not set")

    if not os.path.isfile(path):
        raise FeedNotConfigured(f"{env_var} points to a missing file")

    with open(path, "r") as f:
        return json.load(f) or []
