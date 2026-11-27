"""
Shared helpers for the offline test suite.

Import this module BEFORE any `remediator` module. On import it makes the tests
independent of the machine they run on:

- .env is never read (python-dotenv's load_dotenv is replaced by a no-op),
- credentials and tool settings are removed from the environment,
- the user's/system git configuration is ignored and git never prompts.

The tests need no network, docker, trivy, bob or real credentials.
"""
import os
import shutil
import subprocess
import tempfile
import types
import unittest

import dotenv

dotenv.load_dotenv = lambda *args, **kwargs: False

_REMOVED_PREFIXES = ("JIRA_", "BOB_", "GITHUB_", "GH_", "GIT_CONFIG_")
_REMOVED_NAMES = ()
for _name in list(os.environ):
    if _name.startswith(_REMOVED_PREFIXES) or _name in _REMOVED_NAMES:
        del os.environ[_name]
os.environ["GIT_CONFIG_GLOBAL"] = os.devnull
os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
os.environ["GIT_TERMINAL_PROMPT"] = "0"

# Obviously fake; it only exists to check that it never leaks
FAKE_TOKEN = "ghp_FAKE0TOKEN0FOR0TESTS0ONLY0123456789"

K8S_POD = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"


def write(root, rel_path, text=""):
    """Create a file (and its directories) under root."""
    path = os.path.join(root, rel_path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    return path


def read(root, rel_path):
    with open(os.path.join(root, rel_path)) as f:
        return f.read()


def git(cwd, *args):
    """Run git in cwd and return stdout (raises on failure)."""
    return subprocess.run(["git", *args], cwd=cwd, check=True,
                          capture_output=True, text=True).stdout


def make_origin(tmp, files, branch="main"):
    """A local bare repository holding `files` on `branch`. Returns its path."""
    bare = os.path.join(tmp, "origin.git")
    seed = os.path.join(tmp, "seed")
    git(tmp, "init", "--quiet", "--bare", "-b", branch, bare)
    git(tmp, "init", "--quiet", "-b", branch, seed)
    for rel_path, text in files.items():
        write(seed, rel_path, text)
    git(seed, "add", ".")
    git(seed, "-c", "user.name=Test", "-c", "user.email=test@example.com",
        "commit", "--quiet", "-m", "seed")
    git(seed, "remote", "add", "origin", bare)
    git(seed, "push", "--quiet", "origin", branch)
    return bare


def clone_local(bare, target):
    """Clone a local repository the way the app's clone step would."""
    git(os.path.dirname(target), "clone", "--quiet", bare, target)
    return target


class TempDirTestCase(unittest.TestCase):
    """Gives every test its own temp dir that is always removed."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="remediator-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)


class FakeJira:
    """Stands in for the JIRA client: records calls, can fail for chosen tickets."""

    def __init__(self, fail_link_for=(), fail_comment_for=()):
        self.issues = []
        self.links = []
        self.comments = []
        self.fail_link_for = set(fail_link_for)
        self.fail_comment_for = set(fail_comment_for)

    def create_issue(self, fields):
        self.issues.append(fields)
        return types.SimpleNamespace(key=f"SEC-{len(self.issues)}")

    def add_simple_link(self, key, obj):
        if key in self.fail_link_for:
            raise RuntimeError("boom https://user:SECRETPASS@jira.example.com/rest")
        self.links.append((key, obj))

    def add_comment(self, key, text):
        if key in self.fail_comment_for:
            raise RuntimeError("boom https://user:SECRETPASS@jira.example.com/rest")
        self.comments.append((key, text))
