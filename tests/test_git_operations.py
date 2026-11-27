import io
import json
import os
import subprocess
import types
import urllib.error
from unittest import mock

from tests.helpers import (
    FAKE_TOKEN, TempDirTestCase, clone_local, git, make_origin, read, write,
)

from remediator.integrations import git_operations as go
from remediator.integrations.git_operations import (
    UnsupportedRepositoryHost,
    clone_repository,
    commit_changes,
    create_branch,
    create_pull_request,
    get_default_branch,
    parse_github_repo,
    push_branch,
    scrub_secrets,
    validate_branch_name,
    validate_repo_url,
)


class ValidateRepoUrlTest(TempDirTestCase):
    def test_accepted_forms(self):
        for url in (
            "https://github.com/acme/repo",
            "https://github.com/acme/repo.git",
            "https://github.com/acme/repo/",
            "https://gitlab.example.com:8443/group/sub/repo.git",
            "ssh://git@github.com/acme/repo.git",
            "ssh://git@host.example.com:2222/acme/repo.git",
            "git@github.com:acme/repo.git",
        ):
            with self.subTest(url=url):
                self.assertEqual(validate_repo_url(url), url)

    def test_surrounding_whitespace_is_stripped(self):
        self.assertEqual(validate_repo_url("  https://github.com/acme/repo \n"),
                         "https://github.com/acme/repo")

    def test_rejected_forms(self):
        for url in (
            "",
            "   ",
            "-u",
            "--upload-pack=touch /tmp/pwned",
            "-c core.sshCommand=evil git@github.com:a/b.git",
            "file:///etc/passwd",
            "file:/tmp/repo",
            "/tmp/repo",
            "../repo",
            "ext::sh -c 'touch /tmp/pwned'",
            "ext::sh -c touch% /tmp/pwned",
            "http://github.com/acme/repo",
            "ftp://github.com/acme/repo",
            "git://github.com/acme/repo",
            "https://github.com/acme/repo with space",
            "https://github.com/acme/repo\nsecond-line",
            "https://github.com/acme/repo;rm -rf /",
            "https://github.com/acme/repo$(id)",
            "https://",
            "https://github.com",
            "https://github.com/" + "a" * 3000,
        ):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    validate_repo_url(url)

    def test_non_string_is_rejected(self):
        for value in (None, 5, ["https://github.com/a/b"]):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_repo_url(value)


class CloneRepositoryTest(TempDirTestCase):
    def test_invalid_url_never_reaches_git(self):
        with mock.patch.object(go.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                clone_repository("--upload-pack=x", os.path.join(self.tmp, "c"))
        run.assert_not_called()

    def test_clone_uses_double_dash_and_no_prompt(self):
        target = os.path.join(self.tmp, "c")
        ok = types.SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch.object(go.subprocess, "run", return_value=ok) as run:
            clone_repository("https://github.com/acme/repo.git", target)

        args, kwargs = run.call_args
        self.assertEqual(args[0],
                         ["git", "clone", "--", "https://github.com/acme/repo.git", target])
        self.assertEqual(kwargs["env"]["GIT_TERMINAL_PROMPT"], "0")
        self.assertIn("timeout", kwargs)

    def test_error_text_does_not_contain_url_credentials(self):
        url = f"https://user:{FAKE_TOKEN}@github.com/acme/private.git"
        failed = types.SimpleNamespace(
            returncode=128, stdout="",
            stderr=f"fatal: unable to access '{url}/': The requested URL returned error: 403")
        with mock.patch.object(go.subprocess, "run", return_value=failed):
            with self.assertRaises(Exception) as ctx:
                clone_repository(url, os.path.join(self.tmp, "c"))

        message = str(ctx.exception)
        self.assertIn("Git clone failed", message)
        self.assertNotIn(FAKE_TOKEN, message)
        self.assertNotIn("user:", message)

    def test_timeout_is_reported_without_url(self):
        url = f"https://user:{FAKE_TOKEN}@github.com/acme/private.git"
        with mock.patch.object(go.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired(["git", url], 1)):
            with self.assertRaises(Exception) as ctx:
                clone_repository(url, os.path.join(self.tmp, "c"))
        self.assertNotIn(FAKE_TOKEN, str(ctx.exception))

    def test_clone_and_default_branch_from_local_origin(self):
        bare = make_origin(self.tmp, {"a.txt": "a"}, branch="trunk")
        clone = clone_local(bare, os.path.join(self.tmp, "clone"))

        self.assertEqual(get_default_branch(clone), "trunk")


class ScrubSecretsTest(TempDirTestCase):
    def test_token_and_url_credentials_are_removed(self):
        text = f"failed https://x-access-token:{FAKE_TOKEN}@github.com/a/b and {FAKE_TOKEN}"
        scrubbed = scrub_secrets(text, FAKE_TOKEN)

        self.assertNotIn(FAKE_TOKEN, scrubbed)
        self.assertNotIn("x-access-token", scrubbed)
        self.assertIn("https://github.com/a/b", scrubbed)

    def test_none_secret_is_ignored(self):
        self.assertEqual(scrub_secrets("plain", None, ""), "plain")


class ValidateBranchNameTest(TempDirTestCase):
    def test_accepted(self):
        for name in ("main", "security-remediation-a3f9x2", "release/1.2", "feature_x.y", "A1"):
            with self.subTest(name=name):
                self.assertEqual(validate_branch_name(name), name)

    def test_rejected(self):
        for name in (
            "", "-b", "--force", "a..b", "a//b", "a/", "a.", "a.lock", "/a", ".hidden",
            "has space", "semi;colon", "new\nline", "main\n", "back`tick", "dollar$x", "a" * 101,
            None, 7,
        ):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    validate_branch_name(name)

    def test_create_and_push_reject_bad_names_before_running_git(self):
        with mock.patch.object(go.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                create_branch(self.tmp, "--orphan")
            with self.assertRaises(ValueError):
                push_branch(self.tmp, "-f")
        run.assert_not_called()


class ParseGithubRepoTest(TempDirTestCase):
    def test_all_url_forms(self):
        for url in (
            "https://github.com/acme/repo",
            "https://github.com/acme/repo.git",
            "https://github.com/acme/repo/",
            "https://github.com/acme/repo.git/",
            "https://user:token@github.com/acme/repo.git",
            "https://GitHub.com/acme/repo",
            "ssh://git@github.com/acme/repo.git",
            "ssh://git@github.com/acme/repo",
            "git@github.com:acme/repo.git",
            "git@github.com:acme/repo",
            "  https://github.com/acme/repo  ",
        ):
            with self.subTest(url=url):
                self.assertEqual(parse_github_repo(url), "acme/repo")

    def test_dots_and_dashes_in_names(self):
        self.assertEqual(parse_github_repo("https://github.com/my-org/my.repo-x.git"),
                         "my-org/my.repo-x")

    def test_other_hosts_and_look_alikes_are_rejected(self):
        for url in (
            "https://gitlab.com/acme/repo",
            "https://github.com.evil.com/acme/repo",
            "https://evil.com/github.com/acme/repo",
            "https://evilgithub.com/acme/repo",
            "https://github.com@evil.com/acme/repo",
            "https://user@evil.com/github.com/acme/repo",
            "git@github.com.evil.com:acme/repo.git",
            "git@evil.com:github.com/acme/repo.git",
            "ssh://git@github.com.evil.com/acme/repo.git",
            "http://github.com/acme/repo",
            "https://github.com/acme",
            "https://github.com/acme/repo/extra",
            "",
            None,
        ):
            with self.subTest(url=url):
                with self.assertRaises(UnsupportedRepositoryHost):
                    parse_github_repo(url)


class CommitAndPushTest(TempDirTestCase):
    FILES = {
        "k8s/deploy.yaml": "a: 1\n",
        "Dockerfile": "FROM scratch\n",
        "notes.txt": "keep\n",
    }

    def setUp(self):
        super().setUp()
        self.bare = make_origin(self.tmp, self.FILES)
        self.repo = clone_local(self.bare, os.path.join(self.tmp, "clone"))

    def _modify_everything(self):
        write(self.repo, "k8s/deploy.yaml", "a: 2\n")      # remediated
        write(self.repo, "Dockerfile", "FROM scratch\n# changed\n")  # modified, not listed
        write(self.repo, "stray.bak", "stray\n")            # untracked

    def test_commit_with_paths_only_commits_those_files(self):
        self._modify_everything()
        create_branch(self.repo, "security-remediation-abc123")

        commit_changes(self.repo, "msg", paths=["k8s/deploy.yaml"])

        committed = git(self.repo, "show", "--name-only", "--pretty=format:", "HEAD").split()
        self.assertEqual(committed, ["k8s/deploy.yaml"])
        status = git(self.repo, "status", "--porcelain").splitlines()
        self.assertIn(" M Dockerfile", status)
        self.assertIn("?? stray.bak", status)
        self.assertEqual(len(status), 2)

    def test_commit_rejects_unsafe_paths(self):
        self._modify_everything()
        for paths in (["/etc/passwd"], ["../outside"], ["a/../../b"], [""], [5]):
            with self.subTest(paths=paths):
                with self.assertRaises(ValueError):
                    commit_changes(self.repo, "msg", paths=paths)
        with self.assertRaises(Exception):
            commit_changes(self.repo, "msg", paths=[])
        self.assertEqual(git(self.repo, "rev-list", "--count", "HEAD").strip(), "1")

    def test_legacy_commit_without_paths_stages_everything(self):
        self._modify_everything()

        commit_changes(self.repo, "msg")

        committed = sorted(git(self.repo, "show", "--name-only", "--pretty=format:", "HEAD").split())
        self.assertEqual(committed, ["Dockerfile", "k8s/deploy.yaml", "stray.bak"])

    def test_option_like_file_name_is_a_path_not_an_option(self):
        write(self.repo, "--all", "x\n")
        commit_changes(self.repo, "msg", paths=["--all"])
        committed = git(self.repo, "show", "--name-only", "--pretty=format:", "HEAD").split()
        self.assertEqual(committed, ["--all"])

    def test_push_to_local_origin_keeps_token_out_of_everything(self):
        self._modify_everything()
        branch = "security-remediation-abc123"
        create_branch(self.repo, branch)
        commit_changes(self.repo, "msg", paths=["k8s/deploy.yaml"])

        real_run = subprocess.run
        calls = []

        def recording_run(*args, **kwargs):
            calls.append((args, kwargs))
            return real_run(*args, **kwargs)

        with mock.patch.object(go.subprocess, "run", side_effect=recording_run):
            push_branch(self.repo, branch, FAKE_TOKEN)

        self.assertIn(branch, git(self.bare, "branch", "--list").split())
        for args, kwargs in calls:
            self.assertNotIn(FAKE_TOKEN, " ".join(map(str, args[0])))
        self.assertNotIn(FAKE_TOKEN, git(self.repo, "remote", "get-url", "origin"))
        self.assertNotIn(FAKE_TOKEN, read(self.repo, ".git/config"))
        self.assertNotIn(FAKE_TOKEN, read(self.bare, "config"))

    def test_push_failure_is_reported_without_the_token(self):
        branch = "security-remediation-abc123"
        create_branch(self.repo, branch)
        write(self.repo, "notes.txt", "changed\n")
        commit_changes(self.repo, "msg", paths=["notes.txt"])
        # Origin disappears (push denied / repo gone)
        git(self.repo, "remote", "set-url", "origin", os.path.join(self.tmp, "missing.git"))

        with self.assertRaises(Exception) as ctx:
            push_branch(self.repo, branch, FAKE_TOKEN)

        self.assertIn("Push failed", str(ctx.exception))
        self.assertNotIn(FAKE_TOKEN, str(ctx.exception))

    def test_auth_header_only_for_https_github_remotes(self):
        cases = {
            "https://github.com/acme/repo.git": True,
            "https://user@github.com/acme/repo.git": True,
            "https://gitlab.com/acme/repo.git": False,
            "https://github.com.evil.com/acme/repo.git": False,
            "git@github.com:acme/repo.git": False,
            "ssh://git@github.com/acme/repo.git": False,
            os.path.join(self.tmp, "origin.git"): False,
        }
        for remote, expected in cases.items():
            with self.subTest(remote=remote):
                git(self.repo, "remote", "set-url", "origin", remote)
                env = go._github_auth_env(self.repo, FAKE_TOKEN)

                self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
                if expected:
                    self.assertEqual(env["GIT_CONFIG_KEY_0"], "http.https://github.com/.extraheader")
                    self.assertTrue(env["GIT_CONFIG_VALUE_0"].startswith("Authorization: Basic "))
                    # The token is not in clear text, and not in the URL scope
                    self.assertNotIn(FAKE_TOKEN, env["GIT_CONFIG_VALUE_0"])
                else:
                    self.assertNotIn("GIT_CONFIG_KEY_0", env)
        # and the remote URL never changed to carry the token
        self.assertNotIn(FAKE_TOKEN, read(self.repo, ".git/config"))

    def test_auth_env_without_token_adds_nothing(self):
        env = go._github_auth_env(self.repo, None)
        self.assertNotIn("GIT_CONFIG_COUNT", env)


class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = json.dumps(body).encode() if not isinstance(body, bytes) else body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def http_error(status, body):
    return urllib.error.HTTPError("https://api.github.com/x", status, "err", {}, io.BytesIO(json.dumps(body).encode()))


class CreatePullRequestTest(TempDirTestCase):
    URL = "https://github.com/acme/repo.git"
    PR = "https://github.com/acme/repo/pull/7"

    def _open(self, *responses):
        """Patch the HTTP opener: each call returns (or raises) the next response."""
        return mock.patch.object(go._GITHUB_OPENER, "open", side_effect=list(responses))

    def _request(self, opener, index=0):
        request = opener.call_args_list[index][0][0]
        return request, (json.loads(request.data) if request.data else None)

    def test_request_goes_to_the_github_api_with_the_token_in_the_header_only(self):
        with self._open(FakeResponse(201, {"html_url": self.PR})) as opener:
            url = create_pull_request(self.URL, "security-remediation-abc123", "Title", "Body",
                                      FAKE_TOKEN, base="main")

        self.assertEqual(url, self.PR)
        self.assertEqual(opener.call_count, 1)
        request, payload = self._request(opener)
        self.assertEqual(request.full_url, "https://api.github.com/repos/acme/repo/pulls")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.get_header("Authorization"), f"Bearer {FAKE_TOKEN}")
        self.assertEqual(payload, {"title": "Title", "head": "security-remediation-abc123",
                                   "base": "main", "body": "Body"})
        self.assertNotIn(FAKE_TOKEN, request.full_url)
        self.assertNotIn(FAKE_TOKEN, json.dumps(payload))
        self.assertIn("timeout", opener.call_args[1])

    def test_no_subprocess_and_no_gh_needed(self):
        with mock.patch.object(go.subprocess, "run") as run, \
                self._open(FakeResponse(201, {"html_url": self.PR})):
            create_pull_request(self.URL, "b1", "T", "B", FAKE_TOKEN, base="main")
        run.assert_not_called()

    def test_default_branch_is_looked_up_when_base_is_missing(self):
        with self._open(FakeResponse(200, {"default_branch": "develop"}),
                        FakeResponse(201, {"html_url": self.PR})) as opener:
            create_pull_request(self.URL, "b1", "T", "B", FAKE_TOKEN)

        lookup, _ = self._request(opener, 0)
        self.assertEqual(lookup.full_url, "https://api.github.com/repos/acme/repo")
        self.assertEqual(lookup.get_method(), "GET")
        self.assertEqual(self._request(opener, 1)[1]["base"], "develop")

    def test_token_is_read_from_environment_variable(self):
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": FAKE_TOKEN}):
            with self._open(FakeResponse(201, {"html_url": self.PR})) as opener:
                create_pull_request(self.URL, "b1", "T", "B", base="main")
        self.assertEqual(self._request(opener)[0].get_header("Authorization"), f"Bearer {FAKE_TOKEN}")

    def test_missing_token_fails_before_any_request(self):
        with self._open() as opener:
            with self.assertRaises(Exception) as ctx:
                create_pull_request(self.URL, "b1", "T", "B")
        self.assertIn("GITHUB_TOKEN", str(ctx.exception))
        opener.assert_not_called()

    def test_non_github_host_and_bad_branches_fail_before_any_request(self):
        with self._open() as opener:
            with self.assertRaises(UnsupportedRepositoryHost):
                create_pull_request("https://gitlab.com/acme/repo", "b1", "T", "B", FAKE_TOKEN)
            with self.assertRaises(ValueError):
                create_pull_request(self.URL, "--web", "T", "B", FAKE_TOKEN)
            with self.assertRaises(ValueError):
                create_pull_request(self.URL, "b1", "T", "B", FAKE_TOKEN, base="-x")
        opener.assert_not_called()

    def test_api_error_message_is_reported_and_scrubbed(self):
        error = http_error(422, {"message": "Validation Failed",
                                 "errors": [{"message": f"A pull request already exists {FAKE_TOKEN}"}]})
        with self._open(error):
            with self.assertRaises(Exception) as ctx:
                create_pull_request(self.URL, "b1", "T", "B", FAKE_TOKEN, base="main")
        self.assertIn("PR creation failed (422)", str(ctx.exception))
        self.assertIn("Validation Failed", str(ctx.exception))
        self.assertNotIn(FAKE_TOKEN, str(ctx.exception))

    def test_bad_credentials_and_missing_repo_are_reported(self):
        for status, message in ((401, "Bad credentials"), (404, "Not Found")):
            with self.subTest(status=status):
                with self._open(http_error(status, {"message": message})):
                    with self.assertRaises(Exception) as ctx:
                        create_pull_request(self.URL, "b1", "T", "B", FAKE_TOKEN, base="main")
                self.assertIn(str(status), str(ctx.exception))
                self.assertIn(message, str(ctx.exception))

    def test_default_branch_lookup_failure(self):
        with self._open(http_error(404, {"message": "Not Found"})):
            with self.assertRaises(Exception) as ctx:
                create_pull_request(self.URL, "b1", "T", "B", FAKE_TOKEN)
        self.assertIn("default branch", str(ctx.exception))

    def test_response_without_a_valid_url_is_an_error(self):
        for body in ({}, {"html_url": "http://github.com/x"}, {"html_url": 5}):
            with self.subTest(body=body):
                with self._open(FakeResponse(201, body)):
                    with self.assertRaises(Exception):
                        create_pull_request(self.URL, "b1", "T", "B", FAKE_TOKEN, base="main")

    def test_non_json_error_body_is_handled(self):
        with self._open(FakeResponse(502, b"<html>bad gateway</html>")):
            with self.assertRaises(Exception) as ctx:
                create_pull_request(self.URL, "b1", "T", "B", FAKE_TOKEN, base="main")
        self.assertIn("502", str(ctx.exception))

    def test_network_error_and_timeout(self):
        for error in (urllib.error.URLError(f"unreachable {FAKE_TOKEN}"), TimeoutError("timed out")):
            with self.subTest(error=type(error).__name__):
                with self._open(error):
                    with self.assertRaises(Exception) as ctx:
                        create_pull_request(self.URL, "b1", "T", "B", FAKE_TOKEN, base="main")
                self.assertIn("Could not reach GitHub", str(ctx.exception))
                self.assertNotIn(FAKE_TOKEN, str(ctx.exception))

    def test_redirects_are_never_followed(self):
        handler = go._NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 307, "x", {}, "https://evil.example/"))


class MergePullRequestTest(TempDirTestCase):
    PR = "https://github.com/acme/repo/pull/7"

    def _open(self, *responses):
        return mock.patch.object(go._GITHUB_OPENER, "open", side_effect=list(responses))

    def test_merge_uses_the_api(self):
        with self._open(FakeResponse(200, {"merged": True})) as opener:
            self.assertTrue(go.merge_pull_request(self.PR, FAKE_TOKEN, "squash"))
        request = opener.call_args[0][0]
        self.assertEqual(request.full_url, "https://api.github.com/repos/acme/repo/pulls/7/merge")
        self.assertEqual(request.get_method(), "PUT")
        self.assertEqual(json.loads(request.data), {"merge_method": "squash"})

    def test_not_mergeable_yet_returns_false(self):
        with self._open(http_error(405, {"message": "Required status checks are pending"})):
            self.assertFalse(go.merge_pull_request(self.PR, FAKE_TOKEN))

    def test_invalid_input_is_rejected_before_any_request(self):
        with self._open() as opener:
            with self.assertRaises(Exception):
                go.merge_pull_request("https://evil.example/acme/repo/pull/7", FAKE_TOKEN)
            with self.assertRaises(ValueError):
                go.merge_pull_request(self.PR, FAKE_TOKEN, "--force")
            with self.assertRaises(Exception):
                go.merge_pull_request(self.PR)
        opener.assert_not_called()
