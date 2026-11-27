"""
Offline end-to-end checks of run_security_scan.

Everything that needs the network or a tool is stubbed (scanners, docker, Bob/AI, GitHub API, JIRA).
Git is real but local: the "remote" is a bare repository in a temp dir. Each test runs in
its own temp working directory, so nothing is written to the real repository.
"""
import contextlib
import io
import json
import os
import types
from unittest import mock

from tests.helpers import (
    FAKE_TOKEN, K8S_POD, FakeJira, TempDirTestCase, clone_local, git, make_origin,
)

from remediator.integrations import jira_agent
from remediator.web import app as web_app

GITHUB_URL = "https://github.com/acme/sample.git"
PR_URL = "https://github.com/acme/sample/pull/7"

SAMPLE_REPO = {
    "k8s/deploy.yaml": K8S_POD,
    "svc/Dockerfile": "FROM scratch\n",
    "README.md": "# sample\n",
}

K8S_FINDING = {"id": "KSV001", "title": "Privileged", "severity": "HIGH", "message": "m"}
CVE_FINDINGS = {
    "before": [
        {"cve": "CVE-1", "severity": "CRITICAL", "package": "openssl", "installed": "1", "fixed": "2"},
        {"cve": "CVE-2", "severity": "HIGH", "package": "zlib", "installed": "1", "fixed": "2"},
    ],
    "after": [
        {"cve": "CVE-2", "severity": "HIGH", "package": "zlib", "installed": "1", "fixed": "2"},
    ],
}


class ScanFlowTest(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.work = os.path.join(self.tmp, "work")
        os.makedirs(self.work)
        previous = os.getcwd()
        os.chdir(self.work)
        self.addCleanup(os.chdir, previous)

        self.pr_calls = []
        self.cspm_scanned = []
        self.cspm_result = {}
        self.removed_images = []
        self.clone_dirs = []
        self.change_files = True
        self.token = FAKE_TOKEN
        self.jira = FakeJira()
        self.bare = None
        self.break_origin = False
        self.repo_files = SAMPLE_REPO
        self._counter = 0

    # ---- stubs -------------------------------------------------------------
    def _fake_clone(self, url, target):
        self.clone_dirs.append(target)
        clone_local(self.bare, target)
        if self.break_origin:
            git(target, "remote", "set-url", "origin", os.path.join(self.tmp, "gone.git"))
        return os.path.abspath(target)

    def _fake_create_pr(self, repo_url, branch, title, body, token=None, base=None):
        self.pr_calls.append({"repo_url": repo_url, "branch": branch, "title": title,
                              "body": body, "token": token, "base": base})
        return PR_URL

    def _fake_k8s_summary(self, scan_result):
        # one finding until the manifest has been changed
        return [dict(K8S_FINDING)] if scan_result == "unfixed" else []

    def _fake_scan_k8s(self, path):
        with open(path) as f:
            return "fixed" if "# fixed" in f.read() else "unfixed"

    def _fake_scan_cspm(self, path):
        self.cspm_scanned.append(path)
        return self.cspm_result

    def _fake_remediation(self, findings_json, deployment, package):
        fixed = deployment + ("# fixed\n" if self.change_files else "")
        return "===FIXED_DEPLOYMENT===\n" + fixed

    def _fake_dockerfile_fix(self, original, findings):
        return original + ("# fixed\n" if self.change_files else "")

    def _fake_build(self, repo_dir, dockerfile_rel, tag):
        # a build leaves untracked junk in the clone; it must never be committed
        with open(os.path.join(repo_dir, "stray-build-output.log"), "w") as f:
            f.write("junk\n")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    def _run(self, repo_url=GITHUB_URL, token="default", jira="default", files=None):
        """Run a whole scan against a fresh local origin. Returns (scan_id, result dict)."""
        self._counter += 1
        scan_id = f"test_{self.id().split('.')[-1]}_{self._counter}"
        self.bare = make_origin(os.path.join(self.tmp), files or self.repo_files)
        token = self.token if token == "default" else token
        jira = self.jira if jira == "default" else jira

        env = {"GITHUB_TOKEN": token} if token else {}
        env.update({"BOB_API_KEY": "fake-bob-key", "JIRA_URL": "https://jira.example.com/"})
        stubs = {
            "ensure_bob_configured": lambda: None,
            "cleanup_stale_clones": lambda *a, **k: None,
            "remove_stale_images": lambda: None,
            "clone_repository": self._fake_clone,
            "scan_k8s_config": self._fake_scan_k8s,
            "summarize_findings": self._fake_k8s_summary,
            "build_docker_image": self._fake_build,
            "scan_image": lambda tag: tag,
            "summarize_cves": lambda tag: [dict(f) for f in CVE_FINDINGS[
                "after" if tag.endswith("-fixed") else "before"]],
            "scan_code": mock.Mock(side_effect=FileNotFoundError),
            "scan_secrets": mock.Mock(side_effect=FileNotFoundError),
            "scan_cspm": self._fake_scan_cspm,
            "generate_remediation": self._fake_remediation,
            "generate_dockerfile_remediation": self._fake_dockerfile_fix,
            "create_pull_request": self._fake_create_pr,
            "remove_docker_images": lambda tags: self.removed_images.extend(tags),
        }
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.dict(os.environ, env))
            if not token:
                os.environ.pop("GITHUB_TOKEN", None)
            for name, stub in stubs.items():
                stack.enter_context(mock.patch.object(web_app, name, stub))
            stack.enter_context(mock.patch.object(jira_agent, "jira", jira))
            with self.assertLogs("remediator.web.app", level="DEBUG") as logs:
                web_app.run_security_scan(repo_url, scan_id)
        self.logs = "\n".join(logs.output)
        return scan_id, web_app.scan_results[scan_id]

    # ---- helpers -----------------------------------------------------------
    def _remote_branches(self):
        return [b for b in git(self.bare, "branch", "--list").replace("*", "").split()
                if b.startswith("security-remediation-")]

    def _assert_no_leftovers(self, result):
        self.assertEqual(result["status"], "complete")
        for path in self.clone_dirs:
            self.assertFalse(os.path.exists(path), "clone was not removed")
        blob = json.dumps(result, default=str) + self.logs
        self.assertNotIn(FAKE_TOKEN, blob)
        self.assertNotIn("fake-bob-key", blob)

    def _step(self, result, step):
        return [s for s in result["steps"] if s["step"] == step][-1]

    # ---- scenarios ---------------------------------------------------------
    def test_pr_created_and_tickets_linked(self):
        _, result = self._run()

        self._assert_no_leftovers(result)
        self.assertEqual(result["pr_status"], "created")
        self.assertEqual(result["pr_url"], PR_URL)
        self.assertEqual(result["default_branch"], "main")
        self.assertEqual(result["files_updated"], ["k8s/deploy.yaml", "svc/Dockerfile"])

        self.assertEqual(len(self.pr_calls), 1)
        call = self.pr_calls[0]
        self.assertEqual(call["base"], "main")
        self.assertEqual(call["token"], FAKE_TOKEN)
        self.assertRegex(call["branch"], r"^security-remediation-[a-z0-9]{6}$")
        self.assertIn("`k8s/deploy.yaml`", call["body"])
        self.assertIn("SEC-1", call["body"])
        self.assertIn("| Kubernetes misconfigurations | 1 | 0 | 1 |", call["body"])
        self.assertIn("| Container CVEs | 2 | 1 | 1 |", call["body"])

        # the branch is on origin and contains exactly the remediated files
        self.assertEqual(self._remote_branches(), [call["branch"]])
        changed = git(self.bare, "diff", "--name-only", "main", call["branch"]).split()
        self.assertEqual(sorted(changed), ["k8s/deploy.yaml", "svc/Dockerfile"])

        self.assertEqual(result["jira_keys"], ["SEC-1", "SEC-2", "SEC-3"])
        self.assertEqual(result["jira_links"], {"SEC-1": True, "SEC-2": True, "SEC-3": True})
        self.assertEqual(result["jira_base_url"], "https://jira.example.com")
        self.assertEqual(len(self.jira.links), 3)
        self.assertTrue(all(url["url"] == PR_URL for _, url in self.jira.links))
        self.assertEqual(self._step(result, web_app.STEP_PR)["status"], "success")
        self.assertEqual(self._step(result, web_app.STEP_JIRA_LINK)["status"], "success")
        self.assertEqual(result["metrics"]["total"]["before"], 3)
        self.assertEqual(result["metrics"]["total"]["after"], 1)
        # every image that was built is cleaned up
        self.assertEqual(len(self.removed_images), 2)
        self.assertTrue(any(t.endswith("-fixed") for t in self.removed_images))

    def test_one_ticket_failing_to_link_does_not_stop_the_others(self):
        self.jira = FakeJira(fail_link_for={"SEC-2"})

        with contextlib.redirect_stdout(io.StringIO()):
            _, result = self._run()

        self._assert_no_leftovers(result)
        self.assertEqual(result["jira_links"], {"SEC-1": True, "SEC-2": False, "SEC-3": True})
        self.assertEqual(result["pr_status"], "created")
        self.assertNotIn("SECRETPASS", json.dumps(result, default=str) + self.logs)

    def test_no_token_means_no_branch_no_pr_no_links(self):
        _, result = self._run(token="")

        self._assert_no_leftovers(result)
        self.assertEqual(result["pr_status"], "no_token")
        self.assertIsNone(result["pr_url"])
        self.assertEqual(self.pr_calls, [])
        self.assertEqual(self._remote_branches(), [])
        self.assertEqual(self.jira.links, [])
        self.assertEqual(result["jira_links"], {})
        self.assertEqual(len(result["jira_keys"]), 3)
        self.assertEqual(self._step(result, web_app.STEP_PR)["status"], "info")

    def test_no_changes_means_no_branch_and_no_pr(self):
        self.change_files = False

        _, result = self._run()

        self._assert_no_leftovers(result)
        self.assertEqual(result["pr_status"], "no_changes")
        self.assertEqual(result["files_updated"], [])
        self.assertEqual(self.pr_calls, [])
        self.assertEqual(self._remote_branches(), [])
        self.assertEqual(self.jira.links, [])

    def test_push_denied_means_no_pr(self):
        self.break_origin = True

        _, result = self._run()

        self._assert_no_leftovers(result)
        self.assertEqual(result["pr_status"], "push_failed")
        self.assertIsNone(result["pr_url"])
        self.assertEqual(self.pr_calls, [])
        self.assertEqual(self.jira.links, [])
        self.assertEqual(self._remote_branches(), [])
        self.assertIn("no pull request was created", result["pr_message"])
        self.assertNotIn("Traceback (most recent call last)\n  File", result["pr_message"])

    def test_non_github_url_reports_unsupported_and_creates_nothing(self):
        _, result = self._run(repo_url="https://gitlab.com/acme/sample.git")

        self._assert_no_leftovers(result)
        self.assertEqual(result["pr_status"], "unsupported_host")
        self.assertIsNone(result["pr_url"])
        self.assertEqual(self.pr_calls, [])
        self.assertEqual(self._remote_branches(), [])
        # scanning and remediation still ran
        self.assertEqual(result["files_updated"], ["k8s/deploy.yaml", "svc/Dockerfile"])

    def test_jira_not_configured_still_raises_the_pr(self):
        _, result = self._run(jira=None)

        self._assert_no_leftovers(result)
        self.assertEqual(result["pr_status"], "created")
        self.assertEqual(result["jira_keys"], [])
        self.assertEqual(result["jira_links"], {})
        self.assertNotIn("jira_base_url", result)
        self.assertEqual(self._step(result, web_app.STEP_JIRA_LINK)["status"], "info")
        self.assertNotIn("JIRA tickets", self.pr_calls[0]["body"])

    def test_repo_without_manifests_or_dockerfile_completes_cleanly(self):
        _, result = self._run(files={"app.py": "print('hi')\n", "README.md": "x\n"})

        self._assert_no_leftovers(result)
        self.assertEqual(result["pr_status"], "no_changes")
        self.assertEqual(result["files_updated"], [])
        self.assertEqual(result["metrics"]["total"]["before"], 0)
        self.assertEqual(self.pr_calls, [])
        self.assertEqual(self.removed_images, [])
        self.assertEqual(self._step(result, web_app.STEP_IMAGE)["status"], "info")
        self.assertIn("skipping image scan", self._step(result, web_app.STEP_IMAGE)["message"])

    def test_cloud_posture_scans_the_clone_and_reports_iac_findings(self):
        self.cspm_result = {"Results": [
            {"Target": "infra/main.tf", "Type": "terraform", "Misconfigurations": [
                {"ID": "AWS-0107", "Title": "Open SSH", "Severity": "HIGH", "Message": "m",
                 "CauseMetadata": {"Resource": "aws_security_group.web"}}]},
            # Kubernetes and Dockerfile results already have their own scan steps
            {"Target": "k8s/deploy.yaml", "Type": "kubernetes", "Misconfigurations": [
                {"ID": "KSV001", "Title": "t", "Severity": "HIGH", "Message": "m"}]},
        ]}
        files = dict(SAMPLE_REPO, **{"infra/main.tf": 'resource "aws_s3_bucket" "d" {}\n'})

        with mock.patch.object(web_app, "generate_advisory") as advisory:
            _, result = self._run(files=files)

        self._assert_no_leftovers(result)
        self.assertEqual(len(self.cspm_scanned), 1)
        self.assertTrue(os.path.basename(self.cspm_scanned[0]).startswith("security-remediation-clone-"))
        self.assertEqual(result["metrics"]["advisory"], {"cspm": 1, "runtime": 0, "network": 0})
        self.assertEqual([f["file"] for f in advisory.call_args[0][0]], ["infra/main.tf"])
        self.assertNotIn("infra/main.tf", result["files_updated"])
        self.assertEqual(self._step(result, web_app.STEP_CSPM)["status"], "success")

    def test_runtime_and_network_are_skipped_when_no_feed_is_configured(self):
        env = {name: "" for name in ("CSPM_FINDINGS_PATH", "RUNTIME_FINDINGS_PATH", "NETWORK_FINDINGS_PATH")}
        with mock.patch.dict(os.environ, env):
            _, result = self._run()

        self._assert_no_leftovers(result)
        for step in (web_app.STEP_RUNTIME, web_app.STEP_NETWORK):
            progress = self._step(result, step)
            self.assertEqual(progress["status"], "info")
            self.assertIn("is not set", progress["message"])
        self.assertEqual(result["metrics"]["advisory"], {"cspm": 0, "runtime": 0, "network": 0})

    def test_findings_feeds_are_scanned_and_get_advisory(self):
        feeds = {
            "CSPM_FINDINGS_PATH": [{"CheckID": "S3_PUBLIC_ACCESS", "Severity": "CRITICAL",
                                    "Resource": "bucket", "Description": "public"}],
            "RUNTIME_FINDINGS_PATH": [{"rule": "Terminal shell in container", "priority": "HIGH",
                                       "output": "shell"}],
            "NETWORK_FINDINGS_PATH": [{"id": "KHV001", "severity": "HIGH", "description": "dashboard"}],
        }
        env = {}
        for name, payload in feeds.items():
            path = os.path.join(self.tmp, name.lower() + ".json")
            with open(path, "w") as f:
                json.dump(payload, f)
            env[name] = path

        with mock.patch.dict(os.environ, env), \
                mock.patch.object(web_app, "generate_advisory", return_value="- **x**: fix") as advisory:
            _, result = self._run()

        self._assert_no_leftovers(result)
        self.assertEqual(result["metrics"]["advisory"], {"cspm": 1, "runtime": 1, "network": 1})
        self.assertEqual({f["type"] for f in advisory.call_args[0][0]}, {"CSPM", "RUNTIME", "NETWORK"})
        self.assertEqual(result["advisory"], "- **x**: fix")
        for step in (web_app.STEP_CSPM, web_app.STEP_RUNTIME, web_app.STEP_NETWORK):
            self.assertEqual(self._step(result, step)["status"], "success")

    def test_nested_and_multiple_assets_are_all_handled(self):
        files = {
            "a/deploy.yaml": K8S_POD,
            "b/c/deploy.yaml": K8S_POD,
            "a/Dockerfile": "FROM scratch\n",
            "b/Dockerfile.prod": "FROM scratch\n",
        }

        _, result = self._run(files=files)

        self._assert_no_leftovers(result)
        self.assertEqual(result["files_updated"],
                         ["a/Dockerfile", "a/deploy.yaml", "b/Dockerfile.prod", "b/c/deploy.yaml"])
        self.assertEqual(result["pr_status"], "created")
        # metrics aggregate over every file: 2 manifests x 1 finding, 2 images x 2 CVEs
        self.assertEqual(result["metrics"]["kubernetes"]["before"], 2)
        self.assertEqual(result["metrics"]["cve"]["before"], 4)
        self.assertEqual(len(self.removed_images), 4)


class ApiScanValidationTest(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.client = web_app.app.test_client()

    def test_invalid_urls_are_rejected_with_400(self):
        for url in ("--upload-pack=x", "-u", "file:///etc/passwd", "ext::sh -c id",
                    "http://github.com/a/b", "https://github.com/a/b c", "", None):
            with self.subTest(url=url):
                with mock.patch.object(web_app.threading, "Thread") as thread:
                    response = self.client.post("/api/scan", json={"repo_url": url})
                self.assertEqual(response.status_code, 400)
                self.assertIn("error", response.get_json())
                thread.assert_not_called()

    def test_valid_url_starts_a_scan_thread(self):
        with mock.patch.object(web_app.threading, "Thread") as thread:
            response = self.client.post("/api/scan", json={"repo_url": GITHUB_URL})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "started")
        thread.assert_called_once()
        thread.return_value.start.assert_called_once()

    def test_unknown_scan_id_is_404(self):
        self.assertEqual(self.client.get("/api/scan/does-not-exist").status_code, 404)

    def test_index_renders_pr_and_jira_steps(self):
        html = self.client.get("/").get_data(as_text=True)

        self.assertIn(f'data-step="{web_app.STEP_PR}"', html)
        self.assertIn(f'data-step="{web_app.STEP_JIRA_LINK}"', html)
        self.assertIn("deliveryBody", html)
