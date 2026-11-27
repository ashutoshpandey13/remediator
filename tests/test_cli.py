import io
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from remediator import cli
from remediator.web import app as web_app


class CliTest(__import__("unittest").TestCase):
    def _run(self, argv, scan):
        def fake_scan(repo_url, scan_id):
            web_app.scan_results.set(scan_id, **scan)

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(web_app, "run_security_scan", fake_scan), \
                redirect_stdout(out), redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_invalid_url_is_rejected_without_scanning(self):
        with mock.patch.object(web_app, "run_security_scan") as run:
            with redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["file:///etc/passwd"]), 2)
        run.assert_not_called()

    def test_successful_scan_prints_pr_and_tickets(self):
        code, out, _ = self._run(
            ["https://github.com/a/b.git"],
            {"status": "complete", "files_updated": ["Dockerfile"],
             "pr_url": "https://github.com/a/b/pull/1", "jira_keys": ["SEC-1"]})
        self.assertEqual(code, 0)
        self.assertIn("https://github.com/a/b/pull/1", out)
        self.assertIn("SEC-1", out)

    def test_failed_scan_returns_1(self):
        code, _, err = self._run(["https://github.com/a/b.git"], {"status": "error", "error": "boom"})
        self.assertEqual(code, 1)
        self.assertIn("boom", err)
