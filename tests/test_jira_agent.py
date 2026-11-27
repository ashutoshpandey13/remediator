import io
from contextlib import redirect_stdout
from unittest import mock

from tests.helpers import FAKE_TOKEN, FakeJira, TempDirTestCase

from remediator.integrations import jira_agent


class BuildTicketDescriptionTest(TempDirTestCase):
    def test_contains_allow_listed_fields(self):
        finding = {
            "type": "CVE", "id": "CVE-2024-1", "severity": "HIGH", "package": "openssl",
            "installed_version": "1.0", "fixed_version": "1.1", "file": "svc/Dockerfile",
            "image": "repo-scan-abc123-0",
        }

        text = jira_agent.build_ticket_description(finding, "https://github.com/acme/repo")

        for expected in ("Repository: https://github.com/acme/repo", "Type: CVE", "Severity: HIGH",
                         "ID: CVE-2024-1", "File: svc/Dockerfile", "Package: openssl",
                         "Installed version: 1.0", "Fixed version: 1.1"):
            self.assertIn(expected, text)

    def test_secret_value_and_unknown_fields_never_appear(self):
        finding = {
            "type": "SECRET", "id": "aws-access-key", "severity": "CRITICAL",
            "message": "AWS key found", "file": "src/config.js",
            "Match": "AKIAFAKEFAKEFAKEFAKE", "secret": FAKE_TOKEN, "Secret": FAKE_TOKEN,
            "raw": {"token": FAKE_TOKEN},
        }

        text = jira_agent.build_ticket_description(finding)

        self.assertNotIn("AKIAFAKE", text)
        self.assertNotIn(FAKE_TOKEN, text)
        self.assertIn("aws-access-key", text)
        self.assertIn("src/config.js", text)

    def test_repo_url_credentials_are_stripped(self):
        text = jira_agent.build_ticket_description(
            {"type": "CVE", "id": "X", "severity": "HIGH"},
            f"https://user:{FAKE_TOKEN}@github.com/acme/repo.git")

        self.assertNotIn(FAKE_TOKEN, text)
        self.assertIn("https://github.com/acme/repo.git", text)

    def test_values_are_single_line_and_length_limited(self):
        text = jira_agent.build_ticket_description(
            {"type": "SAST", "id": "r", "severity": "HIGH",
             "message": "line1\nline2\x00" + "x" * 5000})

        message_line = [l for l in text.split("\n\n") if l.startswith("Details:")][0]
        self.assertNotIn("\n", message_line)
        self.assertNotIn("\x00", message_line)
        self.assertLessEqual(len(message_line), len("Details: ") + jira_agent.MAX_FIELD_LENGTH)


class LinkPrToTicketTest(TempDirTestCase):
    PR = "https://github.com/acme/repo/pull/7"

    def _with_jira(self, fake):
        patcher = mock.patch.object(jira_agent, "jira", fake)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_adds_remote_link_and_comment(self):
        fake = FakeJira()
        self._with_jira(fake)

        self.assertTrue(jira_agent.link_pr_to_ticket("SEC-1", self.PR, "Fixed 3 things"))

        self.assertEqual(fake.links[0][0], "SEC-1")
        self.assertEqual(fake.links[0][1]["url"], self.PR)
        self.assertEqual(fake.comments[0][0], "SEC-1")
        self.assertIn("Fixed 3 things", fake.comments[0][1])
        self.assertIn(self.PR, fake.comments[0][1])

    def test_invalid_keys_make_no_jira_calls(self):
        fake = FakeJira()
        self._with_jira(fake)

        for key in ("sec-1", "SEC", "SEC-", "1-SEC", "SEC-1; DROP", "SEC-1\n", "", None, 5):
            with self.subTest(key=key):
                self.assertFalse(jira_agent.link_pr_to_ticket(key, self.PR, "s"))
        self.assertEqual((fake.links, fake.comments), ([], []))

    def test_invalid_pr_urls_make_no_jira_calls(self):
        fake = FakeJira()
        self._with_jira(fake)

        for url in (
            "http://github.com/acme/repo/pull/7",
            "javascript:alert(1)",
            "ftp://github.com/x",
            "https://user:pw@github.com/acme/repo/pull/7",
            "https://",
            "https://github.com/acme/repo/pull/7 extra",
            "https://github.com/acme/repo/pull/7\n",
            "",
            None,
        ):
            with self.subTest(url=url):
                self.assertFalse(jira_agent.link_pr_to_ticket("SEC-1", url, "s"))
        self.assertEqual((fake.links, fake.comments), ([], []))

    def test_link_failure_still_attempts_comment_and_leaks_nothing(self):
        fake = FakeJira(fail_link_for={"SEC-1"})
        self._with_jira(fake)

        with self.assertLogs(jira_agent.logger, level="WARNING") as logs:
            result = jira_agent.link_pr_to_ticket("SEC-1", self.PR, "s")

        self.assertFalse(result)
        self.assertEqual(len(fake.comments), 1)
        self.assertIn("RuntimeError", "\n".join(logs.output))
        self.assertNotIn("SECRETPASS", "\n".join(logs.output))

    def test_comment_failure_returns_false_but_link_was_added(self):
        fake = FakeJira(fail_comment_for={"SEC-1"})
        self._with_jira(fake)

        with redirect_stdout(io.StringIO()):
            self.assertFalse(jira_agent.link_pr_to_ticket("SEC-1", self.PR, "s"))
        self.assertEqual(len(fake.links), 1)

    def test_failure_of_one_ticket_does_not_affect_the_next_call(self):
        fake = FakeJira(fail_link_for={"SEC-1"})
        self._with_jira(fake)

        with redirect_stdout(io.StringIO()):
            results = [jira_agent.link_pr_to_ticket(k, self.PR, "s") for k in ("SEC-1", "SEC-2")]

        self.assertEqual(results, [False, True])

    def test_not_configured_returns_false(self):
        with mock.patch.object(jira_agent, "jira", None):
            self.assertFalse(jira_agent.is_jira_configured())
            self.assertFalse(jira_agent.link_pr_to_ticket("SEC-1", self.PR, "s"))


class CreateJiraTicketTest(TempDirTestCase):
    FINDING = {"type": "CVE", "id": "CVE-1", "severity": "HIGH", "file": "Dockerfile"}

    def test_not_configured_returns_none(self):
        with mock.patch.object(jira_agent, "jira", None):
            self.assertIsNone(jira_agent.create_jira_ticket(self.FINDING, "https://github.com/a/b"))

    def test_configured_creates_issue_with_safe_description(self):
        fake = FakeJira()
        with mock.patch.object(jira_agent, "jira", fake), \
                mock.patch.dict("os.environ", {"JIRA_PROJECT": "PROJ"}):
            key = jira_agent.create_jira_ticket(
                {**self.FINDING, "secret": FAKE_TOKEN}, f"https://u:{FAKE_TOKEN}@github.com/a/b")

        self.assertEqual(key, "SEC-1")
        fields = fake.issues[0]
        self.assertEqual(fields["project"]["key"], "PROJ")
        self.assertEqual(fields["summary"], "[HIGH] CVE-1")
        self.assertNotIn(FAKE_TOKEN, fields["description"])

    def test_creation_failure_returns_none_and_does_not_raise(self):
        class Broken:
            def create_issue(self, fields):
                raise RuntimeError("https://user:SECRETPASS@jira.example.com")

        out = io.StringIO()
        with mock.patch.object(jira_agent, "jira", Broken()), redirect_stdout(out):
            self.assertIsNone(jira_agent.create_jira_ticket(self.FINDING))
        self.assertNotIn("SECRETPASS", out.getvalue())
