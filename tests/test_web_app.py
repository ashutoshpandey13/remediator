from unittest import mock

from tests.helpers import TempDirTestCase

from remediator.web import app as web_app


class GetJiraBaseUrlTest(TempDirTestCase):
    def _base_url(self, value, configured=True):
        env = {"JIRA_URL": value} if value is not None else {}
        with mock.patch.dict("os.environ", env), \
                mock.patch.object(web_app, "is_jira_configured", return_value=configured):
            return web_app.get_jira_base_url()

    def test_accepted(self):
        for raw, expected in (
            ("https://acme.atlassian.net", "https://acme.atlassian.net"),
            ("https://acme.atlassian.net/", "https://acme.atlassian.net"),
            ("https://jira.example.com/jira", "https://jira.example.com/jira"),
            ("https://jira.example.com/jira/", "https://jira.example.com/jira"),
            ("https://jira.example.com:8443", "https://jira.example.com:8443"),
            ("  https://acme.atlassian.net  ", "https://acme.atlassian.net"),
        ):
            with self.subTest(raw=raw):
                self.assertEqual(self._base_url(raw), expected)

    def test_rejected(self):
        for raw in (
            "http://acme.atlassian.net",
            "ftp://acme.atlassian.net",
            "javascript:alert(1)",
            "https://user:pass@acme.atlassian.net",
            "https://user@acme.atlassian.net",
            "https://acme.atlassian.net/a b",
            "https://acme.atlassian.net/\x01",
            "https://",
            "acme.atlassian.net",
            "",
            None,
        ):
            with self.subTest(raw=raw):
                self.assertIsNone(self._base_url(raw))

    def test_none_when_jira_is_not_configured(self):
        self.assertIsNone(self._base_url("https://acme.atlassian.net", configured=False))
