import json
import os
from unittest import mock

from tests.helpers import TempDirTestCase

from remediator.findings import combine_findings
from remediator.scanners.cspm_scanner import scan_cspm_feed, summarize_cspm_feed
from remediator.scanners.feed_loader import FeedNotConfigured, load_feed
from remediator.scanners.network_scanner import scan_network, summarize_network
from remediator.scanners.runtime_scanner import scan_runtime, summarize_runtime


class FeedTest(TempDirTestCase):
    def _feed(self, payload):
        path = os.path.join(self.tmp, "feed.json")
        with open(path, "w") as f:
            json.dump(payload, f)
        return path

    def test_load_feed(self):
        with mock.patch.dict(os.environ, {"X_FEED": self._feed([{"a": 1}])}):
            self.assertEqual(load_feed("X_FEED"), [{"a": 1}])

    def test_not_configured_or_missing(self):
        with mock.patch.dict(os.environ, {"X_FEED": ""}):
            with self.assertRaises(FeedNotConfigured):
                load_feed("X_FEED")
        with mock.patch.dict(os.environ, {"X_FEED": os.path.join(self.tmp, "nope.json")}):
            with self.assertRaises(FeedNotConfigured):
                load_feed("X_FEED")

    def test_cspm_feed(self):
        feed = [{"CheckID": "S3", "Severity": "HIGH", "Resource": "b", "Description": "d"}]
        with mock.patch.dict(os.environ, {"CSPM_FINDINGS_PATH": self._feed(feed)}):
            self.assertEqual(summarize_cspm_feed(scan_cspm_feed()), [
                {"id": "S3", "severity": "HIGH", "message": "d", "resource": "b"}])

    def test_runtime_and_network_feeds_are_normalised(self):
        runtime = [{"rule": "Shell", "priority": "HIGH", "output": "o"}]
        network = [{"id": "KHV1", "severity": "LOW", "description": "d"}]
        with mock.patch.dict(os.environ, {"RUNTIME_FINDINGS_PATH": self._feed(runtime)}):
            runtime_findings = summarize_runtime(scan_runtime())
        with mock.patch.dict(os.environ, {"NETWORK_FINDINGS_PATH": self._feed(network)}):
            network_findings = summarize_network(scan_network())

        combined = combine_findings([], [], runtime_findings=runtime_findings,
                                    network_findings=network_findings)
        self.assertEqual(combined, [
            {"type": "RUNTIME", "id": "Shell", "severity": "HIGH", "message": "o"},
            {"type": "NETWORK", "id": "KHV1", "severity": "LOW", "message": "d"},
        ])
