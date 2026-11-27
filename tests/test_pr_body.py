from tests.helpers import TempDirTestCase

from remediator.integrations.git_operations import generate_remediation_pr_body
from remediator.web.app import metric


def real_metrics():
    """Metrics in the shape run_security_scan builds (via the app's own metric())."""
    metrics = {
        "kubernetes": metric(4, 1),
        "cve": metric(10, 6),
        "sast": metric(2, 2),
        "secrets": metric(1, 0),
    }
    metrics["total"] = metric(sum(m["before"] for m in metrics.values()),
                              sum(m["after"] for m in metrics.values()))
    metrics["advisory"] = {"cspm": 0, "runtime": 0, "network": 0}
    return metrics


class RemediationPrBodyTest(TempDirTestCase):
    FILES = ["Dockerfile", "k8s/deploy.yaml", "svc/package.json"]

    def test_lists_changed_files_and_real_numbers(self):
        body = generate_remediation_pr_body(self.FILES, real_metrics())

        self.assertIn("Files changed (3)", body)
        for path in self.FILES:
            self.assertIn(f"- `{path}`", body)
        self.assertIn("| Kubernetes misconfigurations | 4 | 1 | 3 |", body)
        self.assertIn("| Container CVEs | 10 | 6 | 4 |", body)
        self.assertIn("| Code (SAST) issues | 2 | 2 | 0 |", body)
        self.assertIn("| Hardcoded secrets | 1 | 0 | 1 |", body)
        self.assertIn("| **Total** | 17 | 9 | 8 |", body)
        self.assertIn("Review checklist", body)

    def test_advisory_counts_are_not_a_table_row(self):
        body = generate_remediation_pr_body(self.FILES, real_metrics())
        self.assertNotIn("advisory", body.lower())

    def test_categories_without_metrics_are_left_out(self):
        metrics = real_metrics()
        del metrics["sast"], metrics["secrets"]

        body = generate_remediation_pr_body(self.FILES, metrics)

        self.assertNotIn("SAST", body)
        self.assertNotIn("secrets", body)
        self.assertIn("Container CVEs", body)

    def test_no_hard_coded_claims_for_unchanged_categories(self):
        body = generate_remediation_pr_body(["svc/package.json"], {})

        self.assertNotIn("Kubernetes", body)
        self.assertNotIn("Updated vulnerable dependencies", body)
        self.assertNotIn("Before / after", body)

    def test_only_findings_in_changed_files_are_listed_by_severity(self):
        findings = [
            {"type": "CVE", "id": "CVE-LOW", "severity": "LOW", "file": "Dockerfile"},
            {"type": "MISCONFIG", "id": "KSV001", "severity": "CRITICAL", "file": "k8s/deploy.yaml"},
            {"type": "CVE", "id": "CVE-ELSEWHERE", "severity": "CRITICAL", "file": "other/Dockerfile"},
            {"type": "CSPM", "id": "CSPM-1", "severity": "HIGH"},
        ]

        body = generate_remediation_pr_body(self.FILES, real_metrics(), findings)

        self.assertIn("Findings in the changed files", body)
        self.assertIn("KSV001", body)
        self.assertIn("CVE-LOW", body)
        self.assertNotIn("CVE-ELSEWHERE", body)
        self.assertNotIn("CSPM-1", body)
        self.assertLess(body.index("KSV001"), body.index("CVE-LOW"))

    def test_findings_list_is_capped(self):
        findings = [{"type": "CVE", "id": f"CVE-{i}", "severity": "HIGH", "file": "Dockerfile"}
                    for i in range(40)]

        body = generate_remediation_pr_body(["Dockerfile"], real_metrics(), findings)

        self.assertIn("...and 25 more", body)
        self.assertNotIn("CVE-39", body)

    def test_jira_keys(self):
        with_keys = generate_remediation_pr_body(self.FILES, real_metrics(), None, ["SEC-1", "SEC-2"])
        self.assertIn("JIRA tickets", with_keys)
        self.assertIn("`SEC-1`, `SEC-2`", with_keys)

        self.assertNotIn("JIRA", generate_remediation_pr_body(self.FILES, real_metrics(), None, []))

    def test_scanner_text_cannot_break_the_markdown(self):
        findings = [{"type": "SAST", "id": "x`|<script>\nrow", "severity": "HIGH",
                     "file": "Dockerfile"}]

        body = generate_remediation_pr_body(["Dockerfile"], real_metrics(), findings)

        self.assertNotIn("<script>", body)
        self.assertNotIn("x`|", body)
