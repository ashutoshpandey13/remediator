from unittest import TestCase

from remediator.scanners.cspm_scanner import summarize_cspm


class SummarizeCspmTest(TestCase):
    def test_iac_findings_are_kept_with_file_and_resource(self):
        result = {"Results": [{
            "Target": "infra/main.tf", "Type": "terraform", "Misconfigurations": [{
                "ID": "AWS-0107", "Title": "Open SSH", "Severity": "HIGH", "Message": "msg",
                "CauseMetadata": {"Resource": "aws_security_group.web"}}]}]}

        self.assertEqual(summarize_cspm(result), [{
            "id": "AWS-0107", "title": "Open SSH", "severity": "HIGH", "message": "msg",
            "file": "infra/main.tf", "resource": "aws_security_group.web"}])

    def test_kubernetes_and_dockerfile_results_are_left_to_their_own_scans(self):
        result = {"Results": [
            {"Target": "pod.yaml", "Type": "kubernetes", "Misconfigurations": [{"ID": "KSV1"}]},
            {"Target": "Dockerfile", "Type": "dockerfile", "Misconfigurations": [{"ID": "DS1"}]},
        ]}

        self.assertEqual(summarize_cspm(result), [])

    def test_empty_or_missing_results(self):
        self.assertEqual(summarize_cspm({}), [])
        self.assertEqual(summarize_cspm({"Results": None}), [])
        self.assertEqual(summarize_cspm({"Results": [{"Target": "x.tf", "Type": "terraform"}]}), [])
