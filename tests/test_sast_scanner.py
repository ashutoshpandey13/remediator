import json
import types
from unittest import TestCase, mock

from remediator.scanners import sast_scanner


class ScanCodeTest(TestCase):
    def _run_scan(self, returncode=0, stderr=""):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            self.scratch_dir = kwargs["env"]["TMPDIR"]
            with open(cmd[cmd.index("--output") + 1], "w") as f:
                json.dump({"results": []}, f)
            return types.SimpleNamespace(returncode=returncode, stderr=stderr)

        with mock.patch.object(sast_scanner.subprocess, "run", fake_run):
            result = sast_scanner.scan_code("/tmp/repo")
        return calls[0], result

    def test_command_never_combines_auto_config_with_metrics_off(self):
        # Semgrep refuses: "Cannot create auto config when metrics are off"
        cmd, _ = self._run_scan()
        self.assertIn("--metrics=off", cmd)
        self.assertNotIn("auto", cmd)
        self.assertEqual(cmd[cmd.index("--config") + 1], "p/default")

    def test_scratch_files_are_removed_after_the_scan(self):
        import os
        self._run_scan()
        self.assertFalse(os.path.exists(self.scratch_dir))

    def test_findings_exit_code_is_not_an_error(self):
        self.assertEqual(self._run_scan(returncode=1)[1], {"results": []})

    def test_tool_failure_raises(self):
        with self.assertRaises(Exception) as ctx:
            self._run_scan(returncode=2, stderr="boom")
        self.assertIn("boom", str(ctx.exception))
