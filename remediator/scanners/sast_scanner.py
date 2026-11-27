import json
import os
import subprocess
import tempfile

SEMGREP_TIMEOUT_SECONDS = 600

# "--config auto" cannot be combined with "--metrics=off" (Semgrep needs metrics to pick
# rules automatically), so use the explicit default ruleset from the Semgrep registry
SEMGREP_CONFIG = "p/default"

# Semgrep reports ERROR / WARNING / INFO - map to the severities used everywhere else
SEMGREP_SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW"
}


def scan_code(path):

    # A private report file per call, so concurrent scans never read each other's results
    with tempfile.TemporaryDirectory(prefix="audesec-sast-") as report_dir:

        output_file = os.path.join(report_dir, "sast_scan.json")

        cmd = [
            "semgrep",
            "scan",
            "--config",
            SEMGREP_CONFIG,
            "--metrics=off",
            "--json",
            "--output",
            output_file,
            path
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SEMGREP_TIMEOUT_SECONDS,
            # Semgrep leaves scratch folders in the temp directory; keep them in this
            # scan's own directory so they are removed with it
            env={**os.environ, "TMPDIR": report_dir}
        )

        # semgrep returns:
        # 0 = no findings
        # 1 = findings found

        if result.returncode not in [0, 1]:

            raise Exception(
                f"Semgrep scan failed: {result.stderr}"
            )

        with open(output_file, "r") as f:
            return json.load(f)


def summarize_sast(scan_result):

    findings = []

    for result in scan_result.get(
        "results",
        []
    ):

        extra = result.get(
            "extra",
            {}
        )

        raw_severity = extra.get(
            "severity"
        )

        findings.append({

            "type": "SAST",

            "id": result.get(
                "check_id"
            ),

            "severity": SEMGREP_SEVERITY_MAP.get(
                raw_severity,
                raw_severity
            ),

            "message": extra.get(
                "message"
            ),

            "file": result.get(
                "path"
            )
        })

    return findings
