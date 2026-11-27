import os

from dotenv import load_dotenv

from remediator.remediation.bob_client import call_bob

load_dotenv()

ADVISORY_REPORT = "reports/advisory.md"


def generate_advisory(findings) -> str:
    """
    Recommend remediation for cloud posture findings (CSPM) reported on the
    repository's infrastructure-as-code (Terraform, CloudFormation, Helm, ...).
    These are not applied automatically. Saves the recommendations to
    reports/advisory.md.
    """
    if not findings:
        return ""

    prompt = f"""
You are an expert cloud security engineer.

Each finding below is a cloud misconfiguration found in the repository's
infrastructure-as-code (the "file" field says where). For each finding, give a
short, concrete remediation recommendation, for example the setting or
resource to change.

Findings:
{findings}

Return a Markdown list with one item per finding: the finding id in bold,
followed by the recommended action. No other text.
"""

    advisory = call_bob(prompt).strip()

    os.makedirs("reports", exist_ok=True)

    with open(ADVISORY_REPORT, "w") as f:
        f.write(advisory + "\n")

    return advisory
