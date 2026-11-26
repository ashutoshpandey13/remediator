import os

from dotenv import load_dotenv

from agents.bob_client import call_bob

load_dotenv()

ADVISORY_REPORT = "reports/advisory.md"


def generate_advisory(findings) -> str:
    """
    Recommend remediation for findings that cannot be fixed by editing files
    in the repository: cloud posture (CSPM), runtime behaviour and network
    exposure. Saves the recommendations to reports/advisory.md.
    """
    if not findings:
        return ""

    prompt = f"""
You are an expert cloud and Kubernetes security engineer.

For each finding below, give a short, concrete remediation recommendation.
Cover cloud posture issues (public S3 buckets, overly permissive IAM, open
security groups), suspicious runtime behaviour (shell access in containers,
binary tampering, privilege escalation) and network exposure (exposed
Kubernetes dashboards, anonymous kubelet access, publicly reachable APIs).

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
