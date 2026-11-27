from remediator.remediation.bob_client import call_bob


def generate_advisory(findings) -> str:
    """
    Recommend remediation for findings that cannot be fixed by editing the repository's
    files: cloud posture (CSPM, including infrastructure-as-code such as Terraform),
    runtime behaviour and network exposure. They are not applied automatically.
    Returns the recommendations as Markdown.
    """
    if not findings:
        return ""

    prompt = f"""
You are an expert cloud and Kubernetes security engineer.

For each finding below, give a short, concrete remediation recommendation.
Cover cloud posture issues (public S3 buckets, overly permissive IAM, open
security groups, misconfigured infrastructure-as-code where the "file" field says
where), suspicious runtime behaviour (shell access in containers, binary
tampering, privilege escalation) and network exposure (exposed Kubernetes
dashboards, anonymous kubelet access, publicly reachable APIs).

Findings:
{findings}

Return a Markdown list with one item per finding: the finding id in bold,
followed by the recommended action. No other text.
"""

    return call_bob(prompt).strip()
