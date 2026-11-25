from dotenv import load_dotenv

from agents.bob_client import call_bob, extract_code_block

load_dotenv()

SECTION_MARKERS = (
    "===FIXED_DEPLOYMENT===",
    "===FIXED_PACKAGE_JSON===",
    "===FIXED_SOURCE_CODE==="
)


def _keep_only_sections(content: str) -> str:
    """Drop any prose around the marked sections and unwrap ``` fences."""
    sections = []
    for marker in SECTION_MARKERS:
        if marker not in content:
            continue
        segment = content.split(marker, 1)[1]
        for other in SECTION_MARKERS:
            if other != marker and other in segment:
                segment = segment.split(other, 1)[0]
        sections.append(f"{marker}\n{extract_code_block(segment)}")
    return "\n\n".join(sections) if sections else content


def generate_remediation(
    findings,
    deployment_yaml,
    package_json
):

    prompt = f"""
You are an expert DevSecOps remediation agent.

Your task:
1. Fix Kubernetes security issues
2. Upgrade vulnerable dependencies
3. Preserve application functionality
4. Also fix insecure application source code vulnerabilities.
5. Use only real npm package versions that exist in registry.
6. Use express version 4.21.2 if upgrading express.
7. Remove hardcoded secrets and replace them with environment variables.
8. Also recommend remediation for cloud posture issues including public S3 buckets, overly permissive IAM, open security groups
9. Also recommend remediation for suspicious runtime behavior including: shell access inside containers, binary tampering, privilege escalation
10. Also recommend remediation for network exposure risks including: exposed Kubernetes dashboards, anonymous kubelet access, publicly accessible APIs

Findings:
{findings}

Kubernetes YAML:
{deployment_yaml}

Package JSON:
{package_json}

Return response in this exact format:

===FIXED_DEPLOYMENT===

<fixed yaml>

===FIXED_PACKAGE_JSON===

<fixed package json>

===FIXED_SOURCE_CODE===

<fixed source code>
"""

    return _keep_only_sections(call_bob(prompt))
