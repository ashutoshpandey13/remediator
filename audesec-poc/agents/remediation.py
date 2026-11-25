from openai import OpenAI
from dotenv import load_dotenv

import os

load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)


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

    response = client.chat.completions.create(
        model="gpt-4.1-mini",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    return response.choices[0].message.content
