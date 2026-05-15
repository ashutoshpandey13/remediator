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
