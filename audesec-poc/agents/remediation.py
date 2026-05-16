from openai import OpenAI
from dotenv import load_dotenv

import os

load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)


def generate_remediation(
    findings,
    deployment_yaml=None,
    package_json=None
):
    """
    Generate remediation for security findings.
    
    Args:
        findings: List of security findings
        deployment_yaml: Kubernetes deployment YAML content (optional)
        package_json: Package.json content (optional)
    
    Returns:
        Fixed file contents with appropriate delimiters
    """
    
    # Determine what files we have
    has_deployment = deployment_yaml is not None
    has_package = package_json is not None
    
    if not has_deployment and not has_package:
        return "No files to remediate"
    
    # Build prompt based on available files
    if has_deployment and has_package:
        prompt = f"""
You are an expert DevSecOps remediation agent.

CRITICAL RULES:
- Output ONLY valid YAML and JSON
- NO comments (no //, no #, no inline comments)
- NO explanations or markdown
- NO extra text before or after the fixed content

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

Return response in this exact format (no comments, no extra text):

===FIXED_DEPLOYMENT===

<fixed yaml - no comments>

===FIXED_PACKAGE_JSON===

<fixed package json - no comments>
"""
    elif has_deployment:
        prompt = f"""
You are an expert DevSecOps remediation agent.

CRITICAL RULES:
- Output ONLY valid YAML
- NO comments (no #, no inline comments)
- NO explanations or markdown
- NO extra text before or after the fixed content

Your task:
1. Fix Kubernetes security issues in the deployment YAML
2. Preserve application functionality

Findings:
{findings}

Kubernetes YAML:
{deployment_yaml}

Return response in this exact format (no comments, no extra text):

===FIXED_DEPLOYMENT===

<fixed yaml - no comments>
"""
    else:  # has_package
        prompt = f"""
You are an expert DevSecOps remediation agent.

CRITICAL RULES:
- Output ONLY valid JSON
- NO comments (no //, no #, no inline comments)
- NO explanations or markdown
- NO extra text before or after the fixed content

Your task:
1. Upgrade vulnerable dependencies in package.json
2. Preserve application functionality
3. Use compatible versions

Findings:
{findings}

Package JSON:
{package_json}

Return response in this exact format (no comments, no extra text):

===FIXED_PACKAGE_JSON===

<fixed package json - no comments>
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": "You are a DevSecOps expert. Generate ONLY valid YAML and JSON. NO comments, NO explanations, NO markdown."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.2
    )

    content = response.choices[0].message.content
    
    # Clean up markdown code blocks if present
    content = content.replace("```yaml", "").replace("```json", "").replace("```", "")
    
    # Split by delimiters to process each section
    if has_deployment and has_package:
        # Both files - process separately
        if "===FIXED_DEPLOYMENT===" in content and "===FIXED_PACKAGE_JSON===" in content:
            parts = content.split("===FIXED_PACKAGE_JSON===")
            yaml_part = parts[0].replace("===FIXED_DEPLOYMENT===", "").strip()
            json_part = parts[1].strip() if len(parts) > 1 else ""
            
            # Clean YAML
            yaml_part = clean_yaml(yaml_part)
            
            # Clean JSON
            json_part = clean_json(json_part)
            
            content = f"===FIXED_DEPLOYMENT===\n{yaml_part}\n\n===FIXED_PACKAGE_JSON===\n{json_part}"
    elif has_deployment:
        content = clean_yaml(content.replace("===FIXED_DEPLOYMENT===", "").strip())
    elif has_package:
        content = clean_json(content.replace("===FIXED_PACKAGE_JSON===", "").strip())
    
    return content


def clean_yaml(yaml_content: str) -> str:
    """Clean YAML content by removing comments and invalid syntax."""
    lines = yaml_content.split('\n')
    cleaned_lines = []
    in_string = False
    
    for line in lines:
        # Skip empty lines at start
        if not cleaned_lines and not line.strip():
            continue
        
        # Remove inline comments (but preserve # in strings)
        if '#' in line:
            # Simple heuristic: if # appears after a colon and value, it's likely a comment
            if ':' in line and not line.strip().startswith('#'):
                # Find the colon position
                colon_pos = line.find(':')
                hash_pos = line.find('#', colon_pos)
                
                if hash_pos > colon_pos:
                    # Check if there's a value between colon and hash
                    between = line[colon_pos+1:hash_pos].strip()
                    if between:  # There's a value, so # is likely a comment
                        line = line[:hash_pos].rstrip()
        
        cleaned_lines.append(line)
    
    return '\n'.join(cleaned_lines).strip()


def clean_json(json_content: str) -> str:
    """Clean JSON content by removing comments and fixing syntax."""
    import re
    
    lines = json_content.split('\n')
    cleaned_lines = []
    
    for i, line in enumerate(lines):
        # Skip empty lines at start
        if not cleaned_lines and not line.strip():
            continue
        
        # Remove inline comments (both // and #)
        if '//' in line or '#' in line:
            comment_pos = len(line)
            if '//' in line:
                comment_pos = min(comment_pos, line.find('//'))
            if '#' in line:
                comment_pos = min(comment_pos, line.find('#'))
            
            line = line[:comment_pos].rstrip()
            
            # Remove trailing comma if it's the last property before closing brace
            if line.rstrip().endswith(','):
                remaining_lines = [l.strip() for l in lines[i+1:] if l.strip()]
                if remaining_lines and remaining_lines[0].startswith('}'):
                    line = line.rstrip()[:-1]
        
        cleaned_lines.append(line)
    
    result = '\n'.join(cleaned_lines).strip()
    
    # Validate it's proper JSON structure
    if not result.startswith('{'):
        # Try to find the JSON object
        match = re.search(r'\{.*\}', result, re.DOTALL)
        if match:
            result = match.group(0)
    
    return result
