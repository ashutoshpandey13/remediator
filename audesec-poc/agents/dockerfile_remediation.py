from openai import OpenAI
from dotenv import load_dotenv
import os
import re

load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)


def detect_base_image_type(dockerfile_content: str) -> str:
    """
    Detect the type of base image (Python, Node.js, Java, etc.)
    
    Args:
        dockerfile_content: Content of Dockerfile
        
    Returns:
        Image type (python, node, java, go, etc.)
    """
    first_line = dockerfile_content.split('\n')[0].lower()
    
    if 'python' in first_line:
        return 'python'
    elif 'node' in first_line:
        return 'node'
    elif 'java' in first_line or 'openjdk' in first_line:
        return 'java'
    elif 'golang' in first_line or 'go:' in first_line:
        return 'go'
    elif 'ruby' in first_line:
        return 'ruby'
    elif 'php' in first_line:
        return 'php'
    else:
        return 'unknown'


def get_recommended_base_image(image_type: str, current_image: str) -> str:
    """
    Get recommended secure base image based on type.
    
    Args:
        image_type: Type of image (python, node, etc.)
        current_image: Current FROM statement
        
    Returns:
        Recommended base image
    """
    recommendations = {
        'python': 'python:3.12-alpine',
        'node': 'node:20-alpine',
        'java': 'eclipse-temurin:21-jre-alpine',
        'go': 'golang:1.21-alpine',
        'ruby': 'ruby:3.2-alpine',
        'php': 'php:8.2-alpine'
    }
    
    return recommendations.get(image_type, current_image)


def generate_dockerfile_remediation(
    dockerfile_content: str,
    cve_findings: list
) -> str:
    """
    Generate remediated Dockerfile with updated base image.
    
    Args:
        dockerfile_content: Original Dockerfile content
        cve_findings: List of CVE findings
        
    Returns:
        Fixed Dockerfile content
    """
    
    # Detect image type
    image_type = detect_base_image_type(dockerfile_content)
    
    # Get current FROM statement
    from_match = re.search(r'^FROM\s+(.+)$', dockerfile_content, re.MULTILINE | re.IGNORECASE)
    current_from = from_match.group(1) if from_match else "unknown"
    
    # Get recommended image
    recommended_image = get_recommended_base_image(image_type, current_from)
    
    prompt = f"""
You are an expert DevSecOps engineer specializing in container security.

Your task:
1. Update the Dockerfile to use a more secure base image
2. Minimize CVE vulnerabilities
3. Preserve application functionality
4. Use Alpine or slim variants when possible

Current Dockerfile:
{dockerfile_content}

Current base image: {current_from}
Detected type: {image_type}
Recommended secure image: {recommended_image}

CVE Findings (sample):
{cve_findings[:10]}

Instructions:
- Update FROM statement to use latest secure image
- For Python: Use python:3.12-alpine or python:3.12-slim-bookworm
- For Node.js: Use node:20-alpine or node:20-slim
- For Java: Use eclipse-temurin:21-jre-alpine
- Add any necessary build dependencies for Alpine
- Keep all other Dockerfile instructions intact
- Add comments explaining changes

Return ONLY the fixed Dockerfile content, no explanations or markdown.
"""
    
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.3
    )
    
    content = response.choices[0].message.content
    
    # Clean up markdown code blocks if present
    content = content.replace("```dockerfile", "").replace("```Dockerfile", "").replace("```", "")
    
    # Remove any leading/trailing whitespace from each line
    lines = content.split('\n')
    cleaned_lines = []
    
    for line in lines:
        # Skip empty lines at the start
        if not cleaned_lines and not line.strip():
            continue
        
        # Remove inline comments that break Dockerfile syntax
        # Keep comments that are on their own line (start with #)
        if line.strip() and not line.strip().startswith('#'):
            # Remove inline comments after instructions
            if '#' in line:
                # Find the position of # that's not part of a string
                parts = line.split('#', 1)
                if len(parts) == 2:
                    # Keep the instruction part, remove the comment
                    line = parts[0].rstrip()
        
        cleaned_lines.append(line)
    
    content = '\n'.join(cleaned_lines).strip()
    
    # Validate basic Dockerfile syntax
    if not content.startswith('FROM'):
        # Try to find FROM statement
        for i, line in enumerate(cleaned_lines):
            if line.strip().startswith('FROM'):
                content = '\n'.join(cleaned_lines[i:]).strip()
                break
    
    return content


def update_dockerfile(dockerfile_path: str, cve_findings: list) -> bool:
    """
    Update Dockerfile with secure base image.
    
    Args:
        dockerfile_path: Path to Dockerfile
        cve_findings: List of CVE findings
        
    Returns:
        True if updated successfully
    """
    try:
        # Read current Dockerfile
        with open(dockerfile_path, 'r') as f:
            original_content = f.read()
        
        # Generate remediation
        fixed_content = generate_dockerfile_remediation(original_content, cve_findings)
        
        # Write fixed Dockerfile
        with open(dockerfile_path, 'w') as f:
            f.write(fixed_content)
        
        return True
        
    except Exception as e:
        print(f"Error updating Dockerfile: {e}")
        return False
