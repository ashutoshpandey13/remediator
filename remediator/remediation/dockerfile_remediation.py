from dotenv import load_dotenv
import logging
import re

from remediator.remediation.bob_client import call_bob

load_dotenv()

logger = logging.getLogger(__name__)

_FROM_LINE = re.compile(r'^[ \t]*FROM[ \t]+\S+', re.MULTILINE | re.IGNORECASE)
_FENCED_BLOCK = re.compile(r'```[\w-]*[ \t]*\n(.*?)```', re.DOTALL)
_MAX_LOGGED_REPLY = 200


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


# Red Hat UBI images are published on registry.access.redhat.com without
# authentication. The same images on registry.redhat.io need "docker login",
# which makes the rebuild step fail with 401 on machines that are not logged in.
UBI_REGISTRY = 'registry.access.redhat.com'


def use_anonymous_ubi_registry(dockerfile_content: str) -> str:
    """Rewrite registry.redhat.io/ubi* image references to the anonymous mirror."""
    return re.sub(r'\bregistry\.redhat\.io/(ubi\d)', rf'{UBI_REGISTRY}/\1', dockerfile_content)


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
        'python': f'{UBI_REGISTRY}/ubi9/python-312-minimal:latest',
        'node': f'{UBI_REGISTRY}/ubi9/nodejs-24-minimal:latest',
        'java': f'{UBI_REGISTRY}/ubi9/openjdk-21-runtime:latest',
        'go': f'{UBI_REGISTRY}/ubi9/go-toolset:latest',
        'ruby': f'{UBI_REGISTRY}/ubi9/ruby-33:latest',
        'php': f'{UBI_REGISTRY}/ubi9/php-83:latest'
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
4. Use a minimal Red Hat UBI base image pulled from {UBI_REGISTRY} (never registry.redhat.io, which needs a login)

Current Dockerfile:
{dockerfile_content}

Current base image: {current_from}
Detected type: {image_type}
Recommended secure image: {recommended_image}

CVE Findings (sample):
{cve_findings[:10]}

Instructions:
- Update FROM statement to use the recommended secure image above
- The image must come from {UBI_REGISTRY}
- Run the application as a non-root USER
- Add any packages the app needs with microdnf (UBI minimal) instead of apk
- Keep all other Dockerfile instructions intact
- Add comments explaining changes

Return ONLY the fixed Dockerfile content, no explanations or markdown.
"""
    
    reply = call_bob(prompt)
    try:
        return _dockerfile_from_reply(reply)
    except ValueError as first_error:
        logger.warning("Bob's first Dockerfile reply was not usable, retrying once: %s", first_error)

    # Bob occasionally answers with prose or a question instead of the file: ask again, strictly
    retry_prompt = prompt + """

IMPORTANT: your previous answer did not contain a Dockerfile.
Reply with the complete Dockerfile only. The first non-comment line must be a FROM instruction.
Do not ask questions, do not explain, and do not write any text outside the Dockerfile.
"""
    return _dockerfile_from_reply(call_bob(retry_prompt))


def _dockerfile_from_reply(reply: str) -> str:
    """
    Turn Bob's reply into Dockerfile text.

    Accepts a bare Dockerfile, a Dockerfile in a ``` fence, or one surrounded by
    explanation. Raises ValueError (with a short, single-line snippet of the reply
    for the server log) when the reply holds no FROM instruction.
    """
    reply = reply or ""

    # Prefer the fenced block that holds the Dockerfile (not e.g. a "docker build" example)
    content = reply
    for block in _FENCED_BLOCK.findall(reply):
        if _FROM_LINE.search(block):
            content = block
            break

    # Drop any text before the first FROM (keep ARG lines that may legally precede it)
    match = _FROM_LINE.search(content)
    if not match:
        snippet = " ".join(reply.split())[:_MAX_LOGGED_REPLY]
        raise ValueError(
            f"Bob did not return a valid Dockerfile (no FROM instruction); reply started with: {snippet!r}"
        )
    before_from = content[:match.start()]
    arg_lines = [line for line in before_from.splitlines() if re.match(r'^\s*ARG\s', line, re.IGNORECASE)]
    content = "\n".join(arg_lines + [content[match.start():].lstrip()])

    # Remove any markdown fences that are left
    content = content.replace("```dockerfile", "").replace("```Dockerfile", "").replace("```", "")

    cleaned_lines = []
    for line in content.split('\n'):
        # Skip empty lines at the start
        if not cleaned_lines and not line.strip():
            continue

        # Remove inline comments that break Dockerfile syntax
        # Keep comments that are on their own line (start with #)
        if line.strip() and not line.strip().startswith('#'):
            if '#' in line:
                parts = line.split('#', 1)
                if len(parts) == 2:
                    # Keep the instruction part, remove the comment
                    line = parts[0].rstrip()

        cleaned_lines.append(line)

    return use_anonymous_ubi_registry('\n'.join(cleaned_lines).strip())


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
