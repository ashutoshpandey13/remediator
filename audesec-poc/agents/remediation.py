from dotenv import load_dotenv

from agents.bob_client import call_bob, extract_code_block

load_dotenv()

SECTION_MARKERS = (
    "===FIXED_DEPLOYMENT===",
    "===FIXED_PACKAGE_JSON===",
    "===FIXED_SOURCE_CODE===",
    "===FIXED_DOCKERFILE===",
    "===FIXED_APP_JS===",
    "===FIXED_SECRETS===",
)


def parse_sections(content: str) -> dict:
    """Return {marker: code} for each marked section, with prose and ``` fences removed."""
    positions = sorted(
        (content.index(m), m) for m in SECTION_MARKERS if m in content
    )
    sections = {}
    for i, (start, marker) in enumerate(positions):
        end = positions[i + 1][0] if i + 1 < len(positions) else len(content)
        sections[marker] = extract_code_block(content[start + len(marker):end])
    return sections


def _keep_only_sections(content: str) -> str:
    """Drop any prose around the marked sections and unwrap ``` fences."""
    sections = parse_sections(content)
    if not sections:
        return content
    return "\n\n".join(f"{m}\n{code}" for m, code in sections.items())


def generate_remediation(
    findings,
    deployment_yaml,
    package_json,
    dockerfile="",
    app_js="",
    secrets_py="",
    source_code=""
):

    prompt = f"""
You are an expert DevSecOps remediation agent.

Your task:
1. Fix Kubernetes security issues
2. Upgrade vulnerable dependencies
3. Preserve application functionality
4. Also fix insecure application source code vulnerabilities in EVERY source file provided below (app.js, secrets.py, vulnerable_code.py).
5. Use only real npm package versions that exist in registry.
6. Keep express on the 4.x line (the app uses Express 4 APIs). For every other package use the CVE "fixed_version" data in the findings: pick the highest fixed version, staying on the same major version unless the code is also updated to match.
7. Remove hardcoded secrets and replace them with environment variables (os.environ in Python, process.env in Node). Do not leave any token, key or password literal in any file.
8. Also recommend remediation for cloud posture issues including public S3 buckets, overly permissive IAM, open security groups
9. Also recommend remediation for suspicious runtime behavior including: shell access inside containers, binary tampering, privilege escalation
10. Also recommend remediation for network exposure risks including: exposed Kubernetes dashboards, anonymous kubelet access, publicly accessible APIs
11. Fix the Dockerfile: use the -alpine variant of a current Node.js LTS image pinned to a specific version tag (never "latest"), run as a non-root USER, and add a HEALTHCHECK. The npm CLI bundled in the base image has its own CVEs, so use a multi-stage build: install dependencies in a build stage, and in the final stage copy only node_modules and the app files and delete npm, npx and corepack (rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack). Do NOT run "npm install -g npm@latest" (the newest npm needs a newer Node than the pinned image and the build fails). In the final stage, as root and before the USER instruction, also run "apk upgrade --no-cache" so the OS packages (openssl, zlib, musl) are patched. Keep the app working (it listens on port 3000 and starts with "node app.js").
12. CONSISTENCY IS MANDATORY: the fixed app.js must not require() any module that is missing from the fixed package.json dependencies (Node built-ins excepted). If a vulnerable package has no safe version (for example node-serialize), remove it from package.json AND rewrite the code in app.js that used it with a safe alternative (for example JSON.parse with validation). Never leave a require() for a package you removed.
13. For packages that remain vulnerable only through transitive dependencies, add an "overrides" block to package.json forcing patched versions of those transitive packages.
14. Remove packages from package.json that are not used by the fixed code.
15. In app.js: remove eval, never pass user input to a shell (use execFile with an allow-listed argument or drop the endpoint), HTML-escape user input before writing it to a response, restrict CORS to an explicit origin from an environment variable, read the JWT secret from process.env, and add CSRF/rate-limit protection only if you also add the dependency to package.json.

Findings:
{findings}

Kubernetes YAML:
{deployment_yaml}

Package JSON:
{package_json}

Dockerfile:
{dockerfile}

app.js:
{app_js}

secrets.py:
{secrets_py}

vulnerable_code.py:
{source_code}

Return response in this exact format (every section is required, code only, no comments about the fix):

===FIXED_DEPLOYMENT===

<fixed yaml>

===FIXED_PACKAGE_JSON===

<fixed package json>

===FIXED_SOURCE_CODE===

<fixed vulnerable_code.py>

===FIXED_DOCKERFILE===

<fixed dockerfile>

===FIXED_APP_JS===

<fixed app.js>

===FIXED_SECRETS===

<fixed secrets.py>
"""

    return _keep_only_sections(call_bob(prompt))
