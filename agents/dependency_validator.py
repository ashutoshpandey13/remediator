import json
import re
import shutil
import subprocess


NPM_VIEW_TIMEOUT_SECONDS = 60
NODE_TIMEOUT_SECONDS = 30


def npm_available():

    return shutil.which("npm") is not None


def validate_npm_package(
    package_name,
    version
):

    cmd = [
        "npm",
        "view",
        f"{package_name}@{version}",
        "version"
    ]

    try:

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=NPM_VIEW_TIMEOUT_SECONDS
        )

    except (FileNotFoundError, subprocess.TimeoutExpired):

        # npm unavailable / registry unreachable: cannot confirm the version
        return False

    return result.returncode == 0


def find_missing_node_dependencies(
    js_sources,
    dependencies
):
    """
    Return the packages that the given JavaScript sources require()/import
    but that are not declared in package.json "dependencies".

    Prevents "Cannot find module" crashes after remediation removed or
    replaced a dependency. Node built-ins and relative imports are ignored.
    Returns [] when node is not installed (check is skipped).
    """

    node = shutil.which("node")

    if not node:
        return []

    try:

        result = subprocess.run(
            [
                node,
                "-e",
                "console.log(JSON.stringify("
                "require('module').builtinModules))"
            ],
            capture_output=True,
            text=True,
            timeout=NODE_TIMEOUT_SECONDS
        )

        builtins = set(
            json.loads(result.stdout or "[]")
        )

    except (subprocess.TimeoutExpired, ValueError):

        return []

    required = set()

    for source in js_sources:

        required |= set(
            re.findall(
                r"require\(\s*['\"]([^'\"]+)['\"]\s*\)",
                source
            )
        )

        required |= set(
            re.findall(
                r"from\s+['\"]([^'\"]+)['\"]",
                source
            )
        )

    missing = []

    for module in sorted(required):

        if module.startswith((".", "/", "node:")):
            continue

        # "@scope/pkg/sub" -> "@scope/pkg", "pkg/sub" -> "pkg"
        parts = module.split("/")

        top = (
            "/".join(parts[:2])
            if module.startswith("@")
            else parts[0]
        )

        if top in builtins or top in dependencies:
            continue

        if top not in missing:
            missing.append(top)

    return missing
