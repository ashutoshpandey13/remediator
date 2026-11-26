import json
import shutil
import subprocess
import yaml

NODE_CHECK_TIMEOUT_SECONDS = 30


def validate_yaml(file_path):

    try:

        with open(file_path, "r") as f:
            # Kubernetes manifests commonly hold several documents in one file
            list(yaml.safe_load_all(f))

        return True

    except Exception as e:

        print(
            f"YAML validation failed: {e}"
        )

        return False


def validate_package_json(file_path):

    try:

        with open(file_path, "r") as f:
            json.load(f)

        return True

    except Exception as e:

        print(
            f"Package JSON validation failed: {e}"
        )

        return False


def validate_source_file(file_path):
    """
    Syntax-check a remediated source file.

    Python files are compiled, JavaScript files are checked with `node --check`
    (skipped when node is not installed). Other file types are not checked.
    """

    try:

        if file_path.endswith(".py"):

            # compile() checks syntax without writing a .pyc file
            with open(file_path, "r", encoding="utf-8") as f:
                compile(f.read(), file_path, "exec")

            return True

        if file_path.endswith((".js", ".mjs", ".cjs")):

            node = shutil.which("node")

            if not node:
                return True

            result = subprocess.run(
                [node, "--check", file_path],
                capture_output=True,
                text=True,
                timeout=NODE_CHECK_TIMEOUT_SECONDS
            )

            return result.returncode == 0

        return True

    except Exception as e:

        print(
            f"Source validation failed for {file_path}: {e}"
        )

        return False
