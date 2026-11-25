import subprocess
import json


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

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )

    return result.returncode == 0
