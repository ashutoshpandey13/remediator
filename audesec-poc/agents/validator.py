import yaml
import json


def validate_yaml(file_path):

    try:

        with open(file_path, "r") as f:
            yaml.safe_load(f)

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
