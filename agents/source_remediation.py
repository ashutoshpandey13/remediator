import os
import re
from collections import Counter

from dotenv import load_dotenv

from agents.bob_client import call_bob, extract_code_block
from agents.validator import validate_source_file

load_dotenv()

FILE_MARKER = re.compile(r"^===FILE:\s*(.+?)\s*===\s*$", re.MULTILINE)

# Only languages whose syntax the pipeline can check after the fix is written
FIXABLE_EXTENSIONS = (".py", ".js", ".mjs", ".cjs")

MAX_SOURCE_FILES = 5
MAX_FILE_BYTES = 100_000

SOURCE_FINDING_TYPES = ("SAST", "SECRET")


def parse_source_fixes(response: str, allowed_paths) -> dict:
    """
    Parse "===FILE: <path>===" sections from the model reply.

    Only paths in `allowed_paths` are accepted, so the model can never make
    the pipeline write to a file it was not asked to fix.
    """
    matches = list(FILE_MARKER.finditer(response))

    fixes = {}

    for i, match in enumerate(matches):

        path = match.group(1).strip()

        if path not in allowed_paths:
            continue

        end = matches[i + 1].start() if i + 1 < len(matches) else len(response)

        code = extract_code_block(response[match.end():end])

        if code:
            fixes[path] = code + "\n"

    return fixes


def generate_source_fixes(findings, files: dict) -> dict:
    """
    Fix SAST / hardcoded-secret findings in application source files.

    Args:
        findings: SAST and SECRET findings (normalized dicts)
        files: {relative_path: file_content} of the files to fix

    Returns:
        {relative_path: fixed_content} for the files the model returned
    """
    if not files or not findings:
        return {}

    file_blocks = "\n\n".join(
        f"File: {path}\n```\n{content}\n```"
        for path, content in files.items()
    )

    prompt = f"""
You are an expert application security engineer.

Fix the security findings below in the provided source files.

Rules:
1. Fix every SAST finding (injection, eval, unsafe deserialization, XSS, weak crypto, etc.).
2. Remove hardcoded secrets (tokens, keys, passwords) and read them from environment variables instead (os.environ in Python, process.env in Node.js). Never leave a secret literal in a file.
3. Preserve the application behaviour and public interface.
4. Do NOT introduce new third-party dependencies.
5. Return the COMPLETE fixed content of every file you change, not a diff.
6. Code only, no comments describing the fix.

Findings:
{findings}

Source files:
{file_blocks}

Return response in this exact format, one section per file that needs changes,
using the file path exactly as given above:

===FILE: <path>===

```
<complete fixed file content>
```
"""

    return parse_source_fixes(call_bob(prompt), set(files))


def resolve_repo_file(clone_dir: str, path: str):
    """
    Return `path` relative to `clone_dir`, or None if it does not point at a
    regular file inside the clone (blocks absolute paths / ".." / symlinks
    that escape the repository).
    """
    if not path:
        return None

    root = os.path.realpath(clone_dir)

    candidate = path if os.path.isabs(path) else os.path.join(root, path)
    real = os.path.realpath(candidate)

    if not real.startswith(root + os.sep) or not os.path.isfile(real):
        return None

    return os.path.relpath(real, root)


def select_fixable_findings(clone_dir: str, findings):
    """
    Pick SAST / SECRET findings that point at a source file we can fix.

    Returns:
        (files, scoped_findings) where files is {relative_path: content} for
        the most affected files (capped) and scoped_findings are the findings
        for those files, with `file` rewritten to the relative path.
    """
    by_file = {}

    for finding in findings:

        if finding.get("type") not in SOURCE_FINDING_TYPES:
            continue

        rel = resolve_repo_file(clone_dir, finding.get("file"))

        if not rel or not rel.endswith(FIXABLE_EXTENSIONS):
            continue

        by_file.setdefault(rel, []).append({**finding, "file": rel})

    ranked = Counter({rel: len(items) for rel, items in by_file.items()})

    files = {}
    scoped = []

    for rel, _ in ranked.most_common():

        if len(files) >= MAX_SOURCE_FILES:
            break

        full_path = os.path.join(clone_dir, rel)

        if os.path.getsize(full_path) > MAX_FILE_BYTES:
            continue

        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            files[rel] = f.read()

        scoped.extend(by_file[rel])

    return files, scoped


def apply_source_fixes(clone_dir: str, findings) -> dict:
    """
    Fix SAST / secret findings in the cloned repository's source files.

    Each fixed file is syntax-checked after being written; a file that fails
    the check is restored to its original content.

    Returns:
        {"updated": [relative_path, ...], "skipped": [relative_path, ...]}
    """
    files, scoped = select_fixable_findings(clone_dir, findings)

    result = {"updated": [], "skipped": []}

    if not files:
        return result

    fixes = generate_source_fixes(scoped, files)

    for rel, original in files.items():

        fixed = fixes.get(rel)

        if not fixed or fixed.strip() == original.strip():
            result["skipped"].append(rel)
            continue

        full_path = os.path.join(clone_dir, rel)

        with open(full_path, "w", encoding="utf-8") as f:
            f.write(fixed)

        if validate_source_file(full_path):
            result["updated"].append(rel)
            continue

        with open(full_path, "w", encoding="utf-8") as f:
            f.write(original)

        result["skipped"].append(rel)

    return result
