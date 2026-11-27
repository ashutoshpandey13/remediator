from dotenv import load_dotenv

import json
import os
import re
import subprocess

load_dotenv()

# One AI call must never block a scan forever
BOB_TIMEOUT_SECONDS = int(os.getenv("BOB_TIMEOUT_SECONDS", "600"))


def extract_code_block(text: str) -> str:
    """
    Bob may wrap code in ``` fences and add explanation text around it.
    Return only the fenced content (or the stripped text if there are no fences).
    """
    match = re.search(r"```[\w-]*\n(.*?)```", text, re.DOTALL)
    return (match.group(1) if match else text).strip()


def ensure_bob_configured():
    """Raise if Bob cannot be called, so callers can fail before doing slow work."""
    if not os.getenv("BOB_API_KEY"):
        raise Exception("BOB_API_KEY is not set (add it to .env)")


def call_bob(prompt: str) -> str:
    """
    Send a prompt to IBM Bob Shell (non-interactive) and return the reply text.

    Requires the `bob` CLI on PATH and BOB_API_KEY set (e.g. in .env).
    """
    ensure_bob_configured()

    # Prompt is passed via stdin; ask mode + no MCP/subagents keeps it read-only
    result = subprocess.run(
        [
            "bob", "run",
            "--format", "json",
            "--mode", "ask",
            "--disable-mcp",
            "--disable-subagents"
        ],
        input=prompt,
        capture_output=True,
        text=True,
        timeout=BOB_TIMEOUT_SECONDS
    )

    if result.returncode != 0:
        raise Exception(f"bob run failed: {result.stderr or result.stdout}")

    output = json.loads(result.stdout)

    if output.get("status") != "success":
        raise Exception(f"bob run returned error: {result.stdout}")

    return output["last_message"]
