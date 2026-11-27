"""
Command-line entry point: run the same scan / fix / PR / JIRA workflow as the web UI.

    python -m remediator.cli https://github.com/owner/repo.git
"""
import argparse
import sys

from remediator.web import app as web_app
from remediator.web import security


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m remediator.cli",
        description="Scan a repository, fix what can be fixed, and raise a pull request.",
    )
    parser.add_argument("repo_url", nargs="?", help="Repository URL (prompted for when omitted)")
    args = parser.parse_args(argv)

    repo_url = args.repo_url or input("Enter Git repository URL: ").strip()
    try:
        repo_url = web_app.validate_repo_url(repo_url)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    scan_id = security.new_scan_id()
    web_app.scan_results.try_start(scan_id)
    web_app.run_security_scan(repo_url, scan_id)

    scan = web_app.scan_results.snapshot(scan_id)
    if scan.get("status") != "complete":
        print(f"Scan failed: {scan.get('error', 'unknown error')}", file=sys.stderr)
        return 1

    print(f"Scan complete. Files updated: {', '.join(scan.get('files_updated') or []) or 'none'}")
    if scan.get("pr_url"):
        print(f"Pull request: {scan['pr_url']}")
    else:
        print(f"Pull request: not created ({scan.get('pr_status')}) {scan.get('pr_message', '')}".rstrip())
    if scan.get("jira_keys"):
        print(f"JIRA tickets: {', '.join(scan['jira_keys'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
