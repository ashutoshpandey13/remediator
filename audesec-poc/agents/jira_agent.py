from jira import JIRA
from dotenv import load_dotenv

import os

load_dotenv()

# Initialize JIRA client only if credentials are provided
jira = None
jira_url = os.getenv("JIRA_URL")
jira_email = os.getenv("JIRA_EMAIL")
jira_token = os.getenv("JIRA_API_TOKEN")

if jira_url and jira_email and jira_token:
    try:
        jira = JIRA(
            server=jira_url,
            basic_auth=(jira_email, jira_token)
        )
        print("✓ JIRA integration enabled")
    except Exception as e:
        print(f"⚠ JIRA integration failed: {e}")
        jira = None
else:
    print("ℹ JIRA integration disabled (credentials not provided)")


def create_jira_ticket(finding):
    """
    Create a JIRA ticket for a security finding.
    Returns ticket key if successful, None if JIRA is not configured.
    """
    if not jira:
        return None

    try:
        summary = (
            f"[{finding['severity']}] "
            f"{finding.get('id')}"
        )

        description = f"""
Type: {finding.get('type')}

Severity: {finding.get('severity')}

Details:
{finding}
"""

        issue_dict = {
            "project": {
                "key": os.getenv("JIRA_PROJECT", "SEC")
            },
            "summary": summary,
            "description": description,
            "issuetype": {
                "name": "Task"
            }
        }

        issue = jira.create_issue(
            fields=issue_dict
        )

        return issue.key
    except Exception as e:
        print(f"Error creating JIRA ticket: {e}")
        return None
