from jira import JIRA
from dotenv import load_dotenv

import os

load_dotenv()


jira = JIRA(
    server=os.getenv("JIRA_URL"),
    basic_auth=(
        os.getenv("JIRA_EMAIL"),
        os.getenv("JIRA_API_TOKEN")
    )
)


def create_jira_ticket(finding):

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
            "key": os.getenv("JIRA_PROJECT")
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
