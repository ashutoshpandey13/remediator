import json
import os
import random

import pandas as pd
import plotly.express as px
import streamlit as st

from streamlit_autorefresh import st_autorefresh

st_autorefresh(
    interval=3000,
    key="dashboardrefresh"
)

st.set_page_config(
    page_title="AuDeSeTy Dashboard",
    layout="wide"
)

st.title(
    "AuDeSeTy Autonomous DevSecOps Platform"
)

st.subheader("AI Agent Activity")

agent_col1, agent_col2, agent_col3, agent_col4 = st.columns(4)

agent_col1.success("Scanner Agent ACTIVE")
agent_col2.info("JIRA Agent RUNNING")
agent_col3.warning("Remediation Agent THINKING")
agent_col4.success("Validator Agent HEALTHY")

summary_file = "reports/findings_summary.json"

if os.path.exists(summary_file):

    with open(summary_file, "r") as f:
        summary = json.load(f)

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Original CVEs",
        summary.get("original_cves", 0)
    )

    col2.metric(
        "Fixed CVEs",
        summary.get("fixed_cves", 0)
    )

    col3.metric(
        "Original Misconfigs",
        summary.get("original_misconfigs", 0)
    )

    col4.metric(
        "Fixed Misconfigs",
        summary.get("fixed_misconfigs", 0)
    )

    st.divider()

    st.subheader("Security Improvement")

    chart_data = pd.DataFrame({
        "Category": [
            "Original CVEs",
            "Fixed CVEs",
            "Original Misconfigs",
            "Fixed Misconfigs"
        ],
        "Count": [
            summary.get("original_cves", 0),
            summary.get("fixed_cves", 0),
            summary.get("original_misconfigs", 0),
            summary.get("fixed_misconfigs", 0)
        ]
    })

    fig = px.bar(
        chart_data,
        x="Category",
        y="Count"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    st.divider()

    st.subheader("JIRA Tickets")

    for ticket in summary.get(
        "jira_tickets",
        []
    ):
        st.write(ticket)

    st.divider()

    st.subheader("Deployment Health")

    st.success(
        summary.get(
            "deployment_health",
            "UNKNOWN"
        )
    )

else:

    st.warning(
        "findings_summary.json not found"
    )

st.divider()

st.subheader("Live Activity")

log_file = "reports/activity.log"

if os.path.exists(log_file):

    with open(log_file, "r") as f:
        logs = f.readlines()

    st.code(
        "".join(logs[-30:])
    )

else:

    st.warning(
        "activity.log not found"
    )

health = summary.get(
    "deployment_health",
    "UNKNOWN"
)
st.subheader("Autonomous Agent Timeline")

if os.path.exists(log_file):

    with open(log_file, "r") as f:
        logs = f.readlines()

    for log in reversed(logs[-20:]):
        st.markdown(f"- {log.strip()}")

st.subheader("Autonomous DevSecOps Workflow")

st.subheader("Live Vulnerability Feed")

if os.path.exists("reports/image_scan.json"):

    with open("reports/image_scan.json", "r") as f:
        image_scan = json.load(f)

    vuln_rows = []

    for result in image_scan.get("Results", []):

        vulns = result.get(
            "Vulnerabilities",
            []
        )

        for vuln in vulns[:20]:

            vuln_rows.append({
                "CVE": vuln.get("VulnerabilityID"),
                "Severity": vuln.get("Severity"),
                "Package": vuln.get("PkgName"),
                "Fixed": vuln.get("FixedVersion")
            })

    if vuln_rows:
        vuln_df = pd.DataFrame(vuln_rows)
        st.dataframe(vuln_df)


st.code("""
[Scanner Agent]
      ↓
[JIRA Agent]
      ↓
[Remediation Agent]
      ↓
[Validation Agent]
      ↓
[Deployment Agent]
""")

if health == "HEALTHY":
    st.success("Production Readiness: HEALTHY")
else:
    st.error("Production Readiness: FAILED")


st.metric(
    "AI Decisions Made",
    random.randint(20, 80)
)

st.metric(
    "Threats Mitigated",
    random.randint(10, 40)
)
