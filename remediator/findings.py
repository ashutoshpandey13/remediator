def normalize_k8s_findings(findings):

    normalized = []

    for finding in findings:

        normalized.append({
            "type": "MISCONFIG",
            "id": finding.get("id"),
            "severity": finding.get("severity"),
            "title": finding.get("title"),
            "message": finding.get("message"),
            "file": finding.get("file")
        })

    return normalized


def normalize_cves(cves):

    normalized = []

    for cve in cves:

        normalized.append({
            "type": "CVE",
            "id": cve.get("cve"),
            "severity": cve.get("severity"),
            "package": cve.get("package"),
            "installed_version": cve.get("installed"),
            "fixed_version": cve.get("fixed"),
            "file": cve.get("file"),
            "image": cve.get("image")
        })

    return normalized


def normalize_sast(sast_findings):

    normalized = []

    for finding in sast_findings:

        normalized.append({
            "type": "SAST",
            "id": finding.get("id"),
            "severity": finding.get("severity"),
            "message": finding.get("message"),
            "file": finding.get("file")
        })

    return normalized


def normalize_secrets(secret_findings):

    normalized = []

    for finding in secret_findings:

        normalized.append({
            "type": "SECRET",
            "id": finding.get("rule"),
            "severity": finding.get("severity"),
            "message": finding.get("description"),
            "file": finding.get("file")
        })

    return normalized


def normalize_cspm(cspm_findings):

    normalized = []

    for finding in cspm_findings:

        normalized.append({
            "type": "CSPM",
            "id": finding.get("id"),
            "severity": finding.get("severity"),
            "title": finding.get("title"),
            "message": finding.get("message"),
            "file": finding.get("file"),
            "resource": finding.get("resource")
        })

    return normalized


def normalize_runtime(runtime_findings):

    normalized = []

    for finding in runtime_findings:

        normalized.append({
            "type": "RUNTIME",
            "id": finding.get("rule"),
            "severity": finding.get("severity"),
            "message": finding.get("message")
        })

    return normalized


def normalize_network(network_findings):

    normalized = []

    for finding in network_findings:

        normalized.append({
            "type": "NETWORK",
            "id": finding.get("id"),
            "severity": finding.get("severity"),
            "message": finding.get("message")
        })

    return normalized


def combine_findings(
    k8s_findings,
    cve_findings,
    sast_findings=None,
    secret_findings=None,
    cspm_findings=None,
    runtime_findings=None,
    network_findings=None
):
    """Merge every scanner's findings into one normalized list.

    Only the first two arguments are required, so callers that only run the
    Kubernetes and container image scanners keep working unchanged.
    """

    return (
        normalize_k8s_findings(k8s_findings)
        +
        normalize_cves(cve_findings)
        +
        normalize_sast(sast_findings or [])
        +
        normalize_secrets(secret_findings or [])
        +
        normalize_cspm(cspm_findings or [])
        +
        normalize_runtime(runtime_findings or [])
        +
        normalize_network(network_findings or [])
    )
