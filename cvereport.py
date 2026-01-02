from cveapi import CVE, get_cves
from datetime import datetime, timedelta 
from python_ntfy import NtfyClient
import argparse
import markdown
import json
from datetime import datetime
import os

NTFY_MTU = 32000  # Maximum Transmission Unit for ntfy messages as per default config

parser = argparse.ArgumentParser(description="CVEDaily options")
parser.add_argument("--server", "-s", default="https://ntfy.sh", help="ntfy server hostname or URL")
parser.add_argument("--severity", "-v", default="CRITICAL", help="severity filter for CVEs (e.g. CRITICAL, HIGH, MEDIUM, LOW, ALL)")
parser.add_argument("--topic", "-t", default="topic", help="ntfy topic to publish messages to")

args = parser.parse_args()

server_host = args.server
topic = args.topic

# TODO: Add multiple severity level support. Will require multiple API calls as NVD only accepts one at a time
severity_arg = args.severity.upper()
severity = None if severity_arg == "ALL" else severity_arg

# Re-fetch CVEs using the requested severity
cves = get_cves(start_date=(datetime.now() - timedelta(days=1)), end_date=datetime.now(), severity=severity)

# TODO: Maybe couple priority to CVE criticality, keywords etc?
client = NtfyClient(server=server_host, topic=topic)

message_lines = [f"Total {severity_arg}-level CVEs: {len(cves)}\n"]
for i, c in enumerate(cves, start=1):

    message_lines.append(f"## {c.id}\n")
    first_line = str(c.description).splitlines()[0]
    for metric in c.metrics.values():
        message_lines.append(f"**CVSS {metric.version} Severity**: {metric.baseScore}")
    message_lines.append(f"**Published**: {c.published.strftime('%H:%M %d/%m/%Y')}")
    message_lines.append(f"**Description**: {first_line}")

    # Refs
    if len(c.references) > 0:
        message_lines.append(f"\n**References**:\n")
        for reference in c.references:
            message_lines.append(f"[{reference.source}]({reference.url})")
        
full_report = "\n".join(message_lines)

if len(full_report) > NTFY_MTU: # If message is too long, send full report as file

    report_path = f"cve_report_{datetime.now().strftime('%Y%m%d')}.html"
    with open(report_path, "w", encoding="utf-8") as f:
        full_report = markdown.markdown(full_report, extensions=['nl2br', 'smarty'])
        f.write(full_report)

    client.send_file(title="CVE Daily Report", priority=client.MessagePriority.HIGH, file=report_path)
    if os.path.exists(report_path):
        os.remove(report_path)
else:
    client.send(title="CVE Daily Report", message=full_report, priority=client.MessagePriority.HIGH, format_as_markdown=True)

