INTEGRATION_NAME = "Outpost24"
INTEGRATION_DISPLAY_NAME = "Outpost24"

# Actions
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_DISPLAY_NAME)
ENRICH_ENTITIES_SCRIPT_NAME = "{} - Enrich Entities".format(INTEGRATION_DISPLAY_NAME)

GET_TOKEN_URL = "{}/opi/rest/auth/login"
PING_URL = "{}/opi/rest/outscan/findings?limit=1"
GET_DEVICES_URL = "{}/opi/rest/outscan/targets"
GET_FINDINGS_URL = "{}/opi/rest/outscan/findings"

SUPORTED_RISK_LEVELS = ["low", "medium", "high", "critical", "initial", "recommendation"]
ENRICHMENT_PREFIX = "Outpost24"
DEFAULT_API_LIMIT = 1000

# Connector
CONNECTOR_NAME = "{} - Outscan Findings Connector".format(INTEGRATION_DISPLAY_NAME)
DEFAULT_TIME_FRAME = 1
DEFAULT_LIMIT = 100
DEVICE_VENDOR = "Outpost24"
DEVICE_PRODUCT = "Outpost24"

POSSIBLE_TYPES = ["Information", "Vulnerability", "Port"]

SEVERITY_MAP = {
    "Initial": -1,
    "Recommendation": -1,
    "Low": 40,
    "Medium": 60,
    "High": 80,
    "Critical": 100
}

SEVERITIES = ['initial', 'recommendation', 'low', 'medium', 'high', 'critical']

FINDING_TYPES = {
    "All":"Vulnerability, Information",
    "Vulnerability":"Vulnerability",
    "Information":"Information"
}

RISK_COLOR_MAP = {
    "LOW": "#ffff00",
    "MEDIUM": "#ff9900",
    "HIGH": "#ff0000",
    "CRITICAL": "#ff0000",
}

INSIGHT_HTML_TEMPLATE = """
<table>
<tbody>
<tr>
<td>
<h2 style="text-align: left;"><strong>Business Criticality: <span style="color: {risk_color};">{criticality}</span></strong></h2>
</td>
</tr>
</tbody>
</table>
<p><strong>Hostname: </strong>{hostname}<strong><br />IP: </strong>{ip}<strong><br />Exposed: </strong>{exposed}<strong><br /></strong><strong>Source: </strong>{source}</p>
"""

INSIGHT_HTML_TEMPLATE_FINDINGS = """

<h3><strong>Findings Stats</strong></h3>
<h4>Type</h4>
<p><strong>Vulnerability</strong>: {count_vulnerability_findings}<br /><strong>Information:&nbsp;</strong>{count_information_findings}</p>
<p><strong>Risk Level</strong></p>
<p><strong>Initial:</strong>&nbsp;{count_initial_findings}<strong><br /></strong><strong>Recommendation:&nbsp;</strong>{count_recommendation_findings}<strong><br />Low:&nbsp;</strong>{count_low_findings}<strong><br />Medium:&nbsp;</strong>{count_medium_findings}<strong><br />High:</strong>&nbsp;{count_high_findings}<strong><br />Critical:&nbsp;</strong>{count_critical_findings}</p>
"""