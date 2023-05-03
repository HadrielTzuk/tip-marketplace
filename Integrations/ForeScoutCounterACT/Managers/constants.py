INTEGRATION_NAME = "ForeScoutCounterACT"
INTEGRATION_DISPLAY_NAME = "ForeScout CounterACT"

# Actions
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_DISPLAY_NAME)
ENRICH_ENTITIES_SCRIPT_NAME = "{} - Enrich Entities".format(INTEGRATION_DISPLAY_NAME)

ENRICHMENT_PREFIX = "FSCACT"

ENDPOINT_INSIGHT_TEMPLATE = """
<p style="margin-bottom: -10px;font-size:15px"><strong>Online: <span style="color: {is_online_color}">{is_online}</span></strong></p>
<b>IP Address:</b> {ip_address}
<b>Mac Address:</b> {mac_address}
<b>Fingerprint:</b> {fingerprint}
<b>Classification:</b> {classification}
<b>Agent Version:</b> {agent_version}
"""

GREEN = "#12ab50"
RED = "#ff0000"
