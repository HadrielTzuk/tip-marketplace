# Integrations.MicrosoftGraphMail.Managers.
from Integrations.MicrosoftGraphMail.Managers.MicrosoftGraphMailManager import MicrosoftGraphMailManager

import json
import pytest


def read_config():
    with open("config.json", "r") as f:
        data = f.read()

    config = json.loads(data)
    azure_ad_endpoint = config["azure_ad_endpoint"]
    microsoft_graph_endpoint = config.get("microsoft_graph_endpoint")
    client_id = config.get("client_id")
    client_secret = config.get("client_secret")
    tenant = config.get("tenant")
    mail_box = config.get("mail_box")

    return azure_ad_endpoint, microsoft_graph_endpoint, client_id, client_secret, tenant, mail_box


@pytest.fixture(scope="module")
def ms_graph_mail_manager():
    azure_ad_endpoint, microsoft_graph_endpoint, client_id, client_secret, tenant, mail_box = read_config()

    yield MicrosoftGraphMailManager(
        client_id=client_id,
        client_secret=client_secret,
        tenant=tenant,
        azure_ad_endpoint=azure_ad_endpoint,
        microsoft_graph_endpoint=microsoft_graph_endpoint,
        mail_address=mail_box
    )
