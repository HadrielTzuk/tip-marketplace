# Integrations.Automox.Managers.
from Integrations.Automox.Managers.AutomoxManager import AutomoxManager

import json
import pytest


def read_config():
    with open("config.json", "r") as f:
        data = f.read()

    config = json.loads(data)
    api_root = config["api_root"]
    api_key = config["api_key"]

    return api_root, api_key


@pytest.fixture(scope="module")
def manager_fixture():
    api_root, api_key = read_config()

    yield AutomoxManager(
        api_root=api_root,
        api_key=api_key,
    )
