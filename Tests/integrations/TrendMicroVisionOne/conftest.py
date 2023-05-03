# Integrations.TrendMicroVisionOne.Managers.
from Integrations.TrendMicroVisionOne.Managers.TrendMicroVisionOneManager import TrendMicroVisionOneManager

import json
import pytest


def read_config():
    with open("config.json", "r") as f:
        data = f.read()

    config = json.loads(data)
    api_root = config["api_root"]
    api_token = config["api_token"]

    return api_root, api_token


@pytest.fixture(scope="module")
def manager_fixture():
    api_root, api_token = read_config()

    yield TrendMicroVisionOneManager(
        api_root=api_root,
        api_token=api_token,
        verify_ssl=True
    )
