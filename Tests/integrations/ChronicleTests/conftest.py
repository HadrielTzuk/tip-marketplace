import dataclasses
import json
from dataclasses import dataclass

import google.auth.transport.requests
import pytest
import requests
from _pytest.monkeypatch import MonkeyPatch

from SiemplifyMarketPlace.Integrations.GoogleChronicle.Managers import consts, exceptions
from SiemplifyMarketPlace.Integrations.GoogleChronicle.Managers.GoogleChronicleManager import GoogleChronicleManager
from SiemplifyMarketPlace.Tests.integrations.LoggerMock import Logger


@dataclass
class MockResponse:
    url: str = ''
    content: bytes = b''
    status_code: int = 200
    text: str = 'mock response text'
    error_message: str = 'mock was raised for status'
    headers: dict = dataclasses.field(default_factory=dict)
    mock_json: dict = dataclasses.field(default_factory=dict)

    def json(self) -> dict:
        return self.mock_json if self.mock_json is not None else {"mock_key": "mock_response"}

    def raise_for_status(self) -> None:
        if 400 <= self.status_code < 600:
            raise requests.HTTPError(self.error_message)


@pytest.fixture(scope="module")
def chronicle_manager() -> GoogleChronicleManager:
    with open("config.json", "r") as f:
        data = f.read()

    config = json.loads(data)['valid configuration']
    api_root = config.get("api_root")
    verify_ssl = config.get("verify_ssl")
    creds = config.get("creds")

    yield GoogleChronicleManager(
        api_root=api_root,
        verify_ssl=verify_ssl,
        siemplify_logger=Logger(),
        **creds,
    )


@pytest.fixture
def mock_batch_update_cases_response_to_error(monkeypatch: MonkeyPatch) -> None:
    def mock_post(_, url: str = '', *args, **kwargs) -> MockResponse:
        return MockResponse(
            url=url,
            text=(
                '--batch_9hOiWLMQiI3jjoNTRceidFMt4B42GEQy\n'
                'Content-Type: application/http\n'
                'Content-ID: response-\n'
                '\n'
                'HTTP/1.1 400 Bad Request\n'
                'Vary: Origin\n'
                'Vary: X-Origin\n'
                'Vary: Referer\n'
                'Content-Type: application/json; charset=UTF-8\n'
                '\n'
                '{\n'
                '  "error": {\n'
                '    "code": 400,\n'
                '    "message": "Invalid value at \'case_resource.priority\' (type.googleapis.com/backstory.Priority), 999999999999Invalid value at \'case_resource.status\' (type.googleapis.com/backstory.Status), -999999999999",\n'  # \n between 99999 and Invalid was removed
                '    "status": "INVALID_ARGUMENT",\n'
                '    "details": [\n'
                '      {\n'
                '        "@type": "type.googleapis.com/google.rpc.BadRequest",\n'
                '        "fieldViolations": [\n'
                '          {\n'
                '            "field": "case_resource.priority",\n'
                '            "description": "Invalid value at \'case_resource.priority\' (type.googleapis.com/backstory.Priority), 999999999999"\n'
                '          },\n'
                '          {\n'
                '            "field": "case_resource.status",\n'
                '            "description": "Invalid value at \'case_resource.status\' (type.googleapis.com/backstory.Status), -999999999999"\n'
                '          }\n'
                '        ]\n'
                '      }\n'
                '    ]\n'
                '  }\n'
                '}\n'
                '\n'
                '--batch_9hOiWLMQiI3jjoNTRceidFMt4B42GEQy--'
            ),
            headers={
                'Content-Type': 'multipart/mixed; boundary=batch_9hOiWLMQiI3jjoNTRceidFMt4B42GEQy',
                'Vary': 'Origin, X-Origin, Referer', 'Content-Encoding': 'gzip',
                'Date': 'Mon, 24 Oct 2022 13:00:09 GMT', 'Server': 'ESF', 'Cache-Control': 'private',
                'X-XSS-Protection': '0', 'X-Frame-Options': 'SAMEORIGIN', 'X-Content-Type-Options': 'nosniff',
                'Alt-Svc': 'h3=":443"; ma=2592000,h3-29=":443"; ma=2592000,h3-Q050=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000,quic=":443"; ma=2592000; v="46,43"',
                'Transfer-Encoding': 'chunked'
            },
        )

    monkeypatch.setattr(
        google.auth.transport.requests.AuthorizedSession,
        'post',
        mock_post
    )


@pytest.fixture
def mock_validate_response_to_raise_manager_error(monkeypatch: MonkeyPatch) -> None:
    def mock_raise_manager_error(*args, **kwargs) -> None:
        raise exceptions.GoogleChronicleManagerError("Unable to list IOCs")

    monkeypatch.setattr(
        GoogleChronicleManager,
        'validate_response',
        mock_raise_manager_error
    )


@pytest.fixture
def mock_build_cases_batch_request_data_empty_str(monkeypatch: MonkeyPatch) -> None:
    """batch_update_cases_in_chronicle mocked to return ''."""

    monkeypatch.setattr(
        GoogleChronicleManager,
        "build_cases_batch_request_data",
        lambda *args, **kwargs: ''
    )


@pytest.fixture
def mock_build_alerts_batch_request_data_empty_str(monkeypatch: MonkeyPatch) -> None:
    """batch_update_alerts_in_chronicle mocked to return ''."""

    monkeypatch.setattr(
        GoogleChronicleManager,
        "build_alerts_batch_request_data",
        lambda *args, **kwargs: ''
    )