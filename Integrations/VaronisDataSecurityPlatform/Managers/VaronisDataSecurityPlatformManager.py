from dataclasses import dataclass
from datetime import datetime

from requests.sessions import Session
from requests_ntlm import HttpNtlmAuth
from typing import List, Optional
from urllib.parse import urljoin

from VaronisDataSecurityPlatformParser import VaronisDataSecurityPlatformParser


API_URLS = {
    "login": "datadvantage/api/authentication/win",
    "alerts": "datadvantage/api/alert/alert/GetAlerts",
    "events": "datadvantage/api/alert/alert/GetAlertedEvents",  # ?alertId={alert_id}
    "update_alerts": "datadvantage/api/alert/alert/SetStatusToAlerts",  # ?alertId={alert_id}
}


class VaronisManagerException(Exception):

    status_code: int

    def __init__(self, status_code, text=''):
        self.status_code = status_code

        if status_code == 401:
            msg = "Invalid credentials"
        elif status_code == 404:
            msg = "Not found"
        else:
            msg = text

        super().__init__(msg)


@dataclass
class QueryParams:
    maxResult: int
    alertId: Optional[str] = None
    startTime: Optional[datetime] = None
    severity: Optional[List[str]] = None
    status: Optional[List[str]] = None
    descendingOrder: bool = False
    offset: int = 0

    def make_query_string(self):
        query_string_elements = []

        for key, value in self.__dict__.items():
            if value is None:
                continue
            if not isinstance(value, list):
                value = [value]
            query_string_elements.extend([f"{key}={v}" for v in value])

        return "?" + "&".join(query_string_elements)


class VaronisDataSecurityPlatformManager:
    def __init__(self, api_root: str, username: str, password: str,
                 verify_ssl : bool = True):
        self.api_root = api_root
        self.username = username
        self.password = password

        self.session = Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            "Authorization": f"Bearer {self.get_token()}"
        })

        self.parser = VaronisDataSecurityPlatformParser()

    def __construct_url(self, url_key, **kwargs):
        return urljoin(
            self.api_root,
            API_URLS[url_key].format(**kwargs)
        )

    @staticmethod
    def validate_response(response):
        if response.status_code != 200:
            raise VaronisManagerException(response.status_code, response.text)
        return True

    def get_token(self):
        response = self.session.post(
            self.__construct_url("login"),
            auth=HttpNtlmAuth(self.username, self.password),
            data={"grant_type": "client_credentials"}
        )
        self.validate_response(response)
        return response.json()["access_token"]

    def get_alerts(self, start_time: datetime, max_alerts_per_cycle: int,
                   status: List[str], severity: List[str], existing_ids: List[str]):

        params = QueryParams(
            startTime=start_time,
            maxResult=max_alerts_per_cycle,
            status=status,
            severity=severity
        )

        alerts = []

        while len(alerts) <= max_alerts_per_cycle:
            response = self.session.get(
                self.__construct_url("alerts") + params.make_query_string()
            )
            self.validate_response(response)

            new_alerts = self.parser.build_alerts(response.json())
            if not new_alerts:
                break

            alerts.extend(alert for alert in new_alerts if alert.id not in existing_ids)
            params.offset += params.maxResult

        return alerts[:max_alerts_per_cycle]

    def get_events_by_alert_id(self, alert_id: str, max_events_per_varonis_alert: int):
        params = QueryParams(
            maxResult=max_events_per_varonis_alert,
            alertId=alert_id
        )

        response = self.session.get(
            self.__construct_url("events")
            + params.make_query_string()
        )
        self.validate_response(response)

        events = self.parser.build_events(response.json())

        return events[:max_events_per_varonis_alert]

    def update_alert(self, alert_ids: List[str], status_id: int, close_reason_id: Optional[int] = None):
        form = {
            "AlertGuids": alert_ids,
            "statusId": status_id,
        }

        if close_reason_id is not None:
            form["closeReasonId"] = close_reason_id

        response = self.session.post(
            self.__construct_url("update_alerts"),
            json=form
        )
        self.validate_response(response)

        return True
