from datamodels import *
from datamodels import Threat
from constants import THREAT_TRUE_POSITIVE


class ThreatV21(Threat):
    def __init__(self, incident_status_dsc=None, analyst_verdict_dsc=None, process_user=None, agent_computer_name=None,
                 incident_status=None, analyst_verdict=None, mitigation_statuses=None, *args, **kwargs):
        super().__init__(analyst_verdict=analyst_verdict, *args, **kwargs)

        self.incident_status_dsc = incident_status_dsc
        self.analyst_verdict_dsc = analyst_verdict_dsc
        self.process_user = process_user
        self.agent_computer_name = agent_computer_name
        self.incident_status = incident_status
        self.is_true_positive = analyst_verdict == THREAT_TRUE_POSITIVE
        self.mitigation_statuses = mitigation_statuses

    def to_csv(self):
        return {
            'Analyst Verdict': self.analyst_verdict_dsc,
            'Incident Status': self.incident_status_dsc,
            'Name': self.threat_name,
            'Endpoint': self.agent_computer_name,
            'Process User': self.process_user,
        }


class MitigationStatus(BaseModel):
    def __init__(self, raw_data, action=None, status=None):
        super().__init__(raw_data)
        self.action = action
        self.status = status

    def has_action(self, action):
        return self.action.replace('-', '') == action.replace('-', '')
