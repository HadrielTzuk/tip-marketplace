from SentinelOneV2Parser import SentinelOneV2Parser
from datamodelsV2 import *


class SentinelOneV2ParserV2(SentinelOneV2Parser):

    @staticmethod
    def build_threat_notes(raw_json):
        return ThreatNote(raw_data=raw_json, text=raw_json.get('text', ''))

    def build_threat_obj(self, threat_data):
        return ThreatV21(
            raw_data=threat_data,
            threat_id=threat_data.get('id'),
            threat_name=threat_data.get('threatInfo', {}).get('threatName'),
            agent_id=threat_data.get('agentRealtimeInfo', {}).get('agentId'),
            analyst_verdict=threat_data.get('threatInfo', {}).get('analystVerdict'),
            created_at=threat_data.get('threatInfo', {}).get('createdAt'),
            classification=threat_data.get('threatInfo', {}).get('classification'),
            site_id=threat_data.get('agentRealtimeInfo', {}).get('siteId'),
            site_name=threat_data.get('agentRealtimeInfo', {}).get('siteName'),
            hash_value=threat_data.get('threatInfo', {}).get('sha1'),
            mitigation_status=threat_data.get('threatInfo', {}).get('mitigationStatus'),
            incident_status_dsc=threat_data.get('threatInfo', {}).get('incidentStatusDescription', ''),
            incident_status=threat_data.get('threatInfo', {}).get('incidentStatus', ''),
            analyst_verdict_dsc=threat_data.get('threatInfo', {}).get('analystVerdictDescription', ''),
            agent_computer_name=threat_data.get('agentRealtimeInfo', {}).get('agentComputerName', ''),
            process_user=threat_data.get('threatInfo', {}).get('processUser'),
            in_quarantine=threat_data.get('inQuarantine'),
            description=threat_data.get('threatInfo', {}).get('initiatedByDescription'),
            mitigation_statuses=self.build_results(
                raw_json=threat_data.get('mitigationStatus', []),
                method='build_mitigation_status',
                pure_data=True
            ),
            resolved=threat_data.get('threatInfo', {}).get('incidentStatus') == 'resolved'
        )

    @staticmethod
    def build_mitigation_status(raw_json):
        return MitigationStatus(
            raw_data=raw_json,
            action=raw_json.get('action'),
            status=raw_json.get('status'),
        )
