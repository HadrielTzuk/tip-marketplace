import json
from SentinelOneV2Manager import SentinelOneV2Manager
from SentinelOneV2ParserV2 import SentinelOneV2ParserV2


API_ENDPOINTS = {
    'threat_incident': '/web/api/v{api_version}/threats/incident',
    'get_threats_notes': '/web/api/v{api_version}/threats/{threat_id}/notes',
    'add_threats_notes': '/web/api/v{api_version}/threats/notes',
    'analyst_verdict': '/web/api/v{api_version}/threats/analyst-verdict',
    'move_agents': '/web/api/v{api_version}/groups/{group_id}/move-agents',
    'fetch_file': '/web/api/v{api_version}/threats/fetch-file',
    'get_timeline': '/web/api/v{api_version}/threats/{threat_id}/timeline',
    'download_file': '/web/api/v{api_version}{download_url}'
}


class SentinelOneV2ManagerV2(SentinelOneV2Manager):
    def __init__(self, api_root, api_token, api_version, verify_ssl=False, force_check_connectivity=False, logger=None):
        """
        :param api_root: API root URL.
        :param api_token: SentinelOne api token
        :param verify_ssl: Enable (True) or disable (False). If enabled, verify the SSL certificate for the connection.
        :param force_check_connectivity: True or False. If True it will check connectivity initially.
        :param logger: Siemplify logger.
        """
        super().__init__(api_root, api_token, api_version, verify_ssl, force_check_connectivity, logger)
        self.api_endpoints.update(API_ENDPOINTS)
        self.parser = SentinelOneV2ParserV2()

    def move_agents(self, group_id, agent_ids=None):
        """
        Move agents to a given group
        :param group_id: {str} The ID of the group
        :param agent_ids: {list} List of ids of agents to move to the group
        :return: {int} Number of agents that were moved
            raise SentinelOneV2ManagerError if failed to validate response status code
        """
        payload = {
            'filter': {
                'ids': agent_ids,
            } if agent_ids else {}
        }
        response = self.session.put(
            self._get_full_url('move_agents', group_id=group_id), json=payload
        )
        self.validate_response(response, 'Unable to move agents')

        return self.parser.get_moved_count(response.json())

    def get_threat_notes(self, threat_id):
        """
        Get threats annotation
        :param threat_id {int}
        :return: affected count
        """
        response = self.session.get(self._get_full_url('get_threats_notes', threat_id=threat_id))
        self.validate_response(response, 'Unable get threat notes')

        return self.parser.build_results(response.json(), 'build_threat_notes')

    def resolve_threat(self, threat_ids, annotation=None):
        """
        Resolves threats using the threat ID
        :param threat_ids: {list} List of threat IDs
        :param annotation: {str} Threat annotation
        :return: affected count
        """
        payload = {
            'data': {
                'incidentStatus': 'resolved'
            },
            'filter': {
                'ids': threat_ids
            }
        }

        response = self.session.post(self._get_full_url('threat_incident'), json=payload)
        self.validate_response(response, 'Unable to resolve threat')

        if annotation:
            self.add_notes_to_threat(threat_ids, annotation)

        return self.parser.get_affected(response.json())

    def add_notes_to_threat(self, threat_ids, note):
        """
        Add notes to threats using the threat ID
        :param threat_ids: {list} List of threat IDs
        :param note: {str} Threat note
        :return: {int} affected count
        """
        payload = {
            'data': {
                'text': note
            },
            'filter': {
                'ids': threat_ids
            }
        }
        response = self.session.post(self._get_full_url('add_threats_notes'), json=payload)
        self.validate_response(response, 'Unable to add note to threat')

        return self.parser.get_affected(response.json())

    def mark_as_threat(self, threat_ids):
        """
        Marks suspicious threats as a threat
        :param threat_ids: {list} List ot threat IDs
        :return: {int} count of affected threats
        """
        payload = {
            'data': {
                'analystVerdict': 'true_positive'
            },
            'filter': {
                'ids': threat_ids
            }
        }
        response = self.session.post(self._get_full_url('analyst_verdict'), json=payload)
        self.validate_response(response, 'Unable to mark as threat')

        return self.parser.get_affected(response.json())

    def create_fetch_job(self, threat_id, password):
        """
        Create a fetch job
        :param threat_id: {str} The threat id
        :param password: {str} The password for the zip that contains the threat file
        :return: {int} The job affected value
        """
        url = self._get_full_url("fetch_file")
        payload = json.dumps({
            "data": {
                "password": password
            },
            "filter": {
                "ids": [
                    threat_id
                ]
            }
        })

        response = self.session.post(url, data=payload)
        self.validate_response(response)

        return self.parser.get_affected(response.json())

    def get_file_from_timeline(self, threat_id):
        """
        Get threat file from timeline
        :param threat_id: {str} The threat id
        :return: {tuple} File name, file content
        """
        url = self._get_full_url("get_timeline", threat_id=threat_id)
        params = {
            "skip": 0,
            "limit": 100,
            "sortOrder": "desc"
        }

        response = self.session.get(url, params=params)
        self.validate_response(response)
        name, url = self.parser.get_file_data_from_timeline(response.json())

        if name and url:
            return name, self.get_file_by_download_url(url)
        else:
            return None, None

    def get_file_by_download_url(self, download_url):
        """
        Get file by url
        :param download_url: The file download url
        :return: {dict} The raw data of file
        """
        url = self._get_full_url("download_file", download_url=download_url)
        response = self.session.get(url)
        self.validate_response(response)
        return response.content

    def update_analyst_verdict(self, threat_id, analyst_verdict):
        """
        Update analyst ver dict
        :param threat_id: {str} Threat ID
        :param analyst_verdict: analyst Verdict mapped value
        :return: {bool} True if analyst verdict updated False otherwise
        """
        payload = {
            'data': {
                'analystVerdict': analyst_verdict
            },
            'filter': {
                'ids': [threat_id]
            }
        }

        response = self.session.post(self._get_full_url('analyst_verdict'), json=payload)
        self.validate_response(response)
        updated_threat = self.get_threats(threat_ids=[threat_id])[0]

        return updated_threat.analyst_verdict == analyst_verdict

    def update_incident_status(self, incident_ids, status):
        """
        Update incident status.
        :param incident_ids: {list} List of ids
        :param status: {str} possible values (value of INCIDENT_STATUS_MAPPING)
        :return: {int} count affected count
        """
        payload = {
            'data': {
                'incidentStatus': status
            },
            'filter': {
                'ids': incident_ids
            }
        }
        response = self.session.post(self._get_full_url('threat_incident'), json=payload)
        self.validate_response(response, 'Unable to update incident status')
        updated_threat = self.get_threats(threat_ids=incident_ids)[0]

        return updated_threat.incident_status == status
