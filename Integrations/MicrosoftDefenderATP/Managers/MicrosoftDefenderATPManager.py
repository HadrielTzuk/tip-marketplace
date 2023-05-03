# ============================= IMPORTS ===================================== #
import requests
from datetime import datetime, timedelta
# FIXME: Import urllib while using python 3
import urlparse

from datamodels import Alert, Machine, User, QueryResult, MachineTask, File, Detection
from MicrosoftDefenderATPTransformationLayer import MicrosoftDefenderATPTransformationLayer
from TIPCommon import filter_old_alerts
from constants import DEFAULT_ALERTS_LIMIT


class MicrosoftDefenderATPError(Exception):
    """
    General Exception for MicrosoftDefenderATP Manager
    """
    pass


class MicrosoftDefenderATPValidationError(Exception):
    """
    General Exception for MicrosoftDefenderATP Validation
    """
    pass


class MicrosoftDefenderATPForbiddenError(Exception):
    pass


class MicrosoftDefenderATPManager(object):
    """
    MicrosoftDefenderATP Manager
    """
    TIME_FORMAT = u"%Y-%m-%dT%H:%M:%S.%fZ"
    ACCESS_TOKEN_URL = u'https://login.windows.net/{tenant_id}/oauth2/token'
    DEFENDER_API_ACCESS_TOKEN_URL = u'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
    SIEM_DETECTIONS_URL = u'https://wdatp-alertexporter-us.securitycenter.windows.com'

    TOKEN_PAYLOAD = {
        u'client_id': None,
        u'client_secret': None,
        u'resource': None,
        u'grant_type': u'client_credentials'
    }

    DEFENDER_API_TOKEN_PAYLOAD = {
        u'client_id': None,
        u'client_secret': None,
        u'scope': u'https://api.security.microsoft.com/.default',
        u'grant_type': u'client_credentials'
    }

    URLS = {
        u'test_connectivity': u'/api/alerts',
        u'get_alerts': u'/api/alerts',
        u'update_alert': u'/api/alerts/{alert_id}',
        u'get_machines': u'/api/machines',
        u'get_machine_logon_users': u'/api/machines/{machine_id}/logonusers',
        u'get_machine_related_alerts': u'/api/machines/{machine_id}/alerts',
        u'isolate_machine': u'/api/machines/{machine_id}/isolate',
        u'unisolate_machine': u'/api/machines/{machine_id}/unisolate',
        u'run_antivirus_scan': u'/api/machines/{machine_id}/runAntiVirusScan',
        u'stop_and_quarantine_machine_file': u'/api/machines/{machine_id}/StopAndQuarantineFile',
        u'get_machine_task_status': u'/api/machineactions',
        u'wait_machine_task_status': u'/api/machineactions',
        u'get_file_related_alerts': u'/api/files/{file_hash}/alerts',
        u'get_file_related_machines': u'/api/files/{file_hash}/machines',
        u'run_advanced_hunting_query': u'/api/advancedqueries/run',
        u'get_file_info': u'/api/files/{file_hash}',
        u'get_file_stats': u'/api/files/{file_hash}/stats',
        u'get_detections_siem': u'/api/alerts',
        u'get_incident': u'/api/incidents/{}',
        u'entities': u'/api/indicators',
        u'delete_indicator': u'/api/indicators/{indicator_id}'
    }

    DEFAULT_TIME_FRAME = 3

    DEFAULT_STATUSES = [
        u'Unknown',
        u'New',
        u'InProgress',
        u'Resolved'
    ]

    DEFAULT_SEVERITIES = [
        u'UnSpecified',
        u'Informational',
        u'Low',
        u'Medium',
        u'High'
    ]

    DEFAULT_CATEGORIES = [
        u'Collection',
        u'CommandAndControl',
        u'CredentialAccess',
        u'DefenseEvasion',
        u'Discovery',
        u'Execution',
        u'Exfiltration',
        u'Exploit',
        u'InitialAccess',
        u'LateralMovement',
        u'Malware',
        u'Persistence',
        u'PrivilegeEscalation',
        u'Ransomware',
        u'SuspiciousActivity',
        u'UnwantedSoftware'
    ]

    DEFAULT_CLASSIFICATIONS = [
        u'Unknown',
        u'FalsePositive',
        u'TruePositive',
    ]

    DEFAULT_DETERMINATIONS = [
        u'NotAvailable',
        u'Apt',
        u'Malware',
        u'SecurityPersonnel',
        u'SecurityTesting',
        u'UnwantedSoftware',
        u'Other'
    ]

    DEFAULT_HEALTH_STATUSES = [
        u'Active',
        u'Inactive',
        u'ImpairedCommunication',
        u'NoSensorData',
        u'NoSensorDataImpairedCommunication'
    ]

    DEFAULT_RISK_SCORES = [
        u'None',
        u'Low',
        u'Medium',
        u'High'
    ]

    TASK_SUCCEEDED_STATUS = u'Succeeded'
    TASK_PENDING_STATUS = u'Pending'
    TASK_FAILED_STATUS = u'Failed'
    TASK_TIMEOUT_STATUS = u'TimeOut'
    TASK_CANCELLED_STATUS = u'Cancelled'

    POSSIBLE_SCAN_TYPES = [
        u'Full',
        u'Quick',
    ]

    POSSIBLE_ISOLATION_TYPES = [
        u'Full',
        u'Selective',
    ]

    def __init__(self, client_id, client_secret, tenant_id, resource, defender_api_resource=None, verify_ssl=True,
                 siemplify=None, entities_scope=False):
        # type: (unicode, unicode, unicode, unicode, bool) -> None or Exception
        """
        Init function for MS Defender ATP Manager
        @param client_id:
        @param client_secret:
        @param tenant_id:
        @param resource:
        @param defender_api_resource:
        @param verify_ssl:
        @param siemplify_logger: Siemplify logger
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self.resource = resource
        self.defender_api_resource = defender_api_resource
        self.verify_ssl = verify_ssl
        self.siemplify = siemplify
        self.session = requests.Session()
        self.session.verify = verify_ssl
        if self.defender_api_resource:
            self.access_token = self._generate_defender_api_token(entities_scope=entities_scope)
        else:
            self.access_token = self._generate_token(self.client_id, self.client_secret, self.tenant_id, self.resource)

        self.session.headers.update({
            u"Authorization": u"Bearer {0}".format(self.access_token),
            u"Content-Type": u"application/json"
        })

    def _generate_token(self, client_id, client_secret, tenant_id, resource):
        # type: (unicode, unicode, unicode, unicode) -> unicode or Exception
        """
        Request access token (Valid for 60 min)
        @param client_id: The Application ID that the registration portal
        @param client_secret: The application secret that you created in the app registration portal for your app.
        @param tenant_id: Azure Active Directory Tenant ID
        @param resource: Api root url to use with integration.
        @return: Access token
        """
        self.TOKEN_PAYLOAD["client_id"] = client_id
        self.TOKEN_PAYLOAD["client_secret"] = client_secret
        self.TOKEN_PAYLOAD["resource"] = resource

        response = requests.post(self.ACCESS_TOKEN_URL.format(tenant_id=tenant_id), data=self.TOKEN_PAYLOAD,
                                 verify=self.verify_ssl)
        self._validate_response(response, u'Unable to generate access token for Microsoft Defender ATP')

        return response.json().get('access_token')

    def _generate_defender_api_token(self, entities_scope=False):
        """
        Request Defender API access token
        :return: {str} Access token
        """
        self.DEFENDER_API_TOKEN_PAYLOAD[u"client_id"] = self.client_id
        self.DEFENDER_API_TOKEN_PAYLOAD[u"client_secret"] = self.client_secret
        if entities_scope:
            self.DEFENDER_API_TOKEN_PAYLOAD[u"scope"] = u"https://api.securitycenter.microsoft.com/.default"
        request_url = self.DEFENDER_API_ACCESS_TOKEN_URL.format(tenant_id=self.tenant_id)
        response = requests.post(request_url, data=self.DEFENDER_API_TOKEN_PAYLOAD, verify=self.verify_ssl)
        self._validate_response(response, u"Unable to generate access token for Microsoft 365 Defender")
        return response.json().get(u"access_token")

    def test_connectivity(self):
        # type: () -> None or Exception
        """
        Function that checks the connection to the Microsoft Defender ATP
        """
        url = urlparse.urljoin(self.resource, self.URLS['test_connectivity'])
        params = self._build_api_params(limit=1)

        response = self.session.get(url, params=params)
        self._validate_response(response, u"Unable to connect to Microsoft Defender ATP")

    def get_alerts(
            self,
            alert_time_frame=None,
            start_timestamp=None,
            statuses=None,
            severities=None,
            categories=None,
            incident_id=None,
            limit=None
    ):
        # type: (int, list, list, list, int, int) -> [Alert] or Exception
        """
        Get Alerts with filtration
        @param alert_time_frame: Time frame in hours for which to fetch alerts
        @param start_timestamp: Start timestamp from when to fetch alerts
        @param statuses: Statuses of alerts to look for
        @param severities: Severities of alerts to look for
        @param categories: Categories of alerts to look for
        @param incident_id: Microsoft Defender Incident ID for which you want to find related alerts
        @param limit: How much alerts should be fetched
        @return: Alerts list
        """
        url = urlparse.urljoin(self.resource, self.URLS['get_alerts'])
        params = self._build_api_params(
            alert_time_frame=alert_time_frame,
            start_timestamp=start_timestamp,
            statuses=statuses,
            severities=severities,
            categories=categories,
            incident_id=incident_id,
            limit=limit,
        )

        response = self.session.get(url, params=params)
        self._validate_response(response, u'Failed to fetch alerts')

        alerts_data = response.json().get('value', [])

        return [MicrosoftDefenderATPTransformationLayer.build_alert(alert_data) for alert_data in alerts_data]

    def get_filtered_alerts(self, existing_ids, start_timestamp, statuses=None, severities=None, limit=None):
        """
        Get filtered alerts
        @param existing_ids: {list} The list of existing ids
        @param start_timestamp: {int} Start timestamp from when to fetch alerts
        @param statuses: {list} Statuses of alerts to look for
        @param severities: {list} Severities of alerts to look for
        @param limit: {int} Limit for results
        :return: {list} List of filtered Alert objects
        """
        alerts = self.get_alerts(
            start_timestamp=start_timestamp,
            statuses=statuses,
            severities=severities,
            limit=max(limit, DEFAULT_ALERTS_LIMIT)
        )

        filtered_alerts = filter_old_alerts(self.siemplify, alerts, existing_ids, "id")
        return sorted(filtered_alerts, key=lambda alert: alert.alert_creation_time)

    def update_alert(self, alert_id, status=None, assigned_to=None, classification=None, determination=None):
        # type: (unicode, unicode, unicode, unicode, unicode) -> Alert or Exception
        """
        Update alert
        @param alert_id: Alert ID to update
        @param status: Status to update
        @param assigned_to: Assigned To to update
        @param classification: Classification to update
        @param determination: Determination to update
        @return: Updated Alert
        """
        url = urlparse.urljoin(self.resource, self.URLS['update_alert'].format(alert_id=alert_id))
        params = self._build_api_params()

        data = {
            u'status': status,
            u'assignedTo': assigned_to,
            u'classification': classification,
            u'determination': determination,
        }

        response = self.session.patch(url, params=params, json=data)
        self._validate_response(response, u'Failed to update alert with id {}'.format(alert_id))

        alert_data = response.json()

        return MicrosoftDefenderATPTransformationLayer.build_alert(alert_data)

    def match_machine_dns_name(self, machine, starts_with_name):
        """
        Filter machines by dns name
        allow combinations domain, domain.*
        @param machine: {Machine} instance
        @param starts_with_name: {str} machine dns name
        @return: {bool} is match
        """
        dns_name = machine.computer_dns_name.lower()
        starts_with = dns_name.startswith(starts_with_name.lower())

        if starts_with and len(dns_name) == len(starts_with_name):
            return True

        return starts_with and dns_name[len(starts_with_name)] == '.'

    def get_machines_by_name(self, starts_with_name):
        machines = self.get_machines(starts_with_name=starts_with_name)

        filtered_machines = [machine for machine in machines if self.match_machine_dns_name(machine, starts_with_name)]

        return sorted(filtered_machines, key=lambda machine: machine.last_seen_unix) if filtered_machines else None

    def get_machines(
            self,
            last_seen_time_frame=None,
            name=None,
            starts_with_name=None,
            ip=None,
            risk_scores=None,
            health_statuses=None,
            os_platform=None,
            rbac_group_id=None
    ):
        # type: (int, unicode, unicode, list, list, unicode, int) -> [Machine] or Exception
        """
        Get Machines list
        @param last_seen_time_frame: Last seen time frame to look for in hours
        @param name: A part of the name to look for
        @param starts_with_name: The starts with name to look for
        @param ip: Machine IP address to look for.
        @param risk_scores: Risk scores to look for
        @param health_statuses: Health status to look for
        @param os_platform: OS platform to look for
        @param rbac_group_id: RBAC Group ID to look for
        @return: Machines List
        """
        url = urlparse.urljoin(self.resource, self.URLS['get_machines'])
        params = self._build_api_params(
            last_seen_time_frame=last_seen_time_frame,
            computer_dns_name=name,
            starts_with_computer_dns_name=starts_with_name,
            ip=ip,
            risk_scores=risk_scores,
            health_statuses=health_statuses,
            os_platform=os_platform,
            rbac_group_id=rbac_group_id
        )

        response = self.session.get(url, params=params)
        self._validate_response(response, u'Failed to fetch machines')

        machines_data = response.json().get('value', [])

        return [MicrosoftDefenderATPTransformationLayer.build_machine(machine_data) for machine_data in machines_data]

    def get_machine_logon_users(self, machine_id):
        # type: (unicode) -> [User] or Exception
        """
        Get Logon Users related to machine with given ID
        @param machine_id: Machine ID
        @return: Users list
        """
        url = urlparse.urljoin(self.resource, self.URLS['get_machine_logon_users'].format(machine_id=machine_id))
        params = self._build_api_params()

        response = self.session.get(url, params=params)
        self._validate_response(response, u'Failed to fetch log on users of the machine with id: {}'.format(machine_id))

        logon_users_data = response.json().get('value', [])

        return [MicrosoftDefenderATPTransformationLayer.build_user(user_data) for user_data in logon_users_data]

    def get_machine_related_alerts(self, machine_id, statuses=None, severities=None, categories=None, incident_id=None):
        # type: (unicode, list, list, list, int) -> [Alert] or Exception
        """
        Get Alerts related to machine with given ID
        @param machine_id: Machine ID
        @param statuses: Statuses of alerts to look for
        @param severities: Severities of the incidents to look for
        @param categories: Categories of the incidents to look for
        @param incident_id: Microsoft Defender Incident ID for which you want to find related alerts
        @return: Related Alerts list
        """
        url = urlparse.urljoin(self.resource, self.URLS['get_machine_related_alerts'].format(machine_id=machine_id))
        params = self._build_api_params(
            statuses=statuses,
            severities=severities,
            categories=categories,
            incident_id=incident_id
        )

        response = self.session.get(url, params=params)
        self._validate_response(
            response,
            u'Failed to fetch related alerts of the machine with id: {}'.format(machine_id)
        )

        machine_alerts_data = response.json().get('value', [])

        return [MicrosoftDefenderATPTransformationLayer.build_alert(alert_data) for alert_data in machine_alerts_data]

    def isolate_machine(self, machine_id, isolation_type, comment):
        # type: (unicode, unicode, unicode) -> MachineTask or Exception
        """
        Create Isolate Machine Task
        @param machine_id: Machine ID
        @param isolation_type: Isolation type
        @param comment: Comment as to why the machine needs to be isolated
        @return: Machine Task
        """
        url = urlparse.urljoin(self.resource, self.URLS['isolate_machine'].format(machine_id=machine_id))
        params = self._build_api_params()

        data = {
            'Comment': comment,
            'IsolationType': isolation_type
        }

        response = self.session.post(url, params=params, json=data)
        self._validate_response(response, u'Failed isolate machine with ID: {}'.format(machine_id))

        machine_task_data = response.json()

        return MicrosoftDefenderATPTransformationLayer.build_machine_task(machine_task_data)

    def unisolate_machine(self, machine_id, comment):
        # type: (unicode, unicode) -> MachineTask or Exception
        """
        Create Unisolate Machine Task
        @param machine_id: Machine ID
        @param comment: Comment as to why the machine needs to be unisolated
        @return: Machine Task
        """
        url = urlparse.urljoin(self.resource, self.URLS['unisolate_machine'].format(machine_id=machine_id))
        params = self._build_api_params()

        data = {
            'Comment': comment
        }

        response = self.session.post(url, params=params, json=data)
        self._validate_response(response, u'Failed unisolate machine with ID: {}'.format(machine_id))

        machine_task_data = response.json()

        return MicrosoftDefenderATPTransformationLayer.build_machine_task(machine_task_data)

    def run_antivirus_scan(self, machine_id, av_scan_type, comment):
        # type: (unicode, unicode, unicode) -> MachineTask or Exception
        """
        Create Run AV Scan Machine Task
        @param machine_id: Machine ID
        @param av_scan_type: To start Full or Quick antivirus scan on machine
        @param comment: Comment as to why an antivirus scan needs to be executed on the machine
        @return: Machine Task
        """
        url = urlparse.urljoin(self.resource, self.URLS['run_antivirus_scan'].format(machine_id=machine_id))
        params = self._build_api_params()

        data = {
            'Comment': comment,
            'ScanType': av_scan_type
        }

        response = self.session.post(url, params=params, json=data)
        self._validate_response(response, u'Failed run AV on machine with ID: {}'.format(machine_id))

        machine_task_data = response.json()

        return MicrosoftDefenderATPTransformationLayer.build_machine_task(machine_task_data)

    def stop_and_quarantine_machine_file(self, machine_id, file_hash, comment):
        # type: (unicode, unicode, unicode) -> MachineTask or Exception
        """
        Create Stop And Quarantine Machine file Task
        @param machine_id: Machine ID
        @param file_hash: SHA1 file hash of the file to stop and quarantine
        @param comment: Comment to associate with the action
        @return: Machine Task
        """
        url = urlparse.urljoin(
            self.resource,
            self.URLS['stop_and_quarantine_machine_file'].format(machine_id=machine_id)
        )
        params = self._build_api_params()

        data = {
            'Comment': comment,
            'Sha1': file_hash
        }

        response = self.session.post(url, params=params, json=data)
        self._validate_response(
            response,
            u'Failed stop AV and quarantine file with file hash {} on machine with ID: {}'.format(
                file_hash, machine_id
            )
        )

        machine_task_data = response.json()

        return MicrosoftDefenderATPTransformationLayer.build_machine_task(machine_task_data)

    def get_machine_task_status(self, id):
        # type: (unicode) -> MachineTask or Exception
        """
        Get Machine Task with given ID
        @param id: Machine Task ID
        @return: Machine Task
        """
        url = urlparse.urljoin(self.resource, self.URLS['get_machine_task_status'])
        params = self._build_api_params(id=id)

        response = self.session.get(url, params=params)
        self._validate_response(response, u'Failed to get machine task status with id: {}'.format(id))

        machine_task_data = response.json().get('value', [])

        if not machine_task_data:
            raise MicrosoftDefenderATPError(u'There is no task with id {}'.format(id))

        return MicrosoftDefenderATPTransformationLayer.build_machine_task(machine_task_data[0])

    def get_file_related_alerts(self, file_hash, statuses=None, severities=None, categories=None, incident_id=None):
        # type: (unicode, list, list, list, int) -> [Alert] or Exception
        """
        Get Alerts related to file
        @param file_hash: File hash
        @param statuses: Statuses to look for
        @param severities: Severities to look for
        @param categories: Categories to look for
        @param incident_id: Microsoft Defender Incident ID for which you want to find related alerts
        @return: Alerts List
        """
        url = urlparse.urljoin(self.resource, self.URLS['get_file_related_alerts'].format(file_hash=file_hash))
        params = self._build_api_params()

        response = self.session.get(url, params=params)
        self._validate_response(response, u'Failed to get related alerts of file with hash {}'.format(file_hash))

        alerts_data = response.json().get('value', [])
        alerts = [MicrosoftDefenderATPTransformationLayer.build_alert(alert_data) for alert_data in alerts_data]

        return self._filter_alerts(
            alerts=alerts,
            statuses=statuses,
            severities=severities,
            categories=categories,
            incident_id=incident_id
        )

    @staticmethod
    def _filter_alerts(
            alerts,
            statuses=None,
            severities=None,
            categories=None,
            incident_id=None
    ):
        # type: ([Alert], [unicode], [unicode], [unicode], int) -> object
        """
        Client side filtering alerts (because server side does not work)
        @param alerts: Alerts to filter
        @param statuses: Statuses to look for
        @param severities: Severities to look for
        @param categories: Categories to look for
        @param incident_id: Microsoft Defender Incident ID for which you want to find related alerts
        @return: Filtered Alerts List
        """
        filtered_alerts = []

        for alert in alerts:
            conditions = []

            if statuses:
                conditions.append(
                    alert.status in statuses
                )

            if severities:
                conditions.append(
                    alert.severity in severities
                )

            if categories:
                conditions.append(
                    alert.category in categories
                )

            if incident_id:
                conditions.append(
                    alert.incident_id == incident_id
                )

            if all(conditions):
                filtered_alerts.append(alert)

        return filtered_alerts

    def get_file_related_machines(
            self,
            file_hash,
            name=None,
            ip=None,
            risk_scores=None,
            health_statuses=None,
            os_platform=None,
            rbac_group_id=None
    ):
        # type: (unicode, unicode, unicode, list, list, unicode, int) -> [Machine] or Exception
        """
        Get Machines related to file
        @param file_hash: File Hash
        @param name: A part of the name to look for
        @param ip: Machine IP address to look for.
        @param risk_scores: Risk scores to look for
        @param health_statuses: Health status to look for
        @param os_platform: OS platform to look for
        @param rbac_group_id: RBAC Group ID to look for
        @return: Machines List
        """
        url = urlparse.urljoin(self.resource, self.URLS['get_file_related_machines'].format(file_hash=file_hash))
        params = self._build_api_params()

        response = self.session.get(url, params=params)
        self._validate_response(response, u'Failed to get related machines of file with hash {}'.format(file_hash))

        machines_data = response.json().get('value', [])
        machines = [MicrosoftDefenderATPTransformationLayer.build_machine(machine_data) for machine_data in
                    machines_data]

        return self._filter_machines(
            machines=machines,
            computer_dns_name=name,
            ip=ip,
            risk_scores=risk_scores,
            health_statuses=health_statuses,
            os_platform=os_platform,
            rbac_group_id=rbac_group_id
        )

    @staticmethod
    def _filter_machines(
            machines,
            computer_dns_name=None,
            ip=None,
            risk_scores=None,
            health_statuses=None,
            os_platform=None,
            rbac_group_id=None
    ):
        # type: ([Machine], unicode, unicode, [unicode], [unicode], unicode, int) -> [Machine]
        """
        Client side filtering machines (because server side does not work)
        @param machines: Machines to filter
        @param computer_dns_name: A part of the name to look for
        @param ip: Machine IP address to look for.
        @param risk_scores: Risk scores to look for
        @param health_statuses: Health status to look for
        @param os_platform: OS platform to look for
        @param rbac_group_id: RBAC Group ID to look for
        @return: Filtered Machines List
        """

        filtered_machines = []

        for machine in machines:
            conditions = []

            if computer_dns_name:
                conditions.append(
                    computer_dns_name in machine.computer_dns_name
                )

            if ip:
                conditions.append(
                    machine.last_ip_address == ip
                )

            if risk_scores:
                conditions.append(
                    machine.risk_score in risk_scores
                )

            if health_statuses:
                conditions.append(
                    machine.health_status in health_statuses
                )

            if os_platform:
                conditions.append(
                    machine.os_platform == os_platform
                )

            if rbac_group_id:
                conditions.append(
                    machine.rbac_group_id == rbac_group_id
                )

            if all(conditions):
                filtered_machines.append(machine)

        return filtered_machines

    def run_advanced_hunting_query(self, query):
        # type: (unicode) -> QueryResult or Exception
        """
        Run given query
        @param query: Query to run
        @return: Query Result
        """
        url = urlparse.urljoin(self.resource, self.URLS['run_advanced_hunting_query'])
        params = self._build_api_params()

        data = {
            u'Query': query
        }

        response = self.session.post(url, params=params, json=data)
        self._validate_response(response, u'Failed to run query')

        query_result_data = response.json()

        return MicrosoftDefenderATPTransformationLayer.build_query_result(query_result_data)

    def get_file_info(self, file_hash):
        # type: (unicode) -> dict or Exception
        """
        Get Info about file
        @param file_hash: File Hash
        @return: Info dict
        """
        url = urlparse.urljoin(self.resource, self.URLS['get_file_info'].format(file_hash=file_hash))
        params = self._build_api_params()

        response = self.session.get(url, params=params)
        self._validate_response(response, u'Failed to fetch file with hash {}'.format(file_hash))

        return response.json()

    def get_file_stats(self, file_hash):
        # type: (unicode) -> dict or Exception
        """
        Get file stats
        @param file_hash: File Hash
        @return: Stats dict
        """
        url = urlparse.urljoin(self.resource, self.URLS['get_file_stats'].format(file_hash=file_hash))
        params = self._build_api_params()

        response = self.session.get(url, params=params)
        self._validate_response(response, u'Failed to fetch file with hash {}'.format(file_hash))

        return response.json()

    def get_file(self, file_hash):
        # type: (unicode) -> File or Exception
        """
        Get file
        @param file_hash: File Hash
        @return: File
        """
        file_hash = file_hash.lower()
        file_data = {}
        file_info = self.get_file_info(file_hash)
        file_stats = self.get_file_stats(file_hash)

        file_data.update(file_info)
        file_data.update(file_stats)

        return MicrosoftDefenderATPTransformationLayer.build_file(file_data)

    def get_detections_siem(self, since_time_frame):
        # type: (unicode) -> [Detection] or Exception
        """
        Get Detections
        @param since_time_frame: Since what time get detections
        @return: Detections list
        """
        url = urlparse.urljoin(self.SIEM_DETECTIONS_URL, self.URLS['get_detections_siem'])
        params = self._build_api_params(since_time_frame=since_time_frame)

        response = self.session.get(url, params=params)
        self._validate_response(response, u'Failed to fetch siem detections')

        detections_data = response.json()

        return [
            MicrosoftDefenderATPTransformationLayer.build_detection(detection_data)
            for detection_data in detections_data
        ]

    def get_alert_data(self, alert_id, incident_id):
        """
        Get alert data from the incident
        @param alert_id: {str} alert id
        @param incident_id: {int} incident id
        @return: {dict} raw dict of alert data
        """
        url = urlparse.urljoin(self.defender_api_resource, self.URLS[u'get_incident'].format(incident_id))
        response = self.session.get(url)
        self._validate_response(response, u'Failed to fetch incident by ID {}'.format(incident_id))
        return MicrosoftDefenderATPTransformationLayer.get_alert_data(response.json(), alert_id)

    def delete_indicator(self, indicator_id):
        """
        Delete entity indicator
        :param indicator_id: {str} Indicator ID
        :return:
        """
        url = urlparse.urljoin(self.resource, self.URLS[u'delete_indicator'].format(indicator_id=indicator_id))
        response = self.session.delete(url)
        self._validate_response(response, u'Failed to delete indicator with ID {}'.format(indicator_id))

    def get_entities(self, entities, types=None, actions=None, severities=None):
        """
        Get entities by value
        @param entities: List of entity identifiers
        @param types: Indicator types
        @param actions: Indicator actions
        @param severities: Indicator severities
        @return: Indicators
        """
        url = urlparse.urljoin(self.resource, self.URLS['entities'])
        params = self._build_api_params(entities=entities, types=types, actions=actions, severities=severities,
                                        for_entities=True)

        response = self.session.get(url, params=params)
        self._validate_response(response, u'Failed to fetch indicators')

        return MicrosoftDefenderATPTransformationLayer.build_indicators_list(response.json())

    def submit_entity(self, entity_identifier, entity_type, title, action, application, severity, description,
                      recommended_action):
        """
        Submit entity as indicator
        :param entity_identifier: The entity identifier
        :param entity_type: Type of the entity
        :param title: Title for the indicator
        :param action: Action to apply
        :param application: Application related to entity
        :param severity: Severity level to apply
        :param description: Description for entity
        :param recommended_action: Recommended actions for handling the entity
        :return:
        """
        url = urlparse.urljoin(self.resource, self.URLS['entities'])
        payload = {
            "indicatorValue": entity_identifier,
            "indicatorType": entity_type,
            "title": title,
            "application": application,
            "action": action,
            "severity": severity,
            "description": description,
            "recommendedActions": recommended_action
        }

        if action in ["Audit"]:
            payload["generateAlert"] = True

        response = self.session.post(url, json=payload)
        if response.status_code == 403:
            raise MicrosoftDefenderATPForbiddenError()
        self._validate_response(response, u'Failed to submit entity')

    def _build_api_params(
            self,
            incident_id=None,
            statuses=None,
            severities=None,
            categories=None,
            ip=None,
            risk_scores=None,
            health_statuses=None,
            computer_dns_name=None,
            starts_with_computer_dns_name=None,
            os_platform=None,
            rbac_group_id=None,
            last_seen_time_frame=None,
            alert_time_frame=None,
            start_timestamp=None,
            since_time_frame=None,
            expand=None,
            limit=None,
            id=None,
            entities=None,
            types=None,
            actions=None,
            for_entities=False
    ):
        # type: (int, list, list, list, unicode, list, list, unicode, unicode, int, int, int, unicode, unicode, int, unicode) -> dict
        """
        Create filtration dict
        @param incident_id: Microsoft Defender Incident ID for which you want to find related alerts
        @param statuses: Statuses to look for
        @param severities: Severities to look for
        @param categories: Categories to look for
        @param ip: IP to look for
        @param risk_scores: Risk Scores to look for
        @param health_statuses: Health Statuses to look for
        @param computer_dns_name: A part of name to look for
        @param starts_with_computer_dns_name: Starts with name to look for
        @param os_platform: OS Platform to look for
        @param rbac_group_id: RBAC Group ID to look for
        @param last_seen_time_frame: Last seen time frame
        @param alert_time_frame: Alert time frame
        @param start_timestamp: Start timestamp
        @param since_time_frame: Since time frame
        @param expand: Expand to look for
        @param limit: How much should be fetched
        @param id: ID to look for
        @return: Dict of filters
        """
        filter_params = []

        if incident_id:
            filter_params.append(u'incidentId eq {}'.format(incident_id))

        if statuses and set(statuses) ^ set(self.DEFAULT_STATUSES):
            filter_params.append(self._get_multiple_value_filter(u'status', statuses))

        if severities and set(severities) ^ set(self.DEFAULT_SEVERITIES):
            filter_params.append(self._get_multiple_value_filter(u'severity', severities))

        if categories and set(categories) ^ set(self.DEFAULT_CATEGORIES):
            filter_params.append(self._get_multiple_value_filter(u'category', categories))

        if ip:
            filter_params.append(u'lastIpAddress eq \'{}\''.format(ip))

        if risk_scores and set(risk_scores) ^ set(self.DEFAULT_RISK_SCORES):
            filter_params.append(self._get_multiple_value_filter(u'RiskScore', risk_scores))

        if health_statuses and set(health_statuses) ^ set(self.DEFAULT_HEALTH_STATUSES):
            filter_params.append(self._get_multiple_value_filter(u'healthStatus', health_statuses))

        if computer_dns_name:
            filter_params.append(u'contains(computerDnsName, \'{}\')'.format(computer_dns_name))

        if starts_with_computer_dns_name:
            filter_params.append(u'startswith(computerDnsName, \'{}\')'.format(starts_with_computer_dns_name))

        if os_platform:
            filter_params.append(u'osPlatform eq \'{}\''.format(os_platform))

        if rbac_group_id:
            filter_params.append(u'rbacGroupId eq {}'.format(rbac_group_id))

        if last_seen_time_frame:
            time = datetime.utcnow() - timedelta(hours=last_seen_time_frame)
            filter_params.append(u'lastSeen ge {}'.format(time.strftime(self.TIME_FORMAT)))

        if alert_time_frame:
            time = datetime.utcnow() - timedelta(hours=alert_time_frame)
            filter_params.append(u'alertCreationTime ge {}'.format(time.strftime(self.TIME_FORMAT)))

        if start_timestamp:
            time = datetime.fromtimestamp(start_timestamp / 1000)
            filter_params.append(u'alertCreationTime ge {}'.format(time.strftime(self.TIME_FORMAT)))

        if id:
            filter_params.append(u'id eq {}'.format(id))

        if entities:
            filter_params.append(self._get_multiple_value_filter(u'indicatorValue', entities))

        if types:
            filter_params.append(self._get_multiple_value_filter(u'indicatorType', types))

        if actions:
            filter_params.append(self._get_multiple_value_filter(u'action', actions))

        params = {
            u'$filter': u" and ".join(filter_params) if filter_params else None
        }

        if not for_entities:
            params[u'$top'] = limit
            params[u'$expand'] = expand

        if since_time_frame:
            time = datetime.utcnow() - timedelta(hours=since_time_frame)
            params[u'sinceTimeUtc'] = time.strftime(self.TIME_FORMAT)

        return params

    @staticmethod
    def _get_multiple_value_filter(value_name, value_list):
        # type: (unicode, list) -> unicode
        """
        Join filters
        @param value_name: Name to filter
        @param value_list: List of values to filter
        @return: String filter
        """
        filter_group = u' or '.join(map(lambda x: u'{} eq \'{}\''.format(value_name, x), value_list))
        return u'({})'.format(filter_group)

    @staticmethod
    def _validate_response(response, error_msg=u"An error occurred"):
        # type: (requests.Response, unicode) -> None or Exception
        """
        Validate Response
        @param response: Response
        @param error_msg: Message to raise with
        """
        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            try:
                response = response.json()
                error_info = response.get(u'error', {})
                raise MicrosoftDefenderATPError(
                    u'{error_msg}. {text}'.format(
                        error_msg=error_msg,
                        text=error_info.get(u'message', u'') if isinstance(error_info, dict) else error_info
                    )
                )
            except ValueError:
                raise MicrosoftDefenderATPError(
                    u"{error_msg}: {error} - {text}".format(
                        error_msg=error_msg,
                        error=error,
                        text=response.content)
                )

    @staticmethod
    def validate_statuses(*statuses):
        # type: (list) -> None or Exception
        """
        Validate Statuses
        @param statuses: Statuses
        """
        statuses = set(statuses)
        default_statuses = set(MicrosoftDefenderATPManager.DEFAULT_STATUSES)
        wrong_statuses = statuses ^ default_statuses & statuses
        if wrong_statuses:
            raise MicrosoftDefenderATPValidationError(
                u'Wrong statuses {}.\nPossible values are {}'.format(
                    MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(wrong_statuses),
                    MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(default_statuses)
                )
            )

    @staticmethod
    def validate_severities(*severities):
        # type: (list) -> None or Exception
        """
        Validate Severities
        @param severities: Severities
        """
        severities = set(severities)
        default_severities = set(MicrosoftDefenderATPManager.DEFAULT_SEVERITIES)
        wrong_severities = severities ^ default_severities & severities
        if wrong_severities:
            raise MicrosoftDefenderATPValidationError(
                u'Wrong severities {}.\nPossible values are {}'.format(
                    MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(wrong_severities),
                    MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(default_severities)
                )
            )

    @staticmethod
    def validate_categories(*categories):
        # type: (list) -> None or Exception
        """
        Validate Categories
        @param categories: Categories
        """
        categories = set(categories)
        default_categories = set(MicrosoftDefenderATPManager.DEFAULT_CATEGORIES)
        wrong_categories = categories ^ default_categories & categories
        if wrong_categories:
            raise MicrosoftDefenderATPValidationError(
                u'Wrong categories {}.\nPossible values are {}'.format(
                    MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(wrong_categories),
                    MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(default_categories)
                )
            )

    @staticmethod
    def validate_classifications(*classifications):
        # type: (list) -> None or Exception
        """
        Validate Classifications
        @param classifications: Classifications
        """
        classifications = set(classifications)
        default_classifications = set(MicrosoftDefenderATPManager.DEFAULT_CLASSIFICATIONS)
        wrong_classifications = classifications ^ default_classifications & classifications
        if wrong_classifications:
            raise MicrosoftDefenderATPValidationError(
                u'Wrong classifications {}.\nPossible values are {}'.format(
                    MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(wrong_classifications),
                    MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(default_classifications)
                )
            )

    @staticmethod
    def validate_determinations(*determinations):
        # type: (list) -> None or Exception
        """
        Validate Determinations
        @param determinations: Determinations
        """
        determinations = set(determinations)
        default_determinations = set(MicrosoftDefenderATPManager.DEFAULT_DETERMINATIONS)
        wrong_determinations = determinations ^ default_determinations & determinations
        if wrong_determinations:
            raise MicrosoftDefenderATPValidationError(
                u'Wrong determinations {}.\nPossible values are {}'.format(
                    MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(wrong_determinations),
                    MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(default_determinations)
                )
            )

    @staticmethod
    def validate_risk_scores(*risk_scores):
        # type: (list) -> None or Exception
        """
        Validate Risk Scores
        @param risk_scores: Risk Scores
        """
        risk_scores = set(risk_scores)
        default_risk_scores = set(MicrosoftDefenderATPManager.DEFAULT_RISK_SCORES)
        wrong_risk_scores = risk_scores ^ default_risk_scores & risk_scores
        if wrong_risk_scores:
            raise MicrosoftDefenderATPValidationError(
                u'Wrong risk scores {}.\nPossible values are {}'.format(
                    MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(wrong_risk_scores),
                    MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(default_risk_scores)
                )
            )

    @staticmethod
    def validate_health_statuses(*health_statuses):
        # type: (list) -> None or Exception
        """
        Validate Health Statuses
        @param health_statuses: Health Statuses
        """
        health_statuses = set(health_statuses)
        default_health_statuses = set(MicrosoftDefenderATPManager.DEFAULT_HEALTH_STATUSES)
        wrong_health_statuses = health_statuses ^ default_health_statuses & health_statuses
        if wrong_health_statuses:
            raise MicrosoftDefenderATPValidationError(
                u'Wrong health statuses {}.\nPossible values are {}'.format(
                    MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(wrong_health_statuses),
                    MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(default_health_statuses)
                )
            )

    @staticmethod
    def validate_isolation_type(isolation_type):
        # type: (unicode) -> None or Exception
        """
        Validate Isolation Type
        @param isolation_type: Isolation Type
        """
        if isolation_type not in MicrosoftDefenderATPManager.POSSIBLE_ISOLATION_TYPES:
            raise MicrosoftDefenderATPValidationError(
                u'Wrong isolation type {}.\nPossible values are {}'.format(
                    isolation_type,
                    MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(
                        MicrosoftDefenderATPManager.POSSIBLE_ISOLATION_TYPES
                    )
                )
            )

    @staticmethod
    def validate_av_scan_type(av_scan_type):
        # type: (unicode) -> None or Exception
        """
        Validate Antivirus Scan Type
        @param av_scan_type: Antivirus Scan Type
        """
        if av_scan_type not in MicrosoftDefenderATPManager.POSSIBLE_SCAN_TYPES:
            raise MicrosoftDefenderATPValidationError(
                u'Wrong AV scan type {}.\nPossible values are {}'.format(
                    av_scan_type,
                    MicrosoftDefenderATPManager.convert_list_to_comma_separated_string(
                        MicrosoftDefenderATPManager.POSSIBLE_SCAN_TYPES
                    )
                )
            )

    @staticmethod
    def convert_comma_separated_to_list(comma_separated):
        # type: (unicode) -> list
        """
        Convert comma-separated string to list
        @param comma_separated: String with comma-separated values
        @return: List of values
        """
        return [item.strip() for item in comma_separated.split(',')] if comma_separated else []

    @staticmethod
    def join_validation_errors(validation_errors):
        # type: (list) -> unicode
        """
        Join validation errors list to one string
        @param validation_errors: Validation error messages list
        """
        return u'\n'.join(validation_errors)

    @staticmethod
    def convert_list_to_comma_separated_string(iterable):
        # type: (list or set) -> unicode
        """
        Convert list to comma separated string
        @param iterable: List or Set to covert
        """
        return u', '.join(iterable)
