import urlparse

import requests

from McAfeeMvisionEDRExceptions import (
    McAfeeMvisionEDRException,
    CaseNotFoundException
)
from McAfeeMvisionEDRParser import McAfeeMvisionEDRParser, SEVERITY_MAPPER
from TIPCommon import filter_old_alerts
from UtilsManager import validate_response
from constants import (
    PAGE_LIMIT,
    THREAT_ID_FIELD,
    PID_PROCESS,
    SHA256_PROCESS,
    PATH_PROCESS,
    NAME_PROCESS,
    GET_TOKEN_ENDPOINT
)
from datamodels import Case, Task, TaskStatus

ENDPOINTS = {
    u'login': u'identity/v1/login',
    u'ping': u'ft/api/v2/ft/hosts?limit=1&skip=0',
    u'get_hosts': u'ft/api/v2/ft/hosts',
    u'quarantine': u'remediation/api/v1/actions/hosts-actions',
    u'remove_file': u'remediation/api/v1/actions/hosts-actions',
    u'get_status': u'remediation/api/v1/actions/',
    u'threats': u'ft/api/v2/ft/threats',
    u'detections': u'/ft/api/v2/ft/threats/{}/detections',
    u'get_cases': u'/case-mgmt/v1/cases',
    u'create_dismiss_threat_task': u'/remediation/api/v1/actions/global-threat-actions',
    u'get_task_status': u'/remediation/api/v1/actions/{task_id}/status',
    u'token': u'iam/v1.0/token'
}


class McAfeeMvisionEDRManager(object):

    def __init__(self, api_root, username=None, password=None, client_id=None, client_secret=None, verify_ssl=False,
                 siemplify=None):
        """
        The method is used to init an object of Manager class
        :param api_root: McAfee Mvision EDR API Root
        :param username: Username of McAfee Mvision EDR account
        :param password: Password of the McAfee Mvision EDR account
        :param client_id: Client ID of the McAfee Mvision EDR account.
        :param client_secret: Client Secret of the McAfee Mvision EDR account.
        :param verify_ssl: Enable (True) or disable (False). If enabled, verify the SSL certificate for the connection to the McAfee Mvision EDR public cloud server is valid.
        :param siemplify: (obj) An instance of the SDK SiemplifyConnectorExecution class.
        """
        self.api_root = api_root
        self.username = username
        self.password = password
        self.client_id = client_id
        self.client_secret = client_secret
        self.siemplify = siemplify
        self.parser = McAfeeMvisionEDRParser()
        self.session = requests.session()
        self.session.verify = verify_ssl

        if (client_id and client_secret) or (username and password):
            self.set_auth_token()
        else:
            raise McAfeeMvisionEDRException(
                "Note: you need to either provide Client ID + Client Secret or Username + Password. If both are "
                "provided, integration will use Client ID + Client Secret for authentication."
            )

    def _get_full_url(self, url_id):
        """
        Send full url from url identifier.
        :param url_id: {unicode} The id of url
        :return: {unicode} The full url
        """
        return urlparse.urljoin(self.api_root, ENDPOINTS[url_id])

    def get_auth_token(self):
        """
        Send request in order to get generated tokens.
        :return: {unicode} The Authorization Token to use for the next requests
        """
        try:
            if self.client_id and self.client_secret:
                response = self.session.get(
                    GET_TOKEN_ENDPOINT,
                    params={
                        "grant_type": "client_credentials",
                        "scope": "dxls.evt.r dxls.evt.w mi.user.investigate soc.act.tg "
                                 "soc.evt.vi soc.hts.c soc.hts.r soc.internal "
                                 "soc.inv.ade soc.qry.pr soc.rts.c soc.rts.r",
                    },
                    auth=(self.client_id, self.client_secret),
                )
                validate_response(response)
                return self.parser.get_access_token(response.json())
            elif self.username and self.password:
                login_response = self.session.get(
                    self._get_full_url("login"), auth=(self.username, self.password)
                )
                validate_response(login_response)
                return self.parser.get_auth_token(login_response.json())
        except Exception as err:
            raise McAfeeMvisionEDRException("McAfee Mvision EDR: {0}".format(err.message))

    def set_auth_token(self):
        """
        Set Authorization header to request session.
        """
        self.session.headers.update({u'Authorization': u'Bearer {}'.format(self.get_auth_token())})

    def build_severity_filter(self, severity):
        """
        Build severity filter.
        :param severity: {unicode} Lowest severity that will be used to fetch threats.
        :return: {dict} Severities to filter
        """
        severity_filter = []
        skip = True

        for api_severity, siemplify_severity in iter(sorted(SEVERITY_MAPPER.iteritems())):
            if siemplify_severity.get(u'label').lower() == severity.lower():
                skip = False
            if not skip:
                severity_filter.append(api_severity)

        return severity_filter

    def get_detections(self, threat_id):
        """
        Get detections.
        :param threat_id: {int} The id of threat.
        :return: {list} Results list
        """
        payload = {
            u'sort': u'-firstDetected',
            u'skip': 0,
            u'limit': PAGE_LIMIT
        }
        response = self.session.get(self._get_full_url(u'detections').format(threat_id), params=payload)
        validate_response(response)
        return self.parser.build_siemplify_detections_from_detections_response(response.json())

    def get_threats(self, existing_ids, start_time, severity, limit):
        """
        Get threads.
        :param existing_ids: {list} The list of existing ids.
        :param start_time: {unicode} Time frame of alerts to fetch.
        :param severity: {unicode} Lowest severity that will be used to fetch threats.
        :param limit: {int} A value Specified a number of threads.
        :return: {list} Results list
        """
        payload = {
            u'from': start_time,
            u'sort': u'+lastDetected',
            u'filter': '{{"severities":[{}]}}'.format(
                ','.join(['"{}"'.format(s) for s in self.build_severity_filter(severity)])),

        }

        threats_json = self._paginate_results(
            method=u'GET',
            url=self._get_full_url(u'threats'),
            result_key=u'threats',
            params=payload,
            limit=max(limit, PAGE_LIMIT)
        )
        threats = [self.parser.build_siemplify_threat(threat_json) for threat_json in threats_json]
        return filter_old_alerts(
            siemplify=self.siemplify,
            alerts=threats,
            existing_ids=existing_ids,
            id_key=THREAT_ID_FIELD
        )

    def _paginate_results(self, method, url, result_key=u'hosts', limit=PAGE_LIMIT, params=None, body=None,
                          err_msg=u'Unable to get results'):
        """
        Paginate the results
        :param method: {unicode} The method of the request (GET, POST, PUT, DELETE, PATCH)
        :param url: {unicode} The url to send request to
        :param result_key: {unicode} The key to extract data
        :param limit: {int} The response limit
        :param params: {dict} The params of the request
        :param body: {dict} The json payload of the request
        :param err_msg: {unicode} The message to display on error
        :return: {list} List of results
        """

        if params is None:
            params = {}

        response = self.session.request(method, url, params=params, json=body)
        validate_response(response, err_msg)
        results = response.json().get(result_key, [])
        total_results = response.json().get('total', 0)
        actual_limit = min(total_results, limit)

        params.update({
            u"limit": actual_limit,
            u"skip": 0
        })
        while True:
            if len(results) >= actual_limit:
                break

            params.update({
                u"skip": len(results)
            })

            response = self.session.request(method, url, params=params, json=body)

            validate_response(response, err_msg)
            results.extend(response.json().get(result_key, []))

        return results

    def test_connectivity(self):
        """
        Test connectivity to the McAfee Mvision EDR.
        :return: {bool} True if successful, exception otherwise
        """
        request_url = urlparse.urljoin(self.api_root, self._get_full_url(u'ping'))
        response = self.session.get(request_url)
        validate_response(response, u"Unable to connect to McAfee Mvision EDR.")

    def get_hosts(self):
        """
        Get hosts
        :return: {list} of {McAfeeMvisionEDRHostModel} The host info after parsing
        """
        url = self._get_full_url(u'get_hosts')
        hosts = self._paginate_results("GET", url)
        return [self.parser.build_host_object(host_json) for host_json in hosts]

    def quarantine_unquarantine_endpoint(self, host_id, quarantine=True):
        """
        Create quarantine/unquarantine task on the endpoint.
        :param host_id: {unicode} ma_guid of the endpoint.
        :param quarantine: {bool} If True, will create quarantine task and unquarantine if False.
        :return: {bool} True if successful, raise exception otherwise.
        """
        url = self._get_full_url(u'quarantine')
        action = "QuarantineHost" if quarantine else "UnquarantineHost"
        data = {
            "action": action,
            "hostsActionArguments": {
                "hostIds": [host_id]
            }
        }
        response = self.session.post(url, json=data)
        validate_response(response, error_msg=u"Failed to create task")

    def remove_file(self, host_id, file_full_path, safe_removal=False):
        """
        Create remove task on the endpoint
        :param host_id: {unicode} ma_guid of the endpoint
        :param file_full_path: {unicode} Path to the file to be removed
        :param safe_removal: {bool} If enabled, will ignore files that may be critical or trusted.
        :return: {TaskResponseModel} The task info after creating action
        """
        url = self._get_full_url(u'remove_file')
        action = "removeFileSafe" if safe_removal else "removeFile"
        data = {
            "action": action,
            "hostsActionArguments": {
                "hostIds": [host_id]
            },
            "provider": "AR",
            "actionInputs": [
                {
                    "name": "full_name",
                    "value": file_full_path
                }
            ]
        }
        response = self.session.post(url, json=data)
        validate_response(response, error_msg=u"Unable to create task")
        return self.parser.build_task_response_object(response.json())

    def get_action_status(self, action_id, get_error=False):
        """
        Get the status of the action
        :param action_id: {int} The action id
        :param get_error: {bool} If True, the error message of the action should be parsed
        :return: {TaskResponseModel} The action status information
        """
        last_path = "{}/host-actions".format(action_id) if get_error else "{}/status".format(action_id)
        url = urlparse.urljoin(self._get_full_url(u'get_status'), last_path)
        response = self.session.get(url)
        return self.parser.build_task_response_object(response.json())

    def kill_process(self, host_id, process_type, process_value):
        """
        Create a kill process task on the endpoint.
        :param host_id: {unicode} ma_guid of the endpoint.
        :param process_type: {unicode} Process identifier type.
        :param process_value: {unicode} The value for the process identifier.
        :return: {TaskResponseModel} The task info after creating action.
        """
        url = self._get_full_url(u'remove_file')
        action_name, input_name, input_value = self.get_action_name(process_type, process_value)
        data = {
            "action": action_name,
            "hostsActionArguments": {
                "hostIds": [host_id]
            },
            "provider": "AR",
            "actionInputs": [
                {
                    "name": input_name,
                    "value": input_value
                }
            ]
        }
        response = self.session.post(url, json=data)
        validate_response(response, error_msg=u"Unable to create task")
        return self.parser.build_task_response_object(response.json())

    def get_action_name(self, process_type, process_value):
        """
        Get action input name and value
        :param process_type: {unicode} Process identifier type.
        :param process_value: {unicode} The value for the process identifier.
        :return: The action name, input name and input value for request.
        """
        action_name = u""
        input_name = u""

        if process_type == PID_PROCESS:
            action_name = u"killProcess"
            input_name = u"pid"
            try:
                int_value = int(process_value)
                return action_name, input_name, int_value
            except Exception as error:
                raise Exception(
                    u'The PID value should be int: {error}'.format(error=error)
                )
        elif process_type == SHA256_PROCESS:
            action_name = u"killProcessByHash"
            input_name = u"sha256"
        elif process_type == NAME_PROCESS:
            action_name = u"killProcessByName"
            input_name = u"name"
        elif process_type == PATH_PROCESS:
            action_name = u"killProcessByPath"
            input_name = u"full_name"
        return action_name, input_name, process_value

    def stop_and_remove_content(self, host_id, pid, file_full_path):
        """
        Create stop and remove content task on the endpoint,
        :param host_id: {unicode} ma_guid of the endpoint.
        :param pid: {int} The PID of the interpreter.
        :param file_full_path: {unicode} Path to the file to be removed.
        :return: {TaskResponseModel} The task info after creating action.
        """
        url = self._get_full_url(u'remove_file')
        data = {
            "action": "stopAndRemoveContent",
            "hostsActionArguments": {
                "hostIds": [host_id]
            },
            "provider": "AR",
            "actionInputs": [
                {
                    "name": "pid",
                    "value": pid
                },
                {
                    "name": "full_name",
                    "value": file_full_path
                },
            ]
        }
        response = self.session.post(url, json=data)
        validate_response(response, error_msg=u"Unable to create task")
        return self.parser.build_task_response_object(response.json())

    def get_cases(self, offset=0, limit=PAGE_LIMIT):
        # type: (int, int) -> Generator[Case] or Exception
        """
        Get all cases in McAfee Mvision EDR
        @param offset: Offset from which to start
        @param limit: Limit how many cases to fetch
        @return: Cases generator
        """

        url = self._get_full_url(u'get_cases')

        params = {
            u'$offset': offset,
            u'$limit': limit,
        }

        response = self.session.get(url, params=params)
        validate_response(response, u'Unable to get cases')

        response_data = response.json().get(u'data', {})

        cases_data = response_data.get(u'items', [])
        total_results = response_data.get(u'totalItems', 0)
        offset += response_data.get(u'currentItemCount', 0)

        for case_data in cases_data:
            yield self.parser.build_case(case_data)

        if offset < total_results:
            for gen in self.get_cases(offset, limit):
                yield gen

    def get_case(self, threat_id):
        # type: (str or unicode) -> Case or CaseNotFoundException
        """
        Get case from all cases by threat ID
        @param threat_id: Threat ID to filter from all cases
        @return: Case or CaseNotFoundException
        """
        for case in self.get_cases():
            if case.threat_id == threat_id:
                return case

        raise CaseNotFoundException(u'Threat with id {} was not found'.format(threat_id))

    def create_dismiss_threat_task(self, threat_id):
        # type: (str or unicode) -> Task or Exception
        """
        Create Dismiss threat task
        @param threat_id: Threat ID to filter from all cases
        @return: Task or Exception
        """
        case = self.get_case(threat_id)
        url = self._get_full_url(u'create_dismiss_threat_task')

        payload = {
            u'action': u'DismissThreat',
            u'caseId': case.id,
            u'threatActionArguments': {
                u'threatId': case.threat_id
            }
        }

        response = self.session.post(url, json=payload)

        validate_response(response, u'Failed to dismiss threat with threat ID {}'.format(threat_id))
        task_data = response.json()

        return self.parser.build_task(task_data)

    def get_task_status(self, task_id):
        # type: (int) -> TaskStatus or Exception
        """
        Get current task status
        @param task_id: ID of the task to check
        @return: TaskStatus
        """
        url = self._get_full_url(u'get_task_status').format(task_id=task_id)
        response = self.session.get(url)
        validate_response(response, u'Failed to get task status')

        task_status_data = response.json()

        return self.parser.build_task_status(task_status_data)
