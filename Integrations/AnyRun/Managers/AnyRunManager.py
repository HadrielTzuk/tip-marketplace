import requests
from urllib.parse import urljoin
import json
import copy
from SiemplifyDataModel import EntityTypes
from AnyRunParser import AnyRunParser
from AnyRunExceptions import (
    AnyRunError
)
from AnyRunParser import AnyRunParser
import time
from constants import (
    PING_QUERY,
    ANY_RUN_API_URL,
    ANALYSIS_QUERY,
    ANALYSIS_URL_TASK,
    URL_ELEMENT,
    FILEURL_ELEMENT,
    FILE_ELEMENT,
    ENDPOINTS,
    DEFAULT_SKIP_NUMBER,
    SLEEP_TIME

)

class AnyRunManager(object):
    def __init__(self, api_key=None, siemplify_logger=None):
        """
        The method is used to init an object of Manager class
        :param api_key: API Key of the Any.Run instance.
        :param siemplify_logger: Siemplify logger.
        """
        
        self.api_key = api_key
        self.api_root = ANY_RUN_API_URL
        self.siemplify_logger = siemplify_logger
        self.session = requests.session()
        self.parser = AnyRunParser()
        self.session.headers = {"Authorization": "API-Key {}".format(api_key)}
        self.parser = AnyRunParser()

    @staticmethod
    def validate_response(response, error_msg="An error occurred"):
        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            try:
                response.json()
            except:
                # Not a JSON - return content
                raise AnyRunError(
                    "{error_msg}: {error} - {text}".format(
                        error_msg=error_msg,
                        error=error,
                        text=error.response.content)
                )

            raise AnyRunError(
                "{error_msg}: {error} {text}".format(
                    error_msg=error_msg,
                    error=response.json().get('name'),
                    text=json.dumps(response.json()))
            )

    def _get_full_url(self, url_id, **kwargs):
        """
        Get full url from url identifier.
        :param url_id: {str} The id of url
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        return urljoin(self.api_root, ENDPOINTS[url_id].format(**kwargs))

    def test_connectivity(self):
        """
        Test integration connectivity.
        :return: {bool}
        """

        request_url = "{}{}".format(self.api_root, PING_QUERY)
        result = self.session.get(request_url)
        # Verify result.
        self.validate_response(result)

        return False

    def analyze(self,element_type, active_session, element_for_analysis, os_version ,operation_system_bitness, os_env_type,network_connection_status,fakenet_feature_status, use_tor, opt_network_mitm, opt_network_geo, opt_network_heavyevasion,opt_privacy_type, obj_ext_startfolder,opt_timeout):
        """
        Function that analyzes URLS and Files
        :param active_session{int} How many seconds to wait for the available session
        :param fakenet_feature_status{bool} Whether or now the FakeNet should be used
        :param element_for_analysis{string} URL which should be analyzed
        :param os_env_type{string} Environment Type 
        :param os_version{string} Windows OS Version
        :param operation_system_bitness{string} Operation System Bitness
        :param use_tor{bool} Whether or now the Tor should be used
        :param network_connection_status{bool} Whether or now the Network connection status should be used
        :param opt_network_geo {string} Which GEO Location to use
        :param opt_network_mitm {bool} Whether or now the MITM should be used
        :param opt_network_heavyevasion{bool} Whether or now the HeavyEvasion should be used
        :param opt_privacy_type {string}  Privacy Type
        :param opt_timeout {int} Timeout in seconds
        :param obj_ext_startfolder {string} Type of the startfolder
        :return Response
        """

        files=None
        if element_type == URL_ELEMENT:
            payload = {
                "obj_type":"url",
                "obj_url":element_for_analysis,
                "env_bitness": operation_system_bitness,
                "env_version": os_version,
                "opt_network_fakenet":fakenet_feature_status,
                "env_type":os_env_type,
                "opt_network_connect":network_connection_status,
                "opt_network_tor":use_tor,
                "opt_network_mitm": opt_network_mitm,
                "opt_network_geo":opt_network_geo,
                "opt_network_heavyevasion":opt_network_heavyevasion,
                "opt_privacy_type":opt_privacy_type,
                "opt_timeout":opt_timeout,
                "obj_ext_startfolder":obj_ext_startfolder   
            }
            
        if element_type == FILE_ELEMENT:
            files = [
                ('file', open(element_for_analysis,'rb'))
            ]
            payload = {
                "env_bitness": operation_system_bitness,
                "env_version": os_version,
                "opt_network_fakenet":fakenet_feature_status,
                "env_type":os_env_type,
                "opt_network_connect":network_connection_status,
                "opt_network_tor":use_tor,
                "opt_network_mitm": opt_network_mitm,
                "opt_network_geo":opt_network_geo,
                "opt_network_heavyevasion":opt_network_heavyevasion,
                "opt_privacy_type":opt_privacy_type,
                "opt_timeout":opt_timeout,
                "obj_ext_startfolder":obj_ext_startfolder   
            }
            
        if element_type == FILEURL_ELEMENT:
            payload = {
                "obj_type":"download",
                "obj_url":element_for_analysis,
                "env_bitness": operation_system_bitness,
                "env_version": os_version,
                "opt_network_fakenet":fakenet_feature_status,
                "env_type":os_env_type,
                "opt_network_connect":network_connection_status,
                "opt_network_tor":use_tor,
                "opt_network_mitm": opt_network_mitm,
                "opt_network_geo":opt_network_geo,
                "opt_network_heavyevasion":opt_network_heavyevasion,
                "opt_privacy_type":opt_privacy_type,
                "opt_timeout":opt_timeout,
                "obj_ext_startfolder":obj_ext_startfolder   
            }
            

        request_url = "{}{}".format(self.api_root, ANALYSIS_QUERY)

        counter = 0
        counter_max = active_session
        can_send_request = False
        while not can_send_request:

            if counter == counter_max:
                raise AnyRunError("Action reached timeout waiting for report.")
   
            can_send_request = self.check_available_sessions()  
            if can_send_request:
                response = self.session.post(request_url, data=payload, files=files)
                self.validate_response(response)
                return self.parser.build_task_object(response.json())
               
            counter = counter + 1 
            time.sleep(SLEEP_TIME)    
        
    
    def fetch_report(self, task_id):
        """
        :param task_id {string} ID of the task for which report should be fetched
        :return URLReport Object
        """        
        
        request_url = "{}{}".format(self.api_root, ANALYSIS_URL_TASK.format(task_id))
        
        response = self.session.get(request_url)
        self.validate_response(response)
        
        return self.parser.build_url_report_object(response.json())
        
    def get_analysis_history(self, limit, team_history=False, skip=DEFAULT_SKIP_NUMBER):
        """
        Get recent analysis history
        :param limit: {int} Number of recent items to fetch
        :param team_history: {bool} Whether to get  team history or not
        :param skip: {int} Number of first scans to skip.
        :return: {list} List of History Item objects
        """
        request_url = self._get_full_url('analysis_history')
        payload = {
            "team": json.dumps(team_history),
            "skip": skip,
            "limit": limit
        }
        response = self.session.get(request_url, params=payload)
        self.validate_response(response)
        return self.parser.build_history_items_list(response.json())

    def get_report(self, uuid):
        """
        Get report with uuid
        :param uuid: {str} Report uuid
        :return: Report object
        """
        request_url = self._get_full_url('get_report', uuid=uuid)
        response = self.session.get(request_url)
        self.validate_response(response)
        return self.parser.build_report_object(response.json())


    def check_available_sessions(self):
        """
        Method that checks if there are available sessions for the user
        :param Availability{bool} True if there are available sessions, False if not
        """

        request_url = "{}{}".format(self.api_root, PING_QUERY)
        result = self.session.get(request_url)
        self.validate_response(result)
        
        availability = result.json().get("data",{}).get("limits",{}).get("parallels",{}).get("available")
        
        if availability == 0:
            return False

        return True
