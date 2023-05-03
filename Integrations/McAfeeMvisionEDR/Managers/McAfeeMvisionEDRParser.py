from datamodels import *

SEVERITY_MAPPER = {
    u's0': {u'label': u'Info', u'value': -1},
    u's1': {u'label': u'Low', u'value': 40},
    u's2': {u'label': u'Medium', u'value': 60},
    u's3': {u'label': u'High', u'value': 80},
    u's4': {u'label': u'Critical', u'value': 100},
    u's5': {u'label': u'Critical', u'value': 100},
}
DEFAULT_API_SEVERITY = u's2'


class McAfeeMvisionEDRParser(object):
    @staticmethod
    def get_access_token(raw_json):
        return raw_json.get(u'access_token', u'')

    @staticmethod
    def get_auth_token(raw_json):
        return raw_json.get(u'AuthorizationToken', u'')

    def build_host_object(self, host_json):
        return Host(host_json,
                    ma_guid=host_json.get(u"maGuid"),
                    hostname=host_json.get(u"hostname"),
                    desc=host_json.get(u"os", {}).get(u"desc"),
                    last_boot_time=host_json.get(u"lastBootTime"),
                    certainty=host_json.get(u"certainty"),
                    net_interfaces=[self.build_net_interface_object(net_interface) for net_interface in host_json.get(u"netInterfaces", [])]
                    )

    def build_net_interface_object(self, net_interface_json):
        return NetInterface(net_interface_json,
                            ip=net_interface_json.get(u"ip")
                            )

    def build_task_response_object(self, response_json):
        return TaskResponseModel(response_json,
                                 status_id=response_json.get(u"id"),
                                 status=response_json.get(u"status"),
                                 location=response_json.get(u"location"),
                                 descriptions=[self.build_error_description_object(item) for item in response_json.get(u"items", [])]
                                 )

    def build_error_description_object(self, response_json):
        return ErrorDescription(response_json,
                                desc=response_json.get(u"errorDescription")
                                )

    def build_siemplify_threat(self, threat_json):
        return Threat(
            raw_data=threat_json,
            threat_id=threat_json.get('id'),
            name=threat_json.get('name'),
            priority=SEVERITY_MAPPER.get(threat_json.get('severity', DEFAULT_API_SEVERITY)).get(u'value'),
            threat_type=threat_json.get('type'),
            hashes=threat_json.get('hashes'),
            first_detected=threat_json.get('firstDetected'),
            last_detected=threat_json.get('lastDetected'),
        )

    def build_siemplify_detections_from_detections_response(self, detections_response):
        return [self.build_siemplify_detection(detection_json) for detection_json in
                detections_response.get(u'detections', [])]

    def build_siemplify_detection(self, detection_json):
        return Detection(raw_data=detection_json)

    @staticmethod
    def build_case(case_data):
        # type: (dict) -> Case
        """
        Build Case object
        @param case_data: Case data from McAfee Mvision EDR API
        @return: Case object
        """
        return Case(
            raw_data=case_data,
            name=case_data.get(u'name'),
            summary=case_data.get(u'summary'),
            created=case_data.get(u'created'),
            owner=case_data.get(u'owner'),
            self_link=case_data.get(u'_links', {}).get(u'self', {}).get(u'href'),
            status_link=case_data.get(u'_links', {}).get(u'status', {}).get(u'href'),
            priority_link=case_data.get(u'_links', {}).get(u'priority', {}).get(u'href'),
            source=case_data.get(u'source'),
            is_automatic=case_data.get(u'isAutomatic'),
            last_modified=case_data.get(u'lastModified'),
            investigated=case_data.get(u'investigated')
        )

    @staticmethod
    def build_task(task_data):
        # type: (dict) -> Task
        """
        Build Task object
        @param task_data: Task data from McAfee Mvision EDR API
        @return: Task object
        """
        return Task(
            raw_data=task_data,
            id=task_data.get(u'id'),
            status=task_data.get(u'status'),
            location=task_data.get(u'location')
        )

    @staticmethod
    def build_task_status(task_status_data):
        # type: (dict) -> TaskStatus
        """
        Build Task status object
        @param task_status_data: Task status data from McAfee Mvision EDR API
        @return: Task status object
        """
        return TaskStatus(
            raw_data=task_status_data,
            id=task_status_data.get(u'id'),
            status=task_status_data.get(u'status'),
            success_host_responses=task_status_data.get(u'successHostResponses'),
            error_host_responses=task_status_data.get(u'errorHostResponses')
        )
