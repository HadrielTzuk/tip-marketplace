# =====================================
#              IMPORTS                #
# =====================================
import requests
import SiemplifyUtils
from requests.auth import HTTPBasicAuth
import urlparse
import copy
import sys
import os

# =====================================
#             CONSTANTS               #
# =====================================

ETL_QUERY_PAYLOAD = {
    "query": {
        "bool": {
            "filter": [
              {"term": {"level.keyword" : "Error"}},
              {"range": {"@timestamp": {"gte": "<start_unixtime>"}}},
              {"range": {"@timestamp": {"lt": "<end_unixtime>"}}}
            ]
        }
    }
}

MAX_ERRORS = 100


# =====================================
#              CLASSES                #
# =====================================
class ElasticSearchMonitoringManager(object):

    def __init__(self,settings, siemplify):
        self.siemplify = siemplify
        self.settings = settings

    # ---------------------------- PUBLIC

    # component_name= ETL \ Connectors \ Jobs
    def check_for_component_error_in_range(self, start_unixtime, end_unixtime, component_name, component_display_name, longset_history_search_ms=15 * 60 * 1000, raise_on_error=False):

        notification_messages = []
        minimum_start_time = self.valdiate_maximum_timeback_unixtime(start_unixtime, longset_history_search_ms)

        search_queries = self._get_search_queries(start_unixtime=minimum_start_time,
                                                  end_unixtime=end_unixtime,
                                                  component_name=component_name)

        top_errors = []

        for map_item in search_queries:
            try:
                search_uri_resource = map_item["uri_resource"]
                search_query = map_item["search_query"]
                result = self._perform_search_query(search_uri_resource, search_query)

                if len(result["hits"]["hits"]) > 0:
                    error_count_to_add = max(0, MAX_ERRORS - len(top_errors)) # calculate how many logs to add, so to not get over the total allowed max
                    top_errors.extend(result["hits"]["hits"][:error_count_to_add])

            except Exception as e:
                starttime_dt = SiemplifyUtils.convert_unixtime_to_datetime(start_unixtime)
                endtime_dt = SiemplifyUtils.convert_unixtime_to_datetime(minimum_start_time)
                error_msg = "Monitoring {} between {} to {} Failed.".format(component_display_name, starttime_dt, endtime_dt)
                message_object = {}
                message_object["email_message"] = error_msg
                message_object["notification_message"] = error_msg
                message_object['top_error_logs'] = None

                self.siemplify.LOGGER.error(error_msg)
                self.siemplify.LOGGER.exception(e)
                notification_messages.append(message_object)

                if (raise_on_error == True):
                    raise

        if len(top_errors) > 0:
            message_object = {}
            message_object['email_message'] = self._build_notification_message(minimum_start_time, end_unixtime, component_name, component_display_name)
            message_object['notification_message'] = self._build_notification_message(minimum_start_time, end_unixtime, component_name, component_display_name, notification_format=True)
            message_object['top_error_logs'] = top_errors

            notification_messages.append(message_object)

        return notification_messages

    def _build_notification_message(self, start_unixtime, end_unixtime, component_name, component_display_name, notification_format=False):
        """
        Build notification message.
        :param start_unixtime: Query start time.
        :param end_unixtime:  Query end time.
        :param component_name: Component name.
        :param notification_format: Get the message without links.
        :return: {string}
        """
        display_format ="%Y-%m-%d %H:%M:%S UTC"
        starttime_dt = SiemplifyUtils.convert_unixtime_to_datetime(start_unixtime).strftime(display_format)
        endtime_dt = SiemplifyUtils.convert_unixtime_to_datetime(end_unixtime).strftime(display_format)
        kibana_query_uris = self._get_kibana_uris(start_unixtime, end_unixtime, component_name)

        kibana_query_uris_html = "\r\n\r\n".join(kibana_query_uris)

        notification_msg = "Hello, Siemplify Monitoring service has found errors in component {} between {} to {}. \n\n  For more details, you can visit: \n\n {}".format(
            component_display_name, starttime_dt, endtime_dt, kibana_query_uris_html)
        if notification_format:
            notification_msg = "Hello, Siemplify Monitoring service has found errors in component {0} between {1} to {2}.".format(
                component_display_name, starttime_dt, endtime_dt
            )
        return notification_msg

    def _get_search_queries(self, start_unixtime, end_unixtime, component_name):
        map = []

        if component_name == "ETL":
            map = [{"filename": "search_query_etl.py", "uri_resource": "/smp_etl*/_search"}]
        elif component_name == "Connectors":
            map = [{"filename": "search_query_connectors_python.py", "uri_resource": "/smp_python*/_search"},
                   {"filename": "search_query_connectors_csharp.py", "uri_resource": "/smp_connector*/_search"}]
        elif component_name == "Jobs":
            map = [{"filename": "search_query_jobs_csharp.py", "uri_resource": "/smp_server*/_search"},
                   {"filename": "search_query_jobs_python.py", "uri_resource": "/smp_python*/_search"}]
        elif component_name == "Playbooks":
            map = [{"filename": "search_query_playbooks_csharp.py", "uri_resource": "/smp_server*/_search"},
                   {"filename": "search_query_playbooks_csharp.py", "uri_resource": "/smp_etl*/_search"},
                   {"filename": "search_query_playbooks_python.py", "uri_resource": "/smp_python*/_search"}]

        for map_item in map:
            absolute_path = self.convert_to_absolut_path(map_item["filename"])
            f = open(absolute_path, "r")
            query_template = f.read()
            f.close()
            query = self.replace_query_params(start_unixtime, end_unixtime, query_template)

            map_item["search_query"] = query

        return map

    def _get_kibana_uris(self, start_unixtime, end_unixtime, component_name):
        filenames = []
        link_display_names = []

        if component_name == "ETL":
            filenames = ["kibana_query_etl.py"]
            link_display_names = ["ETL Errors"]
        if component_name == "Connectors":
            filenames = ["kibana_query_connectors_csharp.py", "kibana_query_connectors_python.py"]
            link_display_names = ["Connectors CSharp Errors","Connectors Python Errors"]
        if component_name == "Jobs":
            filenames = ["kibana_query_jobs_charp.py", "kibana_query_jobs_python.py"]
            link_display_names = ["Jobs CSharp Errors","Jobs Python Errors"]
        if component_name == "Playbooks":
            filenames = ["kibana_query_playbooks_csharp.py", "kibana_query_playbooks_python.py"]
            link_display_names = ["Actions CSharp Errors","Actions Python Errors"]

        kibana_query_uris = []
        display_name_index = 0
        for file in filenames:
            absolute_file_path = self.convert_to_absolut_path(file)
            f = open(absolute_file_path, "r")
            uri_template = f.read()
            f.close()
            uri = self._replace_kibana_query_params(start_unixtime, end_unixtime, uri_template)

            link_name = link_display_names[display_name_index]
            display_name_index += 1

            uri ='<a href="{}">{}</a>'.format(uri,link_name)
            kibana_query_uris.append(uri)

        return kibana_query_uris

    def _replace_kibana_query_params(self, start_unixtime, end_unixtime, query_uri):
        KIBANA_TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
        kibana_format_starttime = SiemplifyUtils.convert_unixtime_to_datetime(start_unixtime).strftime(KIBANA_TIME_FORMAT)
        kibana_format_endtime = SiemplifyUtils.convert_unixtime_to_datetime(end_unixtime).strftime(KIBANA_TIME_FORMAT)

        query_uri = query_uri.replace("<kibana_address>", self.settings.kibana_address)
        query_uri = query_uri.replace("<from_time>", kibana_format_starttime)
        query_uri = query_uri.replace("<to_time>", kibana_format_endtime)

        return query_uri

    def _perform_search_query(self, search_uri_resource, search_query):

        uri = urlparse.urljoin(self.settings.elastic_address,search_uri_resource)
        response  = requests.post(url=uri,
                                  headers=self._default_headers(),
                                  data=search_query,
                                  auth=HTTPBasicAuth(self.settings.elastic_query_username,
                                                     self.settings.elastic_query_password))

        if response.status_code < 200 or response.status_code > 300:
            raise Exception("Error performing REST API search. Details: " +response.content)

        result = response.json()

        return result

    def replace_query_params(self,start_unixtime,end_unixtime, query_json):
        result = query_json.replace("<start_unixtime>",str(start_unixtime))
        result = result.replace("<end_unixtime>",str(end_unixtime))
        return result

    # ---------------------------- Private

        # Kibana Connectors Error table Display
        # Kibana ETL Error table Display
        # Kibana Jobs Error table Display

        # GetQueryBodyFromDependencyFile

    def _default_headers(self):
        return {"content-type":"application/json"}

    def valdiate_maximum_timeback_dt(self,last_run_dt,maximum_allowed_time_back_timedelta):
        last_run_unixtime = SiemplifyUtils.convert_datetime_to_unix_time(last_run_dt)
        maximum_allowed_time_back_ms = maximum_allowed_time_back_timedelta.total_seconds()*1000
        return self.valdiate_maximum_timeback_unixtime(last_run_unixtime=last_run_unixtime,
                                                  maximum_allowed_time_back_ms=maximum_allowed_time_back_ms)

    def valdiate_maximum_timeback_unixtime(self,last_run_unixtime,maximum_allowed_time_back_ms):
        maximum_time_back = SiemplifyUtils.unix_now()-maximum_allowed_time_back_ms

        if (last_run_unixtime < maximum_time_back):
            return maximum_time_back

        return last_run_unixtime

    def convert_to_absolut_path(self, relative_path):
        running_folder = os.path.dirname(os.path.abspath(__file__))
        absolut_path = os.path.join(running_folder, relative_path)
        return absolut_path


# ---------------------- Connectors Monitoring Job
    # call AreThereConnectorsErrors?
    # send notification + mail (with kibana link) if there are errors)


class ESMMSettings(object):
    def __init__(self,
                 elastic_query_username,
                 elastic_query_password,
                 elastic_address,
                 kibana_address,
                 maximum_record_fetch=100):
        self.elastic_query_username = elastic_query_username
        self.elastic_query_password = elastic_query_password
        self.elastic_address = elastic_address
        self.kibana_address = kibana_address
        self.maximum_record_fetch = maximum_record_fetch