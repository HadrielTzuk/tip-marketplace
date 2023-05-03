import xmltodict
from PanoramaExceptions import ResponseObjectNotSet
from datamodels import *


class PanoramaParser(object):
    def __init__(self):
        self.__response = None
        self.json_response = {}

    def set_response(self, response):
        self.__response = response
        self.json_response = self.response_to_json()

    def response_to_json(self):
        if not self.__response:
            raise ResponseObjectNotSet
        return xmltodict.parse(self.__response.text)

    def get_response(self):
        return self.json_response.get('response', {})

    def get_result(self):
        return self.get_response().get('result', {})

    def get_job_id(self):
        return self.get_result().get('job')

    def get_timezone_string(self):
        return self.get_result()

    def get_logs_from_query_result(self):
        return self.get_result().get('log', {}).get('logs', {})

    def get_query_result_progress(self):
        return int(self.get_logs_from_query_result().get('@progress', 0))

    def get_job_status(self):
        return self.get_result().get('job', {}).get('status')

    def get_log_entities_from_query_result(self, server_time=u""):
        data = self.get_logs_from_query_result().get('entry', [])
        if not isinstance(data, list):
            data = [data]
        return [self.build_log_entity(json, server_time) for json in data]

    def get_log_entities_from_json(self, entities_json):
        return [self.build_log_entity(json) for json in entities_json]

    def build_log_entity(self, json, server_time=u""):
        return LogEntity(
            raw_data=json,
            log_id=json.get(u'@logid'),
            seqno=json.get(u'seqno'),
            receive_time=json.get(u'receive_time'),
            src=json.get(u'src'),
            dst=json.get(u'dst'),
            action=json.get(u'action'),
            severity=json.get(u'severity'),
            description=json.get(u'threatid'),
            misc=json.get(u'misc'),
            subtype=json.get(u'subtype'),
            category=json.get(u'category'),
            filedigest=json.get(u'filedigest'),
            filetype=json.get(u'filetype'),
            matchname=json.get(u'matchname'),
            repeatcnt=json.get(u'repeatcnt'),
            device_name=json.get(u'device_name'),
            tag_name=json.get(u'tag_name'),
            event_id=json.get(u'event_id'),
            ip=json.get(u'ip'),
            user=json.get(u'user'),
            app=json.get(u'app'),
            admin=json.get(u'admin'),
            cmd=json.get(u'cmd'),
            opaque=json.get(u'opaque'),
            desc=json.get(u'desc'),
            time_generated=json.get(u'time_generated'),
            server_time=server_time
        )
