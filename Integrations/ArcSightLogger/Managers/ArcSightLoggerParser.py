from datamodels import *


class ArcSightLoggerParser(object):
    def get_auth_token(self, raw_json):
        return raw_json.get(u'log.loginResponse', u'').get(u'log.return')

    def build_query_status_object(self, result_json):
        return QueryStatus(result_json,
                           status=result_json.get(u'status'),
                           result_type=result_json.get(u'result_type'),
                           hit=result_json.get(u'hit'),
                           scanned=result_json.get(u'scanned'),
                           elapsed=result_json.get(u'elapsed'),
                           message=result_json.get(u'message')
                           )
