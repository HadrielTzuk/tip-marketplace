from TIPCommon import dict_to_flat, add_prefix_to_dict

class BaseModel(object):
    """
    Base model for inheritance
    """

    def __init__(self, raw_data):
        self.raw_data = raw_data

    def to_json(self):
        return self.raw_data

class URLReport(object):
    def __init__(self, raw_data,
                 verdict=None, threat_level=None, score= None, status=None):
        self.raw_data = raw_data
        self.status = status
        self.verdict = verdict
        self.threat_level = threat_level
        self.score = score

    def to_json(self):
        return self.raw_data

    def to_flat_dict(self):
        return dict_to_flat(self.to_dict())

class HistoryItem(BaseModel):
    def __init__(self, raw_data, name, related, hashes, verdict, date, md5, sha1, sha256):
        super(HistoryItem, self).__init__(raw_data)
        self.name = name
        self.related = related
        self.hashes = hashes
        self.verdict = verdict
        self.date = date
        self.md5 = md5
        self.sha1 = sha1
        self.sha256 = sha256

    def to_csv(self):
        return {
            'Submission Name': self.name,
            'Verdict': self.verdict,
            'Report URL': self.related,
            'Scan Date': self.date,
            'MD5 ': self.md5,
            'SHA1': self.sha1,
            'SHA256': self.sha256
        }

class Report(BaseModel):
    def __init__(self, raw_data, score, threat_level, threat_text, report_url, report_ioc, report_misp, report_html,
                 report_graph):
        super(Report, self).__init__(raw_data)
        self.score = score
        self.threat_level = threat_level
        self.threat_text = threat_text
        self.report_url = report_url
        self.report_ioc = report_ioc
        self.report_misp = report_misp
        self.report_html = report_html
        self.report_graph = report_graph

    def to_csv(self):
        return {
            'Threat Level': self.threat_level,
            'Score': self.score,
            'Report URL': self.report_url,
            'Report IOC': self.report_ioc,
            'Report MISP ': self.report_misp,
            'Report HTML': self.report_html,
            'Report Graph': self.report_graph
        }
        
class Task(BaseModel):
    def __init__(self, raw_data, task_id):
        super(Task, self).__init__(raw_data)
        self.raw_data = raw_data
        self.task_id=task_id
