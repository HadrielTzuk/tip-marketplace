from datamodels import *

class AnyRunParser(object):
    def build_history_items_list(self, raw_json):
        return [self.build_history_item(item_json) for item_json in raw_json.get('data', {}).get('tasks', [])]

    def build_history_item(self, raw_json):
        return HistoryItem(
            raw_data=raw_json,
            name=raw_json.get('name'),
            related=raw_json.get('related'),
            hashes=raw_json.get('hashes', {}).values(),
            verdict=raw_json.get('verdict'),
            date=raw_json.get('date'),
            md5=raw_json.get('hashes', {}).get('md5'),
            sha1=raw_json.get('hashes', {}).get('sha1'),
            sha256=raw_json.get('hashes', {}).get('sha256')
        )

    def build_report_object(self, raw_json):
        return Report(
            raw_data=raw_json,
            score=raw_json.get('data', {}).get('analysis', {}).get('scores', {}).get('verdict', {}).get('score'),
            threat_level=raw_json.get('data', {}).get('analysis', {}).get('scores', {}).get('verdict', {}).get(
                'threatLevel'),
            threat_text=raw_json.get('data', {}).get('analysis', {}).get('scores', {}).get('verdict', {}).get(
                'threatLevelText'),
            report_url=raw_json.get('data', {}).get('analysis', {}).get('permanentUrl'),
            report_ioc=raw_json.get('data', {}).get('analysis', {}).get('reports', {}).get('IOC'),
            report_misp=raw_json.get('data', {}).get('analysis', {}).get('reports', {}).get('MISP'),
            report_html=raw_json.get('data', {}).get('analysis', {}).get('reports', {}).get('HTML'),
            report_graph=raw_json.get('data', {}).get('analysis', {}).get('reports', {}).get('graph')
        )
        
    def build_url_report_object(self, raw_json):
        
        status = raw_json.get("data",{}).get("status")
        verdict = raw_json.get("data",{}).get("analysis",{}).get("scores",{}).get("verdict",{}).get("threatLevelText")
        threat_level = raw_json.get("data",{}).get("analysis",{}).get("scores",{}).get("verdict",{}).get("threatLevel")
        score = raw_json.get("data",{}).get("analysis",{}).get("scores",{}).get("verdict",{}).get("score")
        
        return URLReport(raw_data=raw_json,status=status,verdict=verdict, threat_level=threat_level, score=score)

    def build_task_object(self, raw_json):
        
        task_id = raw_json.get("data",{}).get("taskid")
        return Task(raw_data=raw_json,task_id=task_id)

