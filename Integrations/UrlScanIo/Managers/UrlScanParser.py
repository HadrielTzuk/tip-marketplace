from datamodels import *
from constants import CASE_WALL_LINK


class UrlScanParser(object):
    def build_results(self, raw_data, method):
        return [getattr(self, method)(item_json) for item_json in raw_data.get('results', [])]

    def get_scan_id(self, raw_data):
        return raw_data.get('uuid', '')

    def build_url_object(self, raw_data):
        
        return URL(
            raw_data=raw_data,
            verdicts=raw_data.get('verdicts', {}),
            lists=raw_data.get('lists', {}),
            uuid=raw_data.get('task', {}).get('uuid', ''),
            score=raw_data.get('verdicts', {}).get("overall", {}).get("score", 0),
            screenshot_url=raw_data.get('task', {}).get('screenshotURL', ''),
            result_link=CASE_WALL_LINK.format(raw_data.get('task', {}).get('uuid', '')),
            url=raw_data.get('page', {}).get("url"), 
            ips=raw_data.get('lists', {}).get("ips"), 
            countries=raw_data.get('lists', {}).get("countries"), 
            domains=raw_data.get('lists', {}).get("domains"),  
            transactions=raw_data.get('lists', {}).get("urls"), 
            ip_address=raw_data.get('page', {}).get("ip"),  
            city=raw_data.get('page', {}).get("city"), 
            country=raw_data.get('page', {}).get("country"), 
            asnname=raw_data.get('page', {}).get("asnname"),  
            domain=raw_data.get('page', {}).get("domain"), 
            certificates=raw_data.get("lists", {}).get('certificates', {})  

        )

    @staticmethod
    def build_scan_details_object(raw_data):
        raw_data['Effective URL'] = raw_data.get('page', {}).get('url', '')
        return ScanDetails(
            raw_data=raw_data,
            uuid=raw_data.get('task', {}).get('uuid'),
            report_url=raw_data.get('task', {}).get('reportURL', ''),
            dom_url=raw_data.get('task', {}).get('domURL', ''),
            screenshot_url=raw_data.get('task', {}).get('screenshotURL', '')
        )

    def build_search_object(self, raw_data):
        return SearchObject(
            raw_data=raw_data,
            item_id=raw_data.get("_id", ''),
            task=self.build_search_task_object(raw_data.get('task', {})),
            stats=self.build_search_stats_object(raw_data.get('stats', {})),
            page=self.build_search_page_object(raw_data.get('page', {})),
            screenshot=raw_data.get('screenshot', ''),
            report_link=CASE_WALL_LINK.format(raw_data.get('task', {}).get('uuid', ''))
        )

    def build_search_task_object(self, raw_data):
        return SearchTask(
            raw_data=raw_data,
            task_url=raw_data.get('url', ''),
            time=raw_data.get('time', ''),
            visibility=raw_data.get('visibility', ''),
        )

    def build_search_stats_object(self, raw_data):
        return SearchStats(
            raw_data=raw_data,
            data_length=raw_data.get('dataLength', ''),
            unique_ips=raw_data.get('uniqIPs', ''),
            unique_countries=raw_data.get('uniqCountries', ''),
        )

    def build_search_page_object(self, raw_data):
        return SearchPage(
            raw_data=raw_data,
            country=raw_data.get('country', ''),
        )
