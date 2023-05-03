import requests
import json
from copy import deepcopy
from CofenseTriageParser import CofenseTriageParser
from CofenseTriageExceptions import (
    CofenseTriageException,
    RecordNotFoundException
)
from constants import (
    TOKEN_PAYLOAD,
    ACCESS_TOKEN_URL,
    PING_QUERY,
    ENRICH_URL,
    DOMAIN_URL,
    THREAT_INDICATOR_URL,
    REPORTERS_URL,
    RULES_URL,
    HEADERS_URL,
    CATEGORIES_URL,
    REPORT_TAGS,
    REPORTS_URL,
    CATEGORY_URL,
    CATEGORIZE_REPORT_URL,
    DOWNLOAD_URL,
    PNG_FORMAT,
    JPG_FORMAT,
    DOWNLOAD_PNG_URL,
    DOWNLOAD_JPG_URL,
    REPORTS,
    REPORT_URLS,
    REPORT_HOSTNAMES,
    REPORT_THREAT_INDICATORS,
    REPORT_ATTACHMENT,
    ATTACHMENT_PAYLOADS,
    DEFAULT_LIMIT,
    RELATED_ENTITIES_DEFAULT_LIMIT,
    CONNECTOR_DATETIME_FORMAT,
    REPORT_REQUESTS_FIELDS,
    DEFAULT_PAGE_SIZE,
    GET_THREAT_INDICATOR_IDS_URL,
    GET_RELATED_REPORTS_URL,
    REPORT_COMMENTS_URL,
    REPORT_HEADERS_URL,
    LIST_PLAYBOOKS_URL,
    EQUAL,
    EXECUTE_PLAYBOOK_URL
)
from urllib.parse import urljoin
import datetime
from UtilsManager import filter_old_alerts
from typing import List
from datamodels import Playbook


class CofenseTriageManager(object):
    def __init__(self, api_root=None, client_id=None, client_secret=None, verify_ssl=False, siemplify_logger=None):
        """
        The method is used to init an object of Manager class
        :param api_root: API Root of the Cofense Triage 
        :param client_id: Client ID of the CofenseTriage instance.
        :param client_secret: Client Secret of the CofenseTriage instance.
        :param verify_ssl: If enabled, verify the SSL certificate for the connection to the Cofense Triage server is valid.
        :param siemplify_logger: Siemplify logger.
        """

        self.client_id = client_id
        self.api_root = api_root[:-1] if api_root.endswith('/') else api_root
        self.client_secret = client_secret
        self.siemplify_logger = siemplify_logger
        
        self.parser = CofenseTriageParser()
        self.session = requests.session()
        self.session.verify = verify_ssl
        self.access_token = self.generate_token(self.client_id, self.client_secret) 
        self.session.headers.update(
            {"Authorization": "Bearer {0}".format(self.access_token), "Content-Type": "application/json"}) 

    def generate_token(self, client_id, client_secret):
        """
        :param client_id: {string} The Application ID that the registration portal
        :param client_secret: {string} The application secret that you created in the app registration portal for your app.
        :return: {string} Access token. The app can use this token in API requests
        """
        payload = deepcopy(TOKEN_PAYLOAD)
        payload["client_id"] = client_id
        payload["client_secret"] = client_secret
        res = self.session.post(ACCESS_TOKEN_URL.format(self.api_root), data=payload)
        self.validate_response(res)
        return res.json().get('access_token')
 
    @staticmethod
    def validate_response(response, error_msg="An error occurred"):
        try:
            if response.status_code == 404:
                if response.json().get("errors",):
                     raise RecordNotFoundException(response.json().get("errors",[])[0].get("detail"))
                     
                else:
                    raise RecordNotFoundException(response.json())
            
            response.raise_for_status()

        except requests.HTTPError as error:
            try:
                response.json()
            except:
                # Not a JSON - return content
                raise CofenseTriageException(
                    "{error_msg}: {error} - {text}".format(
                        error_msg=error_msg,
                        error=error,
                        text=error.response.content)
                )

            raise CofenseTriageException(
                "{error_msg}: {error} {text}".format(
                    error_msg=error_msg,
                    error=response.json().get('name'),
                    text=json.dumps(response.json()))
            )

    def test_connectivity(self):
        """
        Test integration connectivity.
        """
        
        result = self.session.get(PING_QUERY.format(self.api_root))
        # Verify result.
        self.validate_response(result)
        
    def enrich_url(self, url):
        """
        Function that enriches an URL
        :param url {str} URL to enrich
        :return: {URLObject} URLObject with data
        """        
        
        request_url = ENRICH_URL.format(self.api_root, url)
        result = self.session.get(request_url)
        # Verify result.
        self.validate_response(result)
        
        return self.parser.build_siemplify_url_object(result.json())
    
    def get_domain_details(self, domain):
        """
        Function that returns details of a domain
        :param domain {str} Domain for which we need details
        :return: {UniversalObject} UniversalObject with data
        """        
        
        request_url = DOMAIN_URL.format(self.api_root, domain)
        result = self.session.get(request_url)
        # Verify result.
        self.validate_response(result)
        
        return self.parser.build_siemplify_domain_details_object(result.json())
    
    def get_threat_indicator_details(self, entity):
        """
        Function that gets the Threat Indicator Details
        :param entity {str} Entity for which we need details
        :return: {ThreaIndicatorDetailsObject} DomainObject with data
        """                
    
        request_url = THREAT_INDICATOR_URL.format(self.api_root, entity)
        result = self.session.get(request_url)
        # Verify result.
        self.validate_response(result)
        
        return self.parser.build_siemplify_ti_object(result.json())
    
    def get_report_reporters(self, report_id):
        """
        Function that gets the report reporters
        :param report_id {str} Report ID 
        :return: {UniversalObject} UniversalObject with data
        """                
    
        request_url = REPORTERS_URL.format(self.api_root, report_id)
        result = self.session.get(request_url)
        # Verify result.
        self.validate_response(result)
        
        return self.parser.build_siemplify_report_reporters_object(result.json())    
    
    def get_report_rules(self, report_id, max_rules_to_return):
        """
        Function that gets the report rules
        :param report_id {str} Report ID 
        :param max_rules_to_return {str} Max rules to return
        :return: {UniversalObject} UniversalObject with data
        """                
    
        request_url = RULES_URL.format(self.api_root, report_id, max_rules_to_return)
        result = self.session.get(request_url)
        # Verify result.
        self.validate_response(result)
        
        return self.parser.build_siemplify_universal_object(result.json())    
    
    def get_report_headers(self, report_id, max_headers_to_return):
        """
        Function that gets the report headers
        :param report_id {str} Report ID 
        :param max_headers_to_return {str} Max headers to return
        :return: {UniversalObject} UniversalObject with data
        """                
    
        request_url = HEADERS_URL.format(self.api_root, report_id, max_headers_to_return)
        result = self.session.get(request_url)
        # Verify result.
        self.validate_response(result)
        
        return self.parser.build_siemplify_report_headers_object(result.json())    
    
    def get_categories(self, name, only_malicious, only_archived, only_not_archived, only_non_malicious,
                                                      max_categories_to_return, lower_score_to_fetch):
        
        """
        Function that gets the categories 
        :param name {str} Name of category
        :param only_malicious {bool} Only Malicious
        :param only_archived {bool} Only Archived
        :param only_non_malicious {bool} Only Non Malicious
        :param only_not_archived {bool} Only Not Archived
        :param max_categories_to_return {int} Max Categories to Return
        :param lower_score_to_fetch {int} Lower Score To Fetch       
        :return: {CategoriesObject} CategoriesObject with data
        """     
        params = {}
        
        if name:
            params["filter[name]"] = name
            
        if lower_score_to_fetch:
            params["filter[score_gteq]"] = lower_score_to_fetch
            
        if only_archived:
            params["filter[archived]"] = only_archived            
        
        if only_malicious:
            params["filter[malicious]"] = only_malicious  
            
        if only_not_archived:
            params["filter[archived]"] = False            
        
        if only_non_malicious:
            params["filter[malicious]"] = False              

        if max_categories_to_return is None:
            max_categories_to_return = 20
            
        params["page[size]"] = max_categories_to_return     
        params["fields[categories]"]= "name,score,malicious,color,archived,created_at,updated_at"
            
        
        request_url = CATEGORIES_URL.format(self.api_root)   
        result = self.session.get(request_url, params=params)
        # Verify result.
        self.validate_response(result)        
        
        return self.parser.build_siemplify_categories_object(result.json())     
    
    
    def get_report_tags(self, report_id):
        """
        Function that gets tags for a report 
        :param report_id {str} Report ID 
        :return: {ReportOject} ReportOject with data
        """                
        
        request_url = REPORT_TAGS.format(self.api_root, report_id)
        result = self.session.get(request_url)
        # Verify result.
        self.validate_response(result)
        
        return self.parser.build_siemplify_reports_object(result.json())            
        
    def update_report(self, report_id, tags):
        """
        Function that updates a report
        :param report_id {str} Report ID 
        :param tags {str} Tags to add to a report
        """                

        request_url = REPORTS_URL.format(self.api_root, report_id)
        self.session.headers["Content-Type"] = 'application/vnd.api+json'

        data= {
                "data": {
                    "id": report_id,
                    "type": "reports",
                    "attributes": {
                        "tags": tags
                    }
                }
            }

        result = self.session.put(request_url, json=data)
        # Verify result.
        self.validate_response(result)
        
    def get_report(self, report_id):
        """
        Function that gets a report
        :param report_id {str} Report ID 
        :return: {ReportOject} ReportOject with data
        """          
        
        request_url = REPORTS_URL.format(self.api_root, report_id)
        result = self.session.get(request_url)
        # Verify result.
        self.validate_response(result)
        
        return self.parser.build_siemplify_reports_object(result.json())      
    
    def get_category_id(self, category):
        """
        Function that gets an ID of a category
        :param category {str} Category
        :return: {CategoryOject} CategoryOject with data
        """          
        
        request_url = CATEGORY_URL.format(self.api_root, category)
        result = self.session.get(request_url)
        # Verify result.
        self.validate_response(result)
        
        return self.parser.build_siemplify_categories_object(result.json())      
    
    
    def categorize_report(self, report_id, category_id):
        """
        Function that categorizes the report
        :param report_id {str} Report ID 
        :param category_id {str} Category ID
        """   
        request_url = CATEGORIZE_REPORT_URL.format(self.api_root, report_id)
        self.session.headers["Content-Type"] = 'application/vnd.api+json'

        data= {
            "data": {
                "category_id": category_id
            }
        }

        result = self.session.post(request_url, json=data)
        # Verify result.
        self.validate_response(result)
        
    def download_report_email(self, report_id):
        """
        Function that gets the report email
        :param report_id {str} Report ID 
        :return {Response} Raw Response Object
        """   

        request_url = DOWNLOAD_URL.format(self.api_root, report_id)

        result = self.session.get(request_url)
        # Verify result.
        self.validate_response(result)
        
        return result
    
    
    def download_report_preview(self, report_id, image_format):
        """
        Function that gets the report preview
        :param report_id {str} Report ID 
        :param image_format {str} Image Format - PNG/JPG
        :return {Response} Raw Response Object
        """           
        
        if image_format == JPG_FORMAT:
            request_url = DOWNLOAD_JPG_URL.format(self.api_root, report_id)
            
        if image_format == PNG_FORMAT:
            request_url = DOWNLOAD_PNG_URL.format(self.api_root, report_id)
        
                
        result = self.session.get(request_url, stream=True)
        # Verify result.
        self.validate_response(result)
        
        return result

    def _get_full_url(self, endpoint, **kwargs):
        """
        Get full url from endpoint and arguments.
        :param endpoint: {str} The endpoint for url
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        return urljoin(self.api_root, endpoint.format(**kwargs))
        
    def get_alerts(self, existing_ids, limit, start_timestamp, lowest_risk_score, report_location):
        """
        Get alerts
        :param existing_ids: {list} The list of existing ids
        :param limit: {int} The limit for alerts
        :param start_timestamp: {int} Timestamp for oldest alert to fetch
        :param lowest_risk_score: {int} Lowest risk score that will be used to fetch data
        :param report_location: {str} Comma-separated list of locations from where to ingest reports
        :return: {list} List of filtered Alert objects.
        """
        reports = self.get_reports(limit, start_timestamp, lowest_risk_score, report_location)
        alerts = []

        for report in reports:
            urls, hostnames, threat_indicators, attachments, attachments_payloads, comments, headers = \
                self.get_report_related_entities(report.get("id"))
            alerts.append(
                self.parser.get_alert(report, urls, hostnames, threat_indicators, attachments, attachments_payloads,
                                      comments, headers)
            )

        filtered_alerts = filter_old_alerts(self.siemplify_logger, alerts, existing_ids, "id")
        return filtered_alerts

    def get_reports(self, limit, start_timestamp, lowest_risk_score, report_location):
        """
        Get reports
        :param limit: {int} The limit for reports
        :param start_timestamp: {int} Timestamp for oldest report to fetch
        :param lowest_risk_score: {int} Lowest risk score that will be used to fetch data
        :param report_location: {str} Comma-separated list of locations from where to ingest reports
        :return: {list} Response raw data.
        """
        request_url = self._get_full_url(REPORTS)
        params = {
            "filter[risk_score_gteq]": lowest_risk_score,
            "sort": "created_at",
            "fields[reports]": REPORT_REQUESTS_FIELDS.get("reports"),
            "filter[created_at_gteq]": self._build_created_at_filter(start_timestamp),
            "filter[location]": report_location,
            "page[size]": max(limit, DEFAULT_LIMIT)
        }

        result = self.session.get(request_url, params=params)
        self.validate_response(result)
        return result.json().get("data", [])

    def _build_created_at_filter(self, start_timestamp):
        """
        Build created_at filter.
        :param start_timestamp: {int} Timestamp for oldest report to fetch
        :return: {str} The created_at filter value
        """
        return "{}Z".format(datetime.datetime.fromtimestamp(start_timestamp / 1000)
                            .strftime(CONNECTOR_DATETIME_FORMAT)[:-3])

    def get_report_related_entities(self, report_id):
        """
        Get report related entities
        :param report_id: {str} The report id
        :return: {tuple} urls, hostnames, threat_indicators, attachments, attachments_payloads, comments, headers
        """
        urls = self.get_report_urls(report_id)
        hostnames = self.get_report_hostnames(report_id)
        threat_indicators = self.get_report_threat_indicators(report_id)
        attachments, attachments_payloads = self.get_report_attachments(report_id)
        comments = self.get_report_comments(report_id)
        headers = self.get_report_headers_for_connector(report_id)
        return urls, hostnames, threat_indicators, attachments, attachments_payloads, comments, headers

    def get_report_urls(self, report_id):
        """
        Get report urls by report id
        :param report_id: {str} The report id
        :return: {list} List of UniversalObject objects
        """
        request_url = self._get_full_url(REPORT_URLS, report_id=report_id)
        params = {
            "fields[urls]": REPORT_REQUESTS_FIELDS.get("urls"),
            "page[size]": RELATED_ENTITIES_DEFAULT_LIMIT
        }

        result = self.session.get(request_url, params=params)
        self.validate_response(result)
        return self.parser.build_related_entities_objects(result.json())

    def get_report_hostnames(self, report_id):
        """
        Get report hostnames by report id
        :param report_id: {str} The report id
        :return: {list} List of UniversalObject objects
        """
        request_url = self._get_full_url(REPORT_HOSTNAMES, report_id=report_id)
        params = {
            "fields[hostnames]": REPORT_REQUESTS_FIELDS.get("hostnames"),
            "page[size]": RELATED_ENTITIES_DEFAULT_LIMIT
        }

        result = self.session.get(request_url, params=params)
        self.validate_response(result)
        return self.parser.build_related_entities_objects(result.json())

    def get_report_threat_indicators(self, report_id):
        """
        Get report threat indicators by report id
        :param report_id: {str} The report id
        :return: {list} List of ThreaIndicatorDetailsObject objects
        """
        request_url = self._get_full_url(REPORT_THREAT_INDICATORS, report_id=report_id)
        params = {
            "fields[threat_indicators]": REPORT_REQUESTS_FIELDS.get("threat_indicators"),
            "page[size]": RELATED_ENTITIES_DEFAULT_LIMIT
        }

        result = self.session.get(request_url, params=params)
        self.validate_response(result)
        return self.parser.build_threat_indicators_objects(result.json())

    def get_report_attachments(self, report_id):
        """
        Get report attachments by report id
        :param report_id: {str} The report id
        :return: {tuple} List of Attachment objects, List of AttachmentPayload objects
        """
        request_url = self._get_full_url(REPORT_ATTACHMENT, report_id=report_id)
        params = {
            "page[size]": RELATED_ENTITIES_DEFAULT_LIMIT
        }

        result = self.session.get(request_url, params=params)
        self.validate_response(result)
        attachments = self.parser.build_attachment_objects(result.json())
        attachment_ids = [attachment.payload_id for attachment in attachments]
        attachments_payloads = self.get_report_attachments_payloads(attachment_ids) if attachment_ids else []
        return attachments, attachments_payloads

    def get_report_attachments_payloads(self, attachment_ids):
        """
        Get attachments payloads by attachment ids
        :param attachment_ids: {list} List of attachment ids
        :return: List of AttachmentPayload objects
        """
        request_url = self._get_full_url(ATTACHMENT_PAYLOADS)
        params = {
            "filter[id]": ",".join(attachment_ids),
            "page[size]": RELATED_ENTITIES_DEFAULT_LIMIT
        }

        result = self.session.get(request_url, params=params)
        self.validate_response(result)
        return self.parser.build_attachment_payload_objects(result.json())

    def get_report_comments(self, report_id):
        """
        Get report comments by report id
        :param report_id: {str} The report id
        :return: {list} List of UniversalObject objects
        """
        request_url = self._get_full_url(REPORT_COMMENTS_URL, report_id=report_id)
        result = self.session.get(request_url)
        self.validate_response(result)
        return self.parser.build_related_entities_objects(result.json())

    def get_report_headers_for_connector(self, report_id):
        """
        Get report headers by report id
        :param report_id: {str} The report id
        :return: {list} List of UniversalObject objects
        """
        request_url = self._get_full_url(REPORT_HEADERS_URL, report_id=report_id)
        result = self.session.get(request_url)
        self.validate_response(result)
        return self.parser.build_related_entities_objects(result.json())

    def get_threat_indicators_id(self, entities, max_reports_to_return):
        """
        Get threat indicators ID
        :param entities: {str} Comma separated string of siemplify entities
        :return: List of Related Reports objects
        """
        request_url = self._get_full_url(GET_THREAT_INDICATOR_IDS_URL)
        params = {
            "filter[threat_value]":entities,
            "fields[threat_indicators]":"id",
            "page[size]": DEFAULT_PAGE_SIZE
        }

        result = self.session.get(request_url, params=params)
        self.validate_response(result)
        
        threat_ids = self.parser.get_alert_ids(result.json())
        threat_reports = []
        list_of_related_reports = []
        
        for threat_id in threat_ids:
            threat_object = self.get_related_reports(threat_id, list_of_related_reports)
            list_of_related_reports = threat_object
            
        threat_reports.append(list_of_related_reports[:max_reports_to_return])    

        return threat_reports
        
    def get_related_reports(self, threat_id, list_of_related_reports):
        """
        Get related reports per threat_id
        :param threat_id: {str} Threat ID for which the report should be fetched
        :return: List of Related Reports objects
        """
        request_url = self._get_full_url(GET_RELATED_REPORTS_URL.format(threat_id=threat_id))

        response = self.session.get(request_url)
        result = response.json()
        self.validate_response(response)
        
        while True:

            related_reports = self.parser.related_reports(result)

            for report in related_reports:
                related_report_obj = self.parser.build_related_report_object(report)

                if not related_report_obj.id in [ added_related_report.id for added_related_report in list_of_related_reports]: #duplications of related reports are not stored
                    list_of_related_reports.append(related_report_obj)            
                
            if not result.get("links", {}).get("next"): #no need for pagination -> all the results fetched
               break
            request_url = result.get("links", {}).get("next")
            response = self.session.get(request_url)
            
            self.validate_response(response) 
            result = response.json()      
           
        return list_of_related_reports

    def get_playbooks(
            self,
            filter_key: str,
            filter_logic: str,
            filter_value: str,
            limit: int
    ) -> List[Playbook]:
        """
        Get playbooks
        Args:
            filter_key: Filter key
            filter_logic: Filter logic
            filter_value: Filter value
            limit: Filtered items limit

        Returns:
            (list)
        """
        request_url = self._get_full_url(LIST_PLAYBOOKS_URL)
        params = {
            "page[size]": limit
        }
        if filter_value and filter_logic:
            if filter_logic == EQUAL:
                params[f"filter[{filter_key}]"] = filter_value
            else:
                params[f"filter[{filter_key}_cont]"] = filter_value

        response = self.session.get(request_url, params=params)
        self.validate_response(response)
        return self.parser.build_playbooks_list(response.json())

    def get_playbook_by_name(
            self,
            name: str
    ) -> Playbook:
        """
        Get playbook by name
        Args:
            name: Playbook name

        Returns:
            (Playbook)
        """
        request_url = self._get_full_url(LIST_PLAYBOOKS_URL)
        params = {
            "page[size]": 1,
            "filter[name]": name
        }
        response = self.session.get(request_url, params=params)
        self.validate_response(response)
        results = self.parser.build_playbooks_list(response.json())
        if results:
            return results[0]

    def execute_playbook(
            self,
            playbook_id: str,
            report_id: str
    ) -> None:
        """
        Execute playbook
        Args:
            playbook_id: ID of the Playbook to execute
            report_id: ID of the report on which to execute

        Returns:
            (None)
        """
        request_url = self._get_full_url(EXECUTE_PLAYBOOK_URL)
        payload = {
            "data": {
                "report_ids": [
                    report_id
                ],
                "playbook_id": playbook_id
            }
        }

        response = self.session.post(request_url, json=payload)
        self.validate_response(response)
