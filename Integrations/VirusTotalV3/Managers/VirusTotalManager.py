from typing import Any
from urllib.parse import urljoin
import requests
from SiemplifyDataModel import EntityTypes
from UtilsManager import prepare_entity_for_manager
from VirusTotalParser import VirusTotalParser
from constants import PER_PAGE_ITEMS_COUNT, EMAIL_TYPE, DOMAIN_TYPE, ERROR_RESPONSE_TEXTS
from exceptions import VirusTotalNotFoundException, UnauthorizedException, VirusTotalBadRequest, \
    VirusTotalInvalidApiKeyException, VirusTotalPermissionException, VirusTotalException
from TIPCommon import filter_old_alerts

# CONSTANTS
API_ROOT = "https://www.virustotal.com/api/v3/"
HEADERS = {
    "Accept-Encoding": "gzip, deflate",
    "Accept": "application/json",
    "Content-Type": "application/json"
}

NOT_FOUND_STATUS_CODE = 404
UNAUTHORIZED_STATUS_CODE = 401
BAD_REQUEST = 400
QUERY_JOIN_PARAMETER = " OR "

ORDER_BY_MAPPING = {
    "Name": "name",
    "Owner": "owner",
    "Creation Date": "creation_date",
    "Last Modified Date": "last_modified_date",
    "Views Count": "views_count",
    "Comments Count": "comments_count"
}

API_ENDPOINTS = {
    "ping": "metadata",
    "get-ip": "ip_addresses/{entity}",
    'get-hash': "files/{entity}",
    'get-comments': "{url_type}/{entity}/comments",
    'get-sigma-analysis': 'sigma_analyses/{entity}',
    "get-related-urls": "{url_prefix}/{entity}/relationships/{url_type}",
    "get-domain": "domains/{entity}",
    'get-url': "urls/{entity}",
    'urls': "urls",
    'analyses': "analyses/{analysis_id}",
    'search-graphs': 'graphs',
    'get-graph': 'graphs/{graph_id}',
    'file-upload-url': "files/upload_url",
    'get_file': 'files/{entity_hash}/download',
    'get_widget': 'widget/url',
    "get_ioc_details": "{url_prefix}/{ioc}",
    "submit_hash_analysis": "files/{hash}/analyse",
    "get_sandbox_data": "file_behaviours/{hash}_{sandbox}",
    "get_livehunt_notifications": "intelligence/hunting_notification_files?order=date%2B&filter=date:{start_timestamp}%2B",
    "add_vote_address": "ip_addresses/{identifier}/votes",
    "add_vote_url": "urls/{identifier}/votes",
    "add_vote_filehash": "files/{identifier}/votes",
    "add_vote_hostname": "domains/{identifier}/votes",
    "add_comment_address": "ip_addresses/{identifier}/comments",
    "add_comment_url": "urls/{identifier}/comments",
    "add_comment_filehash": "files/{identifier}/comments",
    "add_comment_hostname": "domains/{identifier}/comments",
}

ENTITY_MAPPER = {
    EntityTypes.FILEHASH: "file",
    EntityTypes.URL: "url",
    EntityTypes.ADDRESS: "ip_address",
    EntityTypes.HOSTNAME: "domain",
    EntityTypes.USER: "victim",
    EMAIL_TYPE: "email",
    EntityTypes.THREATACTOR: "actor",
    DOMAIN_TYPE: "domain"
}


class VirusTotalManager(object):
    """
    The method is used to init an object of VirusTotalManager class
    :param api_key: API key
    :param verify_ssl: Enable (True) or disable (False). If enabled, verify SSL certificate for the connection
    """
    def __init__(self, api_key, verify_ssl):
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        HEADERS.update({'x-apikey': self.api_key})
        self.session.headers.update(HEADERS)
        self.parser = VirusTotalParser()

    def test_connectivity(self):
        """
        Test Connectivity
        :return: {bool} Return true if successful else raise exception
        """
        response = self.session.get(self._get_full_url("ping"))
        self.validate_response(response)

        return True

    def get_ip_data(self, ip, show_entity_status=False):
        """
        Get IP data
        :param ip: {str} ip
        :param show_entity_status: {bool} Return error message for entity
        :return: {IP} instance
        """
        response = self.session.get(self._get_full_url('get-ip', entity=ip))
        self.validate_response(response, show_entity_status=show_entity_status)

        return self.parser.build_ip_object(response.json(), entity_type='ip-address', entity=ip)

    def check_analysis_status(self, analysis_id, get_data=False, show_entity_status=False):
        """
        Check analysis status
        :param analysis_id: {str} Analysis id
        :param get_data: {bool} get additional data from endpoint
        :param show_entity_status: {bool} Return error message for entity
        :return: {str} analysis id
        """
        response = self.session.get(self._get_full_url('analyses', analysis_id=analysis_id))
        self.validate_response(response, show_entity_status=show_entity_status)
        result = response.json()
        if get_data:
            return self.parser.get_analysis_status(result), self.parser.get_file_hash_from_analysis(result)

        return self.parser.get_analysis_status(result)

    def submit_url_for_analysis(self, url, show_entity_status=False):
        """
        Submit url for analysis
        :param url: {str} url
        :param show_entity_status: {bool} Return error message for entity
        :return: {str} analysis id
        """
        # Content-Type is not working for this endpoint, so we will remove it and then put it back
        del self.session.headers['Content-Type']
        response = self.session.post(self._get_full_url('urls'), data={"url": url})
        # Setting default value for Content-Type
        self.session.headers['Content-Type'] = HEADERS['Content-Type']
        self.validate_response(response, show_entity_status=show_entity_status)
        return self.parser.get_analysis_id(response.json())

    def get_url_data(self, url, show_entity_status=False):
        """
        Get URL data
        :param url: {str} url
        :param show_entity_status: {bool} Return error message for entity
        :return: {URL} instance
        """
        response = self.session.get(self._get_full_url('get-url', entity=url))
        self.validate_response(response, show_entity_status=show_entity_status)
        return self.parser.build_url_object(response.json(), entity_type='url', entity=url)

    def get_upload_url(self):
        """
        Get File Upload URL
        :return: {list} List of Graph instance
        """
        response = self.session.get(self._get_full_url('file-upload-url'))
        self.validate_response(response)

        return self.parser.get_upload_url(response.json())

    def get_analysis(self, url, file, file_bytes=None):
        """
        Get Analysis Id
        :param: {str} url for sending request
        :param: {str} submit file
        :return: {str}, {str} analysis id, file hash
        """
        # Content-Type is not working for this endpoint, so we will remove it and then put it back
        files = {"file": open(file, u'rb')} if not file_bytes else {"file": file_bytes}
        del self.session.headers['Content-Type']
        response = self.session.post(url, files=files)
        self.session.headers['Content-Type'] = HEADERS['Content-Type']
        self.validate_response(response)

        return self.parser.get_analysis_id(response.json())

    def get_hash_data(self, file_hash, report_link_suffix='file', show_entity_status=False):
        """
        Get Hash data
        :param file_hash: {str} hash
        :param report_link_suffix: {str} suffix for report link
        :param show_entity_status: {bool} Return error message for entity
        :return: {Hash} instance
        """
        response = self.session.get(self._get_full_url('get-hash', entity=file_hash))
        self.validate_response(response, show_entity_status=show_entity_status)

        return self.parser.build_hash_object(response.json(), entity_type=report_link_suffix, entity=file_hash)

    def get_livehunt_notifications(self, start_timestamp, limit, siemplify, existing_ids):
        """
        Get Livehunt notifications
        :param start_timestamp: {int} Start time to fetch results from
        :param limit: {int} Max number of notifications To return
        :param siemplify: (obj) An instance of the SDK SiemplifyConnectorExecution class
        :param existing_ids: {list} The list of existing ids.
        :return: {list} list of Notification objects
        """
        url = self._get_full_url('get_livehunt_notifications', start_timestamp=start_timestamp)
        params = {
            "count_limit": 10000
        }
        return self.paginate_connector_data(url=url, limit=limit, parser_method='build_notification_object',
                                            params=params, siemplify=siemplify, existing_ids=existing_ids)

    def get_comments(self, url_type, entity, limit, show_entity_status=False):
        """
        Get Comments for given entity
        :param url_type: {str} url part for ip_address, url or hash
        :param entity: {str} ip url or hash
        :param limit: {int} Max number of comments To return
        :param show_entity_status: {bool} Return error message for entity
        :return: {list} list of Comment instance
        """
        url = self._get_full_url('get-comments', url_type=url_type, entity=entity)
        return self.load_data_using_pagination(url=url, limit=limit, parser_method='get_comment',
                                               show_entity_status=show_entity_status)

    def get_widget(self, entity, show_entity_status=False, theme_colors=None):
        """
        Get Widget for given entity
        :param entity: {str} entity identifier
        :param show_entity_status: {bool} Return error message for entity
        :param theme_colors: {dict} theme colors dict to use for widget
        :return: {str}
        """
        url = self._get_full_url('get_widget')
        params = {"query": entity}
        if theme_colors:
            params.update(theme_colors)

        response = self.session.get(url, params=params)
        self.validate_response(response, show_entity_status=show_entity_status)
        response_json = response.json()
        widget_link = response_json.get('data', {}).get('url')
        if response_json.get('data', {}).get('found'):
            html_response = requests.get(widget_link, verify=self.verify_ssl, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                              'Chrome/46.0.2490.80 Safari/537.36',
                'Content-Type': 'text/html'
            })
            return widget_link, html_response.text
        return None, None

    def get_widget_link(self, entity, show_entity_status=False, theme_colors=None):
        """
        Get widget link for given entity
        :param entity: {str} entity identifier
        :param show_entity_status: {bool} return error message for entity
        :param theme_colors: {dict} theme colors dict to use for widget
        :return: {str} widget link
        """
        url = self._get_full_url("get_widget")
        params = {"query": entity}
        if theme_colors:
            params.update(theme_colors)

        response = self.session.get(url, params=params)
        self.validate_response(response, show_entity_status=show_entity_status)
        response_json = response.json()
        return response_json.get("data", {}).get("url") if response_json.get("data", {}).get("found") else None

    def get_related_items(self, url_id, entity, url_type, parser_method, limit=None):
        """
        Get related urls data
        :param url_id: {str} for entity type it can be files, ip_addresses or urls
        :param entity: {str} entity - ip, hash or url
        :param url_type: {str} end of url
        :param parser_method: parsers method for create relation model
        :param limit: {int} limit for results
        :return: {Relation} instance
        """
        url = self._get_full_url('get-related-urls', url_prefix=url_id, entity=entity, url_type=url_type)
        return self.load_data_using_pagination(url=url, limit=limit or PER_PAGE_ITEMS_COUNT, parser_method=parser_method)

    def load_data_using_pagination(self, url, limit, parser_method, params=None, show_entity_status=False):
        """
        Load data using pagination
        :param url: {str} Url for loading data
        :param limit: {int} Max number of items to return
        :param parser_method: {str} Parser method to convert json to model
        :param params: {dict} Parameters to send
        :param show_entity_status: {bool} Return error message for entity
        :return: {list} list of Comment instance
        """
        data = []
        response = None
        params = params or {}
        params['limit'] = min(limit, PER_PAGE_ITEMS_COUNT)
        while True:
            url = self.parser.get_next_page_url(response.json()) if response else url
            if len(data) >= limit or not url:
                break

            response = self.session.get(url, params=params)
            self.validate_response(response, show_entity_status=show_entity_status)
            data.extend(self.parser.build_results(response.json(), parser_method))

        return data[:limit]

    def paginate_connector_data(self, siemplify, existing_ids, url, limit, parser_method, params=None,
                                show_entity_status=False):
        """
        Load data using pagination
        :param siemplify: (obj) An instance of the SDK SiemplifyConnectorExecution class
        :param existing_ids: {list} The list of existing ids.
        :param url: {str} Url for loading data
        :param limit: {int} Max number of items to return
        :param parser_method: {str} Parser method to convert json to model
        :param params: {dict} Parameters to send
        :param show_entity_status: {bool} Return error message for entity
        :return: {list} list of Comment instance
        """
        data = []
        response = None
        params = params or {}
        params['limit'] = PER_PAGE_ITEMS_COUNT
        while True:
            url = self.parser.get_next_page_url(response.json()) if response else url
            if len(data) >= limit or not url:
                break

            params = {} if response else params
            response = self.session.get(url, params=params)
            self.validate_response(response, show_entity_status=show_entity_status)
            alerts = self.parser.build_results(response.json(), parser_method)
            filtered_alerts = filter_old_alerts(siemplify, alerts, existing_ids, "id")
            data.extend(filtered_alerts)

        return data[:limit]

    def get_sigma_analysis(self, file_hash):
        """
        Get Sigma Analysis for given entity
        :param file_hash: {str} hash
        :return: {SigmaAnalysis} instance
        """
        url = self._get_full_url('get-sigma-analysis', entity=file_hash)
        response = self.session.get(url)
        self.validate_response(response)

        return self.parser.build_analysis_object(response.json())

    def get_domain_data(self, domain, show_entity_status=False):
        """
        Get Domain data
        :param domain: {str} domain
        :param show_entity_status: {bool} Return error message for entity
        :return: {Domain} instance
        """
        response = self.session.get(self._get_full_url('get-domain', entity=domain))
        self.validate_response(response, show_entity_status=show_entity_status)

        return self.parser.build_domain_object(response.json(), entity_type='domain', entity=domain)

    def build_query(self, query_params, join_operator=QUERY_JOIN_PARAMETER):
        """
        Build Query
        :param query_params: {list} list of tuples, which contains key as query_param key and value e.g [(key, value)]
        :param join_operator: {str} operator for concat queries
        :return: {str} query
        """
        query = []
        for query_param in query_params:
            query.append('{key}:{value}'.format(key=ENTITY_MAPPER.get(query_param[0]), value=query_param[1]))

        return join_operator.join(query)

    def get_graph_details(self, query, order_by, limit):
        """
        Get Graph details for given query with given ordering
        :param query: {str} query param for getting graph details
        :param order_by: {str} order by param
        :param limit: {int} limit
        :return: {list} List of Graph instance
        """
        params = {
            "filter": query,
            "order": order_by,
            "limit": limit,
            "attributes": "graph_data"
        }
        url = self._get_full_url("search-graphs")

        return self.load_data_using_pagination(url=url, limit=limit, parser_method="get_graph", params=params)

    def get_graph(self, graph_id, limit):
        """
        Retrieve Graph with id
        :param graph_id: {str} graph id
        :param limit: {int} limit for graph's links
        :return: {Graph} instance
        """
        response = self.session.get(self._get_full_url('get-graph', graph_id=graph_id))
        self.validate_response(response)

        return self.parser.build_graph_object(raw_data=response.json(), limit_for_links=limit)

    @staticmethod
    def _get_full_url(url_id, **kwargs):
        """
        Get full url from url identifier.
        :param url_id: {str} The id of url
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        return urljoin(API_ROOT, API_ENDPOINTS[url_id].format(**kwargs))

    @staticmethod
    def validate_response(response, error_msg='An error occurred', show_entity_status=False):
        """
        Validate response
        :param response: {requests.Response} The response to validate
        :param error_msg: {str} Default message to display on error
        :param show_entity_status: {bool} Return error message for entity
        """
        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            try:
                error_message = response.json().get("error", {}).get("message", "")
            except Exception:
                error_message = ""

            if ERROR_RESPONSE_TEXTS.get("api_key_error") in error_message:
                raise VirusTotalInvalidApiKeyException("Invalid API key provided. Please check if it was copied "
                                                       "correctly.")

            if ERROR_RESPONSE_TEXTS.get("permission_error") in error_message:
                raise VirusTotalPermissionException("Your API key doesn't support this feature. Please upgrade it.")

            if response.status_code == NOT_FOUND_STATUS_CODE:
                if show_entity_status:
                    api_error = response.json().get("error", {})
                    raise VirusTotalNotFoundException(f'{api_error.get("code")}. {api_error.get("message")}')
                raise VirusTotalNotFoundException(error)
            if response.status_code == UNAUTHORIZED_STATUS_CODE:
                raise UnauthorizedException(error)
            if response.status_code == BAD_REQUEST:
                if show_entity_status:
                    api_error = response.json().get("error", {})
                    raise VirusTotalBadRequest(f'{api_error.get("code")}. {api_error.get("message")}')
                raise VirusTotalBadRequest(error)
            raise Exception(
                '{error_msg}: {error} {text}'.format(
                    error_msg=error_msg,
                    error=error,
                    text=error.response.content)
            )

        return True

    def get_file(self, entity_hash):
        """
        Function that downloads file based on hash
        :param entity_hash: {str} Hash
        :return: {str} Text of the response
        """
        
        response = self.session.get(self._get_full_url('get_file', entity_hash=entity_hash))
        self.validate_response(response)
        return response.text

    def get_ioc_details(self, url_prefix, ioc, parser_method):
        """
        Get ioc details
        :param url_prefix: {str} url prefix, for ioc type it can be files, urls, domain or ip_address
        :param ioc: {str} ioc
        :param parser_method: {str} parsers method name to create ioc object
        :return: {IOC} IOC object
        """
        url = self._get_full_url('get_ioc_details', url_prefix=url_prefix, ioc=ioc)
        response = self.session.get(url)
        self.validate_response(response)
        return getattr(self.parser, parser_method)(self.parser.extract_data_from_raw_data(response.json()))

    def submit_hash_for_analysis(self, hash, show_entity_status=False):
        """
        Submit hash for analysis
        :param hash: {str} hash
        :param show_entity_status: {bool} return error message for entity
        :return: {str} analysis id
        """
        response = self.session.post(self._get_full_url("submit_hash_analysis", hash=hash))
        self.validate_response(response, show_entity_status=show_entity_status)
        return self.parser.get_analysis_id(response.json())

    def get_sandbox_data(self, hash, sandbox, show_entity_status=False):
        """
        Get sandbox data
        :param hash: {str} hash
        :param sandbox: {str} sandbox name
        :param show_entity_status: {bool} return error message for entity
        :return: {Sandbox} Sandbox object
        """
        response = self.session.get(self._get_full_url("get_sandbox_data", hash=hash, sandbox=sandbox))
        self.validate_response(response, show_entity_status=show_entity_status)
        return self.parser.build_sandbox_object(self.parser.extract_data_from_raw_data(response.json()))

    def add_vote_to_entity(self, entity: Any, vote: str):
        """
        Add vote to entity
        Args:
            entity: Siemplify entity
            vote: str
        return:
            Bool(True/False)
        """
        identifier = prepare_entity_for_manager(entity)

        if entity.entity_type == EntityTypes.ADDRESS:
            url = self._get_full_url("add_vote_address", identifier=identifier)
        elif entity.entity_type == EntityTypes.FILEHASH:
            url = self._get_full_url("add_vote_filehash", identifier=identifier)
        elif entity.entity_type == EntityTypes.URL:
            url = self._get_full_url("add_vote_url", identifier=identifier)
        elif entity.entity_type == EntityTypes.HOSTNAME:
            url = self._get_full_url("add_vote_hostname", identifier=identifier)
        else:
            raise VirusTotalException("Not supported entity type")

        payload = {
            "data": {
                "type": "vote",
                "attributes": {
                    "verdict": vote.lower()
                }
            }
        }
        response = self.session.post(url=url, json=payload)
        if response.status_code == 409:  # Action returns 409 when duplicate entries(considered as success)
            return True
        self.validate_response(response)
        return True

    def add_comment_to_entity(self, entity: Any, comment: str):
        """
        Add vote to entity
        Args:
            entity: Siemplify entity
            comment: comment to add to entities
        return:
            Bool(True/False)
        """
        identifier = prepare_entity_for_manager(entity)

        if entity.entity_type == EntityTypes.ADDRESS:
            url = self._get_full_url("add_comment_address", identifier=identifier)
        elif entity.entity_type == EntityTypes.FILEHASH:
            url = self._get_full_url("add_comment_filehash", identifier=identifier)
        elif entity.entity_type == EntityTypes.URL:
            url = self._get_full_url("add_comment_url", identifier=identifier)
        elif entity.entity_type == EntityTypes.HOSTNAME:
            url = self._get_full_url("add_comment_hostname", identifier=identifier)
        else:
            raise VirusTotalException("Not supported entity type")

        payload = {
            "data": {
                "type": "comment",
                "attributes": {
                    "text": comment
                }
            }
        }
        response = self.session.post(url=url, json=payload)
        if response.status_code == 409:  # duplicate entries considered as success
            return True
        self.validate_response(response)
