# ==============================================================================
# title           :ElasticseasrchManager.py
# description     :This Module contain all Elastic search functionality
# author          :danield@siemplify.co
# date            :1-3-18
# python_version  :2.7
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan
from elasticsearch_dsl import Search, Q, connections
import json
import base64

DEFAULT_TIMEOUT = 600
# =====================================
#            Json payloads            #
# =====================================
# This json represent an example for the the payload, values will be overridden in the real request
ELASTICSEARCH_QUERY_JSON = {
    "from": 0,
    "query": {
        "bool": {
            "must": [{
                "query_string": {
                    "query": "*"
                }},
                {"range": {
                    "@timestamp": {
                        "gt": "now-1d",
                        "lt": "now"
                    }
                }
                }],
            "must_not": [],
            "should": []
        }
    }
}

# =====================================
#             CONSTANTS               #
# =====================================
ES_INDEX = "*"
ES_QUERY = "*"
DISPLAYFIELD = "*"
SEARCHFIELD = "*"
DSL_INDEX="_all"
OLDESTDATE = "1970-01-01T00:00:00"
EARLIESTDATE = "now"
TIMESTAMPFIELD = "@timestamp"
RESULT_LIMIT = 10
CA_CERTIFICATE_FILE_PATH = "cacert.pem"

# =====================================
#              CLASSES                #
# =====================================


class ElasticsearchManagerError(Exception):
    """
    General Exception for Elastic search manager
    """
    pass


class ElasticsearchManager(object):
    """
    Responsible for all Elastic search operations functionality
    """

    def __init__(self, server, username=None, password=None, verify_ssl=False, api_token=None, authenticate=None, ca_certificate_file=None):
        self.server = server
        ca_certs = False if not verify_ssl else None
        
        #ca_certificate is base64 string which needs to be decoded and a temp file for the cacert is created
        if ca_certificate_file:
            try:
                file_content = base64.b64decode(ca_certificate_file)
                with open(CA_CERTIFICATE_FILE_PATH,"w+") as f:
                        f.write(file_content.decode("utf-8"))
                        
            except Exception as e:
                raise ElasticsearchManagerError(e)
             
        if verify_ssl and ca_certificate_file:
            ca_certs = CA_CERTIFICATE_FILE_PATH
        
        if authenticate and not username and not password and not api_token:
            raise ElasticsearchManagerError('Please specify username and password or API token.')

        if api_token:
            self.es = Elasticsearch([self.server],
                                    api_key=(api_token),
                                    ca_certs=ca_certs,
                                    verify_certs=verify_ssl,
                                    timeout=DEFAULT_TIMEOUT)
        elif username and password:
            self.es = Elasticsearch([self.server],
                                    http_auth=(username, password),
                                    ca_certs=ca_certs,
                                    verify_certs=verify_ssl,
                                    timeout=DEFAULT_TIMEOUT)
        else:
            self.es = Elasticsearch([self.server], verify_certs=verify_ssl, ca_certs=ca_certs, timeout=DEFAULT_TIMEOUT)

    def test_connectivity(self):
        """
        Tests connectivity to Elasticsearch
        :return: bool
        """
        self.es.info()
        return True

    def advanced_es_search(self, **kwargs):
        """
        Gives the ability to run a query with specific paramaters
        :param index: {string} Index name to search
        :param default_field: {string} Default field for querying terms
        :param query: {string} Lucene query string syntax
        :param oldestDate: {string} Start date of search
        :param earliestDate: {string} End date of search
        :param limit: {int} Number of results to return
        :param displayField: {string} Returned fields
        :param existing_ids: {list} List of existing ids to filter by
        :return results: {list} List of results (list of dicts)
        :return status: {bool} Status of search that was executed
        :return total_hits: {int} Number of results returned
        """
        s_index = kwargs.get('Index', ES_INDEX)
        s_query = kwargs.get('Query', ES_QUERY)
        display_field = kwargs.get('Display Field', DISPLAYFIELD)
        search_field = kwargs.get('Search Field', SEARCHFIELD)
        timestamp_field = kwargs.get('Timestamp Field', TIMESTAMPFIELD)
        oldest_date_compare_type = kwargs.get("Oldest Date Compare Type", "gt")
        eariest_date_compare_type = kwargs.get("Earliest Date Compare Type", "lt")
        oldest_date = kwargs.get('Oldest Date')
        earliest_date = kwargs.get('Earliest Date')
        limit = kwargs.get('Limit')
        existing_ids = kwargs.get('Existing IDs', [])

        s = Search(using=self.es, index=s_index) \
            .query("query_string", default_field=search_field, query=s_query)

        if oldest_date and earliest_date:
            # Both were passed
            s = s.query(Q('range', **{
                timestamp_field: {oldest_date_compare_type: oldest_date, eariest_date_compare_type: earliest_date}}))

        elif oldest_date:
            # Only oldest date was passed
            s = s.query(Q('range', **{
                timestamp_field: {oldest_date_compare_type: oldest_date}}))

        elif earliest_date:
            # Only earliest date was passed
            s = s.query(Q('range', **{
                timestamp_field: {eariest_date_compare_type: earliest_date}}))

        # Sort according to timestamp field
        s = s.sort(timestamp_field)

        if existing_ids:
            s = s.exclude('ids', values=existing_ids)

        s = s.source(display_field)

        if limit:
            s = s.extra(from_=0, size=limit)
        else:
            s = s.extra(from_=0, size=s.count())

        response = s.execute()
        status = response.success()
        total_hits = response.hits.total
        results = response.to_dict()

        return results['hits']['hits'], status, total_hits

    def simple_es_search(self, s_index=ES_INDEX, query=ES_QUERY,
                         limit=None):
        """
        Gives you the ability to run a lucene formated query.
        :param s_index: {string} Index name to search
        :param query: {string} Lucene query string syntax
        :return results: {list} List of results (list of dicts)
        :return status: {bool} Status of search that was executed
        :return total_hits: {int} Number of results returned
        """

        if s_index is None:
            s_index = ES_INDEX

        if query is None:
            query = ES_QUERY

        s = Search(using=self.es, index=s_index).query("query_string", query=query)

        if limit:
            s = s.extra(from_=0, size=limit)
        else:
            s = s.extra(from_=0, size=s.count())

        response = s.execute()
        status = response.success()
        total_hits = response.hits.total
        results = response.to_dict()

        return results['hits']['hits'], status, total_hits

    def dsl_search(self, indices=DSL_INDEX, query=None, limit=10):
        """
        runs DSL query search
        :param indices:  Index name to search
        :param query: DSL Query
        :param limit: The limit of search count
        :return: List of results (list of dicts) and number of total results
        """
        if query == ES_QUERY:
            query = ELASTICSEARCH_QUERY_JSON.copy()
        else:
            try:
                query = json.loads(query)
            except Exception as e:
                raise ElasticsearchManagerError(e)

            query = {"query": query}
        result = self.es.search(index=indices, size=limit, body=query)
        hits = result.get("hits", {}).get("hits", [])
        total_hits = result.get("hits", {}).get("total", {})
        return hits, total_hits