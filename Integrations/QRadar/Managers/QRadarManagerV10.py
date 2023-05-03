import requests
import json
import copy
import datetime
import time
import urllib.error
import urllib.parse
import urllib.request

from QRadarManager import QRadarManager
from QRadarParser import QRadarParser
from constants import OFFENSES_STATUS_OPEN, MIN_PAGE_SIZE, PAGE_SIZE
from exceptions import QRadarApiError, QRadarRequestError
from TIPCommon import string_to_multi_value, is_approaching_timeout, TIMEOUT_THRESHOLD


# CONSTANTS
OFFENSE_FIELDS = [
    "id",
    "description",
    "categories",
    "magnitude",
    "domain_id",
    "last_updated_time",
    "start_time",
    "event_count",
    "log_sources(id)",
    "rules(id)"
]

EVENT_FIELDS_QUERY = "SELECT \"CRE Name\" AS CREName,\"CRE Description\" AS CREDescription, QIDNAME(qid) AS \"EventName\"," \
                     "QIDDESCRIPTION(qid) AS \"EventDescription\", RuleName(creEventList), partialmatchlist, qid, category," \
                     "AssetHostname(sourceIP, startTime) AS \"sourceHostname\", AssetHostname(destinationIP, startTime) AS" \
                     "\"destinationHostname\", creEventList, credibility, destinationMAC, destinationIP, destinationPort," \
                     " destinationv6, deviceTime, LogSourceTypeName(deviceType) As \"deviceProduct\", domainID, duration, endTime," \
                     "eventCount, eventDirection, processorId, hasIdentity, hasOffense, highLevelCategory, isCREEvent, magnitude, UTF8(payload)," \
                     "postNatDestinationIP, postNatDestinationPort, postNatSourceIP, postNatSourcePort, preNatDestinationIP, preNatDestinationPort," \
                     "preNatSourceIP, preNatSourcePort, ProtocolName(protocolID) AS \"protocolName\", protocolID, relevance," \
                     " severity, sourceIP, sourceMAC, sourcePort, sourcev6, startTime, isunparsed, userName {custom_fields}" \
                     " FROM events WHERE {log_source_ids} (creEventlist IN ({rules_ids}) OR partialmatchlist IN ({rules_ids}))" \
                     "AND INOFFENSE({offense_id}) LAST {max_days} DAYS"

EVENT_FIELDS_QUERY_WITH_LIMIT = "SELECT \"CRE Name\" AS CREName,\"CRE Description\" AS CREDescription, QIDNAME(qid) AS \"EventName\"," \
                                "QIDDESCRIPTION(qid) AS \"EventDescription\", RuleName(creEventList), partialmatchlist, qid, category," \
                                "AssetHostname(sourceIP, startTime) AS \"sourceHostname\", AssetHostname(destinationIP, startTime) AS" \
                                "\"destinationHostname\", creEventList, credibility, destinationMAC, destinationIP, destinationPort," \
                                " destinationv6, deviceTime, LogSourceTypeName(deviceType) As \"deviceProduct\", domainID, duration, endTime," \
                                "eventCount, eventDirection, processorId, hasIdentity, hasOffense, highLevelCategory, isCREEvent, magnitude, UTF8(payload)," \
                                "postNatDestinationIP, postNatDestinationPort, postNatSourceIP, postNatSourcePort, preNatDestinationIP, preNatDestinationPort," \
                                "preNatSourceIP, preNatSourcePort, ProtocolName(protocolID) AS \"protocolName\", protocolID, relevance," \
                                " severity, sourceIP, sourceMAC, sourcePort, sourcev6, startTime, isunparsed, userName {custom_fields}" \
                                " FROM events WHERE {log_source_ids} (creEventlist IN ({rules_ids}) OR partialmatchlist IN ({rules_ids}))" \
                                "AND INOFFENSE({offense_id}) LIMIT {total_limit_of_events_per_limit} LAST {max_days} DAYS"

EVENT_FIELDS_QUERY_WITH_LIMIT_AND_ORDERING = "SELECT \"CRE Name\" AS CREName,\"CRE Description\" AS CREDescription, QIDNAME(qid) AS \"EventName\"," \
                                             "QIDDESCRIPTION(qid) AS \"EventDescription\", RuleName(creEventList), partialmatchlist, qid, category," \
                                             "AssetHostname(sourceIP, startTime) AS \"sourceHostname\", AssetHostname(destinationIP, startTime) AS" \
                                             "\"destinationHostname\", creEventList, credibility, destinationMAC, destinationIP, destinationPort," \
                                             " destinationv6, deviceTime, LogSourceTypeName(deviceType) As \"deviceProduct\", domainID, duration, endTime," \
                                             "eventCount, eventDirection, processorId, hasIdentity, hasOffense, highLevelCategory, isCREEvent, magnitude, UTF8(payload)," \
                                             "postNatDestinationIP, postNatDestinationPort, postNatSourceIP, postNatSourcePort, preNatDestinationIP, preNatDestinationPort," \
                                             "preNatSourceIP, preNatSourcePort, ProtocolName(protocolID) AS \"protocolName\", protocolID, relevance," \
                                             " severity, sourceIP, sourceMAC, sourcePort, sourcev6, startTime, isunparsed, userName {custom_fields}" \
                                             " FROM events WHERE {log_source_ids} (creEventlist IN ({rules_ids}) OR partialmatchlist IN ({rules_ids}))" \
                                             "AND INOFFENSE({offense_id}) ORDER BY {order_by_key} {sort_order} LIMIT {total_limit_of_events_per_limit} LAST {max_days} DAYS"


class QRadarV10Manager(QRadarManager):
    """
    Responsible for all QRadar Web Service API functionality
    """
    OFFENSE_URL = "api/siem/offenses/{0}"
    GET_SEARCH_RESULTS_URL = "api/ariel/searches/{0}/results"  # {0} - Search result ID.
    GET_SEARCH_URL = "api/ariel/searches/{0}"  # {0} - Search result ID.
    QUERY_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S %p"
    PAGE_SIZE = 100

    def __init__(self, api_root, api_token, api_version=None, is_ssl=False, logger=None):
        super(QRadarV10Manager, self).__init__(api_root, api_token, api_version, is_ssl)
        self.parser = QRadarParser()
        self.logger = logger

    def get_updated_offenses_from_time(self, timestamp_unix_time, status=OFFENSES_STATUS_OPEN, fields=None,
                                       domain_ids=None, magnitude_filter=None, connector_starting_time = None,
                                       python_process_timeout = None):
        """
        Retrieve updated offenses since unix time.
        :param timestamp_unix_time: {num} get updated offenses since time stamp
        :param status: the status of the offenses to fetch {string}
        :param fields: {list} List of offenses fields to retrieve
        :param domain_ids: {[int]} List of domain ids to filter offenses by
        :param magnitude_filter: {int} offenses with the magnitude equal or bigger than provided will be ingested to
            Siemplify.
        :param connector_starting_time: {int} connector starting time unix
        :param python_process_timeout: {int} python process timeout in seconds
        :return: list of dicts when each dict represent an offense {list}
        """
        fields = fields or OFFENSE_FIELDS
        domains_cache = {}
        offenses = []

        filter = "last_updated_time>={} AND status = \"{}\"".format(timestamp_unix_time, status)
        if domain_ids:
            filter += " AND domain_id in ({})".format(','.join(str(domain_id) for domain_id in domain_ids))
        if magnitude_filter:
            filter += " AND magnitude >= {}".format(magnitude_filter)

        fetched_offenses = self.get_offenses_by_filter(filter=filter, sort='+last_updated_time', fields=fields)

        for offense in fetched_offenses:
            # The timeout threshold here is lower than in actual connector, we need to leave at least a little room
            # for actual processing for connector to not get stuck here forever
            check_timeout = python_process_timeout and connector_starting_time
            if check_timeout and is_approaching_timeout(connector_starting_time, python_process_timeout, TIMEOUT_THRESHOLD*0.9):
                self.logger.info("Timeout is approaching. Connector will gracefully exit.")
                break

            domain_id = offense.domain_id

            if domain_id and domain_id in domains_cache:
                offense.domain_name = domains_cache[domain_id]
            elif domain_id:
                domain_name = self.get_domain_name_by_id(offense.domain_id)
                offense.domain_name = domain_name
                domains_cache[domain_id] = domain_name

            offenses.append(offense)

        return offenses

    def list_rules(self):
        """
        Retrieve a list of all rules
        :return: {[Rule]} List of all found rules
        """
        start_index = 0
        last_index = PAGE_SIZE
        pagination_value = PAGE_SIZE

        self.session.headers.update({"Range": "items={}-{}".format(start_index, last_index)})
        response = self.session.get(self._get_full_url('rules'))
        self.validate_response(response)
        rules = []

        while response.json():
            if isinstance(response.json(), list):
                rules.extend(self.parser.build_results(response.json(), 'build_siemplify_rule_object'))

            start_index += last_index - start_index
            last_index += pagination_value
            self.session.headers.update({"Range": "items={}-{}".format(start_index + 1, last_index)})
            try:
                response = self.session.get(self._get_full_url('rules'))
                self.validate_response(response)
            except QRadarRequestError as error:
                if pagination_value - 1 <= MIN_PAGE_SIZE:
                    break
                last_index -= pagination_value

                if pagination_value < 10:
                    pagination_value = MIN_PAGE_SIZE + 1
                else:
                    pagination_value = int(pagination_value / 10)

        del self.session.headers['Range']
        return rules

    def get_events_by_offense_id(self, offense_id, log_source_ids, rules_ids, events_period_padding=1, limit=None,
                                 existing_events_hashes=[], custom_fields=None, page_size=PAGE_SIZE,
                                 total_limit_of_events_per_offense=None, order_by_key=None,
                                 sort_order=None):
        """
        Get events for offense for time.
        :param offense_id: offense id {string}
        :param custom_fields: events custom fields {string}
        :param log_source_ids: Filter events by log sources they belong to {list}
        :param rules_ids: Filter events by rules that triggered them {list} ()
        :param events_period_padding: Events search period padding (to fetch events from last {events_period_padding} days)
        :param limit: Max amount of events to return {int}.
        :param existing_events_hashes: List of events' hashes to filter out {list}.
        :param page_size: {int} page size
        :param total_limit_of_events_per_offense: {int} Specify how many events per Qradar offense should be ingested in total by connector, after reaching that limit  new events will not be ingested for the offense.
        :param order_by_key: {str} key to use for results ordering
        :param sort_order: {str} sort order for results
        :return: Result dict when each key will be a rule and the events that contain its rule {dict} -
                Example: {"rule1":[{event1}, {event2}]}
        """
        # If there is custom fields add comma at the query before the fields.
        if custom_fields:
            # Warp all custom fields with quotes.
            custom_fields = string_to_multi_value(custom_fields)
            custom_fields = ', {0}'.format(",".join(['"{0}"'.format(field) for field in custom_fields]))
        else:
            custom_fields = ""

        if total_limit_of_events_per_offense and order_by_key and sort_order:
            query = EVENT_FIELDS_QUERY_WITH_LIMIT_AND_ORDERING.format(
                offense_id=offense_id,
                custom_fields=custom_fields,
                log_source_ids="logsourceid IN ({}) AND ".format(",".join(log_source_ids)) if log_source_ids else "",
                rules_ids=",".join([str(rule_id) for rule_id in rules_ids]),
                max_days=events_period_padding,
                total_limit_of_events_per_limit=total_limit_of_events_per_offense,
                order_by_key=order_by_key,
                sort_order=sort_order)
        elif total_limit_of_events_per_offense:
            query = EVENT_FIELDS_QUERY_WITH_LIMIT.format(
                offense_id=offense_id,
                custom_fields=custom_fields,
                log_source_ids="logsourceid IN ({}) AND ".format(",".join(log_source_ids)) if log_source_ids else "",
                rules_ids=",".join([str(rule_id) for rule_id in rules_ids]),
                max_days=events_period_padding,
                total_limit_of_events_per_limit=total_limit_of_events_per_offense)
        else:
            query = EVENT_FIELDS_QUERY.format(
                offense_id=offense_id,
                custom_fields=custom_fields,
                log_source_ids="logsourceid IN ({}) AND ".format(",".join(log_source_ids)) if log_source_ids else "",
                rules_ids=",".join([str(rule_id) for rule_id in rules_ids]),
                max_days=events_period_padding)

        if self.logger:
            self.logger.debug("Initiated events search query.")
        query_result_id = self.run_query(query)

        # Fetch query result.
        return self.get_events_search_results(query_result_id, limit=limit,
                                              existing_events_hashes=existing_events_hashes,
                                              page_size=page_size)

    def get_total_results_count(self, query_result_id):
        request_url = urllib.parse.urljoin(self.api_root, self.GET_SEARCH_URL.format(query_result_id))
        response = self.session.get(request_url)
        self.validate_response(response)
        return response.json().get("record_count", 0)

    def get_events_search_results(self, query_result_id, time_out_in_seconds=None, limit=None,
                                  existing_events_hashes=tuple(),
                                  page_size=PAGE_SIZE):
        """
        Retrieves events from QRadar.
        :param query_result_id: {string} Search ID in QRadar.
        :param time_out_in_seconds: time out in seconds {string}.
        :param limit: Max amount of events to return {int}.
        :param page_size: The size of the pages {int}.
        :param existing_events_hashes: List of events' hashes to filter out {list}.
        :return: {[Event]} List of found events
        """
        # Fetch results.
        while not self.is_search_completed(query_result_id):
            time.sleep(1)
            if time_out_in_seconds:
                timeout_time = datetime.datetime.now() + datetime.timedelta(seconds=time_out_in_seconds)
                if datetime.datetime.now() >= timeout_time:
                    raise QRadarApiError('Timeout fetching events for query id: {0}'.format(query_result_id))

        if self.logger:
            self.logger.debug("Event search query has completed.")

        total_results_count = self.get_total_results_count(query_result_id)

        if self.logger:
            self.logger.debug("Total query results: {}".format(total_results_count))

        page_size = page_size if page_size - 1 > MIN_PAGE_SIZE else self.PAGE_SIZE

        start_index = 0
        end_index = page_size - 1

        events = self.get_events_by_range(query_result_id, start_index, end_index)
        filtered_events = set(
            event for event in events
            if event.as_hash()
            not in existing_events_hashes
        )

        while len(events) < total_results_count:
            if len(filtered_events) >= limit:
                break

            start_index = start_index + page_size
            end_index = end_index + page_size

            more_events = self.get_events_by_range(query_result_id, start_index, end_index)
            events.extend(more_events)
            filtered_events.update([
                event for event in more_events
                if event.as_hash()
                not in existing_events_hashes
            ])

        filtered_events = sorted(filtered_events, key=lambda event: event.start_time, reverse=True)
        return filtered_events[:limit] if limit else filtered_events

    def get_events_by_range(self, query_result_id, start_index=0, end_index=49):
        """
        Retrieves events by range from a given search query.
        :param query_result_id: {string} Search ID in QRadar.
        :param start_index: The start index of the range {int}.
        :param end_index: The end index of the range {int}.
        :return: {list} instance of Event objects
        """
        headers = {
            "Range": "items={}-{}".format(start_index, end_index)
        }
        self.session.headers.update(headers)

        response = self.session.get(self._get_full_url('get_search_results_url', search_id=query_result_id))
        del self.session.headers["Range"]
        self.validate_response(response)

        return self.parser.build_siemplify_event_object_list(response.json())
