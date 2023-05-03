# Imports
from passivetotal.libs.dns import DnsRequest
from passivetotal.libs.whois import WhoisRequest
from urlparse import urlparse

ADDRESS = "api.passivetotal.org"
SOURCES = "riskiq"
WHOIS_PREFIX = "WH_"


# Classes
class PassiveTotal(object):

    def __init__(self, **kwargs):
        """
        :param self:
        :param kwargs:
        :return: Initialize
        """
        self.__user = kwargs.pop("user", None)
        self.__key = kwargs.pop("key", None)
        self.__server_address = ADDRESS
        self.__sources = SOURCES

    @staticmethod
    def dns_report_to_csv(report_dict):
        """
        :param report_dict: DNS report dict.
        :return: CSV format output. ['header, header' , 'val, val']
        """
        csv_output = ['Address, Record Hash, Last Seen, Collected, First Seen']

        if 'results' in report_dict.keys():
            for result in report_dict['results']:
                csv_output.append("{0}, {1}, {2}, {3}, {4}".format(str(result.get('resolve')).replace(',', ' '),
                                                                   str(result.get('recordHash')).replace(',', ' '),
                                                                   str(result.get('lastSeen')).replace(',', ' '),
                                                                   str(result.get('collected')).replace(',', ' '),
                                                                   str(result.get('firstSeen')).replace(',', ' ')))
            return csv_output

    @staticmethod
    def dns_report_to_dict(report_dict):
        """
        :param report_dict: DNS report dict.
        :return: Key, Value format output.
        """
        dict_output = {}
        if 'results' in report_dict.keys():
            for index, result in enumerate(report_dict['results']):
                dict_output["{0}{1}".format(WHOIS_PREFIX, "dns_resolve_{}".format(index+1))] = str(result['resolve'])
            return dict_output

    def get_dns_report(self, query_param):
        """
        :param query_param:
        :return: Raw JSON
        """
        client = DnsRequest(self.__user, self.__key, server=self.__server_address)
        res = client.get_passive_dns(query=query_param, sources=self.__sources)
        return res

    def get_whois_report(self, query_param):
        """
        :param query_param:
        :return: Raw JSON
        """
        client = WhoisRequest(self.__user, self.__key, server=self.__server_address)
        res = client.get_whois_details(query=query_param)
        return res

    @staticmethod
    def whois_report_to_csv(whois_report):
        """
        :param whois_report: {dict} Whois report dict.
        :return: CSV format output. ['header, header' , 'val, val']
        """
        csv_output = ['Property, Value']
        # Extract flat values.
        for key, val in whois_report.iteritems():
            if type(val) is unicode:
                csv_output.append("{0}, {1}".format(str(key), str(val).replace(',', ' ')))
        # Extract nested values.
        if 'registrant' in whois_report.keys():
            for key, val in whois_report['registrant'].iteritems():
                if type(val) is unicode:
                    csv_output.append("{0}, {1}".format(str(key), str(val).replace(',', ' ')))
        else:
            if 'admin' in whois_report.keys():
                for key, val in whois_report['admin'].iteritems():
                    if type(val) is unicode:
                        csv_output.append("{0}, {1}".format(str(key), str(val).replace(',', ' ')))
        return csv_output

    @staticmethod
    def whois_report_to_dict(whois_report):
        """
        :param whois_report: {dict} Whois report dict.
        :return: Key, Value format output.
        """
        dict_output = {}
        # Extract flat values.
        for key, val in whois_report.iteritems():
            if type(val) is unicode:
                dict_output[key] = val
        # Extract nested values.
        if 'registrant' in whois_report.keys():
            for key, val in whois_report['registrant'].iteritems():
                if type(val) is unicode:
                    dict_output[WHOIS_PREFIX + key] = str(val)
        else:
            # Fallback for 'registrant' key
            if 'admin' in whois_report.keys():
                for key, val in whois_report['admin'].iteritems():
                    if type(val) is unicode:
                        dict_output[key] = str(val)
        return dict_output



