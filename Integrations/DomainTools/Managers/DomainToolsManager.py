# ==============================================================================
# title           :DomainToolsManagers.py
# description     :This Module contain all DomainTools cloud operations functionality
# author          :nikolay.ryagin@gmail.com
# date            :12-29-17
# python_version  :2.7
# libraries       : -
# requirements    :
# product_version : 1.0
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================
import json
import re
from domaintools import API
import urlparse

# =====================================
#             CONSTANTS               #
# =====================================


# =====================================
#              CLASSES                #
# =====================================
class DomainToolsManagerError(Exception):
    """
    General Exception for DomainTools manager
    """
    pass


class DomainToolsManager(object):
    """
    Responsible for all DomainTools system operations functionality
    """

    def __init__(self, username, apiKey, https=True, verify_ssl=True, rate_limit=True):
        """
        Define an instance of DT Manager.
        :param username: 
        :param apiKey: 
        :param https: False to disable HTTP instead of HTTPS
        :param verify_ssl: False to disable the certificate checking.
        :param rate_limit: False to disable Rate Limit.
        """

        self._api = API(username, apiKey, https, verify_ssl, rate_limit)
        self.listProduct = self._getAccountInfo()


    def _clearResults(self, response):
        """
        Clear response from extra symbols.
        :param response: 
        :return: string
        """

        response = str(response.json)

        for x in ['\n', '    ']:
            response = response.replace(x, '')

        data = json.loads(response)[u'response']
        return data

    def _validIP4(self, ip):
        """
        Check whether or not input value is ip address.
        :param ip: any value to be checked.
        :return: Bool Value
        """
        m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
        return bool(m) and all(map(lambda n: 0 <= int(n) <= 255, m.groups()))

    def _getAccountInfo(self):
        """
        Method helps to define what sort of REST API call you're able to do.
        :return: the list of available of the methods.
        """

        response = self._api.account_information()
        data = self._clearResults(response)

        products = data[u'products']
        list = []

        for x in products:
            list.append(x['id'])
        return list

    def _checkLicense(self, productName):
        """
        Method is being used to check available products for user account.
        :param productName: 
        :return: 
        """

        if productName not in self.listProduct: raise DomainToolsManagerError(
            'You don\'t have {} in your license.'.format(productName))

    def extract_domain_from_string(self, string):
        """
        Extract domain from url or mail address
        :param string: url or mail address
        :return: {string} the domain string
        """
        # Case sensitive
        string = string.lower()
        # Incase of email address
        if '@' in string:
            return string.split('@')[-1]
        elif string.startswith("www"):
            return string.split('www.')[-1]
        # Incase of Url
        return urlparse.urlparse(string).netloc or string

    def getDomainProfile(self, domain):
        """
        Get domain profile
        :param domain: {string}
        :return: {dict}
        """

        productName = 'domain-profile'
        self._checkLicense(productName)

        try:
            response = self._api.domain_profile(domain)
            return self._clearResults(response)

        except:
            return None

    def getDomainRisk(self, domain):
        """
        Get domain risk
        :param domain: {string}
        :return: {string/dict}
        """

        productName = 'reputation'
        self._checkLicense(productName)

        try:
            response = self._api.reputation(domain)
            data = self._clearResults(response)
            return str(data[u'risk_score'])

        except:
            return None

    def getHostingHistory(self, domain):
        """
        Get hosting history
        :param domain: {string}
        :return: {dict}
        """

        productName = 'hosting-history'
        self._checkLicense(productName)

        try:
            response = self._api.hosting_history(domain)
            return self._clearResults(response)

        except:
            return None

    def getDomainsByEmail(self, emailAddress):
        """
        Find domains with an email in their Whois record
        :param emailAddress: {string}
        :return: {list of strings} domains
        """

        productName = 'iris'
        self._checkLicense(productName)

        try:
            response = self._api.iris(email=emailAddress)
            data = self._clearResults(response)

            return data

        except:
            return None

    def getDomainsByIp(self, ipAddress):
        """
        Find domain names that share an IP
        :param ipAddress: {stirng}
        :return: {list of strings} domains
        """

        productName = 'iris'
        self._checkLicense(productName)

        try:
            response = self._api.iris(ip=ipAddress)
            data = self._clearResults(response)

            return data

        except:
            return None

    def enrichDomain(self, domain):
        """
        Enrich external domain or IP with DomainTools reverse DNS data
        :param domain: {string}
        :return: {dict} enrichment data
        """

        productName = 'reverse-ip'
        self._checkLicense(productName)

        try:
            if self._validIP4(domain):
                response = self._api.host_domains(domain)
            else:
                response = self._api.reverse_ip(domain)

            data = self._clearResults(response)

            return data

        except:
            return None

    def getIpByDomain(self, domain):
        """
        Find IPs that point to this domain
        :param domain: {string}
        :return: {list of strings} ip address
        """

        productName = 'iris'
        self._checkLicense(productName)

        try:
            response = self._api.iris(domain=domain)
            data = self._clearResults(response)
            return data

        except:
            return None

    def getRecentDomainsByStringQuery(self, stringQuery):
        """
        Search for new domains containing a word
        :param string_query: {string} The text to look for
        :return: {list of strings} domains
        """

        productName = 'phisheye'
        self._checkLicense(productName)

        try:
            response = self._api.phisheye(stringQuery)
            data = self._clearResults(response)
            return data

        except:
            return None


