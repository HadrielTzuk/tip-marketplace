# ============================================================================#
# title           :ProtectwiseManager.py
# description     :This Module contain all Protectwise operations functionality
# author          :avital@siemplify.co
# date            :22-02-2018
# python_version  :2.7
# libreries       : requests
# requirments     :
# product_version :1.0
# ============================================================================#

# ============================= IMPORTS ===================================== #

import requests

# ============================== CONSTS ===================================== #

API_ROOT = r"https://api.protectwise.com/api/v1"
FIELDS = ["threat", "ip", "geo"]

# ============================= CLASSES ===================================== #


class ProtectwiseManagerError(Exception):
    """
    General Exception for Protectwise manager
    """
    pass


class ProtectwiseManager(object):
    def __init__(self, email, password):
        """
        Connect to Protectwise
        """
        try:
            url = "{0}/token".format(API_ROOT)

            response = requests.post(
                url=url,
                data={
                    "email": email,
                    "password": password
                })

            response.raise_for_status()
            token = response.json()['token']

            self.headers = {
                'X-Access-Token': token,
                'Content-Type': 'application/json'
            }

        except requests.HTTPError as error:
            raise ProtectwiseManagerError(
                error.response.json()['error']['info'])

        except Exception as error:
            raise ProtectwiseManagerError(
                "Unable to connect to Protectwise: {error} {text}".format(
                    error=error,
                    text=error.message)
            )

    def get_ip_reputation(self, ip, start_time, end_time):
        """
        Get reputation for an ip
        :param ip: The ip
        :param start_time: (unixtime) Start time to fetch threat intel from
        :param end_time:(unixtime) End time to fetch threat intel from 
        :return: {dict} Reputation
        """
        try:
            url = "{0}/reputations/ips/{1}".format(
                API_ROOT,
                ip
            )

            response = requests.get(
                url=url,
                headers=self.headers,
                params={
                    'details': ",".join(FIELDS),
                    'start': start_time,
                    'end': end_time
                }
            )

            response.raise_for_status()
            return response.json()

        except requests.HTTPError as error:
            raise ProtectwiseManagerError(
                error.response.json()['error']['info'])

        except Exception as error:
            raise ProtectwiseManagerError(
                "Unable to get reputation of {ip}: {error} {text}".format(
                    ip=ip,
                    error=error,
                    text=error.message)
            )

    def get_domain_reputation(self, domain, start_time, end_time):
        """
        NOTICE - API Endpoint not working!
        Get reputation for a domain
        :param domain: The domain
        :param start_time: (unixtime) Start time to fetch threat intel from
        :param end_time: (unixtime) End time to fetch threat intel from
        :return: {dict} Reputation
        """
        try:
            url = "{0}/reputations/domains/{1}".format(
                API_ROOT,
                domain
            )

            response = requests.get(
                url=url,
                headers=self.headers,
                params={
                    'details': ",".join(FIELDS),
                    'start': start_time,
                    'end': end_time
                }
            )

            response.raise_for_status()
            return response.json()

        except requests.HTTPError as error:
            raise ProtectwiseManagerError(error.response.json()['error']['info'])

        except Exception as error:
            raise ProtectwiseManagerError(
                "Unable to get reputation of {domain}: {error} {text}".format(
                    domain=domain,
                    error=error,
                    text=error.message)
            )

    def get_file_reputation(self, hash, start_time, end_time):
        """
        NOTICE - API Endpoint not working!
        Get reputation for an hash
        :param hash: The hash
        :param start_time: (unixtime) Start time to fetch threat intel from
        :param end_time: (unixtime) End time to fetch threat intel from
        :return: {dict} Reputation
        """
        try:
            url = "{0}/reputations/files/{1}".format(
                API_ROOT,
                hash
            )

            response = requests.get(
                url=url,
                headers=self.headers,
                params={
                    'details': ",".join(FIELDS),
                    'start': start_time,
                    'end': end_time
                }
            )

            response.raise_for_status()
            return response.json()

        except requests.HTTPError as error:
            raise ProtectwiseManagerError(
                error.response.json()['error']['info'])

        except Exception as error:
            raise ProtectwiseManagerError(
                "Unable to get reputation of {hash}: {error} {text}".format(
                    hash=hash,
                    error=error,
                    text=error.message)
            )

    def download_pcap(self, event_id):
        """
        Download Pcap of a specific event by its id
        :param event_id: The event id
        :return: pcap file content
        """
        try:
            url = "{0}/pcaps/events/{1}".format(
                API_ROOT,
                event_id
            )

            response = requests.get(
                url=url,
                headers=self.headers
            )

            response.raise_for_status()
            return response.content # PCAP file content

        except requests.HTTPError as error:
            raise ProtectwiseManagerError(
                error.response.json()['error']['info'])

        except Exception as error:
            raise ProtectwiseManagerError(
                "Unable to download pcap for {event_id}: {error} {text}".format(
                    event_id=event_id,
                    error=error,
                    text=error.message)
            )

    def get_events(self, start_time, end_time):
        """
        Get events in a time frame
        :param start_time: (unixtime) Start time to fetch events from
        :param end_time: (unixtime) End time to fetch events from
        :return: {list} List of events
        """
        try:
            url = "{0}/events".format(
                API_ROOT
            )

            response = requests.get(
                url=url,
                headers=self.headers,
                params={
                    'start': start_time,
                    'end': end_time
                }
            )

            response.raise_for_status()
            return response.json()['events']

        except requests.HTTPError as error:
            raise ProtectwiseManagerError(
                error.response.json()['error']['info'])

        except Exception as error:
            raise ProtectwiseManagerError(
                "Unable to get events: {error} {text}".format(
                    hash=hash,
                    error=error,
                    text=error.message)
            )

    def construct_csv(self, results):
        """
        Construct a csv from results
        :param results: The results (list of flat dicts). i.e: list of flat events
        :return: {str} csv formatted string
        """
        csv_output = []
        headers = reduce(set.union, map(set, map(dict.keys, results)))

        csv_output.append(",".join(map(str, headers)))

        for result in results:
            csv_output.append(
                ",".join([s.replace(',', ' ') for s in
                          map(str, [result.get(h, None) for h in
                                    headers])]))

        return csv_output


