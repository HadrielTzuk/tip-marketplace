# ============================================================================#
# title           :CarbonBlackProtectionManager.py
# description     :This Module contain all Carbon Black Protection operations functionality
# author          :avital@siemplify.co
# date            :08-02-2018
# python_version  :2.7
# libreries       :requests, cbapi
# requirments     :
# product_version :1.0
# ============================================================================#

# ============================ IMPORTS ====================================== #
import time
from cbapi.protection import CbEnterpriseProtectionAPI, Computer, \
    FileCatalog, Policy, Connector, FileInstance, FileRule ,FileAnalysis
import requests
import arrow


# ============================== CONSTS ===================================== #


# ============================== CLASSES ==================================== #


class CBProtectionManagerException(Exception):
    pass


class CBProtectionManager(object):

    def __init__(self, server_address, api_key):
        self.server_address = server_address

        # For Rest Api Calls
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers = {
            'X-Auth-Token': api_key,
            'Content-Type': 'application/json'
        }

        # For CbApi calls
        self.cb_protection = CbEnterpriseProtectionAPI(url=server_address,
                                                       token=api_key,
                                                       ssl_verify=False)

    def get_computer_by_ip(self, ip_address):
        """
        Get computer data by ip address
        :param ip_address: {str} The ip address
        :return: {JSON} Computer data
        """
        computer = self.cb_protection.select(Computer).where(
            "ipAddress:{0}".format(ip_address)).first()

        if computer:
            return computer

    def get_computer_by_id(self, computer_id):
        """
        Get computer data by id
        :param computer_id: {str} The computer's id
        :return: {cbapi.Computer} The found Computer
        """
        computer = Computer(self.cb_protection, computer_id)

        if not computer:
            raise CBProtectionManagerException("Computer {} not found.".format(computer_id))

        return computer

    def get_computer_by_hostname(self, hostname):
        """
        Get computer data by hostname
        :param hostname: {str} The hostname
        :return: {cbapi.Computer} The found Computer
        """
        computer = self.cb_protection.select(Computer).where(
            "name:{0}".format(hostname)).first()

        return computer

    def change_computer_policy(self, computer_id, policy_name):
        """
        Move computer to a new policy
        :param computer_id: {str} The computer id
        :param policy_name: {str} The new policy name
        :return: {bool} True if successful, exception otherwise.
        """
        policy = self.get_policy_by_name(policy_name)

        url = "{}/api/bit9platform/v1/computer/{}".format(
            self.server_address, computer_id)

        response = self.session.put(url, json={
            'policyId': policy.id
        })
        self.validate_response(response,
                               "Unable to get change policy of computer {}".format(
                                   computer_id))

        return True

    def analyze_file(self, md5, connector_id, priority=0, wait=False, timeout=60):
        """
        Request file analysis
        :param md5: {str} The md5 of the file to analyze
        :param connector_id: {str} The id of the analyzing connector
        :param priority: {int} The priority of the analysis (-2 to 2)
        :param wait: {bool} Whether to wait for results of the analysis or not
        :param timeout: {int} Wait timeout
        :return: {dict} The analysis info
        """
        url = "{}/api/bit9platform/v1/fileAnalysis".format(self.server_address)
        catalog = self.get_file_catalog(md5)

        if not catalog:
            raise CBProtectionManagerException(
                "File {} doesn't exist in catalog.".format(md5)
            )

        if not self.get_computers_running_hash(md5):
            raise CBProtectionManagerException(
                "File {} doesn't exist on any computer. Anlysis is impossible.".format(md5)
            )

        # catalog.computer is a Computer if only 1 computer exists,
        # otherwise it is a Query object.
        if isinstance(catalog.computer, Computer):
            computer_id = catalog.computer.id
        else:
            computer_id = catalog.computer.first().id

        data = {
            'computerId': computer_id,
            'fileCatalogId': catalog.id,
            'connectorId': connector_id,
            'priority': priority,

        }

        response = self.session.post(url, json=data)
        self.validate_response(response, "Unable to analyze {}".format(md5))

        if not wait:
            return response.json()

        start_time = arrow.utcnow()

        while not self.is_analysis_complete(response.json()['id']):
            if start_time.shift(seconds=timeout) < arrow.utcnow():
                raise CBProtectionManagerException(
                    "Reached timeout while analyzing {}".format(md5))

            time.sleep(2)

        return self.get_analysis_info(response.json()['id'])

    def get_analysis_info(self, analysis_id):
        """
        Get analysis information
        :param analysis_id: {str} The analysis id
        :return: {dict} The analysis information
        """
        url = "{}/api/bit9platform/v1/fileAnalysis/{}".format(
            self.server_address, analysis_id)

        response = self.session.get(url)
        self.validate_response(response,
                               "Unable to get status of file analysis job {}".format(
                                   analysis_id))
        return response.json()

    def is_analysis_complete(self, analysis_id):
        """
        Is analysis completed
        :param analysis_id: {str} The analysis id
        :return: {bool} True if completed, False otherwise
        """
        analysis = self.get_analysis_info(analysis_id)

        # 4 = error, 5 = cancelled
        if analysis.get('analysisStatus', -1) in [4, 5]:
            raise CBProtectionManagerException("Analysis {} failed or cancelled.".format(analysis_id))

        # 3 = analyzed (file is processed and results are available)
        return analysis.get('analysisStatus', -1) == 3

    def is_file_malicious(self, analysis_id):
        """
        Is analysis has found the file malicious
        :param analysis_id: {str} The analysis id
        :return: {bool} True if completed, False otherwise
        """
        url = "{}/api/bit9platform/v1/fileAnalysis/{}".format(
            self.server_address, analysis_id)

        response = self.session.get(url)
        self.validate_response(response,
                               "Unable to get status of file analysis job {}".format(
                                   analysis_id))

        # 3 = File is malicious
        return response.json().get('analysisResult') == 3

    def is_file_suspicious(self, analysis_id):
        """
        Is anlysis has found the file suspicious
        :param analysis_id: {str} The analysis id
        :return: {bool} True if completed, False otherwise
        """
        url = "{}/api/bit9platform/v1/fileAnalysis/{}".format(
            self.server_address, analysis_id)

        response = self.session.get(url)
        self.validate_response(response,
                               "Unable to get status of file analysis job {}".format(
                                   analysis_id))

        # 2 = File is a potential risk
        return response.json().get('analysisResult') == 2

    def get_policy_by_name(self, policy_name):
        """
        Get policy by name
        :param policy_name: {str} The policy name
        :return: {cbapi.Policy} The policy
        """
        policy = self.cb_protection.select(Policy).where("name:{}".format(policy_name)).first()

        if not policy:
            raise CBProtectionManagerException("Policy {} not found.".format(policy_name))

        return policy

    def get_connector_by_name(self, connector_name):
        """
        Get connector by name
        :param connector_name: {str} The connector name
        :return: {cbapi.Connector} The connector
        """

        connector = self.cb_protection.select(Connector).where(
            "name:{}".format(connector_name)).first()

        if not connector:
            raise CBProtectionManagerException(
                "Connector {} not found.".format(connector_name))

        return connector

    # Not working - getting 401. Probably uploadFile = get computer report and
    # and download it.
    # def upload_file(self, md5, priority=0):
    #     url = "{}/api/bit9platform/v1/fileUpload".format(self.server_address)
    #     data = {
    #         "priority": priority,
    #         "computerId": 0,
    #         "fileCatalogId": self.get_file_catalog(md5).id
    #     }
    #
    #     response = self.session.post(url, json=data)
    #     self.validate_response(response, "Unable to upload {}".format(md5))
    #
    #     return response.json()

    def is_upload_complete(self, upload_job_id):
        """
        Checks whether an upload has completed
        :param upload_job_id: {str} The upload id
        :return: {bool} True if complete, False otherwise.
        """
        url = "{}/api/bit9platform/v1/fileUpload/{}".format(
            self.server_address, upload_job_id)

        response = self.session.get(url)
        self.validate_response(response,
                               "Unable to get status of file upload job {}".format(
                                   upload_job_id))

        return response.json().get('uploadStatus', 4) == 3

    def get_file_instances(self, md5):
        """
        Get the file instances of a given hash
        :param md5: {str} The md5
        :return: {list} List of FileInstances of the hash.
        """
        file_catalog = self.get_file_catalog(md5)

        if not file_catalog:
            raise CBProtectionManagerException(
                "File {} doens't exist in catalog".format(md5))

        file_instances = []

        for file_instance in self.cb_protection.select(FileInstance).where("fileCatalogId:{}".format(file_catalog.id)):
            file_instances.append(file_instance)

        return file_instances

    def get_computers_running_hash(self, md5):
        """
        Get the computers on which the file exists.
        :param md5: {str} The file's md5.
        :return: {list} List of the computers data that were found.
        """
        file_catalog = self.get_file_catalog(md5)

        computers = []
        computer_ids = []

        for file_instance in self.cb_protection.select(FileInstance).where("fileCatalogId:{}".format(file_catalog.id)):
            computer = self.get_computer_by_id(file_instance.computerId)

            # Prevent duplicate computers in the list.
            if computer.id not in computer_ids:
                computers.append(computer)
                computer_ids.append(computer.id)

        return computers

    def ban_hash(self, md5, policies_ids=['0']):
        """
        Ban a file by md5
        :param md5: {Str} The md5
        :param policies_ids: {list} List of IDs of policies where this
         rule applies. 0 if this is a global rule
        :return: {bool} True if successful, exception otherwise.
        """
        if not self.is_md5(md5):
            raise CBProtectionManagerException(
                "Hash {} is not a valid md5".format(md5))

        file_rule = self.cb_protection.select(FileRule).where(
            "hash:{}".format(md5)).first()

        if file_rule:
            policies_ids = list(set(file_rule.policyIds.split(',') + policies_ids))

        url = "{}/api/bit9platform/v1/fileRule".format(self.server_address)
        data = {
            "hash": md5,
            "fileState": 3, # 3 = banned
            "policyIds": ",".join(policies_ids)
        }

        response = self.session.post(url, json=data)
        self.validate_response(response, "Unable to ban {}".format(md5))

        return True

    def get_file_catalog(self, md5):
        """
        Get file catalog by md5
        :param md5: {str} The md5
        :return: {cbapi.FileCatalog} The found file catalog.
        """
        return self.cb_protection.select(FileCatalog).where('md5:{}'.format(md5)).first()

    def unban_hash(self, md5, policies_ids=[]):
        """
        Ban a file by md5
        :param md5: {Str} The md5
        :param policies_ids: {list} List of IDs of policies where this rule
            applies. 0 if this is a global rule
        :return: {bool} True if successful, exception otherwise.
        """
        if not self.is_md5(md5):
            raise CBProtectionManagerException(
                "Hash {} is not a valid md5".format(md5))

        file_rule = self.cb_protection.select(FileRule).where("hash:{}".format(md5)).first()

        if file_rule:
            # Substract the policies to remove from the rule
            policies_ids = list(
                set(file_rule.policyIds.split(',')) - set(policies_ids)
            )

            if policies_ids:
                # Update the rule
                file_rule.policyIds = ",".join(policies_ids)
                file_rule.save()
            else:
                # Delete the rule -  no policies were left.
                file_rule.delete()

            return True

        raise CBProtectionManagerException(
            "Rule doesn't exist for hash {}".format(md5))

    @staticmethod
    def is_md5(filehash):
        """
        Checks whether the filehash is a md5
        :param filehash: {str} The filehash
        :return: {bool} True if md5, False otherwise.
        """
        return len(filehash) == 32

    @staticmethod
    def validate_response(res, error_msg="An error occurred"):
        """
        Validate a response
        :param error_msg: {str} The error message to display
        :param res: {requests.Response} The response to validate
        """
        try:
            res.raise_for_status()

        except requests.HTTPError as error:
            raise Exception(
                "{error_msg}: {error} {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=error.response.content)
            )

    @staticmethod
    def construct_csv(results):
        """
        Construct csv from results
        :param results: The results to add to the csv
        :return: {list} csv formatted output
        """
        csv_output = []
        headers = reduce(set.union, map(set, map(dict.keys, results)))

        csv_output.append(",".join(map(str, headers)))

        for result in results:
            csv_output.append(
                ",".join([s.replace(',', ' ') for s in
                          map(str, [unicode(result.get(h, None)).encode('utf-8') for h in headers])]))

        return csv_output


