# ============================================================================#
# title           :CuckooManager.py
# description     :This Module contain all Cuckoo operations functionality
# author          :avital@siemplify.co
# date            :27-02-2018
# python_version  :2.7
# libreries       : requests, json
# requirments     :
# product_version :1.0
# ============================================================================#

# ============================= IMPORTS ===================================== #

import requests
from requests.packages.urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import os
import json
import base64

# ============================== CONSTS ===================================== #

COMPLETED_STATUSES = ['completed', 'failure', 'reported']
FAILURE_STATUS = 'failure'
REPORTED_STATUS = 'reported'
RETRY_TIMES = 3
CA_CERTIFICATE_FILE_PATH = "cacert.pem"

# ============================= CLASSES ===================================== #
class CuckooManagerError(Exception):
    """
    General Exception for Cuckoo manager
    """
    pass


class CuckooManager(object):
    """
    Cuckoo manager
    """
    def __init__(self, server_address, web_interface_address, ca_certificate_file, verify_ssl, api_token):
        self.server_address = server_address
        self.web_interface_address = web_interface_address  
        self.session = requests.Session()
        self.api_token = api_token
        if ca_certificate_file:
            try:
                file_content = base64.b64decode(ca_certificate_file)
                with open(CA_CERTIFICATE_FILE_PATH,"w+") as f:
                        f.write(file_content.decode("utf-8"))

            except Exception as e:
                raise CuckooManagerError(e)
            
        if verify_ssl and ca_certificate_file:
            verify = CA_CERTIFICATE_FILE_PATH        
            
        elif verify_ssl and not ca_certificate_file:
            verify = True
        else:
            verify = False
        
        self.verify = verify
        
        # will sleep for (sec): {backoff factor} * (2 ** ({number of total retries} - 1))
        # [0.0s, 20s, 40s, etc]
        retries = Retry(total=RETRY_TIMES, backoff_factor=10, status_forcelist=[404])
        self.session.mount('https://', HTTPAdapter(max_retries=retries))

    def test_connectivity(self):
        """
        Test connectivity to Cuckoo instance
        :return: {bool} true if connection successful, exception otherwise
        """
        try:
            url = "{0}/cuckoo/status".format(
                self.server_address
            )
            
            headers = {} 
            if self.api_token:
                headers = {"Authorization": "Bearer {}".format(self.api_token)}

            response = requests.get(url, verify=self.verify, headers=headers)
            response.raise_for_status()

            return True

        except requests.HTTPError as error:
            raise CuckooManagerError(
                "Unable to connect to {server_address}: {error} {text}".format(
                    server_address=self.server_address,
                    error=error,
                    text=error.response.content)
            )
        except Exception as error:
            raise CuckooManagerError(
                "Unable to connect to {server_address}: {error} {text}".format(
                    server_address=self.server_address,
                    error=error,
                    text=error.message)
            )

    def submit_url(self, suspicious_url):
        """
        Submit a url for analysis
        :param suspicious_url: The url to submit
        :return: {int} The newly created task's id
        """
        try:
            url = "{0}/tasks/create/url".format(
                self.server_address
            )

            headers = {} 
            if self.api_token:
                headers = {"Authorization": "Bearer {}".format(self.api_token)}

            response = requests.post(url,
                                     data={'url': suspicious_url},
                                     verify=self.verify, headers=headers)
            response.raise_for_status()

            return response.json()['task_id']

        except requests.HTTPError as error:
            raise CuckooManagerError(
                "Unable to submit {url}: {error} {text}".format(
                    url=suspicious_url,
                    error=error,
                    text=error.response.content)
            )

        except Exception as error:
            raise CuckooManagerError(
                "Unable to submit {url}: {error} {text}".format(
                    url=suspicious_url,
                    error=error,
                    text=error.message)
            )

    def submit_file(self, file_path):
        """
        Submit a file to analysis
        :param file_path: The path of the file to submit
        :return: {int} The newly created task's id
        """
        try:
            with open(file_path, 'rb') as sample:
                files = {"file": (os.path.basename(file_path), sample.read())}
                url = "{0}/tasks/create/file".format(
                    self.server_address
                )
                
                headers = {} 
                if self.api_token:
                    headers = {"Authorization": "Bearer {}".format(self.api_token)}

                response = requests.post(url, files=files, verify=self.verify, headers=headers)
                response.raise_for_status()

                return response.json()['task_id']

        except requests.HTTPError as error:
            raise CuckooManagerError(
                "Unable to submit {path}: {error} {text}".format(
                    path=file_path,
                    error=error,
                    text=error.response.content)
            )

        except Exception as error:
            raise CuckooManagerError(
                "Unable to submit {path}: {error} {text}".format(
                    path=file_path,
                    error=error,
                    text=error.message)
            )

    def submit_file_in_memory(self, filename, file_content):
        """
        Submit a file to analysis from memory
        :param filename: {str} The name of the file to submit
        :param file_content: {str} The content of the file to submit
        :return: {int} The newly created task's id
        """
        try:
            files = {"file": (filename, file_content)}
            url = "{0}/tasks/create/file".format(
                self.server_address
            )

            headers = {} 
            if self.api_token:
                headers = {"Authorization": "Bearer {}".format(self.api_token)}

            response = requests.post(url, files=files, verify=self.verify, headers=headers)
            response.raise_for_status()

            return response.json()['task_id']

        except requests.HTTPError as error:
            raise CuckooManagerError(
                "Unable to submit {filename}: {error} {text}".format(
                    filename=filename,
                    error=error,
                    text=error.response.content)
            )

        except Exception as error:
            raise CuckooManagerError(
                "Unable to submit {filename}: {error} {text}".format(
                    filename=filename,
                    error=error,
                    text=error.message)
            )

    def is_task_completed(self, task_id):
        """
        Checks if task is completed
        :param task_id: The task's id
        :return: {bool} true if completed, false otherwise.
        """
        try:
            status = self.get_task_status(task_id)['task']['status']
            return status in COMPLETED_STATUSES

        except requests.HTTPError as error:
            raise CuckooManagerError(
                "Unable to check status of task {id}: {error} {text}".format(
                    id=task_id,
                    error=error,
                    text=error.response.content)
            )

        except Exception as error:
            raise CuckooManagerError(
                "Unable to check status of task {id}: {error} {text}".format(
                    id=task_id,
                    error=error,
                    text=error.message)
            )

    def is_task_failed(self, task_id):
        """
        CHeck if task has failed
        :param task_id: The task's id
        :return: {bool} true if failed, false otherwise
        """
        try:
            status = self.get_task_status(task_id)['task']['status']
            return status == FAILURE_STATUS

        except requests.HTTPError as error:
            raise CuckooManagerError(
                "Unable to check status of task {id}: {error} {text}".format(
                    id=task_id,
                    error=error,
                    text=error.response.content)
            )

        except Exception as error:
            raise CuckooManagerError(
                "Unable to check status of task {id}: {error} {text}".format(
                    id=task_id,
                    error=error,
                    text=error.message)
            )

    def is_task_reported(self, task_id):
        """
        Check if task has reported
        :param task_id: The task's id
        :return: {bool} true if reported, false otherwise
        """
        try:
            status = self.get_task_status(task_id)['task']['status']
            return status == REPORTED_STATUS

        except requests.HTTPError as error:
            raise CuckooManagerError(
                "Unable to check status of task {id}: {error} {text}".format(
                    id=task_id,
                    error=error,
                    text=error.response.content)
            )

        except Exception as error:
            raise CuckooManagerError(
                "Unable to check status of task {id}: {error} {text}".format(
                    id=task_id,
                    error=error,
                    text=error.message)
            )

    def get_task_status(self, task_id):
        """
        Get tasks' status
        :param task_id: The task's id
        :return: {json} The task's status report
        """
        try:
            url = "{0}/tasks/view/{1}".format(
                self.server_address,
                task_id
            )
            
            headers = {} 
            if self.api_token:
                headers = {"Authorization": "Bearer {}".format(self.api_token)}
                
            response = requests.get(url, verify=self.verify, headers=headers)

            response.raise_for_status()

            return response.json()

        except requests.HTTPError as error:
            raise CuckooManagerError(
                "Unable to check status of task {id}: {error} {text}".format(
                    id=task_id,
                    error=error,
                    text=error.response.content)
            )

        except Exception as error:
            raise CuckooManagerError(
                "Unable to check status of task {id}: {error} {text}".format(
                    id=task_id,
                    error=error,
                    text=error.message)
            )

    def cancel_task(self, task_id):
        """
        Cancel a task by ID
        :param task_id: The ID of the task to cancel
        :return: {JSON} Cancellation status (i.e {u'status': u'OK'})
        """
        try:
            url = "{0}/tasks/delete/{1}".format(
                self.server_address,
                task_id
            )

            headers = {} 
            if self.api_token:
                headers = {"Authorization": "Bearer {}".format(self.api_token)}

            response = requests.get(url, verify=self.verify, headers=headers)

            response.raise_for_status()

            # Cancellation status (i.e: {u'status': u'OK'})
            return response.json()

        except requests.HTTPError as error:
            raise CuckooManagerError(
                "Unable to check status of task {id}: {error} {text}".format(
                    id=task_id,
                    error=error,
                    text=error.response.content)
            )

        except Exception as error:
            raise CuckooManagerError(
                "Unable to check status of task {id}: {error} {text}".format(
                    id=task_id,
                    error=error,
                    text=error.message)
            )

    def get_tar_report(self, task_id):
        """
        Get a full report of a task (tar.bz2 format). Contains cuckoo logs,
        analysis reports, screenshots, etc.
        :param task_id: The task's id
        :return: {str} Content of the tar.bz2 report
        """
        try:
            url = "{0}/tasks/report/{1}/all".format(
                self.server_address,
                task_id,
                format
            )

            headers = {} 
            if self.api_token:
                headers = {"Authorization": "Bearer {}".format(self.api_token)}

            response = requests.get(url, verify=self.verify, headers=headers)

            response.raise_for_status()

            return response.content

        except requests.HTTPError as error:
            raise CuckooManagerError(
                "Unable to get zip report of task {id}: {error} {text}".format(
                    id=task_id,
                    error=error,
                    text=error.response.content)
            )

        except Exception as error:
            raise CuckooManagerError(
                "Unable to get zip report of task {id}: {error} {text}".format(
                    id=task_id,
                    error=error,
                    text=error.message)
            )

    def get_report(self, task_id):
        """
        Get json report of a task
        :param task_id: The task's id
        :return: {json} The task's JSON report
        """
        try:
            url = "{0}/tasks/report/{1}/json".format(
                self.server_address,
                task_id,
            )

            headers = {} 
            if self.api_token:
                headers = {"Authorization": "Bearer {}".format(self.api_token)}

            response = requests.get(url, verify=self.verify, headers=headers)

            response.raise_for_status()

            return response.json()

        except requests.HTTPError as error:
            raise CuckooManagerError(
                "Unable to get report of task {id}: {error} {text}".format(
                    id=task_id,
                    error=error,
                    text=error.response.content)
            )

        except Exception as error:
            raise CuckooManagerError(
                "Unable to get report of task {id}: {error} {text}".format(
                    id=task_id,
                    error=error,
                    text=error.message)
            )

    def construct_csv(self, results):
        """
        Constructs a csv from results
        :param results: The results to add to the csv (results are list of flat dicts)
        :return: {list} csv formatted list
        """
        csv_output = []
        headers = reduce(set.union, map(set, map(dict.keys, results)))

        csv_output.append(",".join(map(str, headers)))

        for result in results:
            csv_output.append(
                ",".join([s.replace(',', ' ') for s in
                          map(str, [unicode(result.get(h, None)).encode('utf-8') for h in headers])]))

        return csv_output

    def construct_report_url(self, task_id):
        """
        Get report GUI URL.
        :param task_id: {string} The ID of the task that needed to be fetched.
        :return: {string} Report URL.
        """
        return "{0}/analysis/{1}/summary/".format(self.web_interface_address, task_id)


# 