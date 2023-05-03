# ============================================================================#
# title           :FireEyeEXManager.py
# description     :This Module contain all FireEye EX operations functionality
# author          :avital@siemplify.co
# date            :18-06-2020
# python_version  :2.7
# libreries       :requests
# requirments     :
# product_version :1.0
# ============================================================================#

# ============================= IMPORTS ===================================== #
import requests
import requests.adapters
from typing import List, Any, Optional
from google.cloud import bigquery
from google.oauth2 import service_account
from google.auth.transport.requests import AuthorizedSession, Request
from google.cloud.exceptions import GoogleCloudError

from GoogleBigQueryExceptions import GoogleBigQueryManagerError, GoogleBigQueryValidationError
from GoogleBigQueryUtils import parse_string_to_dict

# ============================== CONSTS ===================================== #


# ============================= CLASSES ===================================== #


class GoogleBigQueryManager(object):
    """
    Google BigQuery Manager
    """
    def __init__(self, account_type: str, project_id: str, private_key_id: str, private_key: str, client_email: str,
                 client_id: str, auth_uri: str, token_uri: str, auth_provider_x509_cert_url: str,
                 client_x509_cert_url: str, service_account_json: str = "", verify_ssl: bool = True):

        if service_account_json:
            creds = parse_string_to_dict(service_account_json)
        else:
            creds = {
                "type": account_type,
                "project_id": project_id,
                "private_key_id": private_key_id,
                "private_key": private_key.replace("\\n", "\n") if private_key else None,
                "client_email": client_email,
                "client_id": client_id,
                "auth_uri": auth_uri,
                "token_uri": token_uri,
                "auth_provider_x509_cert_url": auth_provider_x509_cert_url,
                "client_x509_cert_url": client_x509_cert_url
            }
            if any(param is None for param in creds.values()):
                raise GoogleBigQueryValidationError(
                    "Please fill either 'Service Account Json File Content' or all other parameters"
                )

        credentials = service_account.Credentials.from_service_account_info(info=creds, scopes=bigquery.Client.SCOPE)
        self.project_id = credentials.project_id
        session = AuthorizedSession(credentials, auth_request=self.prepare_auth_request(verify_ssl))
        session.verify = verify_ssl

        self.client = bigquery.Client(project=self.project_id, _http=session)

    @staticmethod
    def prepare_auth_request(verify_ssl: bool = True):
        """
        Prepare an authenticated request.

        Note: This method is a duplicate of the same method in the AuthorizedSession class. The only change is
        that created session is using verify_ssl parameter to allow self-signed certificates.
        """
        auth_request_session = requests.Session()
        auth_request_session.verify = verify_ssl

        # Using an adapter to make HTTP requests robust to network errors.
        # This adapter retries HTTP requests when network errors occur
        # and the requests seems safely retryable.
        retry_adapter = requests.adapters.HTTPAdapter(max_retries=3)
        auth_request_session.mount("https://", retry_adapter)

        # Do not pass `self` as the session here, as it can lead to
        # infinite recursion.
        return Request(auth_request_session)

    def test_connectivity(self) -> bool:
        """
        Test connectivity
        """
        try:
            list(self.client.list_datasets(max_results=1))
            return True
        except GoogleCloudError as e:
            raise GoogleBigQueryManagerError(f"Unable to connect to Google BigQuery. Please validate your credentials. {e}")

    def run_query(self, dataset_name: str, query: str, limit: Optional[int] = None) -> List[Any]:
        """
        Run a query and get the results
        :param dataset_name: {str} Specify the name of the dataset, which will be used, when executing queries.
        :param query: {str} Specify the SQL query that needs to be executed.
        :param limit: {int} Max amount of results to fetch. Optional.
        :return: {List} The results of the query
        """
        job_config = bigquery.QueryJobConfig(default_dataset=f"{self.project_id}.{dataset_name}")
        # Initiate the query
        query_job = self.client.query(query, job_config=job_config)
        # Start the job and wait for it to complete and get the result.
        rows = query_job.result(max_results=limit)
        # Transform to a pandas data frame
        results = rows.to_dataframe()
        # Transform to list of dicts
        return results.to_dict('records')
