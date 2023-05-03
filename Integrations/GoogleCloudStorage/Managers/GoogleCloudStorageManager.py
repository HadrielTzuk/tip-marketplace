import json
import os

import requests
import requests.adapters
from google.auth.exceptions import TransportError
from google.cloud import storage
from google.oauth2 import service_account
from google.auth.transport.requests import AuthorizedSession, Request

import consts
from GoogleCloudStorageParser import GoogleCloudStorageParser
from exceptions import (
    GoogleCloudStorageBadRequestError,
    GoogleCloudStorageNotFoundError,
    GoogleCloudStorageForbiddenError,
    GoogleCloudStorageNoConnectionsError,
    GoogleCloudStorageManagerError,
)


class GoogleCloudStorageManager(object):
    """
    Google Cloud Storage Manager
    """

    def __init__(self, type: str = None,
                 project_id: str = None,
                 private_key_id: str = None,
                 private_key: str = None,
                 client_email: str = None,
                 client_id: str = None,
                 auth_uri: str = None,
                 token_uri: str = None,
                 auth_provider_x509_cert_url: str = None,
                 client_x509_cert_url: str = None,
                 verify_ssl: bool = True, **kwargs):

        self.creds = {
            "type": type,
            "project_id": project_id,
            "private_key_id": private_key_id,
            "private_key": private_key,
            "client_email": client_email,
            "client_id": client_id,
            "auth_uri": auth_uri,
            "token_uri": token_uri,
            "auth_provider_x509_cert_url": auth_provider_x509_cert_url,
            "client_x509_cert_url": client_x509_cert_url
        }

        #  If the private key is not valid, ValueError will be raised.
        try:
            credentials = service_account.Credentials.from_service_account_info(info=self.creds,
                                                                                scopes=consts.SCOPE)
            session = AuthorizedSession(credentials, auth_request=self.prepare_auth_request(verify_ssl))
            session.verify = verify_ssl
            self.client = storage.client.Client(project=credentials.project_id,
                                                _http=session)
        except ValueError as error:
            raise GoogleCloudStorageManagerError(f"Wrong Credentials: {error}")

        self.parser = GoogleCloudStorageParser()

    @staticmethod
    def prepare_auth_request(verify_ssl: bool = True):
        """
        Prepare an authenticated request.

        Note: This method is a duplicate of the same method in the GoogleCloudComputeManager class. The only change is
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

    @staticmethod
    def validate_error(response, error_msg="An error occurred"):
        try:
            if type(response) == TransportError:
                raise TransportError("No internet connection")

            response = response.response
            if response.status_code == consts.NOT_FOUND:
                try:
                    error_message = json.loads(response.content).get('error')
                    raise GoogleCloudStorageNotFoundError(error_message.get('message', 'Not Found'))
                except json.decoder.JSONDecodeError as error:
                    raise GoogleCloudStorageNotFoundError(response.text)

            if response.status_code == consts.FORBIDDEN:
                error_message = json.loads(response.content).get('error')
                raise GoogleCloudStorageForbiddenError(error_message.get('message', 'Forbidden'))

            else:
                error_message = json.loads(response.content).get('error')
                raise GoogleCloudStorageBadRequestError(f"{error_msg}: {error_message.get('message', 'Bad Request')}")

        except (GoogleCloudStorageBadRequestError, GoogleCloudStorageForbiddenError, GoogleCloudStorageNotFoundError):
            raise

        except TransportError as error:
            raise GoogleCloudStorageNoConnectionsError(error)

        except Exception as error:
            raise GoogleCloudStorageManagerError('Wrong Credentials')

    def test_connectivity(self):
        """
        Test Connectivity
        """
        try:
            list(self.client.list_buckets(max_results=1))
            return True
        except Exception as error:
            raise GoogleCloudStorageManagerError(f"{error}")

    def list_buckets(self, max_results=consts.DEFAULT_PAGE_SIZE):
        """
        Retrieve a list of buckets from Google Cloud Storage.
        param max_results: Max number of results to return
        return: [{datamodels.Bucket}] List of Buckets models
        """
        response = self.client.list_buckets(max_results=max_results)
        buckets = []

        try:
            for page in response.pages:
                if len(buckets) >= max_results:
                    break
                buckets.extend(self.parser.build_buckets_obj(page.raw_page))

            return buckets[:max_results]

        except Exception as error:
            self.validate_error(error, "Unable to list buckets")

    def get_acl(self, bucket_name):
        """
        Retrieve the access control list (ACL) for a Cloud Storage bucket.
        :param bucket_name: {str} The name of the bucket to fetch his ACLs
        :return: [{datamodels.ACL}] List of ACLs models
        """
        try:
            response = self.client.get_bucket(bucket_or_name=bucket_name)
            return self.parser.build_acl_obj(response)
        except Exception as error:
            self.validate_error(error, "Unable to list buckets")

    def list_buckets_objects(self, bucket_name, max_objects_to_return=consts.DEFAULT_PAGE_SIZE, retrieve_acl=True):
        """
        List bucket objects in Google Cloud storage.
        :param bucket_name: {str} bucket name to retrieve objects from
        :param max_objects_to_return:  {int} max number of objects to return
        :param retrieve_acl: {bool} True if to try and retrieve an ACL. Buckets of type uniform will raise and exception if
        retrieve_acl=True.
        :return: {[datamodel.BucketObject]} List of bucket objects
        """
        response = self.client.list_blobs(bucket_name, max_results=max_objects_to_return)
        bucket_objects = []

        try:
            for page in response.pages:
                if len(bucket_objects) >= max_objects_to_return:
                    break

                for blob in page:
                    bucket_objects.append(self.parser.build_bucket_object_obj(blob, retrieve_acl))
            return bucket_objects
        except Exception as error:
            self.validate_error(error, "Unable to list bucket objects")

    def update_acl(self, acl):
        """
        Update ACL of a bucket in Google Cloud Storage
        :param acl: {datamodels.ACL} ACL data model object
        :return: True if there is no errors
        """
        try:
            #  acl.save is an API call from Google Cloud Storage
            response = acl.save()
            return True
        except Exception as error:
            self.validate_error(error, "Unable to update acl permission")

    def get_bucket(self, bucket_name):
        """
        Get bucket from Google Cloud Storage
        :param bucket_name: {str} The name of the bucket
        :return: {datamodels.Bucket} Bucket Data Model
        """
        try:
            response = self.client.get_bucket(bucket_or_name=bucket_name)
            return self.parser.build_bucket_from_google_obj(response)
        except Exception as error:
            self.validate_error(error, "Unable to find bucket")

    def get_blob(self, object_name):
        """
        Google Cloud Storage API call that return the object if exits
        :param object_name: The name of the object to retrieve.
        :return: {Blob} Google Cloud Storage Blob object
        """
        return object_name.get_blob(object_name)

    def upload_file(self, file_object, upload_path):
        """
        Upload file to Cloud Storage bucket.
        :param file_object: {GoogleCloudStorage.Blob} Google Cloud Storage file object
        :param upload_path: {str} The path specified where to upload the file from
        :return: raise Exception if failed to upload file
        """
        try:
            file_object.upload_from_filename(upload_path)
        except Exception as error:
            self.validate_error(error, error_msg=f"Unable to upload file {upload_path}")

    def download_file(self, file_object, download_path):
        """
        Download an object from a Cloud Storage bucket.
        :param file_object: {GoogleCloudStorage.Blob} Google Cloud Storage file object
        :param download_path: {str} The path specified to where to download the file
        :return: True if the file was downloaded successfully
        """
        try:
            if not os.path.exists(os.path.dirname(download_path)):
                os.makedirs(os.path.dirname(download_path))

            with open(download_path, 'wb') as file:
                self.client.download_blob_to_file(file_object, file)
            return True

        except (FileNotFoundError, PermissionError):
            raise

        except Exception as error:
            self.validate_error(error, "Unable to download the file")
