import base64
import json
from urllib.parse import urljoin

import requests

import consts
import utils


class MilsManager:

    def __init__(self, logger):
        self.logger = logger
        configs = self._load_configs()
        self.api_root = configs['api_root']
        self.session = requests.session()
        self.session.verify = False
        self.session.headers.update(consts.HEADERS)

        self._obtain_bearer_token(
            username=configs['username'],
            password=configs['password']
        )

    def _obtain_bearer_token(self, username: str, password: str):
        """
        Obtain bearer token from an Admin user with password
        :return: {str} Token
        """
        request_url = self._get_full_url('login')
        params = {
            'userName': username,
            'password': password
        }
        response = self.session.post(request_url, json=params)
        self._validate_response(
            response,
            error_msg="Failed to obtain bearer token for authorization with Siemplify"
        )
        login_data = response.json()
        self.session.headers.update({"Authorization": f"Bearer {login_data['token']}"})
        self.server_version = login_data['serverVersion']

    def _get_full_url(self, url_key: str, **kwargs) -> str:
        """
        Get full url from url key.
        :param url_id: {str} The key of url
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        return urljoin(self.api_root, consts.ENDPOINTS[url_key].format(**kwargs))

    def get_installed_integrations(self):
        request_url = self._get_full_url('get-installed-integrations')
        response = self.session.get(request_url, timeout=consts.REQUEST_TIMEOUT)
        self._validate_response(
            response, error_msg="Failed to get installed integrations"
        )
        return response.json()

    def get_integration_details(self, path):
        payload = {"data": base64.b64encode(utils.read_file(path)).decode()}
        request_url = self._get_full_url('get-package-details')
        response = self.session.post(
            request_url, timeout=consts.REQUEST_TIMEOUT, json=payload
        )
        self._validate_response(
            response, error_msg="failed to get integration details"
        )
        return response.json()

    def upload_integration_to_smp(self, path, integration_id, isCustom=False):
        payload = {
            "data": base64.b64encode(utils.read_file(path)).decode(),
            "integrationIdentifier": integration_id,
            "isCustom": isCustom
        }
        request_url = self._get_full_url('import-package')
        response = self.session.post(
            request_url, timeout=consts.REQUEST_TIMEOUT, json=payload
        )
        self._validate_response(
            response, error_msg="failed upload integration to Siemplify"
        )
        json_resp = response.json()
        if json_resp['error']:
            self.logger.error(
                f"found errors while uploading package to Siemplify: "
                f"{json_resp['error']}")

        if json_resp['failedDependencies']:
            self.logger.error(
                f"could not install dependencies: "
                f"{json_resp['failedDependencies']}"
            )

        return json_resp

    def upload_usecase(self, path):
        request_url = self._get_full_url('import-usecase')
        self.session.headers.update({"Content-Type": "multipart/form-data"})
        response = self.session.post(
            url=request_url,
            files={"apiZipFile": open(path, "rb")}
        )
        self._validate_response(
            response, error_msg="failed upload usecase to Siemplify"
        )
        return response.text

    def download_usecase(self, usecase, path):
        # TODO: THIS IS A TEST PAYLOAD
        # TODO: REMOVE WHEN 'get_usecase_details' METHOD IS READY
        # TODO: AND POPULATE PAYLOAD ACCORDINGLY
        payload = {
            "identifier": "d26f155d-c5b8-4afb-969e-bb1c0138ca3c",
            "categories": ["test"],
            "description": "<p>test</p>",
            "elements": [],
            "includeIntegrations": True,
            "name": "test",
            "videoLink": None
        }
        request_url = self._get_full_url('export-usecase')
        response = self.session.get(
            url=request_url,
            json=payload
        )
        return utils.write_zip(path, usecase, response.content)

    @staticmethod
    def _load_configs():
        with open(consts.CONFIG_FILE, "r") as f:
            configs = json.loads(f.read())
        return configs

    @staticmethod
    def _validate_response(response, error_msg="An error occurred"):
        try:
            response.raise_for_status()
        except requests.HTTPError as error:
            try:
                response.json()
            except Exception:
                # Not a JSON - return content
                raise requests.HTTPError(
                    "{error_msg}: {error}".format(
                        error_msg=error_msg,
                        error=error)
                )

            raise requests.HTTPError(
                "{error_msg}: {error} {text}".format(
                    error_msg=error_msg,
                    error=response.json(),
                    text=json.dumps(response.json()))
            )
