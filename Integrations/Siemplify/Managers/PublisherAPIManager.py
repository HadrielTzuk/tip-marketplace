import requests
import json
from EncryptionManager import AESManager, RSAManager
from utils import parse_version_string_to_tuple


class PublisherAPIManager(object):
    def __init__(self, publisher_api_root, api_token, verify_ssl=False):
        self.api_root = publisher_api_root

        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update(
            {
                "Authorization": "Token {}".format(api_token)
            }
        )

    @staticmethod
    def validate_response(response, error_msg="An error occurred"):
        """
        Validate the response of the Publisher
        :param response: {requests.Response} The response to validate
        :param error_msg: {str} The error message to display
        """
        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            raise Exception(
                "{error_msg}: {error} - {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=response.content
                )
            )

    def send_ack_task(self, connector_package, cert_file_content):
        """
        When getting new connector package from publisher, Cases collector should send to publisher rest task request
        :param connector_package: {connector_package}
        :param cert_file_content: {string} certificate
        :return:
        """
        aes_manager = AESManager()
        rsa_manager = RSAManager(public_key=cert_file_content)

        encrypted_symmetric_key = rsa_manager.encrypt(aes_manager.key)

        payload = {
            'data': aes_manager.encrypt(data=json.dumps(
                {
                    'connector_package': "{0}-({1}).connector_package".format(connector_package.get("connector_id"),
                                                                              connector_package.get("guid"))
                })),
            'key': encrypted_symmetric_key,
            "type": "CASE_ACK",
            'agent': connector_package.get("agent")
        }

        response = self.session.post(
            "{}/api/tasks/".format(self.api_root),
            json=payload
        )

        self.validate_response(response, "Unable to send ack task")

    def send_bulk_ack_tasks(self, connector_packages, agent_certs_cache, publisher_cert_file_content):
        """
        When getting new connector package from publisher, Cases collector should send to publisher rest task request
        :param connector_package: {connector_package}
        :param cert_file_content: {string} certificate
        :return:
        """
        encrypted_agents_tasks = {}
        rsa_manager = None
        if publisher_cert_file_content:
            rsa_manager = RSAManager(public_key=publisher_cert_file_content)
        for agent_id in connector_packages:
            aes_manager = AESManager()
            if not publisher_cert_file_content:
                rsa_manager = RSAManager(public_key=agent_certs_cache[agent_id])
            encrypted_symmetric_key = rsa_manager.encrypt(aes_manager.key)
            encrypted_agents_tasks[agent_id] = {'tasks': [], 'key': encrypted_symmetric_key}
            for package in connector_packages[agent_id]['packages']:
                enc_package = aes_manager.encrypt(data=json.dumps(
                    {
                        'connector_package': "{0}-({1}).connector_package".format(package.get("connector_id"),
                                                                                  package.get("guid"))
                    }))
                encrypted_agents_tasks[agent_id]['tasks'].append(enc_package)

        payload = {
            'data': encrypted_agents_tasks,
            'type': "CASE_ACK",
        }

        response = self.session.post(
            "{}/api/tasks/create_bulk/".format(self.api_root),
            json=payload
        )

        self.validate_response(response, "Unable to send ack task")

    def fetch_connector_packages(self, connector_id=None, agent_id=None, limit=None, order_by=None):
        """
        Get all the connector packages from Publisher of a given connector and
        agnet (optional)
        :param connector_id: {str} The ID of the connector
        :param agent_id: {str} The ID of the agent
        :param limit: {int} The limit of connector packages to fetch
        :param order_by: {str} The defines how to choose the connector packages (example: oldest created first - 'created')


        :return: {list} The found connector packages
        """
        url = "{}/api/conpackages".format(self.api_root)
        response = self.session.get(
            url,
            params={
                "agent_id": agent_id,
                "connector_id": connector_id,
                "limit": limit,
                "order_by": order_by
            }
        )

        self.validate_response(response, "Unable to fetch connector packages")
        return response.json()

    @staticmethod
    def decrypt_connector_package(encryption_key, connector_package):
        """
        Decrypt the package content of a connector package
        :param encryption_key: {str} The encryption key
        :param connector_package: {dict} The content of the connector
            package to decrypt
        :return: {dict} The decrypted package content (cases + logs)
        """
        aes_manager = AESManager(key=encryption_key)
        return aes_manager.decrypt(connector_package)

    def list_agents(self):
        """
        List the agents registered to Publisher
        :return: {list} The found agents
        """
        url = "{}/api/agents".format(self.api_root)
        response = self.session.get(url)

        self.validate_response(response, "Unable to list agents")
        return response.json()

    def fetch_log_records_since_timestamp(self, since=0):
        """
        Fetch log records since given timestamp
        :param since: {long} Timestamp in milliseconds to fetch records since
        :return: {list} The found records
        """
        url = "{}/api/kibanalogrecords".format(self.api_root)
        response = self.session.get(
            url,
            params={
                "creation_time_unix_gmt": since
            }
        )

        self.validate_response(response, "Unable to fetch log records")
        return response.json()

    def delete_log_records_since_timestamp(self, since=0):
        """
        Delete log records since given timestamp
        :param since: {long} Timestamp in milliseconds to delete records since
        :return: {bool} True if success, exception otherwise
        """
        url = "{}/api/kibanalogrecords/delete_logs/".format(self.api_root)
        response = self.session.post(
            url,
            params={
                "creation_time_unix_gmt": since
            }
        )

        self.validate_response(response, "Unable to delete log records")
        return True

    def delete_connector_package(self, connector_package_id):
        """
        Delete a connector package
        :param connector_package_id: {int} The connector package id
        :return:
        """
        url = "{}/api/conpackages/{}".format(self.api_root, connector_package_id)
        response = self.session.delete(url)
        self.validate_response(response, "Unable to delete connector package {}".format(connector_package_id))
        return True

    def delete_bulk_connector_packages(self, connector_package_ids):
        """
        Delete a connector package
        :param connector_package_id: {int} The connector package id
        :return:
        """
        url = "{}/api/conpackages/delete_packages/".format(self.api_root)
        response = self.session.post(
            url,
            json={"con_ids": connector_package_ids}
        )
        self.validate_response(response, "Unable to delete connector packages {}".format(
            " ".join(str(x) for x in connector_package_ids)))
        return True

    def delete_old_packages(self):
        """
        Delete old connector packages
        :return:
        """
        url = "{}/api/conpackages/delete_packages/".format(self.api_root)
        response = self.session.post(url)
        self.validate_response(response, "Unable to delete old connector packages")
        return True

    def get_pub_version(self):
        """
        Get the Publisher's version
        :return: version number (string)
        """
        url = "{}/api/get_version".format(self.api_root)
        response = self.session.get(url)
        if response.status_code == 200:
            return parse_version_string_to_tuple(response.content.replace('\\n','').strip('"'))
        elif response.status_code == 404:
            # The get_pub_version() was added on 1.3.2. So if the endpoint does not exist, it's lower then 1.3.2
            return None
        else:
            # Something went wrong, looks like the Publisher is unreachable
            raise self.validate_response(response, "Unable to get publisher version")
