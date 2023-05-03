import json
import re

from PublisherAPIManager import PublisherAPIManager
from utils import is_supported_siemplify_version

from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import output_handler
from utils import send_notification

from consts import (
    SDK_JOB_ACTIONS_PLAYBOOK_ACTIONS_ERRORS as NOTIFICATION_PACKAGE_ERROR_ID,
    SDK_CASES_COLLECTOR_ERROR as NOTIFICATION_ERROR_ID
)

REMOTE_CONNECTOR_DEBUG_OUTPUT = "Debug output is not available on remote connectors."


def underscore_to_camel(name):
    under_pat = re.compile(r'_([a-z])')
    return under_pat.sub(lambda x: x.group(1).upper(), name)


def format_attachment(attachments):
    new_attachments = []
    for attachment in attachments:
        new_attachment = {}
        for key, val in attachment.items():
            new_attachment[underscore_to_camel(key)] = val
        new_attachments.append(new_attachment)

    return new_attachments


def create_case_file(siemplify, cases_package):
    """
    Write cases package to a given path
    :param siemplify: {obj} Siemplify job instance
    :param cases_package: {dict} The cases package
    """
    for case in cases_package.get("Cases", []):

        attachments = case.get("Attachments")
        if attachments:
            case["Attachments"] = format_attachment(attachments)

        # Construct and Write Alert.
        siemplify.create_connector_package({"Cases": [case],
                                            "ConnectorIdentifier": cases_package.get("ConnectorIdentifier"),
                                            "IsTestCase": False,
                                            "DebugOutput": REMOTE_CONNECTOR_DEBUG_OUTPUT
                                            })


def send_connector_logs(siemplify, agent_id, connector_id, logs_package):
    """
    Send remote agent's connector logs to the server in a safe manner
    :param siemplify: {obj} Siemplify job instance
    :param agent_id: {string} Relevant agent ID
    :param connector_id: {string} Relevant connector instance ID
    :param logs_package: {dict} Logs package of the specific connector instance
    """
    try:
        if not hasattr(siemplify, "add_agent_connector_logs"):
            return

        siemplify.LOGGER.info("Sending logs from the package. \n")
        siemplify.add_agent_connector_logs(agent_id,
                                           connector_id,
                                           {
                                               "ConnectorIdentifier": connector_id,
                                               "LogItems": logs_package["LogItems"]
                                           })
    except Exception as e:
        """
        Catching all exceptions as we don't want to affect flows dealing with case ingestion.
        """
        siemplify.LOGGER.error("Failed sending connector {} logs".format(connector_id))
        siemplify.LOGGER.exception(e)


def send_ack(siemplify, publisher_api_manager, connector_package, cert_file_content):
    siemplify.LOGGER.info("Sending Ack Task.")
    try:
        publisher_api_manager.send_ack_task(connector_package, cert_file_content)
        siemplify.LOGGER.info("Sent Ack Task for package")
    except Exception as e:
        siemplify.LOGGER.error("Failed to send Ack Task.")
        siemplify.LOGGER.exception(e)


def send_bulk_acks(siemplify, publisher_api_manager, connector_package, cert_file_content,
                   publisher_cert_file_content=None):
    siemplify.LOGGER.info("Sending bulk Ack Tasks.")
    try:
        publisher_api_manager.send_bulk_ack_tasks(connector_package, cert_file_content, publisher_cert_file_content)
        siemplify.LOGGER.info("Sent bulk Ack Tasks for all finished packages")
    except Exception as e:
        siemplify.LOGGER.error("Failed to send Ack Task.")
        siemplify.LOGGER.exception(e)


def bulk_execution(siemplify, publisher_id, publisher_api_manager, publisher_cert_file_content, agent_certs_cache):
    connector_packages = publisher_api_manager.fetch_connector_packages(limit=50)
    agents_finished_packages = {}
    finished_packages_ids = []
    connector_keys = siemplify.get_remote_connector_keys_map(publisher_id)
    errored_package_ids = []
    for connector_package in connector_packages:
        connector_id = connector_package.get("connector_id")
        try:
            siemplify.LOGGER.info(
                "Decrypting package {} for connector {} \n".format(
                    connector_package.get("id"), connector_id
                )
            )
            agent_id = connector_package.get('agent')
            if not publisher_cert_file_content:
                if not agent_certs_cache.get(agent_id):
                    agent_details = siemplify.get_agent_by_id(agent_id)
                    if not agent_details:
                        raise Exception("Failed to get agent details.")
                    cert_file_content = agent_details.get("certificate")
                    agent_certs_cache[agent_id] = cert_file_content

            package = publisher_api_manager.decrypt_connector_package(
                encryption_key=connector_keys[connector_id],
                connector_package=connector_package.get("package")
            )

            package = json.loads(package)
            logs_package = package.get("logs_package")
            send_connector_logs(siemplify, agent_id, connector_id, logs_package)
            cases_package = package.get("cases_package")

            # Siemplify
            siemplify.LOGGER.info("Creating cases from package. \n")
            create_case_file(siemplify, cases_package)

            if not agents_finished_packages.get(agent_id):
                agents_finished_packages[agent_id] = {'packages': [connector_package]}
            else:
                agents_finished_packages[agent_id]['packages'].append(connector_package)
            finished_packages_ids.append(connector_package.get("id"))

        except Exception as e:
            package_id = connector_package.get('id')
            siemplify.LOGGER.error(
                "Failed to process package {} for connector {}. \n".format(
                    package_id,
                    connector_id
                )
            )
            siemplify.LOGGER.exception(e)
            errored_package_ids.append(str(package_id))
    if errored_package_ids:
        msg = "Cases collector for publisher id '{}' has failed to process connector packages: {}." \
                                .format(publisher_id, ', ' .join(errored_package_ids))
        send_notification(siemplify, msg, NOTIFICATION_PACKAGE_ERROR_ID)

    try:
        # Send packages ack back:
        siemplify.LOGGER.info(
            "Sending case acks for packages: {} \n".format(" ".join(str(x) for x in finished_packages_ids)))
        send_bulk_acks(siemplify, publisher_api_manager, agents_finished_packages, agent_certs_cache,
                       publisher_cert_file_content)

        # Delete the package from the publisher
        siemplify.LOGGER.info(
            "Deleting ingested connector packages: {} \n".format(" ".join(str(x) for x in finished_packages_ids)))
        publisher_api_manager.delete_bulk_connector_packages(finished_packages_ids)

    except Exception as e:
        siemplify.LOGGER.error(
            "An error occurred while Deleting ingested connector packages. \n"
        )
        siemplify.LOGGER.exception(e)


def one_by_one_execution(siemplify, publisher_id, publisher_api_manager, publisher_cert_file_content, agent_certs_cache):
    try:
        connector_keys = siemplify.get_remote_connector_keys_map(publisher_id)
        for connector_id, encryption_key in connector_keys.items():
            try:
                siemplify.LOGGER.info(
                    "Fetching packages for connector {}".format(connector_id)
                )

                # Get packages.
                connector_packages = publisher_api_manager.fetch_connector_packages(
                    connector_id=connector_id
                )

                for connector_package in connector_packages:
                    try:
                        siemplify.LOGGER.info(
                            "Decrypting package {}".format(
                                connector_package.get("id")
                            )
                        )
                        agent_id = connector_package.get('agent')
                        if not publisher_cert_file_content:
                            if agent_certs_cache.get(agent_id):
                                cert_file_content = agent_certs_cache[agent_id]
                            else:
                                agent_details = siemplify.get_agent_by_id(agent_id)
                                if not agent_details:
                                    raise Exception("Failed to get agent details.")
                                cert_file_content = agent_details.get("certificate")
                                agent_certs_cache[agent_id] = cert_file_content
                        else:
                            cert_file_content = publisher_cert_file_content
                        package = publisher_api_manager.decrypt_connector_package(
                            encryption_key=encryption_key,
                            connector_package=connector_package.get("package")
                        )

                        package = json.loads(package)
                        logs_package = package.get("logs_package")
                        send_connector_logs(siemplify, agent_id, connector_id, logs_package)
                        cases_package = package.get("cases_package")

                        # Siemplify
                        siemplify.LOGGER.info("Creating cases from package.")
                        create_case_file(siemplify, cases_package)

                        # Send package ack back:
                        send_ack(siemplify, publisher_api_manager, connector_package, cert_file_content)

                        # Delete the package from the publisher
                        siemplify.LOGGER.info(
                            "Deleting package {}".format(
                                connector_package.get("id")
                            )
                        )
                        publisher_api_manager.delete_connector_package(
                            connector_package.get("id")
                        )

                    except Exception as e:
                        siemplify.LOGGER.error(
                            "Failed to process package {}".format(
                                connector_package.get("id")
                            )
                        )
                        siemplify.LOGGER.exception(e)

            except Exception as e:
                siemplify.LOGGER.error(
                    "Failed to process packages of connector {}".format(
                        connector_id
                    )
                )
                siemplify.LOGGER.exception(e)

    except Exception as e:
        siemplify.LOGGER.error(
            "An error occurred while running Cases Collector DB"
        )
        siemplify.LOGGER.exception(e)
        raise e


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = "Cases Collector DB"
    verify_ssl = str(siemplify.parameters.get("Verify SSL")).lower() == str(True).lower()
    siemplify.LOGGER.info("----Cases Collector DB started---")
    publisher_id = siemplify.parameters.get("Publisher Id")
    try:
        publisher_details = siemplify.get_publisher_by_id(publisher_id)
        if not publisher_details:
            raise Exception("Unable to get publisher with id: {}.".format(publisher_id))
        publisher_api_root = publisher_details["server_api_root"]
        api_token = publisher_details["api_token"]
        publisher_cert_file_content = None

        if "get_agent_by_id" not in dir(siemplify):  # Valid method for 5.5.3-hf-8 & 5.6.0-hf-2 and higher versions
            publisher_cert_file_content = publisher_details.get("certificate")
        agent_certs_cache = {}
        publisher_api_manager = PublisherAPIManager(publisher_api_root, api_token, verify_ssl)
        supported_bulk_min_ver = (1, 3, 2)
        bulk_methods = is_supported_siemplify_version(publisher_api_manager.get_pub_version(), supported_bulk_min_ver)

        if bulk_methods:
            # Supported endpoints from Publisher 1.3.2
            bulk_execution(siemplify, publisher_id, publisher_api_manager, publisher_cert_file_content, agent_certs_cache)

        else:
            # Old behavior before Publisher 1.3.2
            one_by_one_execution(siemplify, publisher_id, publisher_api_manager, publisher_cert_file_content, agent_certs_cache)

        siemplify.LOGGER.info("----Cases Collector DB finished---")

    except Exception as e:
        siemplify.LOGGER.error(
            "An error occurred while running Cases Collector DB"
        )
        siemplify.LOGGER.exception(e)
        msg = "Cases collector for publisher id '{}' has failed.".format(publisher_id)
        send_notification(siemplify, msg, NOTIFICATION_ERROR_ID)
        raise e

    if siemplify.LOGGER.error_logged:
        raise Exception("Error was logged during execution, check the logs.s")


if __name__ == "__main__":
    main()
