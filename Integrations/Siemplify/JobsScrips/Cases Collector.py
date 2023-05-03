from SiemplifyUtils import output_handler
from SiemplifyJob import SiemplifyJob
from PublisherAPIManager import PublisherAPIManager
from utils import parse_version_string_to_tuple, is_supported_siemplify_version
import StringIO
import gzip
import uuid
import os
import json
import re
import datetime

CASE_SUFFIX = ".case"
LOGS_SUFFIX = ".conn_log"
LIN_CASES_FOLDER = r"/i/Siemplify_Channels/Cases"
LIN_LOGS_FOLDER = r"/i/Siemplify_Channels/ConnectorsLog"
WIN_CASES_FOLDER = r"I:\Siemplify_Channels\Cases"
WIN_LOGS_FOLDER = r"I:\Siemplify_Channels\ConnectorsLog"
SUPPORTED_BULK_MIN_VER = (1, 3, 2)

REMOTE_CONNECTOR_DEBUG_OUTPUT = "Debug output is not available on remote connectors."


def gzip_content(content):
    """
    Gzip given content and returned the compresses data
    :param content: {string}
    :return: {stringIO} Byte array of the compresses content
    """
    out = StringIO.StringIO()
    with gzip.GzipFile(fileobj=out, mode="w") as f:
        f.write(content)
    return out.getvalue()


def create_package_name(connector_id, package_suffix):
    """
    Generate package delivery path by given extension and connector id
    :param connector_id: {string} The connector identifier
    :param package_suffix: {string} (.case, .conn_log)
    :return: {string} package name
    """
    cycle_id = str(uuid.uuid4())
    return '{}_{}{}'.format(connector_id, cycle_id, package_suffix)


def create_log_file(logs_folder_path, connector_id, log_package):
    """
    Write logs package object to given path
    :param logs_folder_path: {str} The logs folder path
    :param connector_id: {string} The id of the connector
    :param log_package: {dict} The logs package
    """
    # Write the case packet to path
    package_name = create_package_name(connector_id, LOGS_SUFFIX)
    log_package_path = os.path.join(logs_folder_path, package_name)

    # Write log package to path
    with open(log_package_path, "wb") as log_package_file:
        compressed_log_package = gzip_content(json.dumps(log_package))
        log_package_file.write(compressed_log_package)


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


def send_ack(siemplify, publisher_api_manager, connector_package, cert_file_content):
    # TEST ACK TASK
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


def create_case_file(cases_folder_path, connector_id, cases_package):
    """
    Write cases package to a given path
    :param cases_folder_path: {str} The Cases folder path
    :param connector_id: {str} The id of the connector
    :param cases_package: {dict} The cases package
    """
    for case in cases_package.get("Cases", []):
        # Generate case unique name and form path.
        package_name = create_package_name(connector_id, CASE_SUFFIX)
        case_package_path = os.path.join(cases_folder_path, package_name)
        attachments = case.get("Attachments")
        if attachments:
            case["Attachments"] = format_attachment(attachments)

        # Construct and Write Alert to file.
        with open(case_package_path, "w") as case_package_file:
            case_package_file.write(json.dumps({"Cases": [case],
                                                "ConnectorIdentifier": cases_package.get("ConnectorIdentifier"),
                                                "IsTestCase": False,
                                                "DebugOutput": REMOTE_CONNECTOR_DEBUG_OUTPUT
                                                }))


def bulk_execution(siemplify, publisher_id, publisher_api_manager, publisher_cert_file_content, agent_certs_cache):
    try:
        if datetime.datetime.utcnow().time().minute is 0 or 30:
            publisher_api_manager.delete_old_packages()
    except Exception as e:
        siemplify.LOGGER.error("failed to delete old connector packages from publisher. Exception: {}".format(e))
        pass

    connector_packages = publisher_api_manager.fetch_connector_packages(limit=50)
    agents_finished_packages = {}
    finished_packages_ids = []
    connector_keys = siemplify.get_remote_connector_keys_map(publisher_id)
    for connector_package in connector_packages:
        try:
            connector_id = connector_package.get("connector_id")
            siemplify.LOGGER.info(
                "Decrypting package {} for connector {} \n".format(
                    connector_package.get("id"), connector_id
                )
            )
            agent_id = connector_package.get('agent')
            if not publisher_cert_file_content:
                if not agent_certs_cache.get(agent_id):
                    agent_details = siemplify.get_agent_by_id(agent_id)
                    cert_file_content = agent_details.get("certificate")
                    agent_certs_cache[agent_id] = cert_file_content

            package = publisher_api_manager.decrypt_connector_package(
                encryption_key=connector_keys[connector_id],
                connector_package=connector_package.get("package")
            )

            package = json.loads(package)

            cases_package = package.get("cases_package")
            logs_package = package.get("logs_package")

            # Create the cases and logs files to ingest to

            # fix_paths
            if 'win' in os.environ.get('OS', '').lower():
                cases_folder = WIN_CASES_FOLDER
                logs_folder = WIN_LOGS_FOLDER
            else:
                cases_folder = LIN_CASES_FOLDER
                logs_folder = LIN_LOGS_FOLDER

            # Siemplify
            siemplify.LOGGER.info("Creating cases from package.")
            create_case_file(cases_folder, connector_id, cases_package)

            siemplify.LOGGER.info("Creating logs from package.")
            create_log_file(logs_folder, connector_id, logs_package)

            if not agents_finished_packages.get(agent_id):
                agents_finished_packages[agent_id] = {'packages': [connector_package]}
            else:
                agents_finished_packages[agent_id]['packages'].append(connector_package)
            finished_packages_ids.append(connector_package.get("id"))

        except Exception as e:
            siemplify.LOGGER.error(
                "Failed to process package {} for connector {}. \n".format(
                    connector_package.get("id"),
                    connector_id
                )
            )
            siemplify.LOGGER.exception(e)

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


def one_by_one_execution(siemplify, publisher_id, publisher_api_manager, publisher_cert_file_content,
                         agent_certs_cache):
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
                        if not publisher_cert_file_content:
                            agent_id = connector_package.get('agent')
                            if agent_certs_cache.get(agent_id):
                                cert_file_content = agent_certs_cache[agent_id]
                            else:
                                agent_details = siemplify.get_agent_by_id(agent_id)
                                cert_file_content = agent_details.get("certificate")
                                agent_certs_cache[agent_id] = cert_file_content
                        else:
                            cert_file_content = publisher_cert_file_content
                        package = publisher_api_manager.decrypt_connector_package(
                            encryption_key=encryption_key,
                            connector_package=connector_package.get("package")
                        )

                        package = json.loads(package)

                        cases_package = package.get("cases_package")
                        logs_package = package.get("logs_package")

                        # Create the cases and logs files to ingest to

                        # fix_paths
                        if 'win' in os.environ.get('OS', '').lower():
                            cases_folder = WIN_CASES_FOLDER
                            logs_folder = WIN_LOGS_FOLDER
                        else:
                            cases_folder = LIN_CASES_FOLDER
                            logs_folder = LIN_LOGS_FOLDER

                        # Siemplify
                        siemplify.LOGGER.info("Creating cases from package.")
                        create_case_file(cases_folder, connector_id, cases_package)

                        siemplify.LOGGER.info("Creating logs from package.")
                        create_log_file(logs_folder, connector_id, logs_package)

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

        siemplify.LOGGER.info("----Cases Collector finished---")

    except Exception as e:
        siemplify.LOGGER.error(
            "An error occurred while running Cases Collector"
        )
        siemplify.LOGGER.exception(e)
        raise e


@output_handler
def main():
    try:
        siemplify = SiemplifyJob()
        siemplify.script_name = "Cases Collector"
        verify_ssl = str(siemplify.parameters.get("Verify SSL")).lower() == str(True).lower()
        siemplify.LOGGER.info("----Cases Collector started---")
        publisher_id = siemplify.parameters.get("Publisher Id")
        publisher_details = siemplify.get_publisher_by_id(publisher_id)
        publisher_api_root = publisher_details["server_api_root"]
        api_token = publisher_details["api_token"]
        publisher_cert_file_content = None
        if not "get_agent_by_id" in dir(siemplify):  # Valid method for 5.5.3-hf-8 & 5.6.0-hf-2 and higher versions
            publisher_cert_file_content = publisher_details.get("certificate")
        agent_certs_cache = {}
        publisher_api_manager = PublisherAPIManager(publisher_api_root, api_token, verify_ssl)
        bulk_methods = is_supported_siemplify_version(publisher_api_manager.get_pub_version(), SUPPORTED_BULK_MIN_VER)

        if bulk_methods:
            # Supported endpoints from Publisher 1.3.2

            bulk_execution(siemplify, publisher_id, publisher_api_manager, publisher_cert_file_content,
                           agent_certs_cache)

        else:
            # Old behavior before Publisher 1.3.2
            one_by_one_execution(siemplify, publisher_id, publisher_api_manager, publisher_cert_file_content,
                                 agent_certs_cache)


    except Exception as e:
        siemplify.LOGGER.error(
            "An error occurred while running Cases Collector"
        )
        siemplify.LOGGER.exception(e)
        raise e

    if siemplify.LOGGER.error_logged:
        raise Exception("Error was logged during execution, check the logs.s")

    else:
        siemplify.LOGGER.info(
            "-----Cases Collector has finished execution without errors----"
        )


if __name__ == "__main__":
    main()