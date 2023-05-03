from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED
from SiemplifyDataModel import EntityTypes
from EndgameManager import EndgameManager, EndgameNotFoundError, IOC_FILE_SEARCH
from EndgameCommon import EndgameCommon, PROVIDER
from TIPCommon import extract_configuration_param, extract_action_param
import sys
import json

INTEGRATION_NAME = u'Endgame'
SCRIPT_NAME = u'Hunt File'
INVESTIGATIOM_NAME = u"Siemplify File Hunt Investigation API"
DEFAULT_CORE_OS = u"windows"
SUPPORTED_ENTITIES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           is_mandatory=True, input_type=unicode)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                           is_mandatory=True, input_type=unicode)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password",
                                           is_mandatory=True, input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    investigation_name = extract_action_param(siemplify, param_name=u"Investigation Name", is_mandatory=False,
                                        input_type=unicode, default_value=INVESTIGATIOM_NAME,
                                        print_value=True)

    core_os = extract_action_param(siemplify, param_name=u"Endpoints Core OS", is_mandatory=False,
                                              input_type=unicode, default_value=DEFAULT_CORE_OS,
                                              print_value=True)

    md5_hashes = extract_action_param(siemplify, param_name=u"MD5 Hashes", is_mandatory=False,
                                   input_type=unicode, print_value=True)
    md5_hashes = [md5_hash.strip() for md5_hash in md5_hashes.split(u",")] if md5_hashes else []

    sha1_hashes = extract_action_param(siemplify, param_name=u"SHA1 Hashes", is_mandatory=False,
                                   input_type=unicode, print_value=True)
    sha1_hashes = [sha1_hash.strip() for sha1_hash in sha1_hashes.split(u",")] if sha1_hashes else []

    sha256_hashes = extract_action_param(siemplify, param_name=u"SHA256 Hashes", is_mandatory=False,
                                   input_type=unicode, print_value=True)
    sha256_hashes = [sha256_hash.strip() for sha256_hash in sha256_hashes.split(u",")] if sha256_hashes else []

    regexes = extract_action_param(siemplify, param_name=u"Find File", is_mandatory=False,
                                         input_type=unicode, print_value=True)
    regexes = [regex.strip() for regex in regexes.split(u",")] if regexes else []

    directory = extract_action_param(siemplify, param_name=u"Directory", is_mandatory=False,
                                         input_type=unicode, print_value=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    if (not directory) or not (md5_hashes or sha1_hashes or sha256_hashes or regexes):
        siemplify.end(
            u"ERROR: You must specify a file or hash to search for. Directory parameter is required.",
            u'false',
            EXECUTION_STATE_FAILED
        )

    sensor_ids = []
    successful_entities = []
    missing_entities = []
    failed_entities = []
    status = EXECUTION_STATE_COMPLETED
    result_value = u"false"
    output_message = u""

    try:
        endgame_manager = EndgameManager(api_root, username=username, password=password, use_ssl=verify_ssl)

        for entity in siemplify.target_entities:
            try:
                if entity.entity_type not in SUPPORTED_ENTITIES:
                    siemplify.LOGGER.info(u"Entity {} is of unsupported type. Skipping.".format(entity.identifier))
                    continue

                siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))
                matching_endpoints = []

                if entity.entity_type == EntityTypes.HOSTNAME:
                    try:
                        siemplify.LOGGER.info(u"Fetching endpoint for hostname {}".format(entity.identifier))
                        matching_endpoints = endgame_manager.get_endpoint_by_hostname(entity.identifier)
                    except EndgameNotFoundError as e:
                        # Endpoint was not found in Endgame - skip entity
                        missing_entities.append(entity.identifier)
                        siemplify.LOGGER.info(unicode(e))
                        siemplify.LOGGER.info(u"Skipping entity {}".format(entity.identifier))
                        continue

                if entity.entity_type == EntityTypes.ADDRESS:
                    try:
                        siemplify.LOGGER.info(u"Fetching endpoint for address {}".format(entity.identifier))
                        matching_endpoints = endgame_manager.get_endpoint_by_ip(entity.identifier)
                    except EndgameNotFoundError as e:
                        # Endpoint was not found in Endgame - skip entity
                        missing_entities.append(entity.identifier)
                        siemplify.LOGGER.info(unicode(e))
                        siemplify.LOGGER.info(u"Skipping entity {}".format(entity.identifier))
                        continue

                if len(matching_endpoints) > 1:
                    siemplify.LOGGER.info(
                        u"Multiple endpoints matching entity {} were found. First will be used.".format(
                            entity.identifier)
                    )

                # Take the first matching endpoint
                endpoint = matching_endpoints[0]

                if endpoint.core_os.lower() != core_os:
                    siemplify.LOGGER.info(u"Endpoint {} OS doesn't match passed core OS. Skipping.".format(entity.identifier))
                    continue

                if endpoint.sensors:
                    successful_entities.append(entity.identifier)
                    sensor_ids.extend([sensor.id for sensor in endpoint.sensors])

            except Exception as e:
                failed_entities.append(entity.identifier)
                siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            siemplify.LOGGER.info(u"Initiating file hunt task on the following entities: {}".format(
                u"\n   ".join([entity for entity in successful_entities])
            ))

            task_id = endgame_manager.get_task_id(u"iocSearchRequest", core_os)
            task = endgame_manager.create_ioc_file_search_task(
                regexes=regexes,
                with_md5_hash=md5_hashes,
                with_sha1_hash=sha1_hashes,
                with_sha256_hash=sha256_hashes,
                directory=directory
            )

            # By default, the investigation is assigned to the login user
            investigation_id = endgame_manager.create_investigation(
                investigation_name=investigation_name,
                assign_user=username,
                sensor_ids=sensor_ids,
                tasks={task_id: {u'task_list': [task]}},
                core_os=core_os
            )

            siemplify.LOGGER.info(u"Successfully Create investigation with ID {0}".format(investigation_id))

            if successful_entities:
                output_message += u"Successfully initiated file hunt on the following entities:\n   {}".format(
                    u"\n   ".join([entity for entity in successful_entities])
                )

            if missing_entities:
                output_message += u"\n\nThe following entities didn't match an any endpoint and were skipped:\n   {}".format(
                    u"\n   ".join([entity for entity in missing_entities])
                )

            if failed_entities:
                output_message += u"\n\nError occurred while initiating file hunt on the following entities:\n   {}".format(
                    u"\n   ".join([entity for entity in failed_entities])
                )

            output_message += u"\n\nInvestigation ID: {0}. Waiting for investigation to complete.".format(
                investigation_id
            )

            result_value = json.dumps({
                u"investigation_id": investigation_id,
                u"successful_entities": successful_entities,
                u"missing_entities": missing_entities,
                u"failed_entities": failed_entities
            })

            status = EXECUTION_STATE_INPROGRESS

        else:
            # No sensor ids were found
            output_message = u"No suitable endpoints were found. Unable to initiate task."
            result_value = u"false"
            status = EXECUTION_STATE_FAILED

    except Exception as e:
        siemplify.LOGGER.error(u"Action didn't complete due to error: {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Action didn't complete due to error: {}".format(e)

    finally:
        try:
            endgame_manager.logout()
        except Exception as e:
            siemplify.LOGGER.error(u"Logging out failed. Error: {}".format(e))
            siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


def fetch_scan_report_async():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    endgame_common = EndgameCommon(siemplify)
    output_message, return_value, status = endgame_common.fetch_investigation_result()
    siemplify.end(output_message, return_value, status)


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[2] == 'True':
        main()
    else:
        fetch_scan_report_async()
