from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from FireEyeHXManager import FireEyeHXManager, FireEyeHXNotFoundError
from TIPCommon import extract_configuration_param, extract_action_param


INTEGRATION_NAME = u"FireEyeHX"
SCRIPT_NAME = u"Contain Host"
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

    approve = extract_action_param(siemplify, param_name=u"Approve Containment", is_mandatory=False,
                                          input_type=bool, print_value=True, default_value=False)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    successful_entities = []
    missing_entities = []
    failed_entities = []
    multimatch_entities = []
    output_message = u""
    result_value = u"false"

    try:
        hx_manager = FireEyeHXManager(api_root=api_root, username=username, password=password, verify_ssl=verify_ssl)

        for entity in siemplify.target_entities:
            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error(u"Timed out. execution deadline ({}) has passed".format(
                    convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                status = EXECUTION_STATE_TIMEDOUT
                break

            try:
                if entity.entity_type not in SUPPORTED_ENTITIES:
                    siemplify.LOGGER.info(u"Entity {} is of unsupported type. Skipping.".format(entity.identifier))
                    continue

                siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))
                matching_hosts = []

                if entity.entity_type == EntityTypes.HOSTNAME:
                    siemplify.LOGGER.info(u"Fetching host for hostname {}".format(entity.identifier))
                    matching_hosts = hx_manager.get_hosts(host_name=entity.identifier)

                elif entity.entity_type == EntityTypes.ADDRESS:
                    siemplify.LOGGER.info(u"Fetching host for address {}".format(entity.identifier))
                    matching_hosts = hx_manager.get_hosts_by_ip(ip_address=entity.identifier)

                if len(matching_hosts) > 1:
                    siemplify.LOGGER.info(
                        u"Multiple hosts matching entity {} were found. First will be used.".format(
                            entity.identifier)
                    )
                    multimatch_entities.append(entity)

                if not matching_hosts:
                    siemplify.LOGGER.info(u"Matching host was not found for entity.".format(entity.identifier))
                    missing_entities.append(entity)
                    continue

                # Take endpoint with the most recent last_poll_timestamp
                host = sorted(matching_hosts, key=lambda matching_host: matching_host.last_poll_timestamp)[-1]
                siemplify.LOGGER.info(u"Matching host was found for {}".format(entity.identifier))

                siemplify.LOGGER.info(u"Initiating containment of host {} ({})".format(host._id, entity.identifier))
                hx_manager.contain_host_by_id(host._id, approve=approve)

                successful_entities.append(entity)
                siemplify.LOGGER.info(u"Finished processing entity {0}".format(entity.identifier))

            except Exception as e:
                failed_entities.append(entity)
                siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message += u"Successfully created contain host task for the following entities:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in successful_entities])
            )
            result_value = u"true"

        else:
            output_message += u"No tasks were created."
            result_value = u"false"

        if multimatch_entities:
            output_message += u"Multiple matches were found in FireEye HX, " \
                              u"taking the agent info with the most recent last poll time value " \
                              u"for the following entities:/n {0}" \
                .format(u"\n   ".join([entity.identifier for entity in multimatch_entities]))

        if missing_entities:
            output_message += u"\n\nAction was not able to find matching FireEye HX agent for the following entities:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in missing_entities])
            )

        if failed_entities:
            output_message += u"\n\nFailed processing the following entities:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in failed_entities])
            )

    except Exception as e:
        siemplify.LOGGER.error(u"Failed to execute action! Error is {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Failed to execute action! Error is {}".format(e)

    finally:
        try:
            hx_manager.logout()
        except Exception as e:
            siemplify.LOGGER.error(u"Logging out failed. Error: {}".format(e))
            siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
