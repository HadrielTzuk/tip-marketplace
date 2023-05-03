from SiemplifyUtils import output_handler, unix_now, convert_unixtime_to_datetime
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from ActiveDirectoryManager import ActiveDirectoryManager

# =====================================
#             CONSTANTS               #
# =====================================
INTEGRATION_NAME = "ActiveDirectory"
SCRIPT_NAME = "ActiveDirectory - ChangeHostOU"

SUPPORTED_ENTITY_TYPES = [EntityTypes.HOSTNAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    output_message = ""
    result_value = False
    successful_entities = []
    failed_entities = []
    status = EXECUTION_STATE_COMPLETED

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATIONS:
    server = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, is_mandatory=True, param_name="Server", input_type=str
    )
    username = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, is_mandatory=True, param_name="Username", input_type=str
    )
    password = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, is_mandatory=True, param_name="Password", input_type=str
    )
    domain = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, is_mandatory=True, param_name="Domain", input_type=str
    )
    use_ssl = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, is_mandatory=True, param_name="Use SSL", input_type=bool
    )
    custom_query_fields = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, param_name="Custom Query Fields", input_type=str
    )
    ca_certificate = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, param_name="CA Certificate File - parsed into Base64 String"
    )

    # INIT ACTION CONFIGURATIONS:
    ou_name = extract_action_param(
        siemplify, param_name="OU Name", is_mandatory=True, input_type=str, print_value=True
    )

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    try:
        manager = ActiveDirectoryManager(server, domain, username, password, use_ssl, custom_query_fields,
                                         ca_certificate, siemplify.LOGGER)
        target_entities = [
            entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES
        ]
        if target_entities:
            for entity in target_entities:
                siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))
                if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                    siemplify.LOGGER.error("Timed out. execution deadline ({}) has passed".format(
                        convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                    status = EXECUTION_STATE_TIMEDOUT
                    break
                try:
                    manager.change_host_ou(entity.identifier, ou_name)
                    successful_entities.append(entity)
                    siemplify.LOGGER.info("Finished processing entity {0}".format(entity.identifier))
                except Exception as e:
                    output_message += "Unable to change OU for entity {}: \n".format(entity.identifier)
                    failed_entities.append(entity)
                    siemplify.LOGGER.error("An error occurred on entity {0}".format(entity.identifier))
                    siemplify.LOGGER.exception(e)
            if successful_entities:
                output_message += "Active Directory - Changed OU for following host:\n   {} \n".format(
                    "\n   ".join([entity.identifier for entity in successful_entities])
                )
                result_value = True
            else:
                siemplify.LOGGER.info("\n No entities were processed.")
                output_message = "No entities were processed."
            if failed_entities:
                output_message += "\nFailed processing entities:\n   {}".format(
                    "\n   ".join([entity.identifier for entity in failed_entities])
                )
        else:
            output_message = "No suitable entities found.\n"

    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}. Error: {}".format(SCRIPT_NAME, e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = "General error performing action {}. Error: {}".format(SCRIPT_NAME, e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        "\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
