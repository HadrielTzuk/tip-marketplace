from SiemplifyUtils import output_handler, unix_now, convert_unixtime_to_datetime
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from TIPCommon import extract_configuration_param, extract_action_param
from CarbonBlackDefenseManager import CBDefenseManager, CBDefenseManagerException


INTEGRATION_NAME = "CBDefense"
SCRIPT_NAME = "Change Policy"
SUPPORTED_ENTITIES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           is_mandatory=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key",
                                          is_mandatory=True)

    policy_name = extract_action_param(siemplify, param_name='Policy Name', print_value=True, is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    successful_entities = []
    missing_entities = []
    failed_entities = []
    output_message = u""
    result_value = "true"

    try:
        siemplify.LOGGER.info("Connecting to Carbon Black Defense.")
        cb_defense = CBDefenseManager(api_root, api_key)
        cb_defense.test_connectivity()

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

                siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))

                siemplify.LOGGER.info(f"Fetching device data for {entity.identifier}.")
                device_data = None

                if entity.entity_type == EntityTypes.ADDRESS:
                    device_data = cb_defense.get_device_data_by_ip(entity.identifier)

                elif entity.entity_type == EntityTypes.HOSTNAME:
                    device_data = cb_defense.get_device_data_by_hostname(entity.identifier)

                if device_data:
                    siemplify.LOGGER.info(f"Device data was found for {entity.identifier}.")
                    device_id = device_data.device_id

                    siemplify.LOGGER.info(f"Updating device {device_id} for policy {policy_name}.")
                    cb_defense.change_policy(device_id, policy_name)

                    successful_entities.append(entity)

                else:
                    siemplify.LOGGER.info(f"No device data was found for {entity.identifier}")
                    missing_entities.append(entity)

            except CBDefenseManagerException:
                # Device was not found for this entity in CB(get_device_data_by_ip)
                # and get_device_data_by_hostname raise CBDefenseManagerException
                # if no device is found) - entity is irrelevant, continue.
                siemplify.LOGGER.info(f"No device data was found for {entity.identifier}")
                missing_entities.append(entity)
                continue

            except Exception as e:
                failed_entities.append(entity)
                siemplify.LOGGER.error(u"An error occurred on entity {}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message += u"Policy changed for the following entities:\n   {}\n\n".format(
                u"\n   ".join([entity.identifier for entity in successful_entities])
            )

        else:
            output_message += u"No suitable entities found.\n\n"

        if missing_entities:
            output_message += u"Action was not able to find device data for the following entities:\n   {}\n\n".format(
                u"\n   ".join([entity.identifier for entity in missing_entities])
            )

        if failed_entities:
            output_message += u"Failed changing the policy the following entities:\n   {}\n\n".format(
                u"\n   ".join([entity.identifier for entity in failed_entities])
            )

    except Exception as e:
        siemplify.LOGGER.error("General error occurred while running action {}. Error: {}".format(SCRIPT_NAME, e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = "An error occurred while running action. Error: {}".format(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
