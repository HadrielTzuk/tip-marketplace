from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, unix_now, convert_unixtime_to_datetime, convert_dict_to_json_result_dict, \
    get_domain_from_entity
from GoogleChronicleManager import GoogleChronicleManager
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from exceptions import InvalidTimeException
import datetime
import consts
import utils
import json


SCRIPT_NAME = "List Assets"
SUPPORTED_ENTITIES = [EntityTypes.ADDRESS, EntityTypes.URL, EntityTypes.FILEHASH]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{consts.INTEGRATION_NAME} - {SCRIPT_NAME}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    creds = extract_configuration_param(siemplify, provider_name=consts.INTEGRATION_NAME,
                                        param_name="User's Service Account",
                                        is_mandatory=True)
    api_root = extract_configuration_param(siemplify, provider_name=consts.INTEGRATION_NAME,
                                           param_name="API Root", is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=consts.INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, print_value=True)

    try:
        creds = json.loads(creds)
    except Exception as e:
        siemplify.LOGGER.error("Unable to parse credentials as JSON.")
        siemplify.LOGGER.exception(e)
        siemplify.end("Unable to parse credentials as JSON. Please validate creds.", "false", EXECUTION_STATE_FAILED)

    max_hours_backwards = extract_action_param(siemplify, param_name="Max Hours Backwards", is_mandatory=False,
                                               print_value=True, default_value=consts.MAX_HOURS_BACKWARDS,
                                               input_type=int)
    limit = extract_action_param(siemplify, param_name="Max Assets To Return", is_mandatory=False, print_value=True,
                                 default_value=consts.LIMIT, input_type=int)
    timeframe = extract_action_param(siemplify, param_name="Time Frame", is_mandatory=False, print_value=True)
    start_time_string = extract_action_param(siemplify, param_name="Start Time", is_mandatory=False, print_value=True)
    end_time_string = extract_action_param(siemplify, param_name="End Time", is_mandatory=False, print_value=True)

    if limit < 0:
        siemplify.LOGGER.info(f"\"Max Assets To Return\" must be non-negative. Using default of {consts.LIMIT}.")
        limit = consts.LIMIT

    if max_hours_backwards < 0:
        siemplify.LOGGER.info(f"\"Max Hours Backwards\" must be non-negative. Using default of {consts.MAX_HOURS_BACKWARDS}.")
        max_hours_backwards = consts.MAX_HOURS_BACKWARDS

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    successful_entities = []
    missing_entities = []
    failed_entities = []
    json_results = {}
    output_message = ""
    result_value = "false"

    try:
        manager = GoogleChronicleManager(api_root=api_root, verify_ssl=verify_ssl, **creds)

        if timeframe == consts.HOURS_BACKWARDS_STRING:
            end_time = datetime.datetime.utcnow()
            start_time = end_time - datetime.timedelta(hours=max_hours_backwards)

            # Convert to RFC 3339
            end_time = utils.datetime_to_rfc3339(end_time)
            start_time = utils.datetime_to_rfc3339(start_time)
        else:
            start_time, end_time = utils.get_timestamps(timeframe, start_time_string, end_time_string)

        for entity in siemplify.target_entities:
            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error("Timed out. execution deadline ({}) has passed".format(
                    convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                status = EXECUTION_STATE_TIMEDOUT
                break

            try:
                if entity.entity_type not in SUPPORTED_ENTITIES:
                    siemplify.LOGGER.info("Entity {} is of unsupported type. Skipping.".format(entity.identifier))
                    continue

                siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))
                siemplify.LOGGER.info("Fetching assets for {}".format(entity.identifier))

                assets = []
                uri = []

                if entity.entity_type == EntityTypes.ADDRESS:
                    uri, assets = manager.list_assets(start_time=start_time, end_time=end_time, ip=entity.identifier,
                                                 limit=limit)

                elif entity.entity_type == EntityTypes.URL:
                    domain = get_domain_from_entity(entity)
                    uri, assets = manager.list_assets(start_time=start_time, end_time=end_time, domain=domain, limit=limit)

                elif entity.entity_type == EntityTypes.FILEHASH:
                    if len(entity.identifier) not in [consts.SHA256_LENGTH, consts.MD5_LENGTH, consts.SHA1_LENGTH]:
                        siemplify.LOGGER.error(u"Not supported hash type. Provide either MD5, SHA-256 or SHA-1.")
                        siemplify.LOGGER.info(u"Finished processing entity {}".format(entity.identifier))
                        continue
                    uri, assets = manager.list_assets(start_time=start_time, end_time=end_time, file_hash=entity.identifier,
                                                 limit=limit)

                siemplify.LOGGER.info("Found {} assets for {}".format(len(assets), entity.identifier))

                json_results[entity.identifier] = {"assets": [asset.raw_data for asset in assets], "uri": uri}

                if assets:
                    siemplify.result.add_entity_table(entity.identifier,
                                                      construct_csv([asset.as_csv() for asset in assets]))
                    successful_entities.append(entity)

                else:
                    missing_entities.append(entity)
                siemplify.LOGGER.info("Finished processing entity {0}".format(entity.identifier))

            except Exception as e:
                failed_entities.append(entity)
                siemplify.LOGGER.error("An error occurred on entity {0}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message += "Successfully listed related assets for the following entities from Google Chronicle:\n   {}\n\n".format(
                "\n   ".join([entity.identifier for entity in successful_entities])
            )
            siemplify.update_entities(successful_entities)
            result_value = "true"

        if missing_entities:
            output_message += "No related assets were found for the following entities from Google Chronicle:\n   {}\n\n".format(
                "\n   ".join([entity.identifier for entity in missing_entities])
            )
            result_value = "true"

        if not successful_entities and not missing_entities:
            output_message += "No assets were found for the provided entities.\n\n"

        if failed_entities:
            output_message += "Action was not able to list related assets for the following entities from Google Chronicle:\n   {}".format(
                "\n   ".join([entity.identifier for entity in failed_entities])
            )

    except InvalidTimeException:
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{SCRIPT_NAME}\". Reason: \"Start Time\" " \
                         f"should be provided, when \"Custom\" is selected in \"Time Frame\" parameter."

    except Exception as e:
        siemplify.LOGGER.error(f"Error executing action \"{SCRIPT_NAME}\". Reason: {e}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = f"Error executing action \"{SCRIPT_NAME}\". Reason: {e}"

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)



if __name__ == "__main__":
    main()
