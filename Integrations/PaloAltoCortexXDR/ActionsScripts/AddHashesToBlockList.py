from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from XDRManager import XDRManager, XDRAlreadyExistsException
from TIPCommon import extract_configuration_param, extract_action_param


INTEGRATION_NAME = u"PaloAltoCortexXDR"
SCRIPT_NAME = u"Add Hashes to Block List"
SUPPORTED_ENTITIES = [EntityTypes.FILEHASH]
SUCCESSFUL = u"success"
FAILED = u"failed"
ALREADY_EXISTED = u"already_existed"
UNSUPPORTED = u"unsupported"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Root",
                                           is_mandatory=True, input_type=unicode)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Key",
                                          is_mandatory=True, input_type=unicode)
    api_key_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Key ID",
                                             is_mandatory=True, input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    comment = extract_action_param(siemplify, param_name=u"Comment", default_value=None, input_type=unicode,
                                   is_mandatory=False)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    successful_entities = []
    failed_entities = []
    duplicate_entities = []
    unsupported_hashes_entities = []
    output_messages = []
    result_value = False
    json_results = {
        SUCCESSFUL: [],
        FAILED: [],
        ALREADY_EXISTED: [],
        UNSUPPORTED: []
    }

    try:
        xdr_manager = XDRManager(api_root, api_key, api_key_id, verify_ssl)

        for entity in siemplify.target_entities:
            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error(u"Timed out. execution deadline ({}) has passed".format(
                    convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                status = EXECUTION_STATE_TIMEDOUT
                break

            siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))
            try:
                if entity.entity_type not in SUPPORTED_ENTITIES:
                    siemplify.LOGGER.info(u"Entity {} is of unsupported type. Skipping.".format(entity.identifier))
                    continue

                if not xdr_manager.is_sha256(entity.identifier):
                    siemplify.LOGGER.info(u"Entity {} is not a valid SHA256 hash. Skipping.".format(entity.identifier))
                    unsupported_hashes_entities.append(entity)
                    continue

                siemplify.LOGGER.info(u"Adding hash {} to Block List".format(entity.identifier))
                xdr_manager.add_hash_to_block_list(entity.identifier, comment)

                successful_entities.append(entity)

            except XDRAlreadyExistsException as e:
                duplicate_entities.append(entity)
                siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

            except Exception as e:
                failed_entities.append(entity)
                siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

            siemplify.LOGGER.info(u"Finished processing entity {0}".format(entity.identifier))

        if successful_entities:
            output_messages.append(u"Successfully added the following entities to the Block List:\n{}".format(
                u"\n".join([entity.identifier for entity in successful_entities])
            ))
            result_value = True
            json_results[SUCCESSFUL] = [entity.identifier for entity in successful_entities]
        else:
            output_messages.append(u"No entities were added to Block List.")

        if failed_entities:
            output_messages.append(u"Could not add the following entities to the Block List:\n{}".format(
                u"\n".join([entity.identifier for entity in failed_entities])
            ))
            json_results[FAILED] = [entity.identifier for entity in failed_entities]

        if duplicate_entities:
            output_messages.append(u"The following entities already exist in the Block List:\n{}".format(
                u"\n".join([entity.identifier for entity in duplicate_entities])
            ))
            json_results[ALREADY_EXISTED] = [entity.identifier for entity in duplicate_entities]

        if unsupported_hashes_entities and not (successful_entities or failed_entities or duplicate_entities):
            output_messages.append(u"None of the provided hashes are supported.")
            json_results[UNSUPPORTED] = [entity.identifier for entity in unsupported_hashes_entities]
        elif unsupported_hashes_entities:
            output_messages.append(u"The following hashes are unsupported:\n{}".format(
                u"\n".join([entity.identifier for entity in unsupported_hashes_entities])
            ))
            json_results[UNSUPPORTED] = [entity.identifier for entity in unsupported_hashes_entities]

        output_message = u'\n'.join(output_messages)

        if any(json_results.values()):
            siemplify.result.add_result_json(json_results)

    except Exception as e:
        siemplify.LOGGER.error(u"Action didn't complete due to error: {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        output_message = u"Failed to perform action {}. Reason: {}".format(SCRIPT_NAME, e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
