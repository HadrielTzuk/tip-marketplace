from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED
from SandBlastManager import SandBlastManager
import datamodels
import exceptions
import consts
from TIPCommon import extract_configuration_param, extract_action_param


SCRIPT_NAME = 'Upload File'
INTEGRATION_NAME = 'CheckPointSandBlast'
SUPPORTED_ENTITIES = [EntityTypes.FILEHASH]
FEATURES = [datamodels.Features.THREAT_EMULATION, datamodels.Features.ANTI_VIRUS]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Key",
                                          is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool)
    threshold = extract_action_param(siemplify, param_name='Threshold', input_type=int, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    completed_scans = []

    failed_entities = []
    successful_entities = []
    partially_successful_entities = []
    not_found_entities = []

    output_message = ""
    result_value = "false"
    json_results = {}
    status = EXECUTION_STATE_COMPLETED

    all_finished = True

    try:
        manager = SandBlastManager(api_root, api_key, verify_ssl)

        for entity in siemplify.target_entities:
            try:
                if entity.entity_type not in SUPPORTED_ENTITIES:
                    siemplify.LOGGER.info("Entity {} is of unsupported type. Skipping.".format(entity.identifier))
                    continue

                siemplify.LOGGER.info("Querying status of {}".format(entity.identifier))

                try:
                    manager.get_hash_type(entity.identifier)  # Validate hash type is supported
                except exceptions.SandBlastValidationError as e:
                    siemplify.LOGGER.error(e)
                    continue

                query_result = manager.query(entity.identifier, FEATURES)

                siemplify.LOGGER.info("{} query status: {}".format(entity.identifier, query_result.status.label))

                if manager.is_scan_running(query_result):
                    # Scan of the hash is still running - we need to wait until it will reach a terminal state
                    siemplify.LOGGER.info("{} query has not completed yet.".format(entity.identifier))
                    all_finished = False
                    break

                else:
                    completed_scans.append((entity, query_result))

            except Exception as e:
                # In Check Point Sandblast - an exception means a critical error, so we should terminate.
                output_message = "Unable to get query info for {}. Error: {}".format(entity.identifier, e)
                siemplify.LOGGER.error(output_message)
                siemplify.LOGGER.exception(e)

                status = EXECUTION_STATE_FAILED
                result_value = "false"

                siemplify.LOGGER.info("----------------- Main - Finished -----------------")
                siemplify.LOGGER.info("Status: {}:".format(status))
                siemplify.LOGGER.info("Result Value: {}".format(result_value))
                siemplify.LOGGER.info("Output Message: {}".format(output_message))
                siemplify.end(output_message, result_value, status)

        if not all_finished:
            output_message = "Some scans are in progress. Waiting for completion."
            status = EXECUTION_STATE_INPROGRESS
            result_value = "false"

            siemplify.LOGGER.info("----------------- Main - Finished -----------------")
            siemplify.LOGGER.info("Status: {}:".format(status))
            siemplify.LOGGER.info("Result Value: {}".format(result_value))
            siemplify.LOGGER.info("Output Message: {}".format(output_message))
            siemplify.end(output_message, result_value, status)

        siemplify.LOGGER.info("All scans have completed.")

        for (entity, query_result) in completed_scans:
            if query_result.status.code == datamodels.StatusCodes.FOUND:
                successful_entities.append(entity)

            elif query_result.status.code == datamodels.StatusCodes.PARTIALLY_FOUND:
                partially_successful_entities.append(entity)

            elif query_result.status.code == datamodels.StatusCodes.NOT_FOUND:
                not_found_entities.append(entity)

            else:
                failed_entities.append(entity)

            if query_result.te_response:
                # Threat Emulation response is available - enrich if needed
                if query_result.te_response.status.code in [datamodels.StatusCodes.FOUND,
                                                            datamodels.StatusCodes.PARTIALLY_FOUND]:
                    siemplify.LOGGER.info("Enriching {} with {} information.".format(
                        entity.identifier, datamodels.Features.THREAT_EMULATION
                    ))
                    entity.additional_properties.update(query_result.te_response.as_enrichment())
                    entity.is_enriched = True

                if query_result.te_response.combined_verdict == consts.MALICIOUS_VERDICT:
                    siemplify.LOGGER.info("{} verdict is malicious. Marking as suspicious.".format(
                        entity.identifier
                    ))
                    entity.is_suspicious = True

            if query_result.av_response:
                # Antivirus response is available - enrich if needed
                if query_result.av_response.status.code in [datamodels.StatusCodes.FOUND,
                                                            datamodels.StatusCodes.PARTIALLY_FOUND]:
                    siemplify.LOGGER.info("Enriching {} with {} information.".format(
                        entity.identifier, datamodels.Features.ANTI_VIRUS
                    ))
                    entity.additional_properties.update(query_result.av_response.as_enrichment())
                    entity.is_enriched = True

                if query_result.av_response.malware_info and query_result.av_response.malware_info.severity >= threshold:
                    siemplify.LOGGER.info("{} severity is greater than {}. Marking as suspicious.".format(
                        threshold,
                        entity.identifier
                    ))
                    entity.is_suspicious = True

            json_results[entity.identifier] = query_result.raw_data

        if successful_entities:
            output_message = "Successfully found info the following entities:\n   {}\n\n".format(
                "\n   ".join([entity.identifier for entity in successful_entities])
            )
            siemplify.update_entities(successful_entities)
            result_value = "true"

        if partially_successful_entities:
            output_message += "Partial information was found for the following entities:\n   {}\nIf the missing data is required, please upload the matching files.\n\n".format(
                "\n   ".join([entity.identifier for entity in partially_successful_entities])
            )
            siemplify.update_entities(partially_successful_entities)
            result_value = "true"

        if not_found_entities:
            output_message += "No information was found for the following entities:\n   {}\n\n".format(
                "\n   ".join([entity.identifier for entity in not_found_entities])
            )
            siemplify.update_entities(not_found_entities)

        if failed_entities:
            output_message += "Failed to fetch information for the following entities:\n   {}\n\n".format(
                "\n   ".join([entity.identifier for entity in not_found_entities])
            )
            siemplify.update_entities(failed_entities)

        if not (successful_entities or partially_successful_entities or failed_entities or not_found_entities):
            output_message += "No entities were enriched.\n\n"

    except Exception as e:
        siemplify.LOGGER.error("General error occurred while running action {}. Error: {}".format(SCRIPT_NAME, e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = "An error occurred while running action. Error: {}".format(e)

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
