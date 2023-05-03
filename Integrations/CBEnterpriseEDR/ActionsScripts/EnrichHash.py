from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler, \
    convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from CBEnterpriseEDRManager import CBEnterpriseEDRManager, CBEnterpriseEDRUnauthorizedError, \
    CBEnterpriseEDRNotFoundError
from TIPCommon import extract_configuration_param

INTEGRATION_NAME = u"CBEnterpriseEDR"
SCRIPT_NAME = u"Enrich Hash"
SUPPORTED_ENTITIES = [EntityTypes.FILEHASH]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           is_mandatory=True, input_type=unicode)
    org_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Organization Key",
                                          is_mandatory=True, input_type=unicode)
    api_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API ID",
                                         is_mandatory=True, input_type=unicode)
    api_secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name=u"API Secret Key",
                                                 is_mandatory=True, input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    successful_entities = []
    json_results = {}
    failed_entities = []
    missing_entities = []
    partially_enriched_entities = []
    output_message = u""

    try:
        cb_edr_manager = CBEnterpriseEDRManager(api_root, org_key, api_id, api_secret_key, verify_ssl)

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

                if len(entity.identifier) != 64:
                    siemplify.LOGGER.info(u"Hash {} is not of type sha256. Skipping.".format(entity.identifier))
                    continue

                siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))

                not_found = False
                failed = False
                hash_metadata = {}
                hash_summary = {}

                try:
                    siemplify.LOGGER.info(u"Fetching hash metadata for entity {}".format(entity.identifier))
                    hash_metadata = cb_edr_manager.get_filehash_metadata(entity.identifier)
                    siemplify.LOGGER.info(u"Hash metadata was found for entity {}".format(entity.identifier))
                    entity.additional_properties.update(hash_metadata.as_enrichment_data())
                    entity.is_enriched = True

                except CBEnterpriseEDRNotFoundError:
                    not_found = True
                    siemplify.LOGGER.info(u"No metadata was found for hash {}".format(entity.identifier))

                except CBEnterpriseEDRUnauthorizedError as e:
                    # Unauthorized - invalid credentials were passed. Terminate action
                    siemplify.LOGGER.error(u"Failed to execute Enrich Entities action! Error is {}".format(e))
                    siemplify.end(u"Failed to execute Enrich Entities action! Error is {}".format(e), u"false",
                                  EXECUTION_STATE_FAILED)

                except Exception as e:
                    siemplify.LOGGER.error(u"Unable to fetch metadata for hash {}".format(entity.identifier))
                    siemplify.LOGGER.exception(e)
                    failed = True

                try:
                    siemplify.LOGGER.info(u"Trying to get hash summary for entity {}".format(entity.identifier))
                    hash_summary = cb_edr_manager.get_filehash_summary(entity.identifier)
                    siemplify.LOGGER.info(u"Hash summary was found for entity {}".format(entity.identifier))
                    entity.additional_properties.update(hash_summary.as_enrichment_data())
                    entity.is_enriched = True

                except CBEnterpriseEDRNotFoundError:
                    not_found = True
                    siemplify.LOGGER.info(u"No summary was found for hash {}".format(entity.identifier))

                except CBEnterpriseEDRUnauthorizedError as e:
                    # Unauthorized - invalid credentials were passed. Terminate action
                    siemplify.LOGGER.error(u"Failed to execute Enrich Entities action! Error is {}".format(e))
                    siemplify.end(u"Failed to execute Enrich Entities action! Error is {}".format(e), u"false",
                                  EXECUTION_STATE_FAILED)
                    failed = True

                except Exception as e:
                    siemplify.LOGGER.error(u"Unable to fetch summary for hash {}".format(entity.identifier))
                    siemplify.LOGGER.exception(e)

                if not (hash_metadata or hash_summary):
                    if not_found:
                        missing_entities.append(entity)
                    elif failed:
                        failed_entities.append(entity)

                else:
                    if hash_summary and hash_metadata:
                        successful_entities.append(entity)

                    else:
                        # Entity got enriched by at least one request
                        partially_enriched_entities.append(entity)

                    json_results[entity.identifier] = {}

                    if hash_metadata:
                        json_results[entity.identifier].update(hash_metadata.raw_data)

                    if hash_summary:
                        json_results[entity.identifier].update(hash_summary.raw_data)

                siemplify.LOGGER.info(u"Finished processing entity {0}".format(entity.identifier))

            except CBEnterpriseEDRUnauthorizedError as e:
                # Unauthorized - invalid credentials were passed. Terminate action
                siemplify.LOGGER.error(u"Failed to execute Enrich Entities action! Error is {}".format(e))
                siemplify.end(u"Failed to execute Enrich Entities action! Error is {}".format(e), u"false",
                              EXECUTION_STATE_FAILED)

            except Exception as e:
                failed_entities.append(entity)
                siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message += u"Successfully enriched entities:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in successful_entities])
            )
            siemplify.update_entities(successful_entities)
            result_value = u"true"

        else:
            output_message += u"No entities were enriched."
            result_value = u"false"

        if partially_enriched_entities:
            output_message += u"\n\nThe following entities were partially enriched because of the errors getting entity data:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in partially_enriched_entities])
            )

        if missing_entities:
            output_message += u"\n\nAction was not able to find VMware Carbon Black Enterprise EDR info to enrich the following entities\n   {}".format(
                u"\n   ".join([entity.identifier for entity in missing_entities])
            )

        if failed_entities:
            output_message += u"\n\nFailed enriching the following entities:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in failed_entities])
            )

    except Exception as e:
        siemplify.LOGGER.error(u"Failed to execute Enrich Entities action! Error is {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Failed to execute Enrich Entities action! Error is {}".format(e)

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == u"__main__":
    main()
