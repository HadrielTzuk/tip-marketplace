from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from APIVoidManager import APIVoidManager, APIVoidNotFound, APIVoidInvalidAPIKeyError
from ScriptResult import EXECUTION_STATE_FAILED, EXECUTION_STATE_COMPLETED
from SiemplifyUtils import convert_dict_to_json_result_dict
from TIPCommon import extract_configuration_param, extract_action_param, flat_dict_to_csv, add_prefix_to_dict
import re

INTEGRATION_NAME = u"APIVoid"
SCRIPT_NAME = u"Verify Email"
SUPPORTED_ENTITIES = [EntityTypes.USER]


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
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    threshold = extract_action_param(siemplify, param_name=u"Threshold", is_mandatory=False,
                                     input_type=int, default_value=0,
                                     print_value=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    result_value = u"true"
    enriched_entities = []
    missing_entities = []
    failed_entities = []
    json_results = {}
    output_message = u""
    status = EXECUTION_STATE_COMPLETED

    try:
        apivoid_manager = APIVoidManager(api_root, api_key, verify_ssl=verify_ssl)

        for entity in siemplify.target_entities:
            try:
                if entity.entity_type not in SUPPORTED_ENTITIES:
                    siemplify.LOGGER.info(u"Entity {} is of unsupported type. Skipping.".format(entity.identifier))
                    continue

                siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))

                if not (re.search(ur'^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$', entity.identifier)):
                    siemplify.LOGGER.info(u"{} doesn't seem to be an email. Skipping".format(entity.identifier))
                    continue

                email_info_obj = apivoid_manager.get_email_info(entity.identifier)
                enrichment_data = email_info_obj.as_enrichment_data()

                siemplify.LOGGER.info(u"Enriching entity {}".format(entity.identifier))
                enrichment_data = add_prefix_to_dict(enrichment_data, INTEGRATION_NAME)
                entity.additional_properties.update(enrichment_data)

                siemplify.LOGGER.info(u"Adding email information table for entity {}".format(entity.identifier))
                siemplify.result.add_data_table(
                    entity.identifier,
                    flat_dict_to_csv(email_info_obj.as_csv())
                    )

                json_results[entity.identifier] = email_info_obj.raw_data

                if email_info_obj.score > int(threshold):
                    siemplify.LOGGER.info(u"Entity {} has score of {}. Marking as suspicious.".format(
                        entity.identifier,
                        email_info_obj.score
                    ))
                    entity.is_suspicious = True

                entity.is_enriched = True
                enriched_entities.append(entity)

            except APIVoidNotFound as e:
                siemplify.LOGGER.error(e)
                missing_entities.append(entity)

            except APIVoidInvalidAPIKeyError as e:
                siemplify.LOGGER.error(e)
                raise APIVoidInvalidAPIKeyError(u"API key is invalid.")

            except Exception as e:
                failed_entities.append(entity)
                # An error occurred - skip entity and continue
                siemplify.LOGGER.error(u"An error occurred on entity: {}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if enriched_entities:
            output_message = u"APIVoid: Fetched information for the following entities:\n   {}\n\n".format(
                u"\n   ".join([entity.identifier for entity in enriched_entities])
            )

            siemplify.update_entities(enriched_entities)

        if failed_entities:
            output_message += u"An error occurred on the following entities:\n   {}\n\n".format(
                u"\n   ".join([entity.identifier for entity in failed_entities])
            )

        if missing_entities:
            output_message += u"Could not find information for the following entities:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in missing_entities])
            )

        if not (enriched_entities or failed_entities or missing_entities):
            output_message = u"APIVoid: No emails were found."
            result_value = u"false"

    except Exception as e:
        siemplify.LOGGER.error(u"Action didn't complete due to error: {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Action didn't complete due to error: {}".format(e)

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
