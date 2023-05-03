from SiemplifyUtils import output_handler
from ShodanManager import ShodanManager, ShodanIPNotFoundException
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_TIMEDOUT, EXECUTION_STATE_FAILED
from SiemplifyUtils import convert_dict_to_json_result_dict, unix_now, convert_unixtime_to_datetime
from TIPCommon import flat_dict_to_csv, dict_to_flat
from SiemplifyDataModel import EntityTypes
from TIPCommon import extract_configuration_param, extract_action_param

INTEGRATION_NAME = u"Shodan"
SCRIPT_NAME = u"Get IP Info"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)

    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API key",
                                           is_mandatory=True, input_type=unicode)

    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    history = extract_action_param(siemplify, param_name=u"Return Historical Banners", is_mandatory=False, input_type=bool,
                                      print_value=True, default_value=False)
    minify = extract_action_param(siemplify, param_name=u"Set Minify", is_mandatory=False, input_type=bool,
                                      print_value=True, default_value=False)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    shodan = ShodanManager(api_key, verify_ssl=verify_ssl)

    errors = False
    status = EXECUTION_STATE_COMPLETED
    json_results = {}
    successful_entities = []
    missing_entities = []
    failed_entities = []
    result_value = u'false'

    try:

        for entity in siemplify.target_entities:
            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error(u"Timed out. execution deadline ({}) has passed".format(
                    convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                status = EXECUTION_STATE_TIMEDOUT
                break

            if entity.entity_type == EntityTypes.ADDRESS:
                try:
                    siemplify.LOGGER.info(u"Processing entity {}".format(entity.identifier))
                    ip_info = shodan.get_ip_info(entity.identifier, history=history, minify=minify)

                    if ip_info:
                        siemplify.LOGGER.info(u"Found information for entity {}".format(entity.identifier))
                        json_results[entity.identifier] = ip_info

                        # Add csv table
                        siemplify.LOGGER.info(u"Adding CSV table for {}".format(entity.identifier))
                        flat_report = dict_to_flat(ip_info)
                        csv_output = flat_dict_to_csv(flat_report)
                        siemplify.result.add_entity_table(entity.identifier, csv_output)

                        # enrich
                        if not minify:
                            domains_list = ip_info.get(u"data")[0].get(u"domains")
                        else:
                            domains_list = ip_info.get(u"domains")
                        domains = u",".join(domains_list)
                        entity.additional_properties.update({u"Shodan_Country": ip_info.get(u'country_name'),
                                                             u"Shodan_Last_updated": ip_info.get(u'last_update'),
                                                             u"Shodan_Domains": domains})
                        entity.is_enriched = True
                        successful_entities.append(entity)

                    else:
                        siemplify.LOGGER.info(u"No information was found for entity {}".format(entity.identifier))

                    siemplify.LOGGER.info(u"Finished processing entity {}".format(entity.identifier))

                except ShodanIPNotFoundException:
                    # Entity not found
                    siemplify.LOGGER.error(u"Entity {} was not found in Shodan.".format(entity.identifier))
                    missing_entities.append(entity)

                except Exception as e:
                    # An error occurred - skip entity and continue
                    siemplify.LOGGER.error(u"An error occurred on entity: {}\n{}.".format(entity.identifier, e))
                    siemplify.LOGGER.exception(e)
                    failed_entities.append(entity)

        if successful_entities:
            output_message = u"The following IPs were submitted and analyzed in Shodan:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in successful_entities])
            )
            siemplify.update_entities(successful_entities)
            result_value = u'true'

        else:
            output_message = u"No entities were enriched."

        if missing_entities:
            output_message += u"\n\nThe following entities were not found in Shodan:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in missing_entities])
            )

        if failed_entities:
            output_message += u"\n\nFailed enriching the following entities:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in failed_entities])
            )

    except Exception as e:
        siemplify.LOGGER.error(u"General error occurred while running action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"An error occurred while running action. Error: {}".format(e)

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
