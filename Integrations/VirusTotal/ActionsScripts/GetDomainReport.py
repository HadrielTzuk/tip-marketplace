from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import get_domain_from_entity, flat_dict_to_csv, add_prefix_to_dict, \
    convert_dict_to_json_result_dict, unix_now, convert_unixtime_to_datetime, output_handler
from TIPCommon import extract_configuration_param
from VirusTotal import VirusTotalManager, VirusTotalInvalidAPIKeyManagerError, VirusTotalLimitManagerError

# Consts
DOMAIN_RESULT_URL_FORMAT = u'https://www.virustotal.com/#/domain/{0}'
VT_PREFIX = u'VT'
SCRIPT_NAME = u'VirusTotal - GetDomainReport'
IDENTIFIER = u'VirusTotal'
SCAN_REPORT = u'Score Report'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_key = extract_configuration_param(siemplify, provider_name=IDENTIFIER, param_name=u"Api Key",
                                          input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=IDENTIFIER, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    enriched_entities = []
    limit_entities = []
    failed_entities = []
    missing_entities = []
    result_value = u'true'
    json_results = {}
    output_message = u""
    status = EXECUTION_STATE_COMPLETED

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    try:
        vt = VirusTotalManager(api_key, verify_ssl)
        supported_entities = [entity for entity in siemplify.target_entities if
                              entity.entity_type == EntityTypes.HOSTNAME
                              or entity.entity_type == EntityTypes.USER
                              or entity.entity_type == EntityTypes.URL]
        if not supported_entities:
            info_message = u"No HOSTNAME or USER entities were found in current scope.\n"
            siemplify.LOGGER.info(info_message)
            output_message += info_message

        for entity in supported_entities:
            # Search a domains in virus total.
            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error(u"Timed out. execution deadline ({}) has passed".format(
                    convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                status = EXECUTION_STATE_TIMEDOUT
                break
            try:
                domain_report = vt.get_domain_report(get_domain_from_entity(entity).lower())
                if not domain_report:
                    # If report is none, and error not raised - probably entity can't be found.
                    info_message = u'Entity {} was not found in VirusTotal'.format(entity.identifier)
                    siemplify.LOGGER.info(u"\n {}".format(info_message))
                    missing_entities.append(entity.identifier)
                    continue

                json_results[entity.identifier] = domain_report.to_json()
                enrichment_object = domain_report.to_enrichment_data()
                # Scan flat data - update enrichment
                entity.additional_properties.update(add_prefix_to_dict(enrichment_object, VT_PREFIX))
                enriched_entities.append(entity)
                entity.is_enriched = True

                # Scan detections_information
                siemplify.result.add_entity_table(u'{} {}'.format(entity.identifier, SCAN_REPORT),
                                                  flat_dict_to_csv(enrichment_object))

                web_link = DOMAIN_RESULT_URL_FORMAT.format(get_domain_from_entity(entity))
                siemplify.result.add_entity_link(u"{} Link to web report".format(entity.identifier), web_link)

                info_message = u'The following entity was submitted and analyzed in VirusTotal: ' \
                               + u'{}'.format(entity.identifier) \
                               + u'\n \n *Check online report for full details.\n'
                siemplify.LOGGER.info(u"\n{}".format(info_message))

            except VirusTotalInvalidAPIKeyManagerError as e:
                # Invalid key was passed - terminate action
                siemplify.LOGGER.error(u"Invalid API key was provided. Access is forbidden.")
                status = EXECUTION_STATE_FAILED
                result_value = u"false"
                output_message = u"Invalid API key was provided. Access is forbidden."
                break

            except VirusTotalLimitManagerError as e:
                siemplify.LOGGER.error(u"API limit reached.")
                siemplify.LOGGER.exception(e)
                limit_entities.append(entity)

            except Exception as e:
                # An error occurred - skip entity and continue
                siemplify.LOGGER.error(u"An error occurred on entity: {}.\n{}.".format(entity.identifier, e))
                siemplify.LOGGER.exception(e)
                failed_entities.append(entity)

        if missing_entities:
            output_message += u'The following entities were not found in VirusTotal: \n' \
                                   + u'{}'.format(u'\n'.join(missing_entities))

        if failed_entities:
            output_message += u'\n\nThe following entities were failed in VirusTotal: \n'\
                                   + u'{}'.format(u'\n'.join([entity.identifier for entity in failed_entities]))

        if limit_entities:
            output_message += u'\n\nThe following entities were not enriched due to reaching API request limitation: \n'\
                                   + u'{}'.format(u'\n'.join([entity.identifier for entity in limit_entities]))

        if enriched_entities:
            siemplify.update_entities(enriched_entities)
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            output_message += u'\n\nThe following entities were submitted and analyzed in VirusTotal: \n' \
                               + u'{}'.format(u'\n'.join([entity.identifier for entity in enriched_entities])) \
                               + u'\n \n *Check online report for full details.\n'

    except Exception as e:
        siemplify.LOGGER.error(u"General error performing action {}. Error: {}".format(SCRIPT_NAME, e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"General error performing action {}. Error: {}".format(SCRIPT_NAME, e)

    # add json
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
