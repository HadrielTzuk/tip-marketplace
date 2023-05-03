from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import construct_csv, add_prefix_to_dict, convert_dict_to_json_result_dict, \
 output_handler, unix_now, convert_unixtime_to_datetime
from TIPCommon import extract_configuration_param, extract_action_param
from VirusTotal import VirusTotalManager, VirusTotalInvalidAPIKeyManagerError, VirusTotalLimitManagerError

# Const
ADDRESS_RESULT_URL_FORMAT = u'https://www.virustotal.com/#/ip-address/{0}'
VT_PREFIX = u'VT'
SCRIPT_NAME = u'VirusTotal - ScanIP'
IDENTIFIER = u'VirusTotal'


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

    threshold = extract_action_param(siemplify, param_name=u'Threshold', is_mandatory=False,
                                     input_type=int, print_value=True, default_value=25)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    result_value = u'true'
    output_message = u""
    json_results = {}
    status = EXECUTION_STATE_COMPLETED
    enriched_entities = []
    limit_entities = []
    failed_entities = []
    missing_entities = []

    try:
        vt = VirusTotalManager(api_key, verify_ssl)
        address_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS
                            and not entity.is_internal]
        if not address_entities:
            info_message = u"No ADDRESS entities were found in current scope.\n"
            siemplify.LOGGER.info(info_message)
            output_message += info_message

        for entity in address_entities:
            # Search an external ip address in virus total.
            siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))
            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error(u"Timed out. execution deadline ({}) has passed".format(
                    convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                status = EXECUTION_STATE_TIMEDOUT
                break
            try:
                address_report = vt.get_address_report(entity.identifier)

                if not address_report:
                    # If report is none, and error not raised - probably entity can't be found.
                    info_message = u'Entity {} was not found in Virus Total'.format(entity.identifier)
                    siemplify.LOGGER.info(u"\n {}".format(info_message))
                    missing_entities.append(entity.identifier)
                    continue

                json_results[entity.identifier] = address_report.to_json()

                entity.additional_properties.update(
                    add_prefix_to_dict(address_report.to_enrichment_data(), VT_PREFIX))
                entity.is_enriched = True
                enriched_entities.append(entity)

                web_link = ADDRESS_RESULT_URL_FORMAT.format(entity.identifier)
                siemplify.result.add_entity_link(u"{0} Link to web report".format(entity.identifier), web_link)

                # Set entity is_suspicious if positives highest value exceeded threshold
                if int(threshold) <= address_report.positives:
                    entity.is_suspicious = True

                if address_report.resolutions:
                    siemplify.result.add_entity_table(entity.identifier, construct_csv(address_report.resolutions))

                siemplify.add_entity_insight(entity, get_insight_message(address_report), triggered_by=IDENTIFIER)

                info_message = u'Entity {} was submitted and analyzed in VirusTotal'.format(entity.identifier) \
                               + u'\n \n *Check online report for full details.'
                siemplify.LOGGER.info(u"\n {}".format(info_message))
                output_message += info_message

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
                siemplify.LOGGER.error(u"An error occurred on entity: {}.\n{}.".format(entity.identifier, str(e)))
                siemplify.LOGGER.exception(e)
                failed_entities.append(entity)

        if missing_entities:
            output_message += u'\n\nThe following IPs were not found in VirusTotal: \n'\
                                   + u'{}'.format(u'\n'.join(missing_entities))
        if failed_entities:
            output_message += u'\n\nThe following IPs were failed in VirusTotal: \n'\
                                   + u'{}'.format(u'\n'.join([entity.identifier for entity in failed_entities]))

        if limit_entities:
            output_message += u'\n\nThe following IPS were not analyzed due to reaching API request limitation: \n'\
                                   + u'{}'.format(u'\n'.join([entity.identifier for entity in limit_entities]))

        if enriched_entities:
            siemplify.update_entities(enriched_entities)
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

    except Exception as e:
        siemplify.LOGGER.error(u"General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Some errors occurred. Please check log"

    # add json
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


def get_insight_message(result):
    """
    Get Insight message.
    :param result: {IP} Ip class instance
    :return: content {str} insight message
    """
    content = u""
    content += u"Country: {}".format(result.country)
    content += u"\nMalicious Referrer Samples: {}".format(len(result.detected_referrer_samples))
    content += u"\nMalicious Downloaded Samples: {}".format(len(result.detected_downloaded_samples))
    content += u"\nMalicious Communicating Samples: {}".format(len(result.detected_communicating_samples))
    content += u"\nMalicious URLs: {}".format(len(result.detected_urls))

    return content


if __name__ == '__main__':
    main()
