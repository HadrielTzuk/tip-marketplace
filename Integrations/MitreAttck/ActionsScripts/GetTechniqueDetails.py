from SiemplifyUtils import output_handler
from MitreAttckManager import MitreAttckManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from SiemplifyDataModel import InsightSeverity, InsightType

INTEGRATION_NAME = u"MitreAttck"
SCRIPT_NAME = u"Mitre Att&ck - Get Technique Details"
ID_IDENTIFIER = u"ID"
EXTERNAL_ID_IDENTIFIER = u"External ID"
PARAMETERS_DEFAULT_DELIMITER = u","


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    result_value = False
    status = EXECUTION_STATE_FAILED
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=True, input_type=bool, print_value=True)

    # INIT ACTION PARAMETERS:
    identifiers = extract_action_param(siemplify, param_name=u"Technique Identifier", print_value=True,
                                       is_mandatory=True)
    identifier_type = extract_action_param(siemplify, param_name=u"Identifier Type", print_value=True,
                                           is_mandatory=True, default_value=ID_IDENTIFIER)
    create_insights = extract_action_param(siemplify, param_name=u"Create Insights", print_value=True,
                                           input_type=bool)

    identifiers_list = [i.strip() for i in identifiers.split(PARAMETERS_DEFAULT_DELIMITER)]

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    try:
        manager = MitreAttckManager(api_root, verify_ssl)
        successful_identifiers = []
        failed_identifiers = []
        json_results = []
        output_message = ""

        for identifier in identifiers_list:
            siemplify.LOGGER.info(u"\n\nStarted processing identifier: {}".format(identifier))

            if identifier_type == ID_IDENTIFIER:
                attack = manager.get_attack_by_id(identifier)
            elif identifier_type == EXTERNAL_ID_IDENTIFIER:
                attack = manager.get_attack_by_external_id(identifier)
            else:
                attack = manager.get_attack_by_name(identifier)

            if attack:
                siemplify.result.add_data_table(
                    title=u'{} technique information'.format(identifier),
                    data_table=construct_csv([attack.to_data_table()])
                )
                if attack.url:
                    siemplify.result.add_link(u"{} technique link".format(identifier), attack.url)

                json_results.append(attack)
                successful_identifiers.append(identifier)
                if create_insights:
                    if attack.description:
                        siemplify.create_case_insight(triggered_by=INTEGRATION_NAME,
                                                      title="Technique Description - {}".format(identifier),
                                                      content=attack.description,
                                                      entity_identifier="",
                                                      severity=InsightSeverity.INFO,
                                                      insight_type=InsightType.General)
                    else:
                        siemplify.LOGGER.info(u"Insight was not created for technique {}. Reason: description is "
                                              u"empty/not available".format(identifier))

                result_value = True
                siemplify.LOGGER.info(u"Successfully retrieve information about identifier: {}".format(identifier))
            else:
                failed_identifiers.append(identifier)
                siemplify.LOGGER.error(u"Action wasn't able to retrieve information about identifier: {}"
                                       .format(identifier))

            siemplify.LOGGER.info(u"Finished processing identifier: {}".format(identifier))

        if successful_identifiers:
            siemplify.result.add_result_json([result.to_json() for result in json_results])
            output_message += u"\nRetrieved detailed information about the following techniques:\n{}"\
                .format("\n".join(successful_identifiers))
        if failed_identifiers:
            output_message += u"\nAction wasn't able to retrieve detailed information about the following techniques:" \
                              u"\n{}".format("\n".join(failed_identifiers))

        if not successful_identifiers:
            output_message += u"\nAction wasn't able to find the provided techniques."

        status = EXECUTION_STATE_COMPLETED
    except Exception as e:
        siemplify.LOGGER.error(u"Error fetching Technique")
        siemplify.LOGGER.exception(e)
        output_message = u"Error executing action \"Get Technique Details\". Reason:{}".format(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
