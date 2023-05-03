from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from VectraManager import VectraManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import (
    INTEGRATION_NAME,
    GET_TRIAGE_RULE_DETAILS_SCRIPT_NAME
)
from VectraExceptions import ItemNotFoundException

TABLE_HEADER = u"Triage Rules Details"
INSIGHT_TITLE = u"Triage Rule {}"
INSIGHT_DESCRIPTION = u"Detection Category: {}\n Triage Category: {}\n Detection: {} \n Description: {}"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_TRIAGE_RULE_DETAILS_SCRIPT_NAME
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = u""
    successful_ids = []
    failed_ids = []
    detailed_triages = []

    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    # Configuration.
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           input_type=unicode, is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Token",
                                            input_type=unicode, is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=True, input_type=bool, is_mandatory=True)

    # Parameters
    triage_rule_ids = extract_action_param(siemplify, param_name=u'Triage Rule IDs', input_type=unicode,
                                           is_mandatory=True, print_value=True)
    create_insights = extract_action_param(siemplify, param_name=u'Create Insights', input_type=bool,
                                           is_mandatory=False, print_value=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    try:
        vectra_manager = VectraManager(api_root=api_root,
                                       api_token=api_token,
                                       verify_ssl=verify_ssl,
                                       siemplify=siemplify)

        triage_ids = [t.strip() for t in triage_rule_ids.split(u',') if t.strip()]
        for triage_id in triage_ids:
            try:
                triage_object = vectra_manager.get_triage_rule_details(triage_id=triage_id)
                detailed_triages.append(triage_object)
                successful_ids.append(triage_id)
                if create_insights:
                    siemplify.create_case_insight(INTEGRATION_NAME, INSIGHT_TITLE.format(triage_id),
                                                  INSIGHT_DESCRIPTION.format(triage_object.detection_category,
                                                                             triage_object.triage_category,
                                                                             triage_object.detection,
                                                                             triage_object.description),
                                                  triage_id, 0, 0)
            except ItemNotFoundException:
                failed_ids.append(triage_id)

        if successful_ids:
            siemplify.result.add_result_json([triage.to_json() for triage in detailed_triages])
            siemplify.result.add_data_table(title=TABLE_HEADER,
                                            data_table=construct_csv([triage.to_csv() for triage in detailed_triages]))
            output_message = (u'Successfully retrieved information about the following triage rules from Vectra: {}'.
                              format(u"\n".join([id for id in successful_ids])))

        if failed_ids:
            output_message += u"\n\n Action was not able to retrieve information about the following triage rules: {}"\
                .format(u"\n".join([ids for ids in failed_ids]))

        if not successful_ids:
            output_message = u"No information was retrieved about the triage rules."
            result_value = False

    except Exception as e:
        output_message = u"Error executing action \"Get Triage Rule Details\". Reason: {}".format(e)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u'Status: {}'.format(status))
    siemplify.LOGGER.info(u'Result: {}'.format(result_value))
    siemplify.LOGGER.info(u'Output Message: {}'.format(output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
