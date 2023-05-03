from SiemplifyUtils import output_handler
from TIPCommon import extract_action_param, extract_configuration_param, construct_csv, string_to_multi_value
from SiemplifyAction import SiemplifyAction
from Siemplify import InsightSeverity, InsightType
from QRadarManager import QRadarManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import INTEGRATION_NAME, GET_RULE_MITRE_COVERAGE_SCRIPT_NAME

TABLE_TITLE = 'MITRE Coverage'
INSIGHT_TITLE = "Mitre Coverage"
GET_RULE_MITRE_COVERAGE_DISPLAY_NAME = 'Get Rule MITRE Coverage'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_RULE_MITRE_COVERAGE_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True)
    api_version = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Version')

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    status = EXECUTION_STATE_COMPLETED
    result_value = False
    successful_rules, failed_rules = [], []

    try:
        rule_names = extract_action_param(siemplify, param_name='Rule Names', is_mandatory=True, print_value=True)
        create_insight = extract_action_param(siemplify, param_name="Create Insight", print_value=True, input_type=bool)

        rule_names = string_to_multi_value(rule_names)

        manager = QRadarManager(api_root, api_token, api_version)
        mitre_mappings = manager.get_mitre_mappings()

        for rule in rule_names:
            mapping = next((item for item in mitre_mappings if item.rule_name == rule), None)
            if mapping:
                successful_rules.append(mapping)
            else:
                failed_rules.append(rule)

        if successful_rules:
            result_value = True
            output_message = 'Successfully found MITRE coverage for the following rules in QRadar Use Case Manager: ' \
                             '\n{}'.format('\n'.join([rule.rule_name for rule in successful_rules]))
            siemplify.result.add_result_json([rule.to_json() for rule in successful_rules])
            siemplify.result.add_data_table(TABLE_TITLE, construct_csv([rule.to_csv() for rule in successful_rules]))
            if create_insight:
                siemplify.create_case_insight(triggered_by=INTEGRATION_NAME,
                                              title=INSIGHT_TITLE,
                                              content="".join([rule.to_insight() for rule in successful_rules]),
                                              entity_identifier="",
                                              severity=InsightSeverity.INFO,
                                              insight_type=InsightType.General)

            if failed_rules:
                output_message += '\n\nAction didn’t find MITRE coverage for the following rules in QRadar Use Case ' \
                                  'Manager: \n{}\n'.format('\n'.join([rule for rule in failed_rules]))

        else:
            output_message = 'No MITRE coverage was found for the provided rules in QRadar Use Case Manager.'

    except Exception as e:
        output_message = f'Error executing {GET_RULE_MITRE_COVERAGE_DISPLAY_NAME}. Reason {e}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f'\n  status: {status}\n  result_value: {result_value}\n  output_message: {output_message}')
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
