from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from MitreAttckManager import MitreAttckManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv


INTEGRATION_NAME = u"MitreAttck"
SCRIPT_NAME = u"Mitre Att&ck - Get Techniques Details"
ID_IDENTIFIER = u"ID"
EXTERNAL_ID_IDENTIFIER = u"External ID"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                           param_name=u"API Root")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=True, input_type=bool, print_value=True)

    # INIT ACTION PARAMETERS:
    identifiers = extract_action_param(siemplify, param_name=u"Technique Identifier", print_value=True,
                                      is_mandatory=True)
    identifier_type = extract_action_param(siemplify, param_name=u"Identifier Type", print_value=True,
                                           is_mandatory=True, default_value=ID_IDENTIFIER)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = u""
    json_result = {}
    failed_identifiers = []
    succeeded_identifiers = []

    try:
        # Split techniques IDs
        identifiers = [identifier.strip() for identifier in identifiers.split(u",")] if identifiers else []

        manager = MitreAttckManager(api_root, verify_ssl)

        if not manager.test_connectivity():
            output_message = u"Unable to connect to MitreAttack"
            status = EXECUTION_STATE_FAILED
            result_value = u"false"
        else:
            for identifier in identifiers:
                try:
                    siemplify.LOGGER.info(u"Processing technique {}".format(identifier))

                    if identifier_type == ID_IDENTIFIER:
                        siemplify.LOGGER.info(u"Fetching attack by ID.")
                        attack = manager.get_attack_by_id(identifier)
                    elif identifier_type == EXTERNAL_ID_IDENTIFIER:
                        siemplify.LOGGER.info(u"Fetching attack by external ID.")
                        attack = manager.get_attack_by_external_id(identifier)
                    else:
                        siemplify.LOGGER.info(u"Fetching attack by name.")
                        attack = manager.get_attack_by_name(identifier)

                    if attack:
                        siemplify.LOGGER.info(u"Found technique information for {}".format(identifier))
                        siemplify.result.add_data_table(
                            title=u'{} technique information'.format(identifier),
                            data_table=construct_csv([attack.to_data_table()])
                        )
                        if attack.url:
                            siemplify.result.add_link(u"{} technique link".format(identifier), attack.url)

                        json_result[identifier] = attack.to_json()
                        succeeded_identifiers.append(identifier)

                    else:
                        siemplify.LOGGER.info(u"{} technique was not found.".format(identifier))
                        failed_identifiers.append(identifier)

                except Exception as e:
                    siemplify.LOGGER.error(u"An error occurred on Technique {}".format(identifier))
                    siemplify.LOGGER.exception(e)
                    failed_identifiers.append(identifier)

            if succeeded_identifiers:
                output_message += u"Successfully retrieved detailed information for for the following techniques:\n   {}".format(
                    u"\n   ".join(succeeded_identifiers)
                )

            else:
                output_message += u"No techniques were found."
                result_value = False

            if failed_identifiers:
                output_message += u"\n\nAction wasn't able to find information for the following techniques:\n   {}".format(
                    u"\n   ".join(failed_identifiers)
                )

    except Exception as e:
        siemplify.LOGGER.error(u'Error fetching techniques.')
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = u"Error executing action \"Get Technique Details\". Reason: {}".format(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_result))
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
