from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from consts import GET_CONNECTOR_CONTEXT_VALUE_SCRIPT_NAME, CONTEXT_CHARACTERS_LIMIT, CONNECTOR_CONTEXT_TABLE_NAME, \
    CONNECTOR_CONTEXT
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_action_param, construct_csv


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_CONNECTOR_CONTEXT_VALUE_SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Params Init -----------------")
    connector_identifier = extract_action_param(siemplify, param_name='Connector Identifier', is_mandatory=True,
                                                print_value=True, input_type=unicode)
    key_name = extract_action_param(siemplify, param_name='Key Name', print_value=True, is_mandatory=True,
                                    input_type=unicode)
    create_case_wall_table = extract_action_param(siemplify, param_name='Create Case Wall Table', print_value=True,
                                                  input_type=bool)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    output_message = u""
    status = EXECUTION_STATE_COMPLETED
    result_value = True

    try:
        result = siemplify.get_context_property(CONNECTOR_CONTEXT, connector_identifier, key_name)

        if result:
            output_message = u"Successfully found context value for the provided context key \"{}\" connector " \
                             u"identifier \"{}\". \n".format(key_name, connector_identifier)

            json_result = {
                "Key_Name": key_name,
                "Value": result
            }
            siemplify.result.add_result_json(json_result)

            if create_case_wall_table:
                if len(result) > CONTEXT_CHARACTERS_LIMIT:
                    output_message += "Action will not return the Case Wall table as the context value(s) are too big."
                else:
                    csv_result = {
                        'Connector Identifier': connector_identifier,
                        'Key Name': key_name,
                        'Value': result
                    }
                    siemplify.result.add_entity_table(
                        CONNECTOR_CONTEXT_TABLE_NAME,
                        construct_csv([csv_result])
                    )
        else:
            result_value = False
            output_message = u"Context value was not found for the provided context key \"{}\" and connector " \
                             u"identifier \"{}\".".format(key_name, connector_identifier)

    except Exception as e:
        output_message = u'Error executing action {}. Reason: {}'.format(GET_CONNECTOR_CONTEXT_VALUE_SCRIPT_NAME, e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info(u'----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        u'\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
