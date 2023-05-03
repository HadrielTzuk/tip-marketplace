from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from consts import GET_CONTEXT_VALUE_SCRIPT_NAME, CONTEXT_CHARACTERS_LIMIT, CONTEXT_TABLE_NAME
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_action_param, construct_csv
from utils import get_global_context


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_CONTEXT_VALUE_SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Params Init -----------------")
    context_scope = extract_action_param(siemplify, param_name='Context Scope', is_mandatory=True, print_value=True,
                                         input_type=unicode, default_value=u'Not Specified')
    key_name = extract_action_param(siemplify, param_name='Key Name', print_value=True, is_mandatory=True,
                                    input_type=unicode)
    create_case_wall_table = extract_action_param(siemplify, param_name='Create Case Wall Table', print_value=True,
                                                  input_type=bool)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    output_message = u""
    status = EXECUTION_STATE_COMPLETED
    result_value = True

    context_scope_mapping = {
        'Not specified': 0,
        'Alert': siemplify.get_alert_context_property,
        'Case': siemplify.get_case_context_property,
        'Global': get_global_context
    }

    try:
        if not context_scope_mapping[context_scope]:
            raise Exception(u"Value for 'Context Type' parameter is {}.".format(context_scope))

        if context_scope == "Global":
            result = context_scope_mapping[context_scope](siemplify, key_name)
        else:
            result = context_scope_mapping[context_scope](key_name)

        if result:
            output_message = u"Successfully found context value for the provided context key \"{}\" for the provided " \
                             u"context scope \"{}\". \n".format(key_name, context_scope)

            json_result = {
                "Key_Name": key_name,
                "Value": result
            }
            csv_result = {
                "Key Name": key_name,
                "Value": result
            }
            siemplify.result.add_result_json(json_result)

            if create_case_wall_table:
                if len(result) > CONTEXT_CHARACTERS_LIMIT:
                    output_message += "Action will not return the Case Wall table as the context value(s) are too big."
                else:
                    siemplify.result.add_entity_table(
                        CONTEXT_TABLE_NAME.format(context_scope),
                        construct_csv([csv_result])
                    )
        else:
            result_value = False
            output_message = u"Context value was not found for the provided context key \"{}\" with scope \"{}\"."\
                .format(key_name, context_scope)

    except Exception as e:
        output_message = u'Error executing action {}. Reason: {}'.format(GET_CONTEXT_VALUE_SCRIPT_NAME, e)
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
