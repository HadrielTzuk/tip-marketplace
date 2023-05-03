from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from consts import SET_CONTEXT_VALUE_SCRIPT_NAME
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_action_param
from utils import set_global_context, get_global_context


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SET_CONTEXT_VALUE_SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Params Init -----------------")
    context_scope = extract_action_param(siemplify, param_name='Context Scope', is_mandatory=True, print_value=True,
                                         input_type=unicode, default_value=u'Not specified')
    key_name = extract_action_param(siemplify, param_name='Key Name', is_mandatory=True, print_value=True,
                                    input_type=unicode)
    key_value = extract_action_param(siemplify, param_name='Key Value', is_mandatory=True, print_value=True,
                                     input_type=unicode)

    context_scope_mapping = {
        'Not specified': 0,
        'Alert': siemplify.set_alert_context_property,
        'Case': siemplify.set_case_context_property,
        'Global': set_global_context
    }

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    output_message = u""
    status = EXECUTION_STATE_COMPLETED
    result_value = True

    try:
        if not context_scope_mapping[context_scope]:
            raise Exception(u"Value for 'Context Type' parameter is {}.".format(context_scope))
        
        key_value = unicode(key_value).encode("utf8")
        if context_scope == "Global":
            context_scope_mapping[context_scope](siemplify, key_name, key_value)
        else:
            context_scope_mapping[context_scope](key_name, key_value)

        output_message = u"Successfully set context value for the context key \"{}\" with scope \"{}\"."\
            .format(key_name, context_scope)

    except Exception as e:
        output_message = u'Error executing action {}. Reason: {}'.format(SET_CONTEXT_VALUE_SCRIPT_NAME, e)
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
