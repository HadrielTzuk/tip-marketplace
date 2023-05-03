from TIPCommon import extract_action_param

from SiemplifyAction import SiemplifyAction
from SiemplifyUtilitiesManager import SiemplifyUtilitiesManager
from SiemplifyUtils import output_handler

ACTION_NAME = 'SiemplifyUtilities_Query Joiner'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME

    # Parameters.
    query_values = siemplify.parameters.get('Values', "").split(",") if siemplify.parameters.get('Values') else []
    query_field = siemplify.parameters.get('Query Field')
    query_operator = siemplify.parameters.get('Query Operator')

    add_single_quotes = extract_action_param(siemplify, param_name="Add Quotes", default_value=False, input_type=bool,
                                             is_mandatory=False)
    add_double_quotes = extract_action_param(siemplify, param_name="Add Double Quotes", default_value=False,
                                             input_type=bool,
                                             is_mandatory=False)

    query = SiemplifyUtilitiesManager.form_query(query_field, query_operator, query_values, add_single_quotes,
                                                 add_double_quotes)

    output_message = "Successfully formed query: {0}".format(query)

    siemplify.end(output_message, query)


if __name__ == '__main__':
    main()
