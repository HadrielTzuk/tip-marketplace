from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyUtilitiesManager import SiemplifyUtilitiesManager
import copy

ACTION_NAME = 'Siemplify_List Operations'

OPERATORS = ['intersection', 'union', 'subtract', 'xor']

RESULT_JSON = {"results": {
    "count": 0,
    "data": []
}}


def validate_operator(operator):
    """
    Validate operator string.
    :param operator: {string} Operator to validate.
    :return: {void}
    """
    if operator not in OPERATORS:
        raise Exception('Operator is not valid, must be one of {0}'.format(",".join(OPERATORS)))
    return operator


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    result_json = copy.deepcopy(RESULT_JSON)

    # Parameters.
    delimiter = siemplify.parameters.get('Delimiter', ',')
    first_list = siemplify.parameters.get('First List', '').split(delimiter)
    second_list = siemplify.parameters.get('Second List', '').split(delimiter)
    operator = validate_operator(siemplify.parameters.get('Operator'))

    if operator == 'intersection':
        result_list = SiemplifyUtilitiesManager.intersect_lists(first_list, second_list)
    elif operator == 'union':
        result_list = SiemplifyUtilitiesManager.union_lists(first_list, second_list)
    elif operator == 'subtract':
        result_list = SiemplifyUtilitiesManager.subtract_lists(first_list, second_list)
    else:
        result_list = SiemplifyUtilitiesManager.xor_lists(first_list, second_list)

    output_message = "Performed {0} on {1}, {2}\nThe result is: {3}".format(operator, first_list, second_list,
                                                                            result_list)

    result_json["results"]["count"] = len(result_list)
    result_json["results"]["data"] = delimiter.join(result_list)

    siemplify.result.add_result_json(result_json)
    siemplify.end(output_message, delimiter.join(result_list))


if __name__ == '__main__':
    main()

