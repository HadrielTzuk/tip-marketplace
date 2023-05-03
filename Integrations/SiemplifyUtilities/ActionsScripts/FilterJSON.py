from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyUtilitiesManager import SiemplifyUtilitiesManager
import json

ACTION_NAME = 'Siemplify_Filter JSON'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    result_value = ""

    # Parameters.
    json_dict = json.loads(siemplify.parameters.get('JSON Data', '{}'))
    root_path = siemplify.parameters.get('Root Key Path', '')
    condition_path = siemplify.parameters['Condition Path']
    condition_operator = siemplify.parameters['Condition Operator']
    condition_value = siemplify.parameters['Condition Value']
    output_path = siemplify.parameters.get('Output Path', '')
    delimiter = siemplify.parameters.get('Delimeter', ',')

    if root_path:
        condition_path = ".".join([root_path, condition_path])

        if output_path:
            output_path = ".".join([root_path, output_path])

    filtered_json = SiemplifyUtilitiesManager.filter_json(json_dict, condition_path, condition_operator, condition_value)
    result_json = SiemplifyUtilitiesManager.find_values_in_dict(filtered_json, root_path)

    if output_path:
        result_values = SiemplifyUtilitiesManager.find_values_in_dict(filtered_json, output_path)

        is_json = False

        for result in result_values:
            if not isinstance(result, basestring):
                is_json = True
                break

        if is_json:
            result_value = json.dumps(result_values)

        else:
            result_value = delimiter.join(result_values)

    else:
        result_value = json.dumps(result_json)

    siemplify.result.add_json("Filtered JSON", json.dumps(result_json))

    output_message = "Successfully filtered JSON.".format(result_value)

    siemplify.result.add_result_json(json.loads(result_value))
    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
