from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyUtilitiesManager import SiemplifyUtilitiesManager
import json

ACTION_NAME = 'SiemplifyUtilities_Extract Top From JSON'
WILD_CARD_SIGN = '*'
JSON_HEADER_PATTERN = 'Branch No.{0}'  # Brunch Number.


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME

    # Parameters.
    json_data = json.loads(siemplify.parameters.get("JSON Data", {}))
    nested_key = siemplify.parameters.get("Key To Sort By", "").split('.')
    field_type = siemplify.parameters.get("Field Type", "number")
    reverse = siemplify.parameters.get("Reverse (DESC -> ASC)", "false").lower() == 'true'
    top_rows = int(siemplify.parameters.get('Top Rows', 3))
    
    branches = SiemplifyUtilitiesManager.fetch_branches_from_dict(json_data, nested_key, WILD_CARD_SIGN)

    sorted_branches = SiemplifyUtilitiesManager.sort_list_of_dicts_by_nested_key(branches, nested_key, field_type,
                                                                                 reverse=reverse,
                                                                                 wild_card_value=WILD_CARD_SIGN)
    
    top_sorted_branches = sorted_branches[:top_rows]

    for index, branch in enumerate(top_sorted_branches):
        siemplify.result.add_json(JSON_HEADER_PATTERN.format(index+1), json.dumps(branch))

    if sorted_branches:
        output_message = 'Top {0} branches presented.'.format(len(top_sorted_branches))
    else:
        output_message = 'No branches were found.'

    siemplify.result.add_result_json(top_sorted_branches)
    siemplify.end(output_message, json.dumps(top_sorted_branches))


if __name__ == '__main__':
    main()
