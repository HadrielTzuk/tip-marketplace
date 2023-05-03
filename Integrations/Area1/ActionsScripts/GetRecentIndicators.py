from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import dict_to_flat, construct_csv
from Area1Manager import Area1Manager
import arrow
import json

ACTION_NAME = 'Area1_Get Recent Indicators'
INDICATORS_TABLE_HEADER = 'Recent Indicators'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    configurations = siemplify.get_configuration('Area1')
    server_addr = configurations['Api Root']
    username = configurations['Username']
    password = configurations['Password']
    verify_ssl = configurations.get('Verify SSL', 'false').lower() == 'true'

    area1_manager = Area1Manager(server_addr, username, password, verify_ssl)

    seconds_back = int(siemplify.parameters.get('Seconds Back', 60))

    indicators = area1_manager.get_recent_indicators(since=arrow.utcnow().timestamp - seconds_back)

    if indicators:
        output_message = "Found {0} indicators {1} seconds back.".format(len(indicators), seconds_back)
        indicators_csv = construct_csv(map(dict_to_flat, indicators))
        siemplify.result.add_data_table(INDICATORS_TABLE_HEADER, indicators_csv)
    else:
        output_message = "No indicators where found {0} seconds back.".format(seconds_back)

    siemplify.result.add_result_json(json.dumps(indicators))
    siemplify.end(output_message, json.dumps(indicators))


if __name__ == '__main__':
    main()
