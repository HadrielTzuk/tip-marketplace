from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import dict_to_flat, flat_dict_to_csv
from NSMManager import NsmManager
import json

# Consts
ACTION_SCRIPT_NAME = 'NSM Get Alert Details'
NSM_PROVIDER = 'McAfeeNSM'
TABLE_NAME = 'Alert Details: {0}'


@output_handler
def main():
    # Define variables.
    result_value = ""

    # Configuration.
    siemplify = SiemplifyAction()
    # Script Name.
    siemplify.script_name = ACTION_SCRIPT_NAME
    conf = siemplify.get_configuration(NSM_PROVIDER)
    nsm_manager = NsmManager(conf['API Root'], conf['Username'], conf['Password'], conf['Domain ID'],
                             conf['Siemplify Policy Name'], conf['Sensors Names List Comma Separated'])

    # Parameters.
    alert_id = siemplify.parameters.get('Alert ID')
    sensor_name = siemplify.parameters.get('Sensor Name')

    alert_data = nsm_manager.get_alert_info_by_id(alert_id, sensor_name)

    if alert_data:
        result_value = json.dumps(alert_data)
        siemplify.result.add_json(TABLE_NAME.format(alert_id), result_value)

    if result_value:
        output_message = 'Found alert info data for alert with ID - "{0}"'.format(alert_id)
    else:
        output_message = 'Not found alert info data for alert with ID - "{0}"'.format(alert_id)

    siemplify.result.add_result_json(alert_data)
    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
