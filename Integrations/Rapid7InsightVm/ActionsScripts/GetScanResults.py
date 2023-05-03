from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from Rapid7Manager import Rapid7Manager
from SiemplifyUtils import construct_csv, dict_to_flat, flat_dict_to_csv
import time

SCRIPT_NAME = "Rapid7InsightVm - Get Scan Results"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    conf = siemplify.get_configuration("Rapid7InsightVm")
    rapid7_manager = Rapid7Manager(
        conf['Api Root'],
        conf['Username'],
        conf['Password'],
        conf.get('Verify SSL', 'false').lower() == 'true'
    )

    scan_id = siemplify.parameters['Scan ID']
    json_results = {}

    while not rapid7_manager.is_scan_completed(scan_id):
        time.sleep(2)

    scan_info = rapid7_manager.get_scan_by_id(scan_id)

    if scan_info:
        json_results = scan_info

        if 'links' in scan_info:
            del scan_info['links']

        siemplify.result.add_data_table(
            'Scan {} Info'.format(scan_id),
            flat_dict_to_csv(dict_to_flat(scan_info))
        )

    output_message = 'Scan {} results were fetch successfully.'.format(scan_id)

    siemplify.result.add_result_json(json_results)
    siemplify.end(output_message, 'true')


if __name__ == "__main__":
    main()
