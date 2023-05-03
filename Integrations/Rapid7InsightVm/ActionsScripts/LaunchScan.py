import sys
import time

from Rapid7Manager import Rapid7Manager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import (
    dict_to_flat,
    flat_dict_to_csv,
    output_handler
)

SCRIPT_NAME = "Rapid7InsightVm - Launch Scan"


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

    # If scan name is not given - generate one
    scan_name = siemplify.parameters.get('Scan Name') if \
        siemplify.parameters.get('Scan Name') else \
        "siemplify_{}".format(time.strftime("%Y%m%d-%H%M%S"))

    site_name = siemplify.parameters['Site Name']
    scan_engine = siemplify.parameters['Scan Engine']
    scan_template = siemplify.parameters['Scan Template']
    fetch_results = str(
        siemplify.parameters.get('Fetch Results', 'false')).lower() == 'true'

    hosts = []

    for entity in siemplify.target_entities:
        if entity.entity_type == EntityTypes.ADDRESS or \
                entity.entity_type == EntityTypes.HOSTNAME:
            hosts.append(entity.identifier)

    siemplify.LOGGER.info("The following hosts will be scanned: {}".format(
        ", ".join(hosts)
    ))

    scan_id = rapid7_manager.launch_scan(
        name=scan_name,
        site_name=site_name,
        engine_name=scan_engine,
        hosts=hosts,
        scan_template_name=scan_template,
    )

    output_message = 'Scan was initialized. Scan ID: {}.'.format(scan_id)

    if fetch_results:
        # Wait for results
        siemplify.end(output_message, scan_id, EXECUTION_STATE_INPROGRESS)

    else:
        siemplify.end(output_message, scan_id)


def wait_for_results():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    conf = siemplify.get_configuration("Rapid7InsightVm")

    rapid7_manager = Rapid7Manager(
        conf['Api Root'],
        conf['Username'],
        conf['Password'],
        conf.get('Verify SSL', 'false').lower() == 'true'
    )

    scan_id = siemplify.parameters['additional_data']

    json_results = {}

    if rapid7_manager.is_scan_completed(scan_id):
        scan_info = rapid7_manager.get_scan_by_id(scan_id)

        if scan_info:
            json_results = scan_info

            if 'links' in scan_info:
                del scan_info['links']

            siemplify.result.add_data_table(
                'Scan {} Info'.format(scan_id),
                flat_dict_to_csv(dict_to_flat(scan_info))
            )

        # add json
        siemplify.result.add_result_json(json_results)

        siemplify.end(
            "The following hosts were submitted and analyzed in Rapid7 InsightVm: {}".format(
                "\n".join(
                    [entity.identifier for entity in siemplify.target_entities if
                     entity.entity_type == EntityTypes.ADDRESS or
                     entity.entity_type == EntityTypes.HOSTNAME])),
            scan_id, EXECUTION_STATE_COMPLETED)

    else:
        siemplify.end(
            "Scan {} did not complete, waiting.".format(
                scan_id), scan_id, EXECUTION_STATE_INPROGRESS)
        

if __name__ == '__main__':
    if len(sys.argv) < 3 or sys.argv[2] == 'True':
        main()
    else:
        wait_for_results()
