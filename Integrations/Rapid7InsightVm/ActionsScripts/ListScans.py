from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import construct_csv, dict_to_flat
from Rapid7Manager import Rapid7Manager
import json
import arrow

SCRIPT_NAME = "Rapid7InsightVm - List Scans"


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

    days_backwards = int(siemplify.parameters.get(
        "Days Backwards")) if siemplify.parameters.get(
        "Days Backwards") else 0

    if days_backwards:
        start_time = arrow.utcnow().shift(
            days=-days_backwards)
        scans = rapid7_manager.list_scans(start_time=start_time)

    else:
        scans = rapid7_manager.list_scans()

    json_results = []

    if scans:
        for scan in scans:
            if "links" in scan:
                del scan["links"]

        json_results = json.dumps(scans)
        csv_output = construct_csv(map(dict_to_flat, scans))

        siemplify.result.add_data_table(
            'Scans', csv_output)

    output_message = 'Found {} scan results.'.format(len(scans))
    # add json
    siemplify.result.add_result_json(json_results)
    siemplify.end(output_message, len(scans))


if __name__ == "__main__":
    main()
