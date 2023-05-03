# Imports
from XDRManager import XDRManager
from SiemplifyUtils import construct_csv
from SiemplifyAction import SiemplifyAction

# Consts.
PROVIDER_NAME = 'PaloAltoCortexXDR'


def main():
    # Configuration.
    siemplify = SiemplifyAction()

    siemplify.script_name = "Palo Alto Cortex XDR - QUERY"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    conf = siemplify.get_configuration(PROVIDER_NAME)
    api_root = conf.get('Api Root')
    api_key = conf.get('Api Key')
    api_key_id = conf.get('Api Key ID')
    verify_ssl = str(conf.get('Verify SSL', 'False')).lower() == 'true'

    xdr_manager = XDRManager(api_root, api_key, api_key_id, verify_ssl)

    # Parameters.
    incident_id = siemplify.parameters.get('Incident ID')

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    alerts = []
    result_value = 0
    incident_extra_data = xdr_manager.get_extra_incident_data(incident_id)

    if incident_extra_data:
        # create csv table of incident alerts
        alerts = incident_extra_data.get('alerts', {}).get('data', [])
        if alerts:
            csv_output = construct_csv(alerts)
            siemplify.result.add_data_table("Incident {0} Alerts".format(incident_id), csv_output)

    if incident_extra_data and alerts:
        output_message = "Successfully fetched incident information for incident with ID: {0} (Including the alerts, network artifacts, and file artifacts)".format(
            incident_id)
        result_value = len(alerts)
    else:
        output_message = 'Not found data for incident with ID: {0}.'.format(incident_id)

    siemplify.result.add_result_json(incident_extra_data)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        "\n  result_value: {}\n  output_message: {}".format(result_value, output_message))
    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
