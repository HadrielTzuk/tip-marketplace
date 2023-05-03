from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import dict_to_flat
from CylanceManager import CylanceManager
import json

SCRIPT_NAME = "Cylance - GetThreats"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    conf = siemplify.get_configuration('Cylance')

    server_address = conf['Server Address']
    application_secret = conf['Application Secret']
    application_id = conf['Application ID']
    tenant_identifier = conf['Tenant Identifier']

    cm = CylanceManager(server_address, application_id, application_secret,
                        tenant_identifier)

    threats = cm.get_threats()

    if threats:
        threats = map(dict_to_flat, threats)
        csv_output = cm.construct_csv(threats)

        siemplify.result.add_data_table('Cylance Threats', csv_output)

    siemplify.result.add_result_json(json.dumps(threats))
    siemplify.end("Found {} threats.".format(len(threats)), 'true')


if __name__ == "__main__":
    main()
