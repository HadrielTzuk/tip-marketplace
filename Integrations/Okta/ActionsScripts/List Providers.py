from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import construct_csv, dict_to_flat
from OktaManager import OktaManager
import json


PROVIDER = "Okta"
ACTION_NAME = "Okta - ListProviders"

def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    q = siemplify.parameters.get('Query', "")
    _type = siemplify.parameters.get('Type', "")
    limit = siemplify.parameters.get('Limit', "")
    output_message = ""
    errors = "\n\nErrors:\n\n"
    if limit:
        try:
            limit = int(limit)
        except:
            raise Exception("Limit must be a number")
    okta = OktaManager(api_root=conf['Api Root'], api_token=conf['Api Token'],
                       verify_ssl=conf['Verify SSL'].lower() == 'true')
    providers = {}
    try:
        providers = okta.list_providers(q=q, _type=_type, limit=limit)
    except Exception as err:
        siemplify.LOGGER.exception(err)
        siemplify.LOGGER.error(err.message)
        errors += err.message + "\n\n"
        pass
    if providers:
        p = []
        for i, provider in enumerate(providers, 1):
            flat_provider = dict_to_flat(provider)
            csv_output = construct_csv([flat_provider])
            p.append(provider['name'])
            siemplify.result.add_data_table("Okta - Provider " + str(i) + ": " + provider['name'], csv_output)
        output_message = "Found {0} providers: {1}".format(len(providers), ", ".join(p))
    else:
        output_message = "No providers were found"
    siemplify.end(output_message + errors, json.dumps(providers))

if __name__ == '__main__':
    main()