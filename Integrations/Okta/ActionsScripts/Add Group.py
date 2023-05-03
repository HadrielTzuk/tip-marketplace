from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import construct_csv, dict_to_flat
from OktaManager import OktaManager
import json


PROVIDER = "Okta"
ACTION_NAME = "Okta - AddGroup"


def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    name = siemplify.parameters['Group Name']
    description = siemplify.parameters.get('Group Description', '')
    okta = OktaManager(api_root=conf['Api Root'], api_token=conf['Api Token'],
                       verify_ssl=conf['Verify SSL'].lower() == 'true')
    group = {}
    profile = {}
    profile['name'] = name
    profile['description'] = description
    errors = "\n\nErrors:\n\n"
    try:
        group = okta.add_group(profile)
    except Exception as err:
        siemplify.LOGGER.exception(err)
        siemplify.LOGGER.error(err.message)
        errors += err.message + "\n\n"
        pass
    if group:
        output_message = "A group with the name \"{}\" was successfully created.".format(name)
        flat_group = dict_to_flat(group)
        csv_output = construct_csv([flat_group])
        siemplify.result.add_data_table("Okta - Group ".format(name), csv_output)
    else:
        output_message = "The group wasn't created."
        try:
            groups = okta.list_groups(q=profile['name'])
            if isinstance(groups, list):
                for g in groups:
                    if g['profile']['name'] == profile['name']:
                        flat_group = dict_to_flat(g)
                        csv_output = construct_csv([flat_group])
                        siemplify.result.add_data_table("Okta - Group {}".format(name), csv_output)
                        siemplify.end("The group already exists.\n\n" + errors, json.dumps(g))
            else:
                flat_group = dict_to_flat(group)
                csv_output = construct_csv([flat_group])
                siemplify.result.add_data_table("Okta - Group {}".format(name), csv_output)
                siemplify.end("The group already exists.\n\n" + errors, json.dumps(groups))
        except Exception as err:
            siemplify.LOGGER.exception(err)
            siemplify.LOGGER.error(err.message)
            errors += err.message + "\n\n"
            pass
    siemplify.end(output_message + errors, json.dumps(group))

if __name__ == '__main__':
    main()