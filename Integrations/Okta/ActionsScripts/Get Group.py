from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import construct_csv, dict_to_flat
from OktaManager import OktaManager
import json

PROVIDER = "Okta"
ACTION_NAME = "Okta - GetGroup"

def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    group_ids_or_names = siemplify.parameters['Group Ids Or Names']
    is_id = siemplify.parameters.get('Is Id', "false").lower() == "true"
    okta = OktaManager(api_root=conf['Api Root'], api_token=conf['Api Token'],
                       verify_ssl=conf['Verify SSL'].lower() == 'true')
    ids = []
    output_message = ""
    errors = "\n\nErrors:\n\n"
    if group_ids_or_names:
        for _id in group_ids_or_names.split(','):
            _id = _id.strip()
            ids.append(_id)
    message = ""
    ret = {}
    if ids:
        for _id in ids:
            group = {}
            try:
                if is_id:
                    group = okta.get_group(_id)
                else:
                    groups = okta.list_groups(q=_id)
                    if isinstance(groups, list):
                        for g in groups:
                            if g['profile']['name'] == _id:
                                group = g
                                break
                    else:
                        group = groups
                if group:
                    message += "The group corresponding to \"{}\" was found.\n\n".format(_id)
                    ret[_id] = group
                else:
                    message += "No group corresponding to \"{}\" was found.\n\n".format(_id)
            except Exception as err:
                siemplify.LOGGER.exception(err)
                siemplify.LOGGER.error(_id + ": " + err.message)
                errors += err.message + "\n\n"
                pass
    if ret:
        for name, group in ret.items():
            flat_group = dict_to_flat(group)
            csv_output = construct_csv([flat_group])
            siemplify.result.add_data_table("Okta - Group: " + group['profile']['name'], csv_output)
        output_message = message
    else:
        output_message = "No groups were found. {}".format(message)

    siemplify.end(output_message + errors, json.dumps(ret))

if __name__ == '__main__':
    main()