from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import construct_csv, dict_to_flat
from OktaManager import OktaManager
import json


PROVIDER = "Okta"
ACTION_NAME = "Okta - ListUsers"

def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    q = siemplify.parameters.get('Query', "")
    _filter = siemplify.parameters.get('Filter', "")
    search =siemplify.parameters.get('Search', "")
    limit = siemplify.parameters.get('Limit', "")
    output_message = ""
    errors = "\n\nErrors:\n\n"
    if limit:
        try:
            limit = int(limit)
        except:
            raise Exception("Limit must be an integer")
    okta = OktaManager(api_root=conf['Api Root'], api_token=conf['Api Token'],
                       verify_ssl=conf['Verify SSL'].lower() == 'true')
    users = {}
    try:
        users = okta.list_users(q=q, _filter=_filter, search=search, limit=limit)
    except Exception as err:
        siemplify.LOGGER.exception(err)
        siemplify.LOGGER.error(err.message)
        errors += err.message + "\n\n"
        pass
    output_message = "No Users Were Found"
    if users:
        output_message = "Found {} users".format(len(users))
        #i = 1
        for i, user in enumerate(users, 1):
            flat_user = dict_to_flat(user)
            csv_output = construct_csv([flat_user])
            siemplify.result.add_data_table("Okta - User " + str(i) + ": " + user['profile']['login'], csv_output)
            #i += 1
    siemplify.end(output_message + errors, json.dumps(users))

if __name__ == '__main__':
    main()