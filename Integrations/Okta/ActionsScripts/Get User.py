from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import construct_csv, dict_to_flat
from OktaManager import OktaManager
import json

PROVIDER = "Okta"
ACTION_NAME = "Okta - GetUser"

def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    user_ids_or_logins = siemplify.parameters.get('User Ids Or Logins')
    is_scope = siemplify.parameters.get('Also Run On Scope', "false").lower() == "true"
    okta = OktaManager(api_root=conf['Api Root'], api_token=conf['Api Token'],
                       verify_ssl=conf['Verify SSL'].lower() == 'true')
    ids = []

    errors = "\n\nErrors:\n\n"
    if user_ids_or_logins:
        for _id in user_ids_or_logins.split(','):
            _id = _id.strip()
            ids.append(_id)
    message = ""
    ret = {}
    if ids:
        for _id in ids:
            user = {}
            try:
                user = okta.get_user(_id)
                if user:
                    message += "The user \"{}\" was found.\n\n".format(_id)
                    ret[_id] = user
                else:
                    message += "The user \"{}\" was not found.\n\n".format(_id)
            except Exception as err:
                siemplify.LOGGER.exception(err)
                siemplify.LOGGER.error(_id + ": " + err.message)
                errors += err.message + "\n\n"
                pass
    if is_scope:
        entitiesDisabled = []
        for entity in siemplify.target_entities:
            if entity.entity_type == EntityTypes.USER or entity.entity_type == EntityTypes.HOSTNAME:
                try:
                    user = okta.get_user(entity.identifier)
                    if user:
                        entitiesDisabled.append(entity)
                        message += "The user \"{0}\" was found.\n\n".format(entity.identifier)
                        ret[entity.identifier] = user
                    else:
                        message += "The user \"{0}\" couldn't be found.\n\n".format(entity.identifier)
                        continue
                except Exception as err:
                    siemplify.LOGGER.exception(err)
                    siemplify.LOGGER.error(entity.identifier + ": " + err.message)
                    errors += err.message + "\n\n"
                    pass
            else:
                continue
    if ret:
        siemplify.result.add_result_json(list(ret.values()))
        for name, user in ret.items():
            flat_user = dict_to_flat(user)
            csv_output = construct_csv([flat_user])
            siemplify.result.add_data_table("Okta - User: " + name, csv_output)
        output_message = message
    else:
        output_message = "No users were found. {}".format(message)

    siemplify.end(output_message + errors, json.dumps(ret))

if __name__ == '__main__':
    main()