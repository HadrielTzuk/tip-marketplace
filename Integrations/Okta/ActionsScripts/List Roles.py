from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import construct_csv, dict_to_flat
from OktaManager import OktaManager
import json

PROVIDER = "Okta"
ACTION_NAME = "Okta - ListRoles"

def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    user_ids = siemplify.parameters.get('User IDs', "")
    is_scope = siemplify.parameters.get('Also Run On Scope', "false").lower() == "true"
    ids = []
    res = {}
    ret = {}
    output_message = ""
    errors = "\n\nErrors:\n\n"
    okta = OktaManager(api_root=conf['Api Root'], api_token=conf['Api Token'],
                       verify_ssl=conf['Verify SSL'].lower() == 'true')
    if user_ids:
        for _id in user_ids.split(','):
            _id = _id.strip()
            ids.append(_id)
    message = ""
    if ids:
        for _id in ids:
            try:
                res = okta.list_roles(_id)
                if res:
                    ret[_id] = []
                    roles = []
                    for role in res:
                        roles.append(role['type'])
                        ret[_id].append(role)
                    message += "The user with id {0} has {1} roles: {2}\n\n".format(_id, len(roles), ", ".join(roles))
                else:
                    message += "Couldn't find roles for user with id {0}.\n\n".format(_id)
                    continue
            except Exception as err:
                siemplify.LOGGER.exception(err)
                siemplify.LOGGER.error(err.message)
                errors += err.message + "\n\n"
                pass
    if is_scope:
        entitiesWithRoles = []
        entityRoles = {}

        for entity in siemplify.target_entities:
            if entity.entity_type == EntityTypes.USER or entity.entity_type == EntityTypes.HOSTNAME:
                try:
                    _id = okta.login_to_id(entity.identifier)
                    if _id:
                        res = okta.list_roles(_id)
                    else:
                        message += "Couldn't find the user \"{0}\".\n\n".format(entity.identifier)
                        continue
                except Exception as err:
                    siemplify.LOGGER.exception(err)
                    siemplify.LOGGER.error(err.message)
                    errors += err.message + "\n\n"
                    pass
            else:
                continue
            if res:
                entitiesWithRoles.append(entity)
                roles = []
                entityRoles[entity.identifier] = {}
                ret[entity.identifier] = []
                for role in res:
                    roles.append(role['type'])
                    entityRoles[entity.identifier][role['type']] = role
                    ret[entity.identifier].append(role)
                message += "The user \"{0}\" has {1} roles: {2}\n\n".format(entity.identifier, len(roles), ", ".join(roles))
            else:
                message += "Couldn't find roles for user \"{0}\".".format(entity.identifier)
                continue
        #ret = entityRoles
    if ret:
        flag = False
        output_message = message
        for user, roles in ret.items():
            rows = []
            if roles:
                for role in roles:
                    if role:
                        flat_role = dict_to_flat(role)
                        rows.append(flat_role)
            if rows:
                flag = True
                csv_output = construct_csv(rows)
                siemplify.result.add_data_table("Okta - User \"{}\" Roles".format(user), csv_output)
        if not flag:
            output_message = "No Roles were found. {}".format(message)
    else:
        output_message = "No Roles were found. {}".format(message)
    siemplify.end(output_message + errors, json.dumps(ret))

if __name__ == '__main__':
    main()