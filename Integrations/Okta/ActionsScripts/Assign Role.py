from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import construct_csv, dict_to_flat
from OktaManager import OktaManager
import json

PROVIDER = "Okta"
ACTION_NAME = "Okta - AssignRole"

def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    user_ids = siemplify.parameters.get('User IDs', "")
    role_types = siemplify.parameters['Role Types']
    is_scope = siemplify.parameters.get('Also Run On Scope', "false").lower() == "true"
    roles = []
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
    if role_types:
        for role in role_types.split(','):
            role = role.strip()
            roles.append(role)
    message = ""
    if ids:
        for _id in ids:
            if roles:
                ret[_id] = []
                for role in roles:
                    try:
                        res = okta.assign_role(_id, role)
                        if res:
                            ret[_id].append(res)
                            message += "The user with id {0} was assigned the role {1}.\n\n".format(_id, role)
                        else:
                            message += "The user with id {0} couldn't be assigned the role {1}.\n\n".format(_id, role)
                    except Exception as err:
                        siemplify.LOGGER.exception(err)
                        siemplify.LOGGER.error(_id + ", " + role + ": " + err.message)
                        errors += err.message + "\n\n"
                        pass
    if is_scope:
        entitiesAssigned = []
        for entity in siemplify.target_entities:
            if entity.entity_type == EntityTypes.USER or entity.entity_type == EntityTypes.HOSTNAME:
                _id = okta.login_to_id(entity.identifier)
                if _id:
                    if roles:
                        ret[entity.identifier] = []
                        for role in roles:
                            try:
                                res = okta.assign_role(_id, role)
                                if res:
                                    entitiesAssigned.append(entity)
                                    ret[entity.identifier].append(res)
                                    message += "The user \"{0}\" was assigned the role {1}.\n\n".format(entity.identifier, role)
                                else:
                                    message += "The user \"{0}\" couldn't be assigned the role {1}.\n\n".format(entity.identifier, role)
                            except Exception as err:
                                siemplify.LOGGER.exception(err)
                                siemplify.LOGGER.error(entity.identifier + ", " + role + ": " + err.message)
                                errors += err.message + "\n\n"
                                pass
                else:
                    message += "Couldn't find the user \"{0}\".\n\n".format(entity.identifier)
                    continue
            else:
                continue
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
            output_message = "No users were assigned roles. {}".format(message)
    else:
        output_message = "No users were assigned roles. {}".format(message)
    siemplify.end(output_message + errors, json.dumps(ret))

if __name__ == '__main__':
    main()