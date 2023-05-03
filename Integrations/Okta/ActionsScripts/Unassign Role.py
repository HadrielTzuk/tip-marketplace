from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from OktaManager import OktaManager
import json

PROVIDER = "Okta"
ACTION_NAME = "Okta - UnassignRole"

def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    user_ids = siemplify.parameters.get('User IDs', "")
    role_types = siemplify.parameters['Role IDs Or Names']
    is_role_id = siemplify.parameters.get("Is Id", "false").lower() == "true"
    is_scope = siemplify.parameters.get('Also Run On Scope', "false").lower() == "true"
    roles = []
    ids = []
    res = {}
    ret = {}
    flag = False
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
                        if is_role_id:
                            res = okta.unassign_role(_id, role)
                        else:
                            role_id = okta.find_role_id_by_name(_id, role)
                            if role_id:
                                res = okta.unassign_role(_id, role_id)
                            else:
                                message += _id + ": Couldn't find role id for {0}.\n\n".format(role)
                                continue
                        if res:
                            ret[_id].append(role)
                            flag = True
                            message += "The user with id {0} was unassigned the role {1}.\n\n".format(_id, role)
                        else:
                            message += "The user with id {0} couldn't be unassigned the role {1}.\n\n".format(_id, role)
                    except Exception as err:
                        siemplify.LOGGER.exception(err)
                        siemplify.LOGGER.error(_id + ", " + role + ": " + err.message)
                        errors += err.message + "\n\n"
                        pass
    if is_scope:
        entitiesUnassigned = []
        for entity in siemplify.target_entities:
            if entity.entity_type == EntityTypes.USER or entity.entity_type == EntityTypes.HOSTNAME:
                _id = okta.login_to_id(entity.identifier)
                if _id:
                    if roles:
                        ret[entity.identifier] = []
                        for role in roles:
                            try:
                                if is_role_id:
                                    res = okta.unassign_role(_id, role)
                                else:
                                    role_id = okta.find_role_id_by_name(_id, role)
                                    if role_id:
                                        res = okta.unassign_role(_id, role_id)
                                    else:
                                        message += entity.identifier + ": Couldn't find role id {0}.\n\n".format(role)
                                        continue
                                if res:
                                    entitiesUnassigned.append(entity)
                                    ret[entity.identifier].append(role)
                                    flag = True
                                    message += "The user \"{0}\" was unassigned the role {1}.\n\n".format(entity.identifier, role)
                                else:
                                    message += "The user \"{0}\" couldn't be unassigned the role {1}.\n\n".format(entity.identifier, role)
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
    success = "false"
    if ret and flag:
        output_message = message
        success = "true"
    else:
        output_message = "No users were unassigned roles. {}".format(message)
    siemplify.end(output_message + errors, success)

if __name__ == '__main__':
    main()