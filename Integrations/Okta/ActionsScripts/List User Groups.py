from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import construct_csv, dict_to_flat
from OktaManager import OktaManager
import json

PROVIDER = "Okta"
ACTION_NAME = "Okta - ListUserGroups"

def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    user_ids_or_logins = siemplify.parameters.get('User IDs Or Logins', "")
    is_scope = siemplify.parameters.get('Also Run On Scope', "false").lower() == "true"
    ids = []
    res = {}
    ret = {}
    output_message = ""
    errors = "\n\nErrors:\n\n"
    okta = OktaManager(api_root=conf['Api Root'], api_token=conf['Api Token'],
                       verify_ssl=conf['Verify SSL'].lower() == 'true')
    if user_ids_or_logins:
        for _id in user_ids_or_logins.split(','):
            _id = _id.strip()
            ids.append(_id)
    message = ""
    if ids:
        for _id in ids:
            try:
                res = okta.list_user_groups(_id)
                if res:
                    groups = []
                    ret[_id] = []
                    for group in res:
                        groups.append(group['profile']['name'])
                        ret[_id].append(group)
                    message += "The user with id {0} belongs to {1} groups: {2}\n\n".format(_id, len(groups), ', '.join(groups))
                else:
                    message += "The user with id {0} doesn't belong to any group\n\n"
                    continue
            except Exception as err:
                siemplify.LOGGER.exception(err)
                siemplify.LOGGER.error(_id + ": " + err.message)
                errors += err.message + "\n\n"
                pass
    if is_scope:
        entitiesWithGroup = []
        entityGroups = {}
        for entity in siemplify.target_entities:
            if entity.entity_type == EntityTypes.USER or entity.entity_type == EntityTypes.HOSTNAME:
                try:
                    res = okta.list_user_groups(entity.identifier)
                    if res:
                        entitiesWithGroup.append(entity)
                        groups = []
                        entityGroups[entity.identifier] = {}
                        ret[entity.identifier] = []
                        for group in res:
                            groups.append(group['profile']['name'])
                            entityGroups[entity.identifier][group['profile']['name']] = group
                            ret[entity.identifier].append(group)
                        message += "The user \"{0}\" belongs to {1} groups: {2}\n\n".format(entity.identifier, len(groups), ', '.join(groups))
                    else:
                        message += "The user \"{0}\" doen't belong to any group.\n\n".format(entity.identifier)
                        continue
                except Exception as err:
                    siemplify.LOGGER.exception(err)
                    siemplify.LOGGER.error(entity.identifier + ": " + err.message)
                    errors += err.message + "\n\n"
                    pass
            else:
                continue
        #ret = entityGroups
    if ret:
        flag = False
        output_message = message
        for user, groups in ret.items():
            rows = []
            if groups:
                for group in groups:
                    if group:
                        flat_group = dict_to_flat(group)
                        rows.append(flat_group)
            if rows:
                flag = True
                csv_output = construct_csv(rows)
                siemplify.result.add_data_table("Okta - User \"{}\" Groups".format(user), csv_output)
        if not flag:
            output_message = "No groups were found. {}".format(message)
    else:
        output_message = "No groups were found. {}".format(message)
    siemplify.end(output_message + errors, json.dumps(ret))

if __name__ == '__main__':
    main()