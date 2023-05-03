from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from OktaManager import OktaManager
import json

PROVIDER = "Okta"
ACTION_NAME = "Okta - EnableUser"

def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    user_ids_or_logins = siemplify.parameters.get('User IDs Or Logins', "")
    is_reactivate = siemplify.parameters.get('Is Activate', "false").lower() == "true"
    is_send_email_reactivate = siemplify.parameters.get('Send Email If Activate', "false").lower() == "true"
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
    action = "UNSUSPEND"
    if is_reactivate:
        action = "ACTIVATE"
    if ids:
        for _id in ids:
            try:
                res = okta.enable_user(_id, is_reactivate, is_send_email_reactivate)
                if res == True:
                    message += "The user with id {0} was enabled ({1}).\n\n".format(_id, action)
                    ret[_id] = action
                else:
                    message += "The user with id {0} couldn't be enabled ({1}).\n\n".format(_id, action)
                    continue
            except Exception as err:
                siemplify.LOGGER.exception(err)
                siemplify.LOGGER.error(_id + " " + action + ": " + err.message)
                errors += err.message + "\n\n"
                pass
    if is_scope:
        entitiesEnabled = []
        for entity in siemplify.target_entities:
            if entity.entity_type == EntityTypes.USER or entity.entity_type == EntityTypes.HOSTNAME:
                try:
                    res = okta.enable_user(entity.identifier, is_reactivate, is_send_email_reactivate)
                    if res:
                        entitiesEnabled.append(entity)
                        message += "The user \"{0}\" was enabled ({1}).\n\n".format(entity.identifier, action)
                        ret[entity.identifier] = action
                    else:
                        message += "The user \"{0}\" couldn't be enabled ({1}).\n\n".format(entity.identifier, action)
                        continue
                except Exception as err:
                    siemplify.LOGGER.exception(err)
                    siemplify.LOGGER.error(entity.identifier + " " + action + ": " + err.message)
                    errors += err.message + "\n\n"
                    pass
            else:
                continue
    if ret:
        output_message = message
    else:
        output_message = "No users were enabled. {}".format(message)
    siemplify.end(output_message + errors, json.dumps(ret))

if __name__ == '__main__':
    main()