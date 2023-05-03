from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from OktaManager import OktaManager
import json

PROVIDER = "Okta"
ACTION_NAME = "Okta - DisableUser"

def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    user_ids_or_logins = siemplify.parameters.get('User IDs Or Logins', "")
    is_deactivate = siemplify.parameters.get('Is Deactivate', "false").lower() == "true"
    is_send_email_deactivate = siemplify.parameters.get('Send Email If Deactivate', "false").lower() == "true"
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
    action = "SUSPEND"
    if is_deactivate:
        action = "DEACTIVATE"
    if ids:
        for _id in ids:
            try:
                res = okta.disable_user(_id, is_deactivate, is_send_email_deactivate)
                if res:
                    message += "The user with id {0} was disabled ({1}).\n\n".format(_id, action)
                    ret[_id] = action
                else:
                    message += "The user with id {0} couldn't be disabled ({1}).\n\n".format(_id, action)
                    continue
            except Exception as err:
                siemplify.LOGGER.exception(err)
                siemplify.LOGGER.error(_id + " " + action + ": " + err.message)
                errors += err.message + "\n\n"
                pass
    if is_scope:
        entitiesDisabled = []
        for entity in siemplify.target_entities:
            if entity.entity_type == EntityTypes.USER or entity.entity_type == EntityTypes.HOSTNAME:
                try:
                    res = okta.disable_user(entity.identifier, is_deactivate, is_send_email_deactivate)
                    if res:
                        entitiesDisabled.append(entity)
                        message += "The user \"{0}\" was disabled ({1}).\n\n".format(entity.identifier, action)
                        ret[entity.identifier] = action
                    else:
                        message += "The user \"{0}\" couldn't be disabled ({1}).\n\n".format(entity.identifier, action)
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
        output_message = "No users were disabled. {}".format(message)
    siemplify.end(output_message + errors, json.dumps(ret))

if __name__ == '__main__':
    main()