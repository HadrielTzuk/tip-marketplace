import string
import secrets
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from OktaManager import OktaManager
import json

PROVIDER = "Okta"
ACTION_NAME = "Okta - SetPassword"

def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    user_ids_or_logins = siemplify.parameters.get('User IDs Or Logins', "")
    new_password = siemplify.parameters['New Password']
    is_add_random = siemplify.parameters.get("Add 10 Random Chars", "false").lower() == "true"
    is_scope = siemplify.parameters.get('Also Run On Scope', "false").lower() == "true"
    ids = []
    res = {}
    passwords = {}
    output_message = ""
    errors = "\n\nErrors:\n\n"
    if not is_add_random:
        if len(new_password) < 8 or new_password.lower() == new_password or new_password.upper() == new_password:
            siemplify.end("Password requirements were not met. Password requirements: at least 8 characters, a lowercase letter, an uppercase letter, a number, no parts of your username.", "false")
    okta = OktaManager(api_root=conf['Api Root'], api_token=conf['Api Token'],
                       verify_ssl=conf['Verify SSL'].lower() == 'true')
    if user_ids_or_logins:
        for _id in user_ids_or_logins.split(','):
            _id = _id.strip()
            ids.append(_id)
    message = ""
    if ids:
        for _id in ids:
            if is_add_random:
                allchars = string.ascii_letters + string.punctuation + string.digits
                random_10 = "".join(secrets.choice(allchars) for _ in range(0, 10))
                new_password += random_10
            try:
                res = okta.set_password(_id, new_password=new_password)
                if res:
                    passwords.update({_id: new_password})
                    message += "The password was set successfully for user with id {0}: {1}\n\n".format(_id, new_password)
                else:
                    message = "The password couldn't be set for user with id {0}.\n\n".format(_id)
            except Exception as err:
                siemplify.LOGGER.exception(err)
                siemplify.LOGGER.error(_id + ": " + err.message)
                errors += err.message + "\n\n"
                pass
    if is_scope:
        for entity in siemplify.target_entities:
            if entity.entity_type == EntityTypes.USER or entity.entity_type == EntityTypes.HOSTNAME:
                if is_add_random:
                    allchars = string.ascii_letters + string.punctuation + string.digits
                    random_10 = "".join(secrets.choice(allchars) for _ in range(0, 10))
                    new_password += random_10
                try:
                    res = okta.set_password(entity.identifier, new_password=new_password)
                    if res:
                        passwords.update({entity.identifier: new_password})
                        message += "The password was set successfully for user \"{0}\": {1}\n\n".format(entity.identifier, new_password)
                    else:
                        message += "The password couldn't be set for user \"{0}\".\n\n".format(entity.identifier)
                except Exception as err:
                    siemplify.LOGGER.exception(err)
                    siemplify.LOGGER.error(entity.identifier + ": " + err.message)
                    errors += err.message + "\n\n"
                    pass
            else:
                continue
    if passwords:
        output_message = message
    else:
        output_message = "No passwords were set. {}".format(message)
    siemplify.end(output_message + errors, json.dumps(passwords))

if __name__ == '__main__':
    main()