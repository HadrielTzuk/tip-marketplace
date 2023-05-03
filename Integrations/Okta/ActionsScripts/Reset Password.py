from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from OktaManager import OktaManager
import json

PROVIDER = "Okta"
ACTION_NAME = "Okta - ResetPassword"

def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    user_ids_or_logins = siemplify.parameters.get('User IDs Or Logins', "")
    send_email = siemplify.parameters.get('Send Email', "false").lower() == "true"
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
                res = okta.reset_password(_id, send_email_with_reset_link=send_email)
                if res:
                    if send_email:
                        message += "The password reset was requested via email for user with id {0}.\n\n".format(_id)
                    else:
                        message += "The password reset for user with id {0} was requested. Link: {1}.\n\n".format(_id, res['resetPasswordUrl'])
                    ret[_id] = res
                else:
                    if not send_email:
                        message += "{0}: Something went wrong.".format(_id)
                    else:
                        ret[_id] = res
                    continue
            except Exception as err:
                siemplify.LOGGER.exception(err)
                siemplify.LOGGER.error(_id + ": " + err.message)
                errors += err.message + "\n\n"
                pass
    if is_scope:
        entitiesProcessed = []
        entityLinks = {}
        for entity in siemplify.target_entities:
            if entity.entity_type == EntityTypes.USER or entity.entity_type == EntityTypes.HOSTNAME:
                try:
                    res = okta.reset_password(entity.identifier, send_email_with_reset_link=send_email)
                    if res:
                        if not send_email:
                            entityLinks.update({entity.identifier: res})
                            message += "The user \"{0}\" must go to {1} in order to change his password.\n\n".format(entity.identifier, res['resetPasswordUrl'])
                        else:
                            message += "The user \"{0}\" was sent an email in order to change his password.\n\n".format(entity.identifier)
                        entityLinks[entity.identifier] = res
                        entitiesProcessed.append(entity)
                        ret[entity.identifier] = res
                    else:
                        if not send_email:
                            message += "{0}: Something went wrong.\n\n".format(entity.identifier)
                        else:
                            entityLinks[entity.identifier] = res
                        continue
                except Exception as err:
                    siemplify.LOGGER.exception(err)
                    siemplify.LOGGER.error(entity.identifier + ": " + err.message)
                    errors += err.message + "\n\n"
                    pass
            else:
                continue
        #ret = entityLinks
    if ret:
        output_message = message
    else:
        output_message = "No password reset requests could be processed. {}".format(message)
    siemplify.end(output_message + errors, json.dumps(ret))

if __name__ == '__main__':
    main()