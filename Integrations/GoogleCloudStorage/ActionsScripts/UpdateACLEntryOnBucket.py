import json

from TIPCommon import extract_configuration_param, extract_action_param

import consts
import utils
from GoogleCloudStorageManager import GoogleCloudStorageManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from exceptions import GoogleCloudStorageInvalidParameterError


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{consts.INTEGRATION_NAME} - {consts.UPDATE_AN_ACL_ENTRY_ON_BUCKET}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    creds = extract_configuration_param(siemplify, provider_name=consts.INTEGRATION_NAME,
                                        param_name="Service Account",
                                        is_mandatory=True)
    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=consts.INTEGRATION_NAME,
        param_name="Verify SSL",
        input_type=bool,
        print_value=True
    )

    bucket_name = extract_action_param(siemplify, param_name="Bucket Name",
                                       is_mandatory=True,
                                       print_value=True,
                                       input_type=str)

    entity = extract_action_param(siemplify, param_name="Entity",
                                  is_mandatory=True,
                                  print_value=True,
                                  input_type=str)

    role = extract_action_param(siemplify, param_name="Role",
                                is_mandatory=True,
                                print_value=True,
                                input_type=str)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = ''
    result_value = False
    status = EXECUTION_STATE_COMPLETED

    try:
        creds = json.loads(creds)
        manager = GoogleCloudStorageManager(**creds, verify_ssl=verify_ssl)

        siemplify.LOGGER.info(f'Fetching ACL of bucket with name: {bucket_name}')
        acl = manager.get_acl(bucket_name)
        siemplify.LOGGER.info(f'Successfully fetched ACL of bucket with name: {bucket_name}')

        acl = acl.acl_data
        acl_entity = acl.get_entity(entity)

        #  Check if need to update: new_role > current_roles ?
        should_update, current_highest_role = utils.should_update(acl_entity.roles, role) if acl_entity else (True, -1)

        if not utils.is_entity_valid(entity):
            output_message += f"Action wasn’t able to update the ACL entity: '{entity}' to role: '{role}'" \
                              f" in bucket: '{bucket_name}'. The entity holding the permission can be user-userId," \
                              f" user-emailAddress, group-groupId, group-emailAddress, allUsers, or " \
                              f"allAuthenticatedUsers."
            status = EXECUTION_STATE_FAILED

        elif not acl.get_entity(entity):
            raise GoogleCloudStorageInvalidParameterError(f'Entity {entity} does not exist in the ACL '
                                                          f'of bucket {bucket_name} ')

        elif not should_update:
            result_value = True
            output_message += f"Action wasn’t able to update the ACL entity: '{entity}' " \
                              f"to role: '{role}' in bucket '{bucket_name}' " \
                              f"Reason: '{current_highest_role}s' are '{role}s'"

        else:
            siemplify.LOGGER.info(f'Grant {role} permission to entity: {entity} ACL of bucket '
                                  f'with name: {bucket_name}')

            # Revoke previous roles
            current_roles_set = set(acl.entities.get(entity).roles)
            for curr_role in current_roles_set:
                acl.entity(entity).revoke(curr_role)

            acl.entity(entity).grant(role)

            siemplify.LOGGER.info(f'Save updated ACL of bucket with name: {bucket_name} ')
            manager.update_acl(acl=acl)
            siemplify.LOGGER.info(f'Successfully Saved updated ACL of bucket with name: {bucket_name}')

            output_message += f"Successfully updated ACL entity: '{entity}' to role: '{role}' " \
                              f"in bucket: '{bucket_name}'"

            result_value = True

    except json.decoder.JSONDecodeError as error:
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error("Unable to parse credentials as JSON.")
        siemplify.LOGGER.exception(error)
        siemplify.end("Unable to parse credentials as JSON. Please validate creds.", False, EXECUTION_STATE_FAILED)

    except Exception as error:
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action '{consts.UPDATE_AN_ACL_ENTRY_ON_BUCKET}'. " \
                         f'Reason: {error}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
