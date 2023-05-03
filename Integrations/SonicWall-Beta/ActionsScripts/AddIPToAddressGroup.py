from SiemplifyAction import SiemplifyAction
from SonicWallManager import SonicWallManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from SiemplifyDataModel import EntityTypes
from UtilsManager import valid_ip_address
from constants import (
    INTEGRATION_NAME,
    ADD_IP_SCRIPT_NAME,
    IPV4_TYPE_STRING,
    IPV6_TYPE_STRING
)

from SonicWallExceptions import (
    NotFoundException,
    UnableToAddException,
    UnauthorizedException
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_IP_SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    # Configuration.
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           input_type=unicode, is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                           input_type=unicode, is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password",
                                           input_type=unicode, is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=True, input_type=bool, is_mandatory=True)

    # Parameters
    group_name = extract_action_param(siemplify, param_name=u'Group Name', is_mandatory=True)
    ip_zone = extract_action_param(siemplify, param_name=u'IP Zone', is_mandatory=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = u'true'
    output_message = u''
    successful_entities = []
    failed_entities = []
    ipv4_entities = []
    ipv6_entities = []
    ipv4_group = None
    ipv6_group = None

    try:
        sonic_wall_manager = SonicWallManager(api_root, username, password, verify_ssl=verify_ssl,
                                              siemplify_logger=siemplify.LOGGER)
        address_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS]
        for entity in address_entities:
            siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))
            ip_type = valid_ip_address(entity.identifier)
            if ip_type == IPV4_TYPE_STRING:
                ipv4_group = sonic_wall_manager.check_group(group_name, ip_type)
                ipv4_entities.append(entity)
            elif ip_type == IPV6_TYPE_STRING:
                ipv6_group = sonic_wall_manager.check_group(group_name, ip_type)
                ipv6_entities.append(entity)
            else:
                siemplify.LOGGER.info(u"Finished processing entity: {}".format(entity.identifier))
                continue
            siemplify.LOGGER.info(u"Finished processing entity: {}".format(entity.identifier))

        if ipv4_group:
            for entity in ipv4_entities:
                try:
                    object_name = sonic_wall_manager.create_address_object(IPV4_TYPE_STRING, ip_zone, entity.identifier)
                    sonic_wall_manager.add_ip_to_address_group(IPV4_TYPE_STRING, group_name, object_name)
                    sonic_wall_manager.confirm_changes()
                    successful_entities.append(entity)
                except UnableToAddException as e:
                    reason_message = unicode(e.args[0].message)
                    command_message = unicode(e.args[0].command)
                    failed_entities.append({u'entity': entity, u'reason': reason_message, u'command': command_message})

        if ipv6_group:
            for entity in ipv6_entities:
                try:
                    object_name = sonic_wall_manager.create_address_object(IPV6_TYPE_STRING, ip_zone, entity.identifier)
                    sonic_wall_manager.add_ip_to_address_group(IPV6_TYPE_STRING, group_name, object_name)
                    sonic_wall_manager.confirm_changes()
                    successful_entities.append(entity)
                except UnableToAddException as e:
                    reason_message = unicode(e.args[0].message)
                    command_message = unicode(e.args[0].command)
                    failed_entities.append({u'entity': entity, u'reason': reason_message, u'command': command_message})

        if successful_entities:
            output_message = u'Successfully added the following IPs to the SonicWall Address Group \"{}\": {}'.format(
                group_name, u'\n'.join([entity.identifier for entity in successful_entities]))

        if failed_entities:
            for item in failed_entities:
                output_message += u'\n\nAction was not able to add the following IP to the SonicWall Address Group \"{}\"' \
                                  u': {}. \nReason: {}. Command: {}.'.format(group_name, item.get(u"entity"),
                                                                             item.get(u'reason'), item.get(u'command'))

        if not successful_entities:
            output_message = u''
            for item in failed_entities:
                output_message += u'\nIP address was not added to the SonicWall Address Group \"{}\"' \
                                  u': {}. \nReason: {}. Command: {}.'.format(group_name, item.get(u"entity"),
                                                                             item.get(u'reason'), item.get(u'command'))
            result_value = u'false'

        if not ipv4_group and not ipv6_group:
            output_message = u"Address Group \"{}\" wasn't found in SonicWall".format(group_name)
            result_value = u'false'
        elif (not ipv4_group and ipv4_entities) or (not ipv6_group and ipv6_entities):
            ip_type = IPV4_TYPE_STRING if not ipv4_group else IPV6_TYPE_STRING
            output_message += u"\n\n{} Address Group \"{}\" wasn't found in SonicWall".format(ip_type, group_name)

        if not address_entities:
            output_message = u'No suitable entities found'
            result_value = u'false'

    except UnauthorizedException as e:
        output_message = unicode(e)
        result_value = u'false'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    except Exception as e:
        output_message = u"Error executing action \"Add IP to Address Group\". Reason: {}".format(e)
        result_value = u'false'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info(u'----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        u"\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()