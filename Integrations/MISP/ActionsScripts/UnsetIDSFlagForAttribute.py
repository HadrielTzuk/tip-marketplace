from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from MISPManager import MISPManager, MISPManagerError
from TIPCommon import extract_configuration_param, extract_action_param
from utils import string_to_multi_value, adjust_categories
from exceptions import (
    MISPManagerEventIdNotProvidedError,
    MISPNotAcceptableParamError,
    MISPManagerEventIdNotFoundError)
from constants import (
    INTEGRATION_NAME,
    ATTRIBUTE_SEARCH_MAPPER,
    PROVIDED_EVENT,
    EXISTING_CATEGORY_TYPES,
    UNSET_IDS_FLAG_ON_AN_ATTRIBUTE_SCRIPT_NAME)
import arrow


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = UNSET_IDS_FLAG_ON_AN_ATTRIBUTE_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root")
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key")
    use_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Use SSL",
                                          default_value=False, input_type=bool)
    ca_certificate = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="CA Certificate File - parsed into Base64 String")

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    # INIT ACTION PARAMETERS:
    event_id = extract_action_param(siemplify, param_name='Event ID', print_value=True)
    attribute_names = string_to_multi_value(extract_action_param(siemplify, param_name='Attribute Name',
                                                                 print_value=True))
    categories = adjust_categories(string_to_multi_value(extract_action_param(siemplify, param_name='Category',
                                                                              print_value=True)))
    attribute_types = string_to_multi_value(extract_action_param(siemplify, param_name='Type', print_value=True))
    attribute_search = extract_action_param(siemplify, param_name='Attribute Search', print_value=True,
                                            default_value=ATTRIBUTE_SEARCH_MAPPER[PROVIDED_EVENT])
    attribute_uuids = string_to_multi_value(extract_action_param(siemplify, param_name="Attribute UUID",
                                                                 print_value=True))
    id_type = ('ID' if event_id.isdigit() else 'UUID') if event_id else None

    output_message = ''
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    successful_attributes, failed_attributes = [], []

    try:
        if attribute_search == ATTRIBUTE_SEARCH_MAPPER[PROVIDED_EVENT] and not event_id:
            raise MISPManagerEventIdNotProvidedError("Event ID needs to be provided, if \"Provided Event\" is selected "
                                                     "for the parameter \"Attribute Search\"")

        if set(map(str.lower, categories)).difference(set(EXISTING_CATEGORY_TYPES)):
            raise MISPNotAcceptableParamError(
                'Category',
                opt_msg='Acceptable values: {}'.format(', '.join(
                    [category.capitalize() for category in EXISTING_CATEGORY_TYPES])))

        manager = MISPManager(api_root, api_token, use_ssl, ca_certificate)

        if attribute_search == ATTRIBUTE_SEARCH_MAPPER[PROVIDED_EVENT]:
            manager.get_event_by_id_or_raise(event_id)

        for attribute in manager.get_attributes(attribute_names=attribute_names, attribute_uuids=attribute_uuids,
                                                attribute_search=attribute_search, event_id=[event_id],
                                                categories=categories, types=attribute_types):
            attribute_uuid_or_value = attribute.uuid if attribute_uuids else attribute.value
            try:
                manager.set_unset_ids_flag_for_attribute(attribute.id, False)
                successful_attributes.append(attribute_uuid_or_value)
                siemplify.LOGGER.info(
                    'Successfully unset IDS flag for the following attribute {}'.format(attribute_uuid_or_value))
            except Exception as e:
                siemplify.LOGGER.error(
                    'Failed to unset IDS flag for the following {}'.format(attribute_uuid_or_value))
                siemplify.LOGGER.exception(e)
                failed_attributes.append(attribute_uuid_or_value)

        if successful_attributes:
            output_message += "Successfully unset IDS flag for the following attributes in {}:\n {}\n" \
                .format(INTEGRATION_NAME, ', '.join(successful_attributes))

            if failed_attributes:
                output_message += "Action didn’t unset IDS flag for the following attributes in {}: \n {} \n" \
                    .format(INTEGRATION_NAME, ', '.join(failed_attributes))
        else:
            output_message = "IDS flag was not unset for the provided attributes in {}".format(INTEGRATION_NAME)
            result_value = False

    except Exception as e:
        output_message = "Error executing action {}. Reason: ".format(UNSET_IDS_FLAG_ON_AN_ATTRIBUTE_SCRIPT_NAME)
        output_message += 'Event with {} {} was not found in {}'.format(id_type, event_id, INTEGRATION_NAME) \
            if isinstance(e, MISPManagerEventIdNotFoundError) else str(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        "\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
