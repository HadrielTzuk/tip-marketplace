# coding=utf-8
import copy
from SiemplifyAction import SiemplifyAction
from VectraManager import VectraManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from constants import (
    INTEGRATION_NAME,
    REMOVE_TAGS_SCRIPT_NAME
)
from VectraExceptions import (
    ItemNotFoundException,
    TagsUpdateFailException,
    UnknownTagsUpdateException
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = REMOVE_TAGS_SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    # Configuration.
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           input_type=unicode, is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Token",
                                           input_type=unicode, is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=True, input_type=bool, is_mandatory=True)

    # Parameters
    item_type = extract_action_param(siemplify, param_name=u"Item Type", input_type=unicode, is_mandatory=True)
    item_id = extract_action_param(siemplify, param_name=u"Item ID", input_type=unicode, is_mandatory=True)
    tags = extract_action_param(siemplify, param_name=u"Tags", input_type=unicode, is_mandatory=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = u'true'

    try:
        vectra_manager = VectraManager(api_root, api_token, verify_ssl=verify_ssl, siemplify=siemplify)
        received_item = vectra_manager.get_item_info(item_type, item_id)

        if not received_item:
            raise ItemNotFoundException(u'{} with ID {} was not found'.format(item_type, item_id))

        existing_tags = copy.deepcopy(received_item.tags)
        tags_to_remove = [t.strip() for t in tags.split(u',') if t.strip()]
        successfully_removed_tags = []
        for tag in tags_to_remove:
            if tag in existing_tags:
                existing_tags.remove(tag)
                successfully_removed_tags.append(tag)

        if not successfully_removed_tags:
            raise TagsUpdateFailException(u"Tags {} don't exist in {} with ID {}".format(tags, item_type, item_id))

        vectra_manager.update_tags(item_type, item_id, existing_tags)
        output_message = u"Successfully removed tags {} from {} with ID {}".format(u','.join(successfully_removed_tags),
                                                                                   item_type, item_id)
        siemplify.LOGGER.info(output_message)

    except (ItemNotFoundException, TagsUpdateFailException) as e:
        output_message = unicode(e)
        result_value = u'false'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
    except UnknownTagsUpdateException:
        output_message = u"Action wasn't able to remove tags from {} with ID {}".format(item_type, item_id)
        result_value = u'false'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(output_message)
    except Exception as e:
        output_message = u"Error executing action \"Remove Tags\". Reason: {}".format(e)
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
