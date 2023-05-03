from SiemplifyAction import SiemplifyAction
from VectraManager import VectraManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from constants import (
    INTEGRATION_NAME,
    UPDATE_NOTE_SCRIPT_NAME
)
from VectraExceptions import (
    ItemNotFoundException
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = UPDATE_NOTE_SCRIPT_NAME
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
    item_note = extract_action_param(siemplify, param_name=u"Note", input_type=unicode, is_mandatory=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = u'true'

    try:
        vectra_manager = VectraManager(api_root, api_token, verify_ssl=verify_ssl, siemplify=siemplify)
        received_item = vectra_manager.get_item_info(item_type, item_id)

        if not received_item:
            raise ItemNotFoundException(u'{} with ID {} was not found'.format(item_type, item_id))

        vectra_manager.update_note(item_type, item_id, item_note)
        output_message = u"Successfully updated note on {} with ID {}".format(item_type, item_id)
        siemplify.LOGGER.info(output_message)

    except ItemNotFoundException as e:
        output_message = unicode(e)
        result_value = u'false'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
    except Exception as e:
        output_message = u"Error executing action \"Update Note\". Reason: {}".format(e)
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
