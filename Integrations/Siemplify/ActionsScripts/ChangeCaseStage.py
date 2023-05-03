from SiemplifyUtils import output_handler
import re

from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

CHANGE_STAGE_INVALID_OPERATION_MESSAGE_RE = "^.*\"(User tried to change stage of requested case: .*, which had stage of Incident).*$"
INVALID_OPERATION_USER_MESSAGE = "User tried to change stage of requested case, which had stage of Incident"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "Change Case Stage"
    action_status = EXECUTION_STATE_COMPLETED

    stage = siemplify.parameters["Stage"]
    previousStage = siemplify.case.stage

    if (previousStage == stage):
        output_message = "Case stage change was attempted unsuccessfully, because the case is already assigned to stage %s." % (
            stage)
    else:
        try:
            siemplify.change_case_stage(stage)
            output_message = "Case stage was successfully changed to %s." % (stage)
        except Exception as e:
            if re.findall(CHANGE_STAGE_INVALID_OPERATION_MESSAGE_RE, e.message):
                output_message = INVALID_OPERATION_USER_MESSAGE
                action_status = EXECUTION_STATE_FAILED
            else:
                raise

    siemplify.end(output_message, True, action_status)


if __name__ == '__main__':
    main()
