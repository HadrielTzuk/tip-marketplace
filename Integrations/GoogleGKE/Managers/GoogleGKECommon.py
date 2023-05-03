import json
from typing import List, Any

from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_TIMEDOUT
from consts import COMMA_SPACE, IN_PROGRESS_STATUSES, DONE, INTEGRATION_DISPLAY_NAME
from datamodels import FilterLogicParam, KubeClusterOperation


class GoogleGKECommon(object):
    def get_filtered_objects(self, objs: List[Any], attribute: str, filter_logic: str, filter_value: str):
        """
        Get filtered objects
        :param objs: [{obj}] List of objects to filter
        :param attribute: {str} Objects attribute to filter
        :param filter_logic: {str} Enum value of Filter logic parameter
        :param filter_value: {str} Value to use in the filter
        :return: {[obj]} List of filtered objects
        """
        if filter_logic == FilterLogicParam.Equal.value:
            return list(filter(lambda x: getattr(x, attribute) == filter_value, objs))
        elif filter_logic == FilterLogicParam.Contains.value:
            return list(filter(lambda x: filter_value in getattr(x, attribute), objs))
        else:
            raise Exception(
                f"Invalid \"Filter Logic\" parameter was provided. Possible values are: {COMMA_SPACE.join([f.value for f in FilterLogicParam])}")

    def check_operation_status(self, operation: KubeClusterOperation, timeout_approached: bool = False):
        """
        Check Kubernetes Cluster operation status and return appropriate action results
        :param operation: {KubeClusterOperation} Kubernetes cluster data model
        :param timeout_approached: {bool} True if action's timeout is approaching, otherwise False
        :return: {output message, result value, status} Output message, result value and the status of the action
        """
        result_value = False
        status = EXECUTION_STATE_COMPLETED

        if not timeout_approached and operation.status in IN_PROGRESS_STATUSES:
            status = EXECUTION_STATE_INPROGRESS
            output_message = f"Operation {operation.name} is still in progress, current status: {operation.status}."
            result_value = json.dumps(operation.name)

        elif operation.status == DONE:
            output_message = f"Operation {operation.name} successfully finished."
            result_value = True
        else:
            output_message = f"Operation {operation.name} failed to complete with the following status: {operation.status}."
            if timeout_approached:
                status = EXECUTION_STATE_TIMEDOUT
                output_message += f"\nNote: This action is an async action. The Siemplify action timed out but the {INTEGRATION_DISPLAY_NAME} operation might be still " \
                                  f"running. Please use the action \"Get Operation Status\" or check the status on the {INTEGRATION_DISPLAY_NAME}'s side. Additionally, " \
                                  f"consider adjusting action's timeout in the IDE for action to be able to finish completely."

        return output_message, result_value, status
