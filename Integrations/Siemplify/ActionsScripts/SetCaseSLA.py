from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_action_param
from consts import SET_CASE_SLA_SCRIPT_NAME
from SiemplifyExceptions import SdkVersionException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SET_CASE_SLA_SCRIPT_NAME

    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    sla_time_unit = extract_action_param(
        siemplify,
        param_name=u"SLA Time Unit",
        is_mandatory=True,
        print_value=True
    )

    sla_time_to_critical_unit = extract_action_param(
        siemplify,
        param_name=u"SLA Time To Critical Unit",
        is_mandatory=True,
        print_value=True
    )

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        try:
            sla_period = extract_action_param(
                siemplify,
                param_name=u"SLA Period",
                is_mandatory=True,
                input_type=int,
                print_value=True
            )

            if sla_period <= 0:
                raise

        except Exception:
            raise Exception(u"Invalid value provided in the parameter \"SLA Period\". Value should be a positive number")

        try:
            sla_time_to_critical_period = extract_action_param(
                siemplify,
                param_name=u"SLA Time To Critical Period",
                is_mandatory=True,
                input_type=int,
                print_value=True
            )

            if sla_time_to_critical_period < 0:
                raise
        except:
            raise Exception(u"Invalid value provided in the parameter \"SLA Time To Critical Period\". Value should "
                            u"be a positive number or zero")

        if not validate_sdk_version():
            raise SdkVersionException(u"Action is not supported for this SDK version")

        siemplify.LOGGER.info(u"Attempting to set case {} with SLA.".format(siemplify.case_id))
        siemplify.set_case_sla(sla_period, sla_time_unit, sla_time_to_critical_period, sla_time_to_critical_unit)
        output_message = u"Case {} was set with SLA of {} {} and critical period of {} {}.".format(
            siemplify.case_id, sla_period, sla_time_unit, sla_time_to_critical_period, sla_time_to_critical_unit
        )
        siemplify.LOGGER.info(output_message)

    except Exception as e:
        output_message = u"Error executing action {}. Reason: {}".format(SET_CASE_SLA_SCRIPT_NAME, e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}".format(status))
    siemplify.LOGGER.info(u"Result: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))

    siemplify.end(output_message, result_value, status)


def validate_sdk_version():
    """
    Validates if sdk version supports needed method
    Args:

    Returns:
        (bool) true if currently used SDK version supports set_case_sla() method, false otherwise
    """
    return hasattr(SiemplifyAction, "set_case_sla")


if __name__ == "__main__":
    main()
