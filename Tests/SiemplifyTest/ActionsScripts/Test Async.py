from SiemplifyAction import *
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
import SiemplifyUtils
from SiemplifyUtils import unix_now, output_handler
import sys

SCRIPT_NAME = "WaitFor3rdParty"


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    siemplify.LOGGER.info("FirstRun = {0}".format(is_first_run))

    async_mode = siemplify.parameters["IsAsync"].lower() == str(True).lower()
    finish_in_time = siemplify.parameters["FinishInTime"].lower() == str(True).lower()
    finish_in_grace = siemplify.parameters["FinishInGrace"].lower() == str(True).lower()
    async_never_finish = siemplify.parameters["AsyncNeverFinish"].lower() == str(True).lower()
    fail_normal = siemplify.parameters["Fail Normal"].lower() == str(True).lower()
    fail_async = siemplify.parameters["Fail Async"].lower() == str(True).lower()
    exception_on_fail = siemplify.parameters["Exception on Fail"].lower() == str(True).lower()
    password = siemplify.parameters["Password"]
    comment = siemplify.parameters["Comment"]

    if (async_never_finish):
        siemplify.end("ASYNC never finish", "ASYNC never finish", EXECUTION_STATE_INPROGRESS)
    else:
        finished = False
        result = siemplify.default_result_value
        status = EXECUTION_STATE_COMPLETED

        if not async_mode and fail_normal:
            result = "Normal (First run) failure"
            status = EXECUTION_STATE_FAILED
            finished = True
            if (exception_on_fail):
                raise Exception("Explosion!")

        if async_mode and fail_async:
            result = "Async run failure"
            status = EXECUTION_STATE_FAILED
            finished = True
            if (exception_on_fail):
                raise Exception("Explosion!")

        while (not finished and SiemplifyUtils.unix_now() < siemplify.execution_deadline_unix_time_ms):
            if (finish_in_time):
                if (async_mode):
                    finished = True
                    if (is_first_run):
                        result = "Asnyc In Progress"
                        status = EXECUTION_STATE_INPROGRESS
                    if (not is_first_run):
                        result = "Asnyc Finished"
                        status = EXECUTION_STATE_COMPLETED
                else:
                    finished = True
                    result = "Finished In Time"


        while (not finished and SiemplifyUtils.unix_now() < (siemplify.execution_deadline_unix_time_ms+30000)):
            if (finish_in_grace):
                finished = True
                result += "Finished In Grace"
                status = EXECUTION_STATE_TIMEDOUT

        while (not finished):
            result = "Im never gonna finish"
            status = EXECUTION_STATE_TIMEDOUT

        result += "{0} Password: {1} Comment: {2}".format(result, password, comment)

        siemplify.LOGGER.info(result)

        if (not finished and async_mode and is_first_run):
            result += " - First Action"
            status = EXECUTION_STATE_INPROGRESS

        siemplify.LOGGER.info("{0} - {1}".format(result, status))
        siemplify.end(result, result, status)


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[2] == 'True':
        main(True)
    else:
        main(False)