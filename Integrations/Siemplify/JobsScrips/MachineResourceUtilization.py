from SiemplifyUtils import output_handler
# ==============================================================================
# title           :MachineResource.py
# description     :This Module contain the current memory and CPU usage
# author          :zivh@siemplify.co
# date            :05-08-18
# python_version  :2.7
# libraries       :
# requirements    : psutil,
# product_version :
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================
import psutil
import os
from SiemplifyJob import SiemplifyJob
from utils import send_notification
from consts import SDK_JOB_MACHINE_RESOURCE as NOTIFICATION_ID


MONITORING_PROVIDER = 'Siemplify'

WIN_DEFAULT_DISKS = ['C:\\', 'D:\\', 'I:\\']
LINUX_DEFAULT_DISKS = ['/']

# Messages.
MAIL_SUBJECT_PATTERN = 'Mail From Siemplify: Detected errors in Machine Resources'


def send_mail(siemplify, mail_message):
    try:
        recipients = siemplify.get_configuration(MONITORING_PROVIDER).get('Recipients').split(",")
        siemplify.send_mail(MAIL_SUBJECT_PATTERN, mail_message, recipients, None, None)


    except Exception as e:
        siemplify.LOGGER.warn(e)



def check_utilization_limit(siemplify, error_messages, parameter_name, current_percentage_value, max_percentage_value):
    message = "Current %s is at %s out of acceptable limit of %s" % (
    parameter_name, str(current_percentage_value) + "%", str(max_percentage_value) + "%")
    siemplify.LOGGER.info(message)
    if (current_percentage_value >= max_percentage_value):
        error_messages.append(message)


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = 'MachineResourceUtilizationJob'

    try:
        siemplify.LOGGER.info("-----Job Started-----")

        # Parameters
        cpu_limit = int(siemplify.parameters['CPU Limit'])
        memory_limit = int(siemplify.parameters['Memory Limit'])
        drive_limit = int(siemplify.parameters['Drives Limit'])

        # fix_paths
        if 'win' in os.environ.get('OS', '').lower():
            disks_list = siemplify.parameters['Disks'].split(',') if siemplify.parameters.get("Disks") else WIN_DEFAULT_DISKS
        else:
            disks_list = siemplify.parameters['Disks'].split(',') if siemplify.parameters.get("Disks") else LINUX_DEFAULT_DISKS

        error_messages = []

        # Get Current Utilization Values:
        cpu_percent = psutil.cpu_percent()
        memory_percent = psutil.virtual_memory()[2]

        # Check CPU:
        check_utilization_limit(siemplify, error_messages, "CPU utilization", cpu_percent, cpu_limit)

        # Check Memory
        check_utilization_limit(siemplify, error_messages, "memory utilization", memory_percent, memory_limit)

        # Check Disks:
        for disk in disks_list:
            disk_usage_percent = psutil.disk_usage(disk)[3]
            disk_name = "Disk %s usage" % disk
            check_utilization_limit(siemplify, error_messages, disk_name, disk_usage_percent, drive_limit)

        if (error_messages):
            aggregatedMessage = "\r\n".join(error_messages)
            send_notification(siemplify, aggregatedMessage, NOTIFICATION_ID)
            email_mag = aggregatedMessage.replace("\r\n", "<br>")
            send_mail(siemplify, email_mag)

        siemplify.LOGGER.info("-----Job Finished-----")

    except Exception as e:
        siemplify.LOGGER.error("MachineResource Monitor ERROR. Details: " + e.message)
        siemplify.LOGGER.info("===========================================================================")
        siemplify.LOGGER.exception(e)
        raise e

    if (hasattr(siemplify.LOGGER, 'error_logged') and siemplify.LOGGER.error_logged):
        raise Exception("Error was logged during execution, check the logs")


if __name__ == '__main__':
    main()
