from SiemplifyUtils import output_handler
from ExchangeManager import ExchangeManager
from constants import TOKEN_EXPIRY_NOTIFICATION_SCRIPT_NAME, INTEGRATION_NAME
from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import unix_now, utc_now, convert_unixtime_to_datetime

EMAIL_SUBJECT = "Siemplify Exchange Integration Refresh Token Expiry"
EMAIL_BODY = "Oauth refresh token configured in the Siemplify Exchange Integration will expire in {} {}. " \
             "We recommend obtaining a new refresh token and configure it in the integration to avoid any downtime " \
             "due to the refresh token expiry."
TOKEN_EXPIRATION_DAYS = 90
FIRST_NOTIFICATION_DAYS = 80
SECOND_NOTIFICATION_DAYS = 85
THIRD_NOTIFICATION_DAYS = 89


@output_handler
def main():
    siemplify = SiemplifyJob()

    try:
        siemplify.script_name = TOKEN_EXPIRY_NOTIFICATION_SCRIPT_NAME

        siemplify.LOGGER.info('--------------- JOB STARTED ---------------')

        server_address = siemplify.extract_job_param(param_name='Mail Server Address', is_mandatory=True)
        mail_address = siemplify.extract_job_param(param_name='Mail Address for sending notifications', is_mandatory=True)
        send_to = siemplify.extract_job_param(param_name='Notifications Recipients List', is_mandatory=True)
        client_id = siemplify.extract_job_param(param_name='Client ID', is_mandatory=True)
        client_secret = siemplify.extract_job_param(param_name='Client Secret', is_mandatory=False)
        tenant_id = siemplify.extract_job_param(param_name='Tenant (Directory) ID', is_mandatory=True)
        refresh_token = siemplify.extract_job_param(param_name='Refresh Token', is_mandatory=True)

        timestamp_data = ExchangeManager.read_token_timestamp(siemplify.LOGGER)
        token_save_date = convert_unixtime_to_datetime(timestamp_data.get("Token Update Date", unix_now()))
        siemplify.LOGGER.info(f"Refresh Token save date is {token_save_date}")

        delta_in_days = (utc_now() - token_save_date).days
        days_left = TOKEN_EXPIRATION_DAYS - delta_in_days
        days_string = "days" if days_left > 1 else "day"

        if days_left > 0:
            siemplify.LOGGER.info(f"Refresh Token will expire in {days_left} {days_string}."
                                  )
        else:
            siemplify.LOGGER.info("Refresh Token has expired. Please generate a new one and use it in "
                                  "integration's configuration.")

        if delta_in_days in [FIRST_NOTIFICATION_DAYS, SECOND_NOTIFICATION_DAYS, THIRD_NOTIFICATION_DAYS]:
            manager = ExchangeManager(
                exchange_server_ip=server_address,
                domain=None,
                user_mail_address=mail_address,
                siemplify_logger=siemplify.LOGGER,
                client_id=client_id,
                client_secret=client_secret,
                tenant_id=tenant_id,
                auth_token=refresh_token
            )
            siemplify.LOGGER.info("Sending a notification email.")
            manager.send_mail(to_addresses=send_to, subject=EMAIL_SUBJECT, body=EMAIL_BODY.format(days_left,
                                                                                                  days_string))

        siemplify.LOGGER.info('--------------- JOB FINISHED ---------------')

    except Exception as e:
        siemplify.LOGGER.error('Got exception on main handler.Error: {0}'.format(e))
        siemplify.LOGGER.exception(e)


if __name__ == '__main__':
    main()
