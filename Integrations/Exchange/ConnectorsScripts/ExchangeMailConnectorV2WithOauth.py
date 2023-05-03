import sys
import pytz
from SiemplifyUtils import output_handler, utc_now
from SiemplifyConnectors import SiemplifyConnectorExecution
from ExchangeManager import ExchangeManager
from ExchangeCommon import ExchangeCommon
from ExchangeConnectors import set_proxy, filter_emails_with_regexes, ExchangeConnector
from EmailUtils import EmailUtils
from TIPCommon import extract_connector_param, read_ids, write_ids
from ExchangeUtilsManager import is_invalid_prefix, convert_comma_separated_to_list
from exceptions import InvalidParameterException
from constants import STORED_IDS_LIMIT

# =====================================
#              CONSTANTS              #
# =====================================
CONNECTOR_NAME = "Exchange EML Connector v2 with Oauth Authentication"
DEFAULT_DIVIDER = ","
connector_starting_time = utc_now().replace(tzinfo=pytz.UTC)


@output_handler
def main(test_run):
    cases = []
    connector_scope = SiemplifyConnectorExecution()
    connector_scope.script_name = CONNECTOR_NAME

    if test_run:
        connector_scope.LOGGER.info("***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******")

    connector_scope.LOGGER.info("-------------------- Main - Param Init --------------------")

    environment_field_name = extract_connector_param(connector_scope, param_name="Environment Field Name")
    environment_regex = extract_connector_param(connector_scope, param_name='Environment Regex Pattern')
    headers_to_add_to_events = extract_connector_param(connector_scope, param_name='Headers to add to events')
    headers_to_add_to_events = [header.strip() for header in headers_to_add_to_events.split(DEFAULT_DIVIDER)
                                if header and header.strip()] if headers_to_add_to_events else []
    email_exclude_pattern = extract_connector_param(connector_scope, param_name='Email exclude pattern')
    mail_server_address = extract_connector_param(connector_scope, param_name='Mail Server Address', is_mandatory=True)
    mail_address = extract_connector_param(connector_scope, param_name="Mail Address", is_mandatory=True)
    client_id = extract_connector_param(siemplify=connector_scope, param_name="Client ID", is_mandatory=True)
    client_secret = extract_connector_param(siemplify=connector_scope, param_name="Client Secret", is_mandatory=False)
    tenant_id = extract_connector_param(siemplify=connector_scope, param_name="Tenant (Directory) ID",
                                        is_mandatory=True)
    refresh_token = extract_connector_param(siemplify=connector_scope, param_name="Refresh Token", is_mandatory=True)
    folder_name = extract_connector_param(connector_scope, param_name="Folder to check for emails", is_mandatory=True)
    unread_only = extract_connector_param(connector_scope, param_name="Unread Emails Only", input_type=bool)
    mark_as_read = extract_connector_param(connector_scope, param_name="Mark Emails as Read", input_type=bool)
    attach_original_eml = extract_connector_param(connector_scope, param_name="Attach Original EML", input_type=bool)
    offset_time_in_days = extract_connector_param(connector_scope, param_name="Offset Time In Days",
                                                  input_type=int, is_mandatory=True)
    time_interval = extract_connector_param(connector_scope, param_name="Fetch Backwards Time Interval (minutes)",
                                            input_type=int)
    padding_period = extract_connector_param(connector_scope, param_name="Email Padding Period (minutes)",
                                             input_type=int)
    max_email_per_cycle = extract_connector_param(connector_scope, param_name="Max Emails Per Cycle",
                                                  input_type=int, is_mandatory=True)
    extract_html_content_urls = extract_connector_param(siemplify=connector_scope,
                                                        param_name="Extract urls from HTML email part?",
                                                        input_type=bool)
    disable_overflow = extract_connector_param(siemplify=connector_scope, param_name="Disable Overflow",
                                               input_type=bool)
    verify_ssl = extract_connector_param(siemplify=connector_scope, param_name="Verify SSL", input_type=bool,
                                         default_value=False)

    original_mail_prefix = extract_connector_param(siemplify=connector_scope, param_name="Original Received Mail Prefix")
    attached_mail_prefix = extract_connector_param(siemplify=connector_scope, param_name="Attached Mail File Prefix")
    alert_per_attachment = extract_connector_param(siemplify=connector_scope, param_name="Create a Separate Siemplify "
                                                                                         "Alert per Attached Mail File?",
                                                   input_type=bool)
    case_name_template = extract_connector_param(siemplify=connector_scope, param_name="Case Name Template")
    alert_name_template = extract_connector_param(siemplify=connector_scope, param_name="Alert Name Template")
    folder_names = convert_comma_separated_to_list(folder_name)

    set_proxy(connector_scope)

    connector_scope.LOGGER.info("------------------- Main - Started -------------------")

    try:
        if original_mail_prefix and is_invalid_prefix(original_mail_prefix):
            raise InvalidParameterException("Original Received Mail Prefix configured contains a space, which is not "
                                            "supported, please remove any spaces and try again.")

        if attached_mail_prefix and is_invalid_prefix(attached_mail_prefix):
            raise InvalidParameterException("Attached Mail File Prefix configured contains a space, which is not "
                                            "supported, please remove any spaces and try again.")

        if padding_period is not None and padding_period < 0:
            raise InvalidParameterException(f"\"Email Padding Period (minutes)\" must be non-negative")

        connector_scope.LOGGER.info("Connecting to Exchange.")
        email_client = ExchangeManager(
            exchange_server_ip=mail_server_address,
            domain=None,
            user_mail_address=mail_address,
            siemplify_logger=connector_scope.LOGGER,
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id,
            auth_token=refresh_token,
            verify_ssl=verify_ssl
        )
        exchange_connector = ExchangeConnector(
            connector_scope,
            email_client,
            ExchangeCommon(connector_scope.LOGGER, email_client),
            EmailUtils(),
            offset_time_in_days,
            environment_field_name,
            environment_regex,
            test_run,
            headers_to_add_to_events,
            extract_html_content_urls=extract_html_content_urls,
            time_interval=time_interval,
            connector_starting_time=connector_starting_time,
            case_name_template=case_name_template,
            alert_name_template=alert_name_template,
            padding_period=padding_period)

        # Read already existing alerts ids
        existing_ids = read_ids(connector_scope)
        connector_scope.LOGGER.info(f"Successfully loaded {len(existing_ids)} existing ids")

        emails = exchange_connector.get_new_emails(unread_only, folder_names, existing_ids)
        # get oldest max_email_per_cycle emails
        emails = emails[-max_email_per_cycle:]

        if mark_as_read and not test_run:
            exchange_connector.mark_emails_as_read(emails)
        elif mark_as_read:
            connector_scope.LOGGER.info("This is a TEST run. Email won't be marked as read")

        emails = filter_emails_with_regexes(
            emails,
            email_exclude_pattern,
            email_exclude_pattern)

        connector_scope.LOGGER.info("Number of emails after filtering by regexes {}".format(len(emails)))

        if test_run:
            emails = emails[:1]
            connector_scope.LOGGER.info("Trimmed number of emails for processing to 1, since it's a test run")

        connector_scope.LOGGER.info("Fetching emails according to timestamp.")

        for original_msg in emails:
            try:
                connector_scope.LOGGER.info('Running on email with ID: {0}'.format(original_msg.message_id))

                if not alert_per_attachment:
                    cases_list = [exchange_connector.create_case_from_message(original_msg,
                                                                              attach_original_eml,
                                                                              original_mail_prefix,
                                                                              attached_mail_prefix)]
                else:
                    cases_list = exchange_connector.create_cases_from_message(original_msg,
                                                                              attach_original_eml,
                                                                              original_mail_prefix,
                                                                              attached_mail_prefix)

                # Update existing alerts
                existing_ids.append(original_msg.message_id)

                for case in cases_list:
                    if disable_overflow or not exchange_connector.is_original_case_info_overflow(case):
                        cases.append(case)

            except Exception as e:
                connector_scope.LOGGER.error(
                    "Failed to process email with message_id={0}".format(original_msg.message_id))
                connector_scope.LOGGER.exception(e)
                if test_run:
                    raise

        if not test_run:
            connector_scope.LOGGER.info("Saving existing ids.")
            write_ids(connector_scope, existing_ids, stored_ids_limit=STORED_IDS_LIMIT)
            exchange_connector.save_timestamp(emails, time_interval)

        connector_scope.LOGGER.info("Created {} cases.".format(len(cases)))

    except InvalidParameterException as error:
        connector_scope.LOGGER.error(error)
        if test_run:
            raise error

        raise

    except Exception as error:
        connector_scope.LOGGER.error("Error in main handler")
        connector_scope.LOGGER.exception(error)
        if test_run:
            raise error

        raise

    connector_scope.LOGGER.info("------------------- Main - Finished -------------------")
    connector_scope.return_package(cases)


if __name__ == "__main__":
    # Connectors are run in iterations. The interval is configurable from the ConnectorsScreen UI.
    is_test = not (len(sys.argv) < 2 or sys.argv[1] == u'True')
    main(is_test)
