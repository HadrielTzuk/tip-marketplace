from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from EmailSMTPManager import EmailSMTPManager
from EmailIMAPManager import EmailIMAPManager
from EmailActions import BaseEmailAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

class PingAction(BaseEmailAction):
    """
    Class wrapping all logic for PingAction.
    System uses it when you click Test in Integration configurations.
    """

    def __init__(self):
        """
        Class constructor. Comparing to other BaseEmailAction ancestors,
        it doesn't login to SMTP and IMAP immediately. Instead this is done within run() method.
        """
        super(PingAction, self).__init__("EmailV2 - Ping")

        # Instantiate EmailSMTPManager & EmailIMAPManager
        self.email_smtp_manager = EmailSMTPManager(self.from_address)
        self.email_imap_manager = EmailIMAPManager(
            mail_address=self.from_address,
            logger=self.logger,
            environment=None,
        )

    # noinspection PyAttributeOutsideInit
    def load_integration_configuration(self):
        """
        Protected method, which should load whole Email integration configuration.
        I'm calling same method of the superclass to avoid copy paste of basic params initiation.
        :return:
        """
        super(PingAction, self).load_integration_configuration()

        self.imap_host = self._get_integration_param(
            param_name='IMAP Server Address',
            default_value='Not yet configured')
        # noinspection PyTypeChecker
        self.imap_port = self._get_integration_param(
            param_name='IMAP Port',
            default_value='Not yet configured')
        # noinspection PyTypeChecker
        self.imap_use_ssl = self._get_integration_param(
            param_name='IMAP USE SSL',
            input_type=bool,
            default_value=True)

    def load_action_configuration(self):
        """
        No specific action configurations.
        """
        pass

    def run(self):
        """
        Try to connect to SMTP and IMAP to test integration configuration.
        """
        # And Login to them
        smtp_configured = True
        imap_configured = True
        result = True
        status = EXECUTION_STATE_COMPLETED

        try:
            self.validate_configuration(self.smtp_host, self.smtp_port)
        except:
            smtp_configured = False

        try:
            self.validate_configuration(self.imap_host, self.imap_port)
        except:
            imap_configured = False

        smtp_configured_message = ' SMTP ' if smtp_configured else ''
        imap_configured_message = ' IMAP ' if imap_configured else ''

        try:
            if smtp_configured:
                self.email_smtp_manager.login_smtp(
                    host=self.smtp_host,
                    port=self.smtp_port,
                    username=self.username,
                    password=self.password,
                    use_ssl=self.smtp_use_ssl,
                    use_auth=self.smtp_use_auth)

            if imap_configured:
                self.email_imap_manager.login_imap(
                    host=self.imap_host,
                    port=self.imap_port,
                    username=self.username,
                    password=self.password,
                    use_ssl=self.imap_use_ssl)

            output_message = "Connected successfully with{}{}".format(smtp_configured_message,
                                                                          imap_configured_message)
        except Exception as e:
            result = False
            status = EXECUTION_STATE_FAILED
            output_message = "Failed to connect! Error is {}".format(e)
            self.siemplify.LOGGER.error(output_message)
            self.siemplify.LOGGER.exception(e)


        if not smtp_configured and not imap_configured:
            result = False
            status = EXECUTION_STATE_FAILED
            output_message = "SMTP (or IMAP) configuration is needed to execute action. Please configure STMP (or " \
                             "IMAP) on integration configuration page in Marketplace. "

        self.siemplify.LOGGER.info("----------------- Main - Finished -----------------")
        self.siemplify.LOGGER.info("Output Message: {}".format(output_message))
        self.siemplify.LOGGER.info("Result: {}".format(result))
        self.siemplify.LOGGER.info("Status: {}".format(status))

        self.siemplify.end(output_message, result, status)


@output_handler
def main():
    action = PingAction()
    action.run()


if __name__ == "__main__":
    main()
