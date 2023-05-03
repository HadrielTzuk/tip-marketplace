from ExchangeActions import extract_action_parameter, init_manager
from ExchangeCommon import ExchangeCommon
from exchangelib import FileAttachment
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from email.iterators import typed_subpart_iterator
from email.header import decode_header
from email import message_from_string
from EmailUtils import get_unicode_str, get_charset, EmailUtils
import json
import os
from constants import INTEGRATION_NAME, EXTRACT_EML_DATA_SCRIPT_NAME, DEFAULT_CHARSET


EML_EXTENSION = ".eml"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = EXTRACT_EML_DATA_SCRIPT_NAME

    output_message = "No matching mails were found."
    result_value = json.dumps([])
    status = EXECUTION_STATE_COMPLETED

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    message_id = extract_action_parameter(siemplify=siemplify, param_name="Message ID", is_mandatory=True)
    folder_name = extract_action_parameter(siemplify=siemplify, param_name="Folder Name", default_value="Inbox")
    regex_map_json = extract_action_parameter(siemplify=siemplify, param_name="Regex Map JSON", default_value="{}")

    try:
        regex_map = json.loads(regex_map_json)
    except Exception:
        raise ValueError("Invalid regex map.")

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        # Create new exchange manager instance
        em = init_manager(siemplify, INTEGRATION_NAME)

        emails = em.receive_mail(message_id=message_id, folder_name=folder_name)

        if emails:
            # Only 1 should match a message ID but method
            # returns a list
            found_email = emails[0]

            results = get_eml_data(found_email, regex_map)
            # Unless we encode result_value to UTF-8, it's not shown properly in Script Results
            # Looks like it doesn't like unicode on input.
            result_value = json.dumps(results, ensure_ascii=False)
            siemplify.result.add_result_json(results)
            siemplify.result.add_json("EML Data", result_value)

            output_message = "Data was extracted from {} EML files.".format(len(results))

    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}".format(EXTRACT_EML_DATA_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        output_message = "An error occurred while running action: {}".format(e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result_value, status)


def extract_metadata(msg):
    """
    Extract metadata (sender, recipient, date) from EML
    :param msg: {email.message.Message} An eml object
    :return: {tuple} sender, recipient, date
    """
    return msg.get("from", "").strip(), msg.get("to", "").strip(), msg.get("date", "").strip()


def extract_data(msg):
    """
    Extracts all data from e-mail, including sender, to, etc., and returns
    :param msg: {email.message.Message} An eml object
    :return: {dict} The data of the eml
    """
    subject = extract_subject(msg)
    sender, to, date = extract_metadata(msg)
    text_body, html_body = extract_content(msg)

    return {
        "subject": subject,
        "from": sender,
        "to": to,
        "date": date,
        "text": text_body,
        "html": html_body
    }


def get_eml_data(msg, regex_map):
    """
    Fetch EML data from message attachments.
    :param msg: {email.message.Message} An eml object
    :param regex_map:
    :return: {dict} Dict with message eml attachments data.
    """
    eml_data = []

    for attachment in msg.attachments:
        if isinstance(attachment, FileAttachment):
            if os.path.splitext(attachment.name)[-1] == EML_EXTENSION:
                # This is an eml - extract the data
                eml_msg = message_from_string(get_unicode_str(attachment.content))
                data = extract_data(eml_msg)
                email_html = data.get("html", "")
                email_text = data.get("text", "")

                if email_html:
                    data["regex"] = ExchangeCommon.extract_regex_from_content(email_html, regex_map)

                if email_text:
                    data["regex_from_text_part"] = ExchangeCommon.extract_regex_from_content(email_text, regex_map)

                eml_data.append(data)

    return eml_data


def extract_subject(msg):
    """
    Extract message subject from email message.
    :param msg: {email.message.Message} Message object.
    :return: {str} Subject text.
    """

    raw_subject = msg.get("subject")

    if not raw_subject:
        return ""

    try:
        parsed_value, encoding = decode_header(raw_subject)[0]
        if encoding is None:
            return parsed_value
        return parsed_value.decode(encoding)
    except UnicodeDecodeError:
        msg = "Unable to decode email subject"
        return msg


# noinspection PyBroadException
def extract_content(msg):
    """
    Extracts content from an e-mail message.
    :param msg: {email.message.Message} An eml object
    :return: {tuple} Text body, Html body
    """
    email_utils = EmailUtils()

    def extract_text_parts():
        text_parts = [part for part in typed_subpart_iterator(msg, "text", "plain")]
        text_body_parts = []
        parent_charset = get_charset(msg)

        for part in text_parts:
            try:
                charset = get_charset(part, parent_charset)
                text_body_parts.append(
                    email_utils.decode_by_charset(part.get_payload(decode=True), charset, DEFAULT_CHARSET)
                )
            except (UnicodeDecodeError, UnicodeEncodeError):
                pass

        return "\n".join(text_body_parts).strip()

    def extract_html_parts():
        html_parts = [part for part in typed_subpart_iterator(msg, "text", "html")]
        html_body_parts = []
        parent_charset = get_charset(msg)
        for part in html_parts:
            try:
                charset = get_charset(part, parent_charset)
                html_body_parts.append(
                    email_utils.decode_by_charset(part.get_payload(decode=True), charset, DEFAULT_CHARSET)
                )
            except (UnicodeDecodeError, UnicodeEncodeError):
                pass

        return "\n".join(html_body_parts).strip()

    if not msg.is_multipart():
        body = email_utils.decode_by_charset(msg.get_payload(decode=True), get_charset(msg), DEFAULT_CHARSET)
        return body.strip(), body.strip()
    else:
        return extract_text_parts(), extract_html_parts()


if __name__ == "__main__":
    main()
