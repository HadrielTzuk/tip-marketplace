from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
import base64
from constants import PROVIDER_NAME, PARSE_EML_TO_JSON_SCRIPT_NAME, PARAMETERS_DEFAULT_DELIMITER
from TIPCommon import extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
import extract_msg
from msg_parser import MsOxMessage
from UtilsManager import is_ole_file, prepare_json, prepare_body_json, prepare_attachment_json, filter_eml_headers
from EmailParser import EmailParser


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PARSE_EML_TO_JSON_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    eml_content = extract_action_param(siemplify, param_name="EML Content", is_mandatory=True)
    blacklisted_headers = extract_action_param(siemplify, param_name="Blacklisted Headers", print_value=True)
    use_blacklist_as_whitelist = extract_action_param(siemplify, param_name="Use Blacklist As Whitelist",
                                                      input_type=bool, print_value=True)

    blacklisted_headers_list = [blacklisted_header.strip() for blacklisted_header in blacklisted_headers
        .split(PARAMETERS_DEFAULT_DELIMITER)] if blacklisted_headers else []

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result_value = True
    output_message = "Successfully parsed EML to JSON."
    status = EXECUTION_STATE_COMPLETED

    try:
        content = base64.b64decode(eml_content)
        parsed_email, is_eml = get_parsed_email(siemplify, content, blacklisted_headers_list, use_blacklist_as_whitelist)
        attachments, nested_emails = get_attachments_and_nested_emails(siemplify, parsed_email.get("attachment", []))
        parsed_email["attachments"] = list(
            {attachment["hash"]["sha256"]: attachment for attachment in attachments}.values()
        )
        parsed_email["attached_emails"] = list(nested_emails.values())
        if is_eml:
            parsed_email.pop("attachment", None)

        for body_item in parsed_email.get("body", []):
            parsed_email["domains"].extend(body_item.get("domain", []))
            parsed_email["urls"].extend(body_item.get("uri", []))
            parsed_email["ips"].extend(body_item.get("ip", []))
            parsed_email["emails"].extend(body_item.get("email", []))

        for attached_email in parsed_email.get("attached_emails", []):
            for body_item in attached_email["email"]["body"]:
                parsed_email["domains"].extend(body_item.get("domain", []))
                parsed_email["urls"].extend(body_item.get("uri", []))
                parsed_email["ips"].extend(body_item.get("ip", []))
                parsed_email["emails"].extend(body_item.get("email", []))

        parsed_email["domains"] = list(set(parsed_email["domains"]))
        parsed_email["urls"] = list(set(parsed_email["urls"]))
        parsed_email["emails"] = list(set(parsed_email["emails"]))
        parsed_email["ips"] = list(set(parsed_email["ips"]))

        siemplify.result.add_json("Parsed EML", parsed_email)
        siemplify.result.add_result_json(parsed_email)
    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}".format(PARSE_EML_TO_JSON_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = "Error executing action \"{}\". Reason: {}".format(PARSE_EML_TO_JSON_SCRIPT_NAME, e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result_value, status)


def get_parsed_email(siemplify, content, blacklisted_headers_list, use_blacklist_as_whitelist):
    """
    Get parsed email from eml or msg files content
    :param siemplify: {SiemplifyAction} SiemplifyAction object
    :param content: {str} The content of email
    :param blacklisted_headers_list: {list} The list headers to exclude from the response
    :param use_blacklist_as_whitelist: {bool} Specify whether use blacklist as whitelist or no
    :return: {dict} Dictionary containing parsed email data
    """
    if is_ole_file(content):
        parsed_email = parse_msg(content, blacklisted_headers_list, use_blacklist_as_whitelist)
        is_eml = False
    else:
        mail_parser = EmailParser(siemplify, content.decode("utf-8"))
        parsed_email = mail_parser.return_parsed_json_email()
        filter_eml_headers(parsed_email.get("header", {}), blacklisted_headers_list,
                           use_blacklist_as_whitelist)
        is_eml = True
    return parsed_email, is_eml


def get_attachments_and_nested_emails(siemplify, parsed_email_attachments):
    attachments = []
    nested_emails = {}

    for attachment in parsed_email_attachments:
        attachments.append(attachment)

        try:
            nested_email = process_attachment(siemplify, attachment)
            nested_attachments = []

            for nested_attachment in nested_email["attachment"]:
                a = nested_attachment
                del a["raw"]
                nested_attachments.append(a)

            nested_email["attachments"] = nested_attachments

            for nested_attachment in nested_email["attachment"]:
                attachments.append(nested_attachment)

                try:
                    nested_nested_email = process_attachment(siemplify, nested_attachment)
                    nested_attachments_holder = []

                    for nested_nested_attachment in nested_nested_email["attachment"]:
                        attachments.append(nested_nested_attachment)
                        del nested_nested_attachment["raw"]
                        nested_attachments_holder.append(nested_nested_attachment)

                    nested_nested_email["attachments"] = nested_attachments_holder
                    del nested_nested_email["attachment"]

                    nested_emails[nested_attachment["hash"]["md5"]] = {
                        "filename": nested_attachment["filename"],
                        "email": nested_nested_email
                    }

                except Exception:
                    siemplify.LOGGER.info("Failed to process nested email attachment")

            del nested_email["attachment"]
            nested_emails[attachment["hash"]["md5"]] = {
                "filename": attachment["filename"],
                "email": nested_email
            }
        except Exception:
            pass

    return attachments, nested_emails


def process_attachment(siemplify, attachment):
    attached_msg = base64.b64decode(attachment["raw"])
    attached_msg_parsed = EmailParser(siemplify, attached_msg.decode('utf-8')).return_parsed_json_email()
    if len(attached_msg_parsed["header"]["to"]) == 0:
        attached_msg_parsed = parse_msg(attached_msg)

    return attached_msg_parsed


def parse_msg(msg, blacklist, is_whitelist):
    """
    Parse email from msg file
    :param msg: {str} The content of email
    :param blacklist: {list} The list headers to exclude from the response
    :param is_whitelist: {bool} Specify whether use blacklist as whitelist or no
    :return: {dict} Extracted MSG json
    """
    extracted_msg = extract_msg.Message(msg)
    msg_obj = MsOxMessage(msg)
    msox_msg = msg_obj._message.as_dict()

    current_json = prepare_json(extracted_msg, msox_msg, blacklist, is_whitelist)
    current_json['attached_emails'] = {}
    current_json['attachment'] = []

    # add the attachments to current json
    _att_counter = 0
    for _attachment in extracted_msg.attachments:
        msox_obj = None

        for msox_attachments in msox_msg['attachments']:
            if msox_msg.get('attachments', {}).get(msox_attachments, {}).get(
                    'AttachFilename') == _attachment.shortFilename:
                msox_obj = msox_msg.get('attachments', {}).get(msox_attachments, {})

        if _attachment.type in 'msg':
            _attached_json = prepare_json(_attachment.data, msox_obj.get('EmbeddedMessage', {}).get('properties', {}),
                                          blacklist, is_whitelist)
            try:
                _attached_json['body'].append(
                    prepare_body_json(base64.b64encode(_attachment.data.compressedRtf).decode(), "text/base64"))
                _attached_json['body'].append(prepare_body_json(_attachment.data.rtfBody, "text/rtf"))
            except Exception:
                pass

            for _attach_attached in _attachment.data.attachments:
                _attached_json['attachment'].append(prepare_attachment_json(filename=_attach_attached.shortFilename,
                                                                            content=_attach_attached.data))
            current_json['attached_emails'][_attachment.shortFilename] = _attached_json

        elif _attachment.type in "data":
            # if attachment in parent msg has binary content
            _att_counter += 1
            current_json['attachment'].append(prepare_attachment_json(filename=msox_obj['AttachLongFilename'],
                                                                      content=_attachment.data))

    current_json["domains"] = []
    current_json["urls"] = []
    current_json["ips"] = []
    current_json["emails"] = []

    for body_item in current_json.get("body", []):
        current_json["domains"].extend(body_item.get("domain", []))
        current_json["urls"].extend(body_item.get("uri", []))
        current_json["ips"].extend(body_item.get("ip", []))
        current_json["domains"].extend(body_item.get("domain", []))
        current_json["emails"].extend(body_item.get("email", []))

    for attached_email in current_json.get("attached_emails", []):
        for body_item in attached_email["email"]["body"]:
            current_json["domains"].extend(body_item.get("domain", []))
            current_json["urls"].extend(body_item.get("uri", []))
            current_json["ips"].extend(body_item.get("ip", []))
            current_json["domains"].extend(body_item.get("domain", []))
            current_json["emails"].extend(body_item.get("email", []))

    current_json["domains"] = list(set(current_json["domains"]))
    current_json["urls"] = list(set(current_json["urls"]))
    current_json["emails"] = list(set(current_json["emails"]))
    current_json["ips"] = list(set(current_json["ips"]))

    return current_json


if __name__ == "__main__":
    main()
