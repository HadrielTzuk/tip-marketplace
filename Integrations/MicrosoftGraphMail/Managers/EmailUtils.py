import email
import hashlib
import itertools
import re
import time
import urllib.parse
from datetime import datetime
from base64 import b64decode, b64encode
from io import BytesIO

import compressed_rtf
import extract_msg
import html2text
from emaildata.metadata import MetaData
from emaildata.metadata import text_to_utf8
from icalendar import Calendar
from pyth.plugins.rtf15.reader import Rtf15Reader
from pyth.plugins.xhtml.writer import XHTMLWriter
from constants import TIME_FORMAT

ANSWER_PLACEHOLDER_PATTERN = "(?<={{)[^{]*(?=}})"
CHARS_TO_STRIP = " \r\n"
DATA_ATTACHMENT = "data"
DEFAULT_DIVIDER = ";"
DEFAULT_LIST_DELIMITER = ";"
EMAIL_PREFIX = "mailto:"
INNER_MSG_NOT_SUPPORTED = "Inner .msg attachment is present but not supported."
MAIL_SUBJECT_KEY = 'subject'
MESSAGE_ID_FORMAT = "<{}>"
URL_ENCLOSING_PREFIX = "["
URL_ENCLOSING_SUFFIX = "]"
URLS_REGEX = r"(?i)\[?(?:(?:(?:http|https)(?:://))|www\.(?!://))(?:[a-zA-Z0-9\-\._~:;/\?#\[\]@!\$&'\(\)\*\+,=%])+"
URLS_REGEX_COMPLEX = r"(?i)\[?(?:(?:(?:http|https)(?:://))|www\.(?!://))(?:[a-zA-Z0-9\-\._~:;/\?#\[\]@!\$&'\(\)\*\+,=%<>])+"

SIEMPLIFY_MAIL_DICT_HTML_BODY_KEY = 'html_body'
SIEMPLIFY_MAIL_DICT_PLAINTEXT_BODY_KEY = 'plaintext_body'
SIEMPLIFY_MAIL_DICT_RESOLVED_BODY_KEY = 'body'
SIEMPLIFY_MAIL_DICT_TO_KEY = 'to'
SIEMPLIFY_MAIL_DICT_CC_KEY = 'cc'
SIEMPLIFY_MAIL_DICT_BCC_KEY = 'bcc'
SIEMPLIFY_MAIL_DICT_SENDER_KEY = 'sender'
SIEMPLIFY_MAIL_DICT_SUBJECT_KEY = 'subject'
SIEMPLIFY_MAIL_DICT_MESSAGE_ID_KEY = 'message_id'
SIEMPLIFY_MAIL_DICT_RECEIVERS_KEY = 'receivers'
SIEMPLIFY_MAIL_DICT_REPLY_TO_KEY = 'reply_to'
SIEMPLIFY_MAIL_DICT_IN_REPLY_TO_KEY = 'in_reply_to'
SIEMPLIFY_MAIL_DICT_RAW_EML_KEY = 'raw'
SIEMPLIFY_MAIL_DICT_DATE_KEY = 'date'
SIEMPLIFY_MAIL_DICT_TIMESTAMP_KEY = 'timestamp'
SIEMPLIFY_MAIL_DICT_UNIXTIME_DATE_KEY = 'unixtime_date'
SIEMPLIFY_MAIL_DICT_EMAIL_ID_KEY = 'email_uid'
SIEMPLIFY_MAIL_DICT_ANSWER_ID_KEY = 'answer'
SIEMPLIFY_MAIL_DICT_NAMES_KEY = 'names'
SIEMPLIFY_MAIL_DICT_DISPLAY_NAME_KEY = 'display_name'


def decode_url(url):
    """
    Decode encoded url
    :param url: {str} encoded url
    :return: {str} decoded url
    """
    return urllib.parse.unquote_plus(url)


def filter_emails_with_regexes(emails, exclude_regex_pattern=None):
    """
    Walks through all provided emails, matches their subject and all possible body fields against regexes and takes just non matching ones.
    :param emails: {list} List of email instances
    :param exclude_regex_pattern: {str} String representing regex to exclude email by matching subject or body
    :return: {list} List of filtered email dictionaries
    """
    filtered_emails = []
    excluded = []

    for email in emails:
        if is_matching_exclude_patterns(email, exclude_regex_pattern):
            excluded.append(email)
        else:
            filtered_emails.append(email)

    return filtered_emails, excluded


def is_matching_exclude_patterns(message, exclude_regex_pattern):
    """
    Get first message content from list which is not matching patterns.
    :param message: {exchangelib.Message} Message object, which we have received from exchangelib
    :param exclude_regex_pattern: {str} Regex pattern, which would exclude emails with matching subject or body.
    :return: {bool} Relevant reply: True if matches one of the exclude patterns; False - otherwise.
    """

    if exclude_regex_pattern:
        _body = message.body.get("content")
        if _body and re.findall(exclude_regex_pattern, _body):
            return True
        elif message.subject and re.findall(exclude_regex_pattern, message.subject):
            return True

    return False


def get_html_urls(html_content):
    """
    Get urls from html content
    :param html_content: {str} The html content
    :return: {tuple} Comma-separated list of visible urls, comma-separated list of not visible urls from original src attribute
    """
    regex_object = re.compile(URLS_REGEX_COMPLEX)
    urls_list, original_src_urls_list = get_html_urls_from_html_2_text_obj(html_content)

    urls_list = list(set(
        [check_url_enclosing(decode_url(regex_object.search(url).group(0)))
         for url in urls_list if regex_object.search(url)]
    ))
    original_src_urls_list = list(set(
        [check_url_enclosing(decode_url(regex_object.search(url).group(0)))
         for url in original_src_urls_list if regex_object.search(url)]
    ))

    return DEFAULT_DIVIDER.join(urls_list), DEFAULT_DIVIDER.join(original_src_urls_list)


def check_url_enclosing(url):
    """
    Check if url enclosed and remove enclosing characters
    :param url: {str} url to check
    :return: {str} transformed url
    """
    if url.startswith(URL_ENCLOSING_PREFIX) and url.endswith(URL_ENCLOSING_SUFFIX):
        return url[1:-1]

    return url


def get_html_urls_from_html_2_text_obj(html_content):
    """
    Create a HTML2Text object and get html urls
    :param html_content: {str} The html content
    :return: {tuple} The list of visible urls, the list of not visible urls from original src attribute
    """
    html_renderer = html2text.HTML2Text()
    html_renderer.ignore_tables = True
    html_renderer.protect_links = True
    html_renderer.ignore_images = False
    html_renderer.ignore_links = False
    html_renderer.handle(html_content)
    return html_renderer.html_links, html_renderer.html_links_original_src


def get_charset(message, default_charset="utf-8"):
    """
    Get the message charset
    :param message: {email.message.Message} An eml object
    :param default_charset: {str} Default charset, which should be used
    :return: {str} Charset name
    """
    try:
        charset = message.get_content_charset()
        if not charset:
            charset = message.get_charset()

        if charset:
            if charset.find('"') > 0:
                charset = charset[:charset.find('"')]
            if charset == 'iso-8859-8-i':
                charset = 'iso-8859-8'
            return charset
    except Exception:
        pass
    return default_charset


def get_unicode_str(value):
    """
    Checks type of the string and if it's a binary string, then decodes it to unicode
    :param value: {object} string or binary string
    :return: {str} Unicode decoded string
    """

    try:
        if isinstance(value, bytes):
            return value.decode()
        return str(value)
    except Exception:
        return value


def decode_header_value(header_value):
    """
    Extract message header value from email message.
    :param header_value: {str} The raw header value.
    :return: {unicode} The parsed header value.
    """
    if not header_value:
        return ""

    try:
        parsed_value, encoding = email.header.decode_header(header_value)[0]
        if isinstance(parsed_value, str):
            return parsed_value

        if not encoding:
            return parsed_value.decode("utf-8")

        return parsed_value.decode(encoding)

    except Exception:
        try:
            return parsed_value.decode()
        except Exception:
            return "Unable to decode email subject"


class EmailUtils:
    EMPTY_SUBJECT = "Empty subject"
    UNKNOWN_SENDER = "Unknown sender"

    @staticmethod
    def is_attachment(mime_part, include_inline=False):
        """
        Determine if a MIME part is a valid attachment or not.
        Based on :
        https://www.ietf.org/rfc/rfc2183.txt
        More about the content-disposition allowed fields and values:
        https://www.iana.org/assignments/cont-disp/cont-disp.xhtml#cont-disp-1
        :param mime_part: {email.message.Message} The MIME part
        :param include_inline: {bool} Whether to consider inline attachments as well or now
        :return: {bool} True if MIME part is an attachment, False otherwise
        """
        # Each attachment should have the Content-Disposition header
        content_disposition = mime_part.get("Content-Disposition")

        if not content_disposition or not isinstance(content_disposition, str):
            return False

        # "Real" attachments differs from inline attachments (like images in signature)
        # by having Content-Disposition headers, that starts with 'attachment'.
        # Inline attachments have the word 'inline' at the beginning of the header.
        # Inline attachments are being displayed as part of the email, and not as a separate
        # file. In most cases, the term attachment is related to the MIME parts that start with
        # 'attachment'.
        # The values are not case sensitive
        if content_disposition.lower().startswith("attachment"):
            return True

        if include_inline and content_disposition.lower().startswith("inline"):
            return True

        return False

    def convert_siemplify_ics_to_connector_msg(self, ics_content):
        parsed_ics_attachments = []
        cal = Calendar.from_ical(ics_content)

        for component in cal.walk('vevent'):
            subject = get_unicode_str(component.get('summary', ''))
            body = get_unicode_str(component.get('description', ''))
            location = get_unicode_str(component.get('location', ''))
            start = component.get('dtstart', '').dt.isoformat() if component.get('dtstart', '') else None
            end = component.get('dtend', '').dt.isoformat() if component.get('dtend', '') else None
            message_id = MESSAGE_ID_FORMAT.format(component.get('uid', ''))
            organizer = component.get('organizer', '').replace(EMAIL_PREFIX, '')
            attendees_list = component.get('attendee', '')
            attendees_list = [attendees_list, ] if isinstance(attendees_list, str) else attendees_list
            attendees = DEFAULT_DIVIDER.join([a.replace(EMAIL_PREFIX, '').strip() for a in attendees_list])
            attachments_urls_list = self.extract_urls_from_ics_attachments(component)
            received_datetime = datetime.fromisoformat(start).strftime(TIME_FORMAT)
            created_datetime = datetime.fromisoformat(end).strftime(TIME_FORMAT)

            parsed_ics_attachment = {
                "subject": subject,
                "body": {
                    "contentType": "text/plain",
                    "content": body
                },
                "location": location,
                "receivedDateTime": received_datetime,
                "createdDateTime": created_datetime,
                "internetMessageId": message_id,
                "from": {
                    "emailAddress": {
                        "address": organizer
                    }
                },
                "organizer": organizer,
                "toRecipients": [
                    {
                        "emailAddress": {
                            "address": attendee
                        }
                    } for attendee in attendees.split(DEFAULT_DIVIDER)
                ],
                "attendees": attendees,
            }

            if attachments_urls_list:
                parsed_ics_attachment["urls"] = attachments_urls_list

            parsed_ics_attachments.append(parsed_ics_attachment)

        return parsed_ics_attachments

    def extract_urls_from_ics_attachments(self, content):
        regex_object = re.compile(URLS_REGEX)
        attachments = content.get('attach', [])
        attachments = attachments if isinstance(attachments, list) else [attachments]
        attachments_list = [check_url_enclosing(url.strip(CHARS_TO_STRIP)) for url in
                            regex_object.findall(DEFAULT_LIST_DELIMITER.join(attachments)) if '@' not in url]
        return DEFAULT_LIST_DELIMITER.join(attachments_list)

    def extract_headers_value_from_message(self, msg, headers):
        """
        Extract headers value from message.
        :param msg: {Message} An eml object
        :param headers: {list} List containing headers regexp.
        :return: {dict (connector_eml)} Extracted header according to headers regex
        """
        filtered_headers = {}
        if headers:
            header_keys = msg.keys()
            for header in headers:
                r = re.compile(header)
                matched_keys = list(filter(r.match, header_keys))
                for key in matched_keys:
                    filtered_headers[key] = msg.get(key)

        return filtered_headers

    def extract_filename(self, mime_part):
        """
        Extract the filename of an attachment MIME part
        :param mime_part: {email.message.Message} The MIME part
        :return: {unicode} The decoded filename
        """
        # This is based on email.get_filename() method. The original method decodes
        # the header according to rfc2231, but its not consistent on the return value
        # (sometimes its str, if all the text is ASCII, and otherwise its unicode).
        missing = object()

        filename = mime_part.get_param('filename', missing, 'content-disposition')

        if filename is missing:
            filename = mime_part.get_param('name', missing, 'content-disposition')

        if filename is missing:
            return

        return decode_header_value(filename)

    def _extract_attachments_from_eml(self, msg, encode_as_base64=False, convert_utf8=True, exclude_attachments=None):
        """
        Extract the attachments {filename: file_content} from a email.message.Message object (eml Mime).
        :param msg: {email.message.Message} the msg to extract from
        :param encode_as_base64: {bool} Whether to encode the attachments content with base64 or not
        :param convert_utf8: {bool} Whether to convert the filename to utf8
        :param exclude_attachments: {list} The list of the attachments names should be ignored
        :return: {dict} The extracted attachments (filename: content)
        """
        attachments_dict = {}

        if msg.is_multipart():
            attachments = msg.get_payload()
            index = 0

            for attachment in attachments:
                if self.is_attachment(attachment):

                    if attachment.get_content_type() == 'message/rfc822':
                        # The attachment is an inner message object similar to ItemAttachment like in Outlook
                        file_content = attachment.get_payload()[0].as_string()
                        file_content_for_md5 = file_content.encode() if isinstance(file_content, str) else file_content
                        md5_file_hash = hashlib.md5(file_content_for_md5).hexdigest()
                        filename = self.extract_subject(email.message_from_string(file_content))
                        if exclude_attachments and filename in exclude_attachments:
                            continue
                        # Here we are using dict instead of list because in case of list
                        # we will have the following structure:
                        # Attachments{index}attachment_name
                        # which is not good for mapping, thus we are using dict

                        attachments_dict.update({
                            "attachment_name_{}".format(index): filename,
                            "base64_encoded_content_{}".format(index): file_content.decode() if isinstance(file_content, bytes) else file_content,
                            "md5_filehash_{}".format(index): md5_file_hash,
                        })
                        index += 1

                    else:
                        # Extract filename from attachment
                        filename = self.extract_filename(attachment)
                        if exclude_attachments and filename in exclude_attachments:
                            continue
                        # Some emails can return an empty attachment.
                        # Validate that the attachment has a filename
                        if filename:
                            # Get attachment content - decode to raw
                            file_content = attachment.get_payload(decode=True)
                            md5_file_hash = hashlib.md5(file_content).hexdigest()

                            # In case of EML file - probably bug.
                            # TODO: This might be problematic. As .eml attachment (content-type of messade/rfc822)
                            # TODO: are considered multipart, then get_payload() will return None.
                            # TODO: The extraction of file_data is correct, and in most cases
                            # TODO: it will be encoded with base64, but it's not guaranteed,
                            # TODO: so we might have to extract the Content-Transfer-Encoding
                            # TODO: and parse accordingly.
                            if not file_content and '.eml' in filename:
                                file_data = attachment.get_payload()[0]
                                payload = file_data.get_payload()
                                md5_file_hash = hashlib.md5(payload).hexdigest()
                                file_content = b64decode(payload)

                            if encode_as_base64:
                                file_content = b64encode(file_content)

                            # Here we are using dict instead of list because in case of list
                            # we will have the following structure:
                            # Attachments{index}attachment_name
                            # which is not good for mapping, thus we are using dict

                            attachments_dict.update({
                                "attachment_name_{}".format(index): filename,
                                "base64_encoded_content_{}".format(index): file_content.decode() if isinstance(file_content, bytes) else file_content,
                                "md5_filehash_{}".format(index): md5_file_hash,
                            })
                            index += 1

    def convert_siemplify_eml_to_connector_eml(self,
                                               eml_content,
                                               convert_body_to_utf8=False,
                                               convert_subject_to_utf8=False,
                                               encode_attachments_as_base64=True,
                                               convert_filenames_to_utf8=True,
                                               exclude_attachments=None,
                                               headers_to_add=None):
        """
        Convert a Siemplify EML object to connector EML object. Used for avoiding regressions.
        :param eml_content: {email.message.Message} An eml object
        :param convert_body_to_utf8: {boolean} Return message body as utf-8 encoded str(Avoid regression).
        :param convert_subject_to_utf8: {boolean} Return message subject as utf-8 encoded str(Avoid regression).
        :param convert_filenames_to_utf8: {boolean} Return message filenames as utf-8 encoded str.
        :param encode_attachments_as_base64: {boolean} Whether to encode the attachments content with base64.
        :param exclude_attachments: {list} The list of the attachments names should be ignored
        :param headers_to_add: {list} The list of the headers/header_regexp to add to the final result
        :return: {dict (connector_eml)} The data of the eml
        """
        msg = email.message_from_bytes(eml_content)

        metadata = self.convert_eml_to_siemplify_eml(
            msg,
            convert_body_to_utf8=convert_body_to_utf8,
            convert_subject_to_utf8=convert_subject_to_utf8
        )

        received_datetime = datetime.fromtimestamp(
            metadata.get(SIEMPLIFY_MAIL_DICT_UNIXTIME_DATE_KEY) / 1000.0
        )

        main_content = {
            "attachments": self._extract_attachments_from_eml(msg, encode_as_base64=encode_attachments_as_base64,
                                                              convert_utf8=convert_filenames_to_utf8,
                                                              exclude_attachments=exclude_attachments),
            "bccRecipients": [
                {
                    "emailAddress": {
                        "address": bcc_email

                    }
                } for bcc_email in metadata.get(SIEMPLIFY_MAIL_DICT_BCC_KEY, [])
            ],
            "ccRecipients": [
                {
                    "emailAddress": {
                        "address": cc_email
                    }
                } for cc_email in metadata.get(SIEMPLIFY_MAIL_DICT_CC_KEY, [])
            ],
            "body": {
                "contentType": "html",
                "content": metadata.get(SIEMPLIFY_MAIL_DICT_RESOLVED_BODY_KEY),
            },
            "receivedDateTime": received_datetime.strftime(TIME_FORMAT),
            "date": metadata.get(SIEMPLIFY_MAIL_DICT_DATE_KEY),
            "replyTo": [{
                "emailAddress": {
                    "address": metadata.get(SIEMPLIFY_MAIL_DICT_IN_REPLY_TO_KEY),
                }
            }],
            "internetMessageId": metadata.get(SIEMPLIFY_MAIL_DICT_MESSAGE_ID_KEY),
            "uniqueBody": {
                "contentType": "html",
                "content": metadata.get(SIEMPLIFY_MAIL_DICT_PLAINTEXT_BODY_KEY),
            },
            "from": {
                "emailAddress": {
                    "address": metadata.get(SIEMPLIFY_MAIL_DICT_SENDER_KEY)
                },
            },
            "subject": metadata.get(SIEMPLIFY_MAIL_DICT_SUBJECT_KEY),
            "toRecipients": [{
                "emailAddress": {
                    "address": recipient
                }
            } for recipient in metadata.get(SIEMPLIFY_MAIL_DICT_TO_KEY, [])],
            SIEMPLIFY_MAIL_DICT_UNIXTIME_DATE_KEY: metadata.get(SIEMPLIFY_MAIL_DICT_UNIXTIME_DATE_KEY)
        }
        main_content.update(self.extract_headers_value_from_message(msg, headers_to_add))
        return main_content

    @staticmethod
    def extract_email_addresses_from_msg(message, header_name):
        """
        Extract addresses from email headers.
        This function replaces the emaildata.Metadata._address function due to incorrect extraction of the addresses for emails sent from Exchange
        Server. Instead, after the headers will be decoded (using the same functionality) we will pass it to email.utils.getaddresses() function
        for proper extraction of the email addresses.
        :param message: {email.message.Message} Email message
        :param header_name: {str} The header content to extract the addresses from
        :return: {[str]} List of extracted email addresses, excluding duplicates
        """

        def decode(text, encoding):
            """Decode a text. If an exception occurs when decoding returns the
            original text"""
            try:
                if isinstance(text, bytes):
                    return text.decode(encoding or 'utf-8')
                return text
            except:
                return text_to_utf8(text)

        header_value = message[header_name]

        if not header_value:
            return []

        if isinstance(header_value, str):
            header_value = header_value.replace('\n', ' ')

        pieces = email.header.decode_header(header_value)
        pieces = [decode(text, encoding) for text, encoding in pieces]
        addresses = sorted(list(set(e for realname, e in email.utils.getaddresses(["".join(pieces).strip()]) if e)))
        return [address for address in addresses if '@' in address]

    def convert_eml_to_siemplify_eml(self,
                                     msg,
                                     include_raw_eml=False,
                                     convert_body_to_utf8=False,
                                     convert_subject_to_utf8=False,
                                     email_uid=None):
        """
        Create a Siemplify eml object from a given eml MIME (email.message.Message).
        The method is parsing the email.Message object relevant data and created a dict in Siemplify format.
        :param msg: {email.message.Message} The msg object
        :param include_raw_eml: {boolean} get the mail eml (in eml format)
        :param convert_body_to_utf8: {boolean} Return message body as utf-8 encoded str(Avoid regression).
        :param convert_subject_to_utf8: {boolean} Return message subject as utf-8 encoded str(Avoid regression).
        :param email_uid: {int} The uid of the email (in case the email was fetched from an IMAP server, like gmail)
        :return: {dict} The mail data
        """

        extractor = MetaData(msg)
        # Start building "siemplify mail dict". base it on "email library dict"
        # It's assumed that message_id key is already there
        mail_dict = extractor.to_dict()

        mail_dict[SIEMPLIFY_MAIL_DICT_UNIXTIME_DATE_KEY] = self.extract_unixtime_date_from_msg(msg.get('date'))
        mail_dict[SIEMPLIFY_MAIL_DICT_DATE_KEY] = msg.get('date')

        subject = self.extract_subject(msg, convert_subject_to_utf8)

        if subject:
            subject = subject.strip()

        mail_dict[SIEMPLIFY_MAIL_DICT_SUBJECT_KEY] = subject if subject else self.EMPTY_SUBJECT

        mail_dict[SIEMPLIFY_MAIL_DICT_PLAINTEXT_BODY_KEY] = self.extract_bodies_from_eml(msg, convert_body_to_utf8)[0]
        mail_dict[SIEMPLIFY_MAIL_DICT_HTML_BODY_KEY] = self.extract_bodies_from_eml(msg, convert_body_to_utf8)[1]
        mail_dict[SIEMPLIFY_MAIL_DICT_EMAIL_ID_KEY] = email_uid

        if not mail_dict.get(SIEMPLIFY_MAIL_DICT_SENDER_KEY):
            mail_dict[SIEMPLIFY_MAIL_DICT_SENDER_KEY] = self.UNKNOWN_SENDER
        if not mail_dict.get(SIEMPLIFY_MAIL_DICT_TO_KEY):
            mail_dict[SIEMPLIFY_MAIL_DICT_TO_KEY] = []
        if not mail_dict.get(SIEMPLIFY_MAIL_DICT_CC_KEY):
            mail_dict[SIEMPLIFY_MAIL_DICT_CC_KEY] = []
        if not mail_dict.get(SIEMPLIFY_MAIL_DICT_BCC_KEY):
            mail_dict[SIEMPLIFY_MAIL_DICT_BCC_KEY] = []

        if mail_dict[SIEMPLIFY_MAIL_DICT_PLAINTEXT_BODY_KEY]:
            mail_dict[SIEMPLIFY_MAIL_DICT_RESOLVED_BODY_KEY] = mail_dict[SIEMPLIFY_MAIL_DICT_PLAINTEXT_BODY_KEY]
        else:
            # Can't know the original charset of the body - try and hope for the best.
            mail_dict[SIEMPLIFY_MAIL_DICT_RESOLVED_BODY_KEY] = self.render_html_body(
                mail_dict[SIEMPLIFY_MAIL_DICT_HTML_BODY_KEY])

        # Try extracting the answer
        try:
            match = re.search(ANSWER_PLACEHOLDER_PATTERN, mail_dict[SIEMPLIFY_MAIL_DICT_RESOLVED_BODY_KEY])
            if match:
                mail_dict[SIEMPLIFY_MAIL_DICT_ANSWER_ID_KEY] = match.group()
            else:
                mail_dict[SIEMPLIFY_MAIL_DICT_ANSWER_ID_KEY] = ""
        except Exception:
            mail_dict[SIEMPLIFY_MAIL_DICT_ANSWER_ID_KEY] = ""

        if include_raw_eml:
            # original message as string
            mail_dict['original_message'] = msg.as_string()

        return mail_dict

    def extract_bodies_from_eml(self, msg, convert_body_to_utf8=False):
        """
        Extracts bodies (plaintext + html) from an email.message.Message (eml mimes).
        :param msg: {email.message.Message} An eml object
        :param convert_body_to_utf8: {bool} True to return body as ut8 encoded string(Avoid regression).
        :return: {tuple} Text body, Html body, count of parts of the emails
        """
        html_body = ""
        text_body = ""
        count = 0

        if not msg.is_multipart() and not self.is_attachment(msg):
            # Not an attachment!
            # See where this belong - text_body or html_body
            content_type = msg.get_content_type()
            message_payload = msg.get_payload(decode=True)
            charset = get_charset(msg, "utf-8")

            if content_type == "text/plain":
                text_body += self.decode_by_charset(message_payload, charset)
            elif content_type == "text/html":
                html_body += self.decode_by_charset(message_payload, charset)

            return text_body, html_body, 1

        # This IS a multipart message.
        # So, we iterate over it and call extract_bodies_from_eml() recursively for
        # each part.
        for part_msg in msg.get_payload():
            # Verify that the mime part is not an attachment to avoid body containing attachment data
            if not self.is_attachment(part_msg):
                # Th part is a new Message object which goes back to extract_bodies_from_eml
                part_text_body, part_html_body, part_count = self.extract_bodies_from_eml(
                    part_msg)
                text_body += part_text_body
                html_body += part_html_body
                count += part_count

        return text_body, html_body, count

    @staticmethod
    def decode_by_charset(bytes_string, charset, default_charset="latin1"):
        """
        Decode bytes string by a given charset
        :param bytes_string: {bytes} bytes string
        :param charset: {str} charset to use for decoding
        :param default_charset: {str} default charset to use when given charset is not supported
        :return: {str} decoded string
        """
        try:
            return bytes_string.decode(charset)
        except:
            try:
                # If there is an exception with provided charset, try to decode with default charset
                return bytes_string.decode(default_charset)
            except:
                # If there is an exception also with default charset, decode with provided charset ignoring the errors
                return bytes_string.decode(charset, 'ignore')

    def extract_subject(self, msg, convert_utf8=False):
        """
        Extract message subject from email message.
        :param msg: {Message} Message object.
        :param convert_utf8: {bool} True to convert subject to utf-8 encoded string.
        :return: {string} Subject text.
        """
        raw_subject = msg.get(MAIL_SUBJECT_KEY)

        return decode_header_value(raw_subject)

    @staticmethod
    def extract_unixtime_date_from_msg(date_str, default_value=1):
        """
        Extract the date of the msg in unixtime
        :param date_str: {str} The date string to parse
        :param default_value: {long} The default value to return on failure. If not passed (None, 0, any False value) - an exception will be raised on failure.
        :return: {long} The unixtime of the message. If failed parsing - return 1.
        """
        try:
            if date_str:
                date_tuple = email.utils.parsedate_tz(date_str)
                if date_tuple:
                    # Returns time in seconds, not in milliseconds
                    return email.utils.mktime_tz(date_tuple) * 1000

            return default_value

        except Exception:
            return default_value

    @staticmethod
    def _build_html_2_text_obj():
        """
        Create a HTML2Text object
        :return: {html2text.HTML2Text} The HTMl2Text object
        """
        html_renderer = html2text.HTML2Text()
        # Configuration was decided by Product Team
        html_renderer.ignore_tables = True
        html_renderer.protect_links = True
        html_renderer.ignore_images = False
        html_renderer.ignore_links = False
        return html_renderer

    @classmethod
    def render_html_body(cls, html_body):
        """
        Render html body to plain text plain
        :param html_body: {str} The HTML body of the email
        :return: {str} Plain text rendered HTML
        """
        try:
            html_renderer = cls._build_html_2_text_obj()
            return html_renderer.handle(html_body)

        except Exception:
            # HTML2Text is not performing well on non-ASCII str. On failure - try to decode the str to unicode
            # using utf8 encoding. If failed - return a proper message.
            try:
                # HTML2Text object shouldn't be used twice - it can cause problems and errors according to google
                # Therefore rebuild the object
                html_renderer = cls._build_html_2_text_obj()
                html_body = html_body.decode("utf8")
                # Encode back to utf8
                return html_renderer.handle(html_body).encode("utf8")
            except Exception as e:
                return "Failed rendering HTML. Error: {}".format(str(e))

    def convert_siemplify_msg_to_connector_msg(self, msg_content, convert_body_to_utf8=False,
                                               convert_subject_to_utf8=False,
                                               encode_attachments_as_base64=True,
                                               convert_filenames_to_utf8=True):
        """
        Convert Siemplify MSG object to connector MSG object. Used to avoid regressions.
        :param msg_content: {extract_msg.message.Message} An msg object
        :param convert_body_to_utf8: {boolean} Return message body as utf-8 encoded str(Avoid regression).
        :param convert_subject_to_utf8: {boolean} Return message subject as utf-8 encoded str(Avoid regression).
        :param convert_filenames_to_utf8: {boolean} Return message filenames as utf-8 encoded str.
        :param encode_attachments_as_base64: {boolean} Whether to encode the attachments content with base64.
        :return: {dict (connector_msg)} The data of the .msg
        """

        msg = extract_msg.Message(msg_content)
        # Build the Siemplify MSG object
        metadata = self.convert_outlook_msg_to_siemplify_msg(
            msg,
            convert_body_to_utf8=convert_body_to_utf8,
            convert_subject_to_utf8=convert_subject_to_utf8
        )

        main_content = {
            "answer": metadata.get(SIEMPLIFY_MAIL_DICT_ANSWER_ID_KEY),
            "attachments": self._extract_attachment_from_outlook_msg(
                msg, encode_as_base64=encode_attachments_as_base64, convert_utf8=convert_filenames_to_utf8),
            "bccRecipients": [
                {
                    "emailAddress": {
                        "address": bcc_email

                    }
                } for bcc_email in metadata.get(SIEMPLIFY_MAIL_DICT_BCC_KEY, [])
            ],
            "ccRecipients": [
                {
                    "emailAddress": {
                        "address": cc_email
                    }
                } for cc_email in metadata.get(SIEMPLIFY_MAIL_DICT_CC_KEY, [])
            ],
            "body": {
                "contentType": "html",
                "content": metadata.get(SIEMPLIFY_MAIL_DICT_RESOLVED_BODY_KEY),
            },
            "receivedDateTime": metadata.get(SIEMPLIFY_MAIL_DICT_DATE_KEY),
            "replyTo": [{
                "emailAddress": {
                    "address": metadata.get(SIEMPLIFY_MAIL_DICT_IN_REPLY_TO_KEY),
                }
            }],
            "internetMessageId": metadata.get(SIEMPLIFY_MAIL_DICT_MESSAGE_ID_KEY),
            "uniqueBody": {
                "contentType": "html",
                "content": metadata.get(SIEMPLIFY_MAIL_DICT_PLAINTEXT_BODY_KEY),
            },
            "from": {
                "emailAddress": {
                    "address": metadata.get(SIEMPLIFY_MAIL_DICT_SENDER_KEY)
                },
            },
            "subject": metadata.get(SIEMPLIFY_MAIL_DICT_SUBJECT_KEY),
            "toRecipients": [{
                "emailAddress": {
                    "address": recipient
                }
            } for recipient in metadata.get(SIEMPLIFY_MAIL_DICT_TO_KEY, [])],
        }

        return main_content

    def convert_outlook_msg_to_siemplify_msg(self, msg, convert_body_to_utf8=False,
                                             convert_subject_to_utf8=False, email_uid=None):
        """
        Create a Siemplify msg object from a given outlook msg (extract_msg.message.Message).
        The method is parsing the extract_msg.Message object relevant data and created a dict in Siemplify format.
        :param msg: {extract_msg.message.Message} The msg object
        :param convert_body_to_utf8: {boolean} Return message body as utf-8 encoded str(Avoid regression).
        :param convert_subject_to_utf8: {boolean} Return message subject as utf-8 encoded str(Avoid regression).
        :param email_uid: {int} The uid of the email (in case the email was fetched from an IMAP server, like gmail)
        :return: {dict (siemplify_msg)} The mail data
        """
        mail_dict = dict()
        mail_dict[SIEMPLIFY_MAIL_DICT_UNIXTIME_DATE_KEY] = self.extract_unixtime_date_from_msg(msg.date)
        mail_dict[SIEMPLIFY_MAIL_DICT_DATE_KEY] = datetime(*msg.parsedDate[0:6])
        mail_dict[SIEMPLIFY_MAIL_DICT_TIMESTAMP_KEY] = int(time.mktime(msg.parsedDate))
        mail_dict[SIEMPLIFY_MAIL_DICT_SENDER_KEY] = self.extract_addresses(msg.sender or '')
        mail_dict[SIEMPLIFY_MAIL_DICT_TO_KEY] = self.extract_addresses(msg.to)
        mail_dict[SIEMPLIFY_MAIL_DICT_CC_KEY] = self.extract_addresses(msg.cc)
        mail_dict[SIEMPLIFY_MAIL_DICT_BCC_KEY] = self.extract_addresses(msg.header.get("bcc"))
        mail_dict[SIEMPLIFY_MAIL_DICT_REPLY_TO_KEY] = msg.inReplyTo
        mail_dict[SIEMPLIFY_MAIL_DICT_IN_REPLY_TO_KEY] = msg.inReplyTo
        mail_dict[SIEMPLIFY_MAIL_DICT_MESSAGE_ID_KEY] = msg.messageId
        mail_dict[SIEMPLIFY_MAIL_DICT_EMAIL_ID_KEY] = email_uid
        mail_dict[SIEMPLIFY_MAIL_DICT_DISPLAY_NAME_KEY] = self.extract_names(msg.sender or '')

        # Construct the receivers from to + cc + bcc addresses
        mail_dict[SIEMPLIFY_MAIL_DICT_RECEIVERS_KEY] = set()
        mail_dict[SIEMPLIFY_MAIL_DICT_RECEIVERS_KEY].union(mail_dict[SIEMPLIFY_MAIL_DICT_TO_KEY])
        mail_dict[SIEMPLIFY_MAIL_DICT_RECEIVERS_KEY].union(mail_dict[SIEMPLIFY_MAIL_DICT_CC_KEY])
        mail_dict[SIEMPLIFY_MAIL_DICT_RECEIVERS_KEY].union(mail_dict[SIEMPLIFY_MAIL_DICT_BCC_KEY])
        mail_dict[SIEMPLIFY_MAIL_DICT_SUBJECT_KEY] = get_unicode_str(msg.subject)
        mail_dict[SIEMPLIFY_MAIL_DICT_PLAINTEXT_BODY_KEY] = get_unicode_str(msg.body)

        try:
            mail_dict[SIEMPLIFY_MAIL_DICT_HTML_BODY_KEY] = self.extract_html_body_from_outlook_msg(msg,
                                                                                                   convert_body_to_utf8)
        except Exception as e:
            mail_dict[SIEMPLIFY_MAIL_DICT_HTML_BODY_KEY] = "Unable to extract HTML body. Error: {}".format(e)
        if mail_dict[SIEMPLIFY_MAIL_DICT_PLAINTEXT_BODY_KEY]:
            mail_dict[SIEMPLIFY_MAIL_DICT_RESOLVED_BODY_KEY] = mail_dict[SIEMPLIFY_MAIL_DICT_PLAINTEXT_BODY_KEY]
        else:
            # Can't know the original charset of the body - try and hope for the best.
            mail_dict[SIEMPLIFY_MAIL_DICT_RESOLVED_BODY_KEY] = self.render_html_body(
                mail_dict[SIEMPLIFY_MAIL_DICT_HTML_BODY_KEY])

        # Try extracting the answer
        try:
            match = re.search(ANSWER_PLACEHOLDER_PATTERN, mail_dict[SIEMPLIFY_MAIL_DICT_RESOLVED_BODY_KEY])
            if match:
                mail_dict[SIEMPLIFY_MAIL_DICT_ANSWER_ID_KEY] = match.group()
            else:
                mail_dict[SIEMPLIFY_MAIL_DICT_ANSWER_ID_KEY] = ""
        except Exception:
            mail_dict[SIEMPLIFY_MAIL_DICT_ANSWER_ID_KEY] = ""

        return mail_dict

    @staticmethod
    def extract_html_body_from_outlook_msg(msg, convert_body_to_utf8=False):
        """
        Extract the body from extract_msg.message.Message (according to product defined logic). Extract HTML if available,
        or extract the HTML from the RTF, based on product defined logic.
        :param msg: {extract_msg.message.Message} The message obj
        :param convert_body_to_utf8: {bool} Return message body as utf-8 encoded str(Avoid regression).
        :return: {str/unicode} The extracted body (unicode of convert_body_to_utf8 is False)
        """
        if msg.htmlBody:
            return get_unicode_str(msg.htmlBody)
        else:
            # decompress the rtf content of the msg
            rtf_content = compressed_rtf.decompress(msg.compressedRtf)
            rtf_file = BytesIO()
            rtf_file.write(rtf_content)

            rdf_handler = Rtf15Reader.read(rtf_file)
            html_body = XHTMLWriter.write(rdf_handler, pretty=True).read()
            return get_unicode_str(html_body)

    @staticmethod
    def extract_addresses_with_names(header_content):
        """
        Extract addresses and corresponding display names from email headers. Based on the _address method of email.Metadata.
        :param header_content: {str} The header content to extract the addresses from
        :return: {list} The extracted addresses (list of unicodes)
        """

        def decode(text, encoding):
            """Decode a text. If an exception occurs when decoding returns the
            original text"""
            if encoding is None:
                return get_unicode_str(text)
            try:
                return text.decode(encoding)
            except Exception:
                return get_unicode_str(text)

        result = dict()
        pieces = email.header.decode_header(header_content or '')
        pieces = [decode(text, encoding) for text, encoding in pieces]
        header_value = "".join(pieces).strip()
        name, address = email.utils.parseaddr(header_value)
        while address:
            result[address] = name or None
            index = header_value.find(address) + len(address)
            if index >= len(header_value):
                break
            if header_value[index] == '>':
                index += 1
            if index >= len(header_value):
                break
            if header_value[index] == ',':
                index += 1
            header_value = header_value[index:].strip()
            name, address = email.utils.parseaddr(header_value)

        return result

    def extract_addresses(self, header_content):
        """
        Extract addresses from email headers. Based on the _address method of email.Metadata.
        :param header_content: {str} The header content to extract the addresses from
        :return: {list} The extracted addresses (list of unicodes)
        """
        result = self.extract_addresses_with_names(header_content)
        return [address for address in result.keys() if address and address != str(None)]

    def extract_names(self, header_content):
        """
        Extract display names corresponding to addresses from email headers. Based on the _address method of email.Metadata.
        :param header_content: {str} The header content to extract the addresses from
        :return: {list} The extracted names
        """
        result = self.extract_addresses_with_names(header_content)
        return [name for name in result.values() if name and name != str(None)]

    def _extract_attachment_from_outlook_msg(self, msg, encode_as_base64=False, convert_utf8=True):
        """
        Extract the attachments (filename: file_content} from an extract_msg.messageMessage object (parsed outlook msg)
        :param msg: {extract_msg.messageMessage} the msg to extract from
        :param encode_as_base64: {bool} Whether to encode the attachments content with base64 or not
        :param convert_utf8: {bool} Whether to convert the filename to utf8
        :return: {dict} The extracted attachments (filename: content)
        """
        attachments_dict = {}

        for attachment in msg.attachments:
            if attachment.type == DATA_ATTACHMENT:
                # Extract filename
                if convert_utf8:
                    filename = attachment.longFilename.encode("utf8")
                else:
                    filename = attachment.longFilename

                # The content returned raw - no way of knowing the encoding of the attachment.
                # So leave it like that
                file_content = attachment.data

                if encode_as_base64:
                    file_content = b64encode(file_content)

                attachments_dict.update({filename: file_content})
            else:
                attachments_dict.update({get_unicode_str(attachment.data.subject): INNER_MSG_NOT_SUPPORTED})

        return attachments_dict

