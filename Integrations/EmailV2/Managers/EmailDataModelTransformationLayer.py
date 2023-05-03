# -*- coding: utf-8 -*-
import base64
import email.utils
import quopri
import re
import uuid
from base64 import b64encode
from datetime import datetime
from email import message_from_bytes
from email.header import decode_header
from email.iterators import typed_subpart_iterator

import requests
import chardet
import extract_msg
from emaildata.metadata import MetaData
from html2text import HTML2Text
from icalendar import Calendar

from EmailCommon import safe_str_cast, URLS_REGEX, DEFAULT_REGEX_MAP, IMG_REGEX
from EmailDataModels import EmailModel, EmailAttachmentModel


class BaseEmailBuilder(object):
    DEFAULT_DELIMITER = ";"

    ANSWER_PLACEHOLDER_PATTERN = r"^(?!>|On|--)(.*)+"
    CHARS_TO_STRIP = " \r\n"

    def __init__(self, email_string, email_uid, mailbox, environment, logger, regex_map=DEFAULT_REGEX_MAP,
                 urls_regex=URLS_REGEX, include_raw_email=False, additional_headers=None):
        """
        Basic constructor
        :param email_string: {str} String representation of email. Basically it's equal to self.imap.uid('fetch', email_uid, '(BODY.PEEK[])')[1][0][1]
        :param email_uid: {str} Email sequential ID on the IMAP server
        :param mailbox: {str} Email address of the monitored mailbox
        :param environment: {str} Name of the current environment
        :param logger: {SiemplifyLogger} Logger instance to log email messages
        :param regex_map: {dict} Dictionary, which may be used to extract additional data from the email body. If keys are matching class attributes, then values are assigned to them. If class is missing such attributes, then these values are stored in self.extra_data dict
        :param urls_regex: {str} Regex string, which should be used to extract all URLs from email HTML body
        :param include_raw_email: {bool} If True, then original email message is attached to EmailModel() instance as an attachment. Otherwise - just ignored.
        :param additional_headers: {list} The list of the headers/header_regexp to add to the final result
        """
        self.email_string = email_string
        self.email_uid = email_uid
        self.mailbox = mailbox
        self.environment = environment
        self.logger = logger
        self.regex_map = regex_map
        if not isinstance(self.regex_map, dict):
            raise AttributeError("regex_map should be a dict")
        self.urls_regex = urls_regex
        self.include_raw_email = include_raw_email
        self.additional_headers = additional_headers

        self.email = EmailModel()

    def extract_base_info(self):
        """
        Phase 1: Extract base information
        """
        raise NotImplementedError()

    def process_body(self):
        """
        Phase 2: Fill in email body with either plaintext data, either rendered HTML
        """
        raise NotImplementedError()

    def extract_answer(self):
        """
        Phase 3: Extract answer in case of a forwarded email
        """
        if not self.email.body or not self.email.is_forward:
            self.email.answer = None
            return

        match = re.search(self.ANSWER_PLACEHOLDER_PATTERN, self.email.body)
        self.email.answer = match.group() if match else None
        if self.email.answer:
            self.email.answer = self.email.answer.strip(self.CHARS_TO_STRIP)

    def extract_additional_data(self):
        """
        Phase 4: Extract additional data using regex_map value
        """
        for key, regex_value in list(self.regex_map.items()):
            if key == 'subject':
                continue
            try:
                regex_object = re.compile(regex_value)
                all_results = regex_object.findall(self.email.body)

                if all_results:
                    # We need to avoid overwriting existing attributes within data model,
                    # as it may lead to uncontrolled types changes, which would cause further
                    # exceptions in the system
                    for index, result in enumerate(all_results, 1):
                        # Divide keys
                        result = result.strip(self.CHARS_TO_STRIP)
                        key_name = '{0}_{1}'.format(key, index) if len(all_results) > 1 else key
                        self.email.extra_data[key_name] = result
            except Exception as e:
                self.logger.error("Unable to find key {0} with regex {1}".format(key, regex_value))
                self.logger.exception(e)

    def extract_attachments(self):
        """
        Phase 5: Extract attachments from the email string and wrap them into EmailAttachmentModel objects
        """
        raise NotImplementedError()

    def extract_urls(self):
        """
        Phase 6: Extracts all urls from the email body
        """
        try:
            regex_object = re.compile(self.urls_regex)
            # Workaround to exclude emails. ATTENTION: It can remove the whole valid domain with email in params
            all_results = [url for url in regex_object.findall(self.email.body) if '@' not in url]

            for index, result in enumerate(all_results, 1):
                # Divide keys
                result = result.strip(self.CHARS_TO_STRIP)
                key_name = '{0}_{1}'.format("url", index)
                self.email.urls[key_name] = safe_str_cast(result, default_value=None)
        except Exception as e:
            self.logger.error("Unable to extract URLs from email with email_uid={0}".format(self.email.email_uid))
            self.logger.exception(e)

    def get_email(self):
        """
        Returns back built email value
        """
        return self.email

    @staticmethod
    def _get_charset(message, default_charset="utf-8"):
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
        except:
            try:
                return chardet.detect(bytes(message)).get('encoding', 'utf-8')
            except:
                pass

        return default_charset

    @staticmethod
    def _is_attachment(mime_part, include_inline=False, include_cid=False):
        # type: (email.message.Message, bool, bool) -> bool
        """
        Determine if a MIME part is a valid attachment or not.
        Based on :
        https://www.ietf.org/rfc/rfc2183.txt
        More about the content-disposition allowed fields and values:
        https://www.iana.org/assignments/cont-disp/cont-disp.xhtml#cont-disp-1
        :param mime_part: {email.message.Message} The MIME part
        :param include_inline: {bool} Whether to consider inline attachments as well or not
        :return: {bool} True if MIME part is an attachment, False otherwise
        """
        # Each attachment should have the Content-Disposition header
        content_disposition = mime_part.get("Content-Disposition", '')

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

        if include_cid and mime_part.get_content_maintype() == 'image' and mime_part.get('Content-ID'):
            return True

        return False

    def get_unicode_str(self, value):
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

    def _decode_string(self, value, charset):
        """
        Decodes a string using provided charset
        :param value: {str} String value to decode
        :param charset: {str} Charset, which should be used for decoding
        :return: Unicode value
        """
        if not value:
            return None
        if isinstance(value, str):
            return value
        try:
            return value.decode(charset)
        except UnicodeDecodeError:
            msg = "Unable to decode value to the desired charset"
            self.logger.error(msg)
            return msg

    def _decode_list(self, list_value, charset):
        """
        Decodes all values in the list using provided charset
        :param list_value: List of values to be decoded
        :param charset: Charset, which should be used for decoding
        :return: {list} List of unicode values
        """
        new_list = []
        if not list_value:
            return new_list

        for val in list_value:
            new_list.append(self._decode_string(val, charset))
        return new_list


class EmailModelBuilder(BaseEmailBuilder):
    """
    This class may be used to build an EmailModel object from email string
    """
    DEFAULT_FILENAME = "Undefined"
    DEFAULT_FILENAME_CHARSET = "utf-8"
    EML_ATTACHMENT_EXTENSION = '.eml'
    ENCODED_WORD_REGEX = r'=\?{1}(.+)\?{1}([B|Q])\?{1}(.+)\?{1}=.*'
    MESSAGE_RFC822_CONTENT_TYPE = 'message/rfc822'

    def __init__(self, email_string, email_uid, mailbox, environment, logger, regex_map=DEFAULT_REGEX_MAP,
                 urls_regex=URLS_REGEX, include_raw_email=False, additional_headers=None):
        """
        Basic constructor
        :param email_string: {str} String representation of email. Basically it's equal to self.imap.uid('fetch', email_uid, '(BODY.PEEK[])')[1][0][1]
        :param email_uid: {str} Email sequential ID on the IMAP server
        :param mailbox: {str} Email address of the monitored mailbox
        :param environment: {str} Name of the current environment
        :param logger: {SiemplifyLogger} Logger instance to log email messages
        :param regex_map: {dict} Dictionary, which may be used to extract additional data from the email body. If keys are matching class attributes, then values are assigned to them. If class is missing such attributes, then these values are stored in self.extra_data dict
        :param urls_regex: {str} Regex string, which should be used to extract all URLs from email HTML body
        :param include_raw_email: {bool} If True, then original email message is attached to EmailModel() instance as an attachment. Otherwise - just ignored.
        :param additional_headers: {list} The list of the headers/header_regexp to add to the final result
        """
        super(EmailModelBuilder, self).__init__(email_string, email_uid, mailbox, environment, logger, regex_map,
                                                urls_regex, include_raw_email, additional_headers)

    def extract_base_info(self):
        """
        Phase 1: Extract base information - Overridden
        """
        msg = message_from_bytes(self.email_string)

        extractor = MetaData(msg)
        email_dict = extractor.to_dict()
        self.email.encoding = self._get_charset(msg)
        self.email.email_uid = self.email_uid
        self.email.mailbox = self.mailbox
        self.email.environment = self.environment
        self.email.message_id = email_dict.get('message_id', '')

        recipients = email_dict.get("to", [])
        self.email.original_recipient = self.DEFAULT_DELIMITER.join(recipients)
        self.email.recipients = recipients
        self.email.original_sender = email_dict.get("sender", "")
        self.email.senders = [self.email.original_sender]
        self.email.cc = email_dict.get("cc", [])
        self.email.bcc = email_dict.get("bcc", [])
        self.email.receivers = [*self.email.recipients, *self.email.cc, *self.email.bcc]
        self.email.email_date = email_dict.get('date')
        self.email.email_date_aware = email.utils.parsedate_to_datetime(msg['Date'])
        self.email.original_subject = self.email.subject = self._extract_subject(msg)

        self.email.text_body, self.email.html_body = self._extract_content(msg)

        self.email.reply_to = email_dict.get("in_replay_to")
        # original message as string
        self.email.original_message = msg.as_string() if self.include_raw_email else None

    def process_body(self):
        """
        Phase 2: Fill in email body with either plaintext data, either rendered HTML - Overridden
        """
        if self.email.text_body:
            self.email.body = self.email.text_body
        else:
            # Can't know the original charset of the body - try and hope for the best.
            self.email.body = self.__render_html_body(self.email.html_body)

    def extract_attachments(self):
        """
        Phase 5: Extract attachments from the email string and wrap them into EmailAttachmentModel objects
        """
        msg = message_from_bytes(self.email_string)
        attachments = self._extract_attachments(msg)

        for file_name, file_contents in list(attachments.items()):
            attachment = EmailAttachmentModel(
                file_name=file_name,
                file_contents=file_contents
            )
            self.email.attachments.append(attachment)

    # noinspection PyBroadException
    @staticmethod
    def __render_html_body(html_body):
        # type: (str) -> unicode
        """
        Render html body to plain text plain
        :param html_body: {str} The HTML body of the email
        :return: {unicode} Plain text rendered HTML
        """

        def build_html_rendered():
            """
            Create a HTML2Text object
            :return: {html2text.HTML2Text} The HTMl2Text object
            """
            renderer = HTML2Text()
            # Configuration was decided by Product Team
            renderer.ignore_tables = True
            renderer.protect_links = True
            renderer.ignore_images = False
            renderer.ignore_links = False
            return renderer

        try:
            html_renderer = build_html_rendered()
            return html_renderer.handle(html_body)
        except:
            # HTML2Text is not performing well on non-ASCII str. On failure - try to decode the str to unicode
            # using utf8 encoding. If failed - return a proper message.
            try:
                # HTML2Text object shouldn't be used twice - it can cause problems and errors according to google
                # Therefore rebuild the object
                html_renderer = build_html_rendered()
                return html_renderer.handle(html_body)
            except Exception as e:
                return "Failed rendering HTML. Error: {}".format(e)

    def _extract_subject(self, msg):
        # type: (email.message.Message) -> unicode
        """
        Extract message subject from email message.
        :param msg: {email.message.Message} Message object.
        :return: {string} Subject text.
        """
        raw_subject = msg.get('subject')
        if not raw_subject:
            return ''

        try:
            parsed_value, encoding = decode_header(raw_subject)[0]
            subject = parsed_value if encoding is None else parsed_value.decode(encoding)
            regex_object = re.compile(self.regex_map.get('subject'), re.MULTILINE)
            result = regex_object.findall(subject)
            return ''.join(result)

        except UnicodeDecodeError:
            msg = 'Unable to decode email subject'
            self.logger.error(msg)
            return msg

        except Exception as e:
            self.logger.error('Unable to extract subject from email with email_uid={0}'.format(self.email.email_uid))
            self.logger.exception(e)
            return 'Unable to extract subject'

    # noinspection PyBroadException
    def _extract_content(self, msg):
        # type: (email.message.Message) -> tuple
        """
        Extracts content from an e-mail message.
        :param msg: {email.message.Message} An eml object
        :return: {tuple} Text body, Html body, email parts counter
        """

        def extract_text_parts():
            text_parts = [part for part in typed_subpart_iterator(msg, 'text', 'plain')]
            text_body_parts = []
            for part in text_parts:
                try:
                    charset = self._get_charset(part, self._get_charset(msg))
                    text_body_parts.append(str(part.get_payload(decode=True), charset, "replace"))
                except (UnicodeDecodeError, UnicodeEncodeError):
                    self.logger.error("Unable to decode part of the email text body")

            return "\n".join(text_body_parts).strip()

        def extract_html_parts():
            html_parts = [part for part in typed_subpart_iterator(msg, 'text', 'html')]
            html_body_parts = []
            for part in html_parts:
                try:
                    charset = self._get_charset(part, self._get_charset(msg))
                    html_body_parts.append(str(part.get_payload(decode=True), charset, "replace"))
                except (UnicodeDecodeError, UnicodeEncodeError):
                    self.logger.error("Unable to decode part of the email text body")

            return "\n".join(html_body_parts).strip()

        if not msg.is_multipart():
            body = str(msg.get_payload(decode=True),
                       self._get_charset(msg),
                       "replace")

            return body.strip(), body.strip()
        else:
            return extract_text_parts(), extract_html_parts()

    def _extract_attachments(self, msg, encode_as_base64=False):
        # type: (email.message.Message, bool) -> dict
        """
        Extract the attachments from a Message object
        :param msg: {Message} the msg to extract from
        :param encode_as_base64: {bool} Whether to encode the attachments content with base64 or not
        :return: {dict} The extracted attachments (filename: content)
        """
        return self.__extract_attachments_recursively(msg=msg, encode_as_base64=encode_as_base64)

    def __extract_img_attachments(self, msg):
        # type: (email.message.Message) -> dict
        """
        Extract all image tags except tags with Content ID (cid) and return dict with file name (k) and file content (v)
        :param msg: {Message} the msg to extract from
        :param encode_as_base64: {bool} Whether to encode the attachments content with base64 or not
        :return: {dict} The extracted attachments (filename: content)
        """
        img_attachments = {}
        img_regex = re.compile(IMG_REGEX, re.MULTILINE)
        images_src = img_regex.findall(msg.get_payload())
        url_regex = re.compile(URLS_REGEX)

        for image_src in images_src:
            # TODO: Thank about more elegant algorithm
            if image_src.startswith('data:image') and 'base64' in image_src:
                filename = '{}.{}'.format(uuid.uuid4(), image_src.split(';')[0].split('/')[-1])
                img_attachments[filename] = base64.b64decode(image_src.split(',')[-1])

            elif url_regex.findall(image_src):
                image_url = url_regex.findall(image_src)[-1]
                filename = image_url.split('/')[-1].split('?')[0]
                try:
                    img_content = requests.get(image_src)
                    img_attachments[filename] = img_content.content
                    img_content.close()
                except requests.exceptions.HTTPError:
                    # @TODO maybe we should add log here
                    pass

        return img_attachments

    def __extract_attachments_recursively(self, msg, encode_as_base64=False, attachments=None):
        if attachments is None:
            attachments = {}

        payload = msg.get_payload()
        parts = payload if isinstance(payload, list) else [msg]
        for part in parts:
            if isinstance(part.get_payload(), list):
                self.__extract_attachments_recursively(part, encode_as_base64=encode_as_base64, attachments=attachments)

            try:
                if part.get_content_type() == 'text/html':
                    attachments.update(self.__extract_img_attachments(part))
                    continue

                if not self._is_attachment(part, include_inline=True, include_cid=True):
                    continue

                # Extract filename from attachment
                filename = self.__extract_attachment_filename(part)

                # Get attachment content - decode to raw
                file_content = part.get_payload(decode=True)

                # Get file content from eml file
                if not file_content and self.EML_ATTACHMENT_EXTENSION in filename:
                    file_data = part.get_payload()[0]
                    file_content = file_data.as_bytes()

                if encode_as_base64:
                    file_content = b64encode(file_content)

                if filename and file_content:
                    attachments.update({filename: file_content})
                else:
                    self.logger.error(f"Error Code 1: Encountered an email object with missing headers. Please "
                                      f"visit documentation portal for more details.")
            except Exception as e:
                self.logger.error("Unable to extract attachment from the email")
                self.logger.exception(e)

        return attachments

    def __extract_attachment_filename(self, mime_part):
        # type: (email.message.Message, email.message.Message) -> unicode
        """
        Extract the filename of an attachment MIME part on the base of RFC2047: https://dmorgan.info/posts/encoded-word-syntax/
        :param mime_part: {email.message.Message} The MIME part
        :return: {unicode} The decoded filename
        """
        filename = mime_part.get_filename()

        if not filename:
            if mime_part.get_content_maintype() == 'image' and mime_part.get('Content-ID'):
                return '{}.{}'.format(mime_part.get('Content-ID'), mime_part.get_content_subtype())

            if mime_part.get_content_type() == self.MESSAGE_RFC822_CONTENT_TYPE:
                return f"{self.DEFAULT_FILENAME}_{uuid.uuid4()}{self.EML_ATTACHMENT_EXTENSION}"
            return self.DEFAULT_FILENAME

        # if isinstance(filename, bytes):
        #     filename = filename.decode(self.DEFAULT_FILENAME_CHARSET)

        if len(filename.split('.')) == 1:
            filename = '{}.{}'.format(filename, mime_part.get_content_subtype())

        # for non-trivial characters in file name (such as emoji)
        # file name will contain line break and will have different encoding
        # if nothing special, we'll have file name as ["file_name"]
        #result_filename = filename.split("\n")
        result_filename = filename.replace("\n", " ").replace("\t", "").split(" ")
        encoded_string = list(filter(lambda v: re.match(self.ENCODED_WORD_REGEX, v), result_filename))

        if not encoded_string:
            # Sometimes we get filename as a binary string (e.g. if it's ASCII),
            # In such cases we manually decode to unicode

            # if everything is good, we return a file name (concatenating in back)
            return " ".join(result_filename)

        # if not we just decode every part
        result = []

        for part in result_filename:
            # part.strip(" ") is to ensure we can match because we'll get whitespaces
            charset, encoding, encoded_text = re.match(self.ENCODED_WORD_REGEX, part.strip(" ")).groups()
            if charset and encoding and encoded_text:
                if encoding.lower() == 'b':
                    byte_string = base64.b64decode(encoded_text)
                else:
                    byte_string = quopri.decodestring(encoded_text, header=True)
                result.append(byte_string.decode(charset))
            else:
                return result_filename[0]
        # collect decoded parts into single file name
        return "".join(result)


class MSGEmailModelBuilder(BaseEmailBuilder):
    """
    Builder, which allows to convert MSG represented by a string into an EmailModel.
    """
    EMAIL_REGEX = r"[a-z0-9.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+"
    ATTACHMENT_EXTRACTION_ERROR = "Unable to extract"

    def __init__(self, email_string, email_uid, mailbox, environment, logger, regex_map=DEFAULT_REGEX_MAP,
                 urls_regex=URLS_REGEX, include_raw_email=False):
        """
        Basic constructor
        :param email_string: {str} String representation of MSG.
        :param email_uid: {str} Email sequential ID on the IMAP server
        :param mailbox: {str} Email address of the monitored mailbox
        :param environment: {str} Name of the current environment
        :param logger: {SiemplifyLogger} Logger instance to log email messages
        :param regex_map: {dict} Dictionary, which may be used to extract additional data from the email body. If keys are matching class attributes, then values are assigned to them. If class is missing such attributes, then these values are stored in self.extra_data dict
        :param urls_regex: {str} Regex string, which should be used to extract all URLs from email HTML body
        :param include_raw_email: {bool} If True, then original email message is attached to EmailModel() instance as an attachment. Otherwise - just ignored.
        """
        super(MSGEmailModelBuilder, self).__init__(email_string, email_uid, mailbox, environment, logger, regex_map,
                                                   urls_regex, include_raw_email)
        self.msg_object = None

    def extract_base_info(self):
        """
        Phase 1: Extract base information - Overridden
        """
        msg_string = self.email_string
        msg = extract_msg.Message(msg_string)
        self.msg_object = msg

        self.email.encoding = "utf-8"
        self.email.email_uid = self.email_uid
        self.email.message_id = self._decode_string(msg.message_id, self.email.encoding) or ''
        self.email.mailbox = self.mailbox
        self.email.environment = self.environment
        self.email.original_subject = self._decode_string(msg.subject, self.email.encoding)
        self.email.subject = self._decode_string(msg.subject, self.email.encoding)
        sender = self._decode_string(msg.sender, self.email.encoding) or ''
        self.email.senders = re.findall(self.EMAIL_REGEX, sender)
        self.email.original_sender = self.DEFAULT_DELIMITER.join(self.email.senders)

        self.email.recipients = []
        for recipient in msg.recipients:
            self.email.recipients.append(self._decode_string(recipient.email, self.email.encoding))

        if msg.cc:
            self.email.cc = self._decode_string(msg.cc, self.email.encoding)
        self.email.receivers = [*self.email.recipients, *self.email.cc, *self.email.bcc]

        self.email.original_recipient = self.DEFAULT_DELIMITER.join(self.email.recipients)
        self.email.email_date = datetime(
            msg.parsedDate[0], msg.parsedDate[1], msg.parsedDate[2],
            msg.parsedDate[3], msg.parsedDate[4], msg.parsedDate[5],
            msg.parsedDate[6])
        self.email.text_body = self._decode_string(msg.body, self.email.encoding)
        self.email.html_body = self._decode_string(msg.body, self.email.encoding)

        if self.include_raw_email:
            self.email.original_message = self.email_string

    def process_body(self):
        """
        Phase 2: Fill in email body with either plaintext data, either rendered HTML - Overridden
        """
        if self.email.text_body:
            self.email.body = self.email.text_body

    def extract_attachments(self):
        """
        Phase 5: Extract attachments from the email string and wrap them into EmailAttachmentModel objects - Overridden
        """
        if not self.msg_object:
            return

        for attachment in self.msg_object.attachments:
            file_name = attachment.longFilename if attachment.longFilename else attachment.shortFilename
            file_content = attachment.data if attachment.type != "msg" else self.ATTACHMENT_EXTRACTION_ERROR
            attachment_model = EmailAttachmentModel(
                file_name=file_name,
                file_contents=file_content
            )
            self.email.attachments.append(attachment_model)


class ICSEmailModelBuilder(BaseEmailBuilder):
    """
    Builder, which allows to convert ICS represented by a string into an EmailModel.
    """
    EMAIL_REGEX = r"[a-z0-9.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+"
    MESSAGE_ID_FORMAT = "<{}>"
    DEFAULT_DELIMITER = " "

    def __init__(self, email_string, email_uid, mailbox, environment, logger, regex_map=DEFAULT_REGEX_MAP,
                 urls_regex=URLS_REGEX, include_raw_email=False):
        """
        Basic constructor
        :param email_string: {str} String representation of MSG.
        :param email_uid: {str} Email sequential ID on the IMAP server
        :param mailbox: {str} Email address of the monitored mailbox
        :param environment: {str} Name of the current environment
        :param logger: {SiemplifyLogger} Logger instance to log email messages
        :param regex_map: {dict} Dictionary, which may be used to extract additional data from the email body. If keys are matching class attributes, then values are assigned to them. If class is missing such attributes, then these values are stored in self.extra_data dict
        :param urls_regex: {str} Regex string, which should be used to extract all URLs from email HTML body
        :param include_raw_email: {bool} If True, then original email message is attached to EmailModel() instance as an attachment. Otherwise - just ignored.
        """
        super(ICSEmailModelBuilder, self).__init__(email_string, email_uid, mailbox, environment, logger, regex_map,
                                                   urls_regex, include_raw_email)
        self.msg_object = None

    def extract_base_info(self):
        """
        Phase 1: Extract base information - Overridden
        """

        start = self.email_string.get('dtstart', '').dt.isoformat() if self.email_string.get('dtstart', '') else None
        end = self.email_string.get('dtend', '').dt.isoformat() if self.email_string.get('dtend', '') else None
        self.email.encoding = "utf-8"
        self.email.email_uid = self.email_uid
        self.email.message_id = self.MESSAGE_ID_FORMAT.format(self.get_unicode_str(self.email_string.get('uid', '')))
        self.email.mailbox = self.mailbox
        self.email.environment = self.environment
        self.email.original_subject = self.get_unicode_str(self.email_string.get('summary', ''))
        self.email.subject = self.get_unicode_str(self.email_string.get('summary', ''))
        sender = self.get_unicode_str(self.email_string.get('organizer', ''))
        if sender:
            self.email.senders = re.findall(self.EMAIL_REGEX, sender)
            self.email.original_sender = self.DEFAULT_DELIMITER.join(self.email.senders)

        self.email.recipients = []
        for recipient in self.email_string.get('attendee', ''):
            self.email.recipients.append(
                self.get_unicode_str(recipient if isinstance(recipient, str) else recipient.email)
            )

        if self.email_string.get('cc', ''):
            self.email.cc = self.get_unicode_str(self.email_string.get('cc', ''))
        self.email.receivers = [*self.email.recipients, *self.email.cc, *self.email.bcc]

        self.email.original_recipient = self.DEFAULT_DELIMITER.join(self.email.recipients)
        self.email.email_date = start
        self.email.body = self.get_unicode_str(self.email_string.get('description', ''))

        if self.include_raw_email:
            self.email.original_message = self.email_string

    def extract_urls_from_ics_attachments(self, starting_index):
        """
        Phase 7: Extracts all urls from the ics attachments
        """
        try:
            regex_object = re.compile(self.urls_regex)
            attachments = self.email_string.get('attach', [])
            attachments = attachments if isinstance(attachments, list) else [attachments]
            all_results = [url for url in regex_object.findall(self.DEFAULT_DELIMITER.join(attachments)) if '@' not in url]
            for index, result in enumerate(all_results, starting_index):
                # Divide keys
                result = result.strip(self.CHARS_TO_STRIP)
                key_name = '{0}_{1}'.format("url", index)
                self.email.urls[key_name] = safe_str_cast(result, default_value=None)
        except Exception as e:
            self.logger.error("Unable to extract URLs from ics attachments with email_uid={0}".format(self.email.email_uid))
            self.logger.exception(e)


class EmailDataModelTransformationLayer(object):
    """
    Transformator class for Email Integrator.
    This class contains one-way transformation (from external to internal).
    Note: When you need to transform back use build in methods within data models themselves.
    """

    EMAIL_EML_RESOLUTION = '.eml'
    EMAIL_MSG_RESOLUTION = '.msg'
    EMAIL_ICS_RESOLUTION = '.ics'

    def __init__(self, logger=None, regex_map=DEFAULT_REGEX_MAP):
        """
        Base constructor
        :param logger: {SiemplifyLogger} Logger instance to log email messages
        :param regex_map: {dict} Dictionary, which may be used to extract additional data from the email body. If keys are matching class attributes, then values are assigned to them. If class is missing such attributes, then these values are stored in self.extra_data dict
        """
        self.logger = logger
        self.regex_map = regex_map

    def convert_string_to_email(self,
                                email_string,
                                email_uid,
                                environment,
                                mailbox,
                                include_raw_email=False,
                                additional_headers=None):
        """
        Converts email string representation into EmailModel() object
        :param email_string: {str} String representation of email. Basically it's equal to self.imap.uid('fetch', email_uid, '(BODY.PEEK[])')[1][0][1]
        :param email_uid: {str} Email sequential ID on the IMAP server
        :param mailbox: {str} Email address of the monitored mailbox
        :param environment: {str} Name of the current environment
        :param include_raw_email: {bool} If True, then original email message is attached to EmailModel() instance as an attachment. Otherwise - just ignored.
        :param additional_headers: {list} The list of the headers/header_regexp to add to the final result
        :return: {EmailDataModels.EmailModel} EmailModel() instance
        """
        builder = EmailModelBuilder(
            email_string=email_string,
            email_uid=email_uid,
            environment=environment,
            mailbox=mailbox,
            logger=self.logger,
            regex_map=self.regex_map,
            urls_regex=URLS_REGEX,
            include_raw_email=include_raw_email,
            additional_headers=additional_headers
        )

        builder.extract_base_info()
        builder.process_body()
        builder.extract_answer()
        builder.extract_additional_data()
        builder.extract_attachments()
        builder.extract_urls()
        email = builder.get_email()

        self._update_extracted_headers(email, email_string, additional_headers)
        self.update_email_attachments(email, email_uid, environment, mailbox, additional_headers)

        return email

    def _update_extracted_headers(self, email, email_string, additional_headers):
        extracted_headers = self.__extract_headers_from_message(email_string, additional_headers)
        email.extracted_headers.update(extracted_headers)

    def __extract_headers_from_message(self, email_string, additional_headers):
        """
        Extract headers value from message.
        :param email_string: {str} String representation of email. Basically it's equal to self.imap.uid('fetch',
        email_uid, '(BODY.PEEK[])')[1][0][1]
        :param additional_headers: {list} The list of the headers/header_regexp to add to the final result
        :return: {EmailDataModels.EmailModel} EmailModel() instance
        """
        filtered_headers = {}

        if additional_headers:
            msg = message_from_bytes(email_string)
            header_keys = msg.keys()
            for header in additional_headers:
                r = re.compile(header)
                matched_keys = list(filter(r.match, header_keys))

                for key in matched_keys:
                    filtered_headers[key] = msg.get(key)

        return filtered_headers

    def convert_msg_string_to_email(self, email_string, email_uid, environment, mailbox, include_raw_email=False):
        """
        Converts email string representation into EmailModel() object
        :param email_string: {str} String representation of MSG.
        :param email_uid: {str} Email sequential ID on the IMAP server
        :param mailbox: {str} Email address of the monitored mailbox
        :param environment: {str} Name of the current environment
        :param include_raw_email: {bool} If True, then original email message is attached to EmailModel() instance as an attachment. Otherwise - just ignored.
        :return: {EmailDataModels.EmailModel} EmailModel() instance
        """
        builder = MSGEmailModelBuilder(
            email_string=email_string,
            email_uid=email_uid,
            environment=environment,
            mailbox=mailbox,
            logger=self.logger,
            regex_map=self.regex_map,
            urls_regex=URLS_REGEX,
            include_raw_email=include_raw_email
        )

        builder.extract_base_info()
        builder.process_body()
        builder.extract_answer()
        builder.extract_additional_data()
        builder.extract_attachments()
        builder.extract_urls()
        return builder.get_email()

    def convert_ics_string_to_email(self, email_string, email_uid, environment, mailbox, include_raw_email=False):
        """
        Converts email string representation into EmailModel() object
        :param email_string: {str} String representation of MSG.
        :param email_uid: {str} Email sequential ID on the IMAP server
        :param mailbox: {str} Email address of the monitored mailbox
        :param environment: {str} Name of the current environment
        :param include_raw_email: {bool} If True, then original email message is attached to EmailModel() instance as an attachment. Otherwise - just ignored.
        :return: {EmailDataModels.EmailModel} EmailModel() instance
        """
        builder = ICSEmailModelBuilder(
            email_string=email_string,
            email_uid=email_uid,
            environment=environment,
            mailbox=mailbox,
            logger=self.logger,
            regex_map=self.regex_map,
            urls_regex=URLS_REGEX,
            include_raw_email=include_raw_email
        )

        builder.extract_base_info()
        builder.extract_answer()
        builder.extract_additional_data()
        builder.extract_urls()
        email = builder.get_email()
        builder.extract_urls_from_ics_attachments(len(email.urls)+1)
        return email

    def update_email_attachments(self, email, email_uid, environment, mailbox, additional_headers):
        """
        Converts all emails from attachments to EmailModel objects and appends them to the original email
        :param email: {EmailModel} Original email
        :param email_uid: {str} Email sequential ID on the IMAP server
        :param mailbox: {str} Email address of the monitored mailbox
        :param additional_headers: {list} The list of the headers/header_regexp to add to the final result
        :param environment: {str} Name of the current environment
        """
        for attachment in email.attachments:
            try:
                if self.EMAIL_EML_RESOLUTION in attachment.file_name.lower():
                    attached_email = self.convert_string_to_email(
                        email_string=attachment.file_contents,
                        email_uid=email_uid,
                        environment=environment,
                        mailbox=mailbox,
                        include_raw_email=False,
                        additional_headers=additional_headers
                    )
                    email.attached_emails.append(attached_email)
                elif self.EMAIL_MSG_RESOLUTION in attachment.file_name.lower():
                    attached_email = self.convert_msg_string_to_email(
                        email_string=attachment.file_contents,
                        email_uid=email_uid,
                        environment=environment,
                        mailbox=mailbox,
                        include_raw_email=False
                    )
                    email.attached_emails.append(attached_email)
                elif self.EMAIL_ICS_RESOLUTION in attachment.file_name.lower():
                    cal = Calendar.from_ical(attachment.file_contents)
                    for component in cal.walk('vevent'):
                        attached_email = self.convert_ics_string_to_email(
                            email_string=component,
                            email_uid=email_uid,
                            environment=environment,
                            mailbox=mailbox,
                            include_raw_email=False
                        )
                        email.attached_emails.append(attached_email)
            except Exception as e:
                self.logger.error("Failed to extract email from the attachment {}".format(
                    attachment.file_name))
                self.logger.exception(e)