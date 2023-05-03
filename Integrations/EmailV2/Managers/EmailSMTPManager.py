# -*- coding: utf-8 -*-
# ==============================================================================
# title           :EmailSMTPManager.py
# description     :This Module contain all Email cloud operations functionality
# author          :org@siemplify.co
# date            :2-5-18
# python_version  :2.7
# libraries       :BeautifulSoup, email, emaildata
# requirements    :
# product_version :
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================
import email
import email.header
import os
import smtplib
import ssl
from base64 import b64decode
from email import encoders
from email.header import Header
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr
from urllib.parse import urlparse

import socks
from bs4 import BeautifulSoup

# =====================================
#             CONSTANTS               #
# =====================================
OK_STATUS = 'OK'

HTML_IMAGE_TAG = "cstimage"
HTML_IMAGE_TAG_NAME_ATTR = "cid"
HTML_IMAGE_TAG_BASE64_ATTR = "base64image"
HTML_EMBEDED_IMAGES_FORMAT = """
<template>
    <cstImage cid="image1" base64Image ="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" />
    <cstImage cid="image2" base64Image ="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" />
    <html>
    <head>
        <style type="text/css">
        .title {
            color: blue;
            text-decoration: bold;
            text-size: 1em;
        }

        .author {
            color: gray;
        }
        </style>
    </head>
    <body>
        <img alt="StartHeader" src="cid:image1" />
        <span class="title">La super bonne</span>
        This is the message body
        </h1>
        <br/>
        <img alt="EndHeader" src="cid:image2" />
    </body>
    </html>
</template>
"""
HUMAN_READABLE_EMAIL_DATE_FORMAT = "%a, %b %-d, %Y at %-I:%M %p %Z"
ESCAPED_HTML_BRACKETS_WRAP = "&lt;{}&gt;"


# =====================================
#              CLASSES                #
# =====================================

class EmailManagerError(Exception):
    """
    General Exception for Email manager
    """
    pass


class ProxySMTP(smtplib.SMTP):
    def __init__(self, host='', port=smtplib.SMTP_PORT,
                 proxy_type=socks.PROXY_TYPE_SOCKS5, proxy_addr=None,
                 proxy_port=None, proxy_username=None, proxy_password=None):
        self.proxy_type = proxy_type
        self.proxy_addr = proxy_addr
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        smtplib.SMTP.__init__(self, host, port)

    def _get_socket(self, host, port, timeout):
        # This makes it simpler for SMTP_SSL to use the SMTP connect code
        # and just alter the socket connection bit.
        return socks.create_connection(dest_pair=(host, port),
                                       proxy_type=self.proxy_type,
                                       proxy_addr=self.proxy_addr,
                                       proxy_port=self.proxy_port,
                                       proxy_username=self.proxy_username,
                                       proxy_password=self.proxy_password,
                                       timeout=timeout)


class ProxySMTPSSL(smtplib.SMTP_SSL):
    def __init__(self, host='', port=smtplib.SMTP_SSL_PORT, keyfile=None,
                 certfile=None, proxy_type=socks.PROXY_TYPE_SOCKS5,
                 proxy_addr=None, proxy_port=None, proxy_username=None,
                 proxy_password=None):
        self.proxy_type = proxy_type
        self.proxy_addr = proxy_addr
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        smtplib.SMTP_SSL.__init__(self, host, port, keyfile, certfile)

    def _get_socket(self, host, port, timeout):
        new_socket = socks.create_connection(dest_pair=(host, port),
                                             proxy_type=self.proxy_type,
                                             proxy_addr=self.proxy_addr,
                                             proxy_port=self.proxy_port,
                                             proxy_username=self.proxy_username,
                                             proxy_password=self.proxy_password,
                                             timeout=timeout)
        new_socket = ssl.wrap_socket(new_socket, self.keyfile, self.certfile)
        self.file = smtplib.SSLFakeFile(new_socket)
        return new_socket


class EmailSMTPManager(object):
    """
    Responsible for all Email system operations functionality
    """

    def __init__(self, mail_address, proxy_server=None, proxy_username=None, proxy_password=None):
        self.mail_address = mail_address

        if proxy_server:
            server_url = urlparse(proxy_server)
            scheme = server_url.scheme

            if scheme and server_url.hostname:
                self.proxy_addr = "{}://{}".format(scheme, server_url.hostname)
                self.proxy_port = server_url.port
            else:
                if ":" in proxy_server:
                    self.proxy_addr = proxy_server.split(":")[0]
                    self.proxy_port = int(proxy_server.split(":")[1])
                else:
                    self.proxy_addr = proxy_server
                    self.proxy_port = None

            self.proxy_username = proxy_username
            self.proxy_password = proxy_password

        else:
            self.proxy_addr = None
            self.proxy_port = None
            self.proxy_username = None
            self.proxy_password = None

        self.smtp = None

    def login_smtp(self, host, port, username="", password="", use_ssl=False, use_auth=False):
        if self.proxy_addr:
            self.smtp = ProxySMTPSSL(
                host=host,
                port=port,
                proxy_addr=self.proxy_addr,
                proxy_port=self.proxy_port,
                proxy_username=self.proxy_username,
                proxy_password=self.proxy_password
            ) if use_ssl else ProxySMTP(
                host=host,
                port=port,
                proxy_addr=None,
                proxy_port=None,
                proxy_username=None,
                proxy_password=None
            )
        else:
            self.smtp = smtplib.SMTP_SSL(host=host, port=port) if use_ssl else smtplib.SMTP(host=host, port=port)

        self.smtp.ehlo()
        # Try to start TLS
        try:
            self.smtp.starttls()
        except:
            # The server does not support TLS protocol
            pass
        if use_auth:
            try:
                self.smtp.login(username, password)
            except Exception as error:
                raise EmailManagerError(
                    "Cannot login to SMTP Server with given creds, error: {0}".format(error))
        return True

    def send_mail(self, to_addresses, subject, body):
        """
        Send plain text email using SMTP without any attachments
        :param to_addresses: {string} Comma-separated list of addresses to send the mail to
        :param subject: {string} Subject of the mail
        :param body: {string} Body of the mail
        :return: {boolean} Returns True on successful send.
        """
        if not self.smtp:
            raise EmailManagerError("SMTP Server is not configured yet. Try to call email_manager.login_smtp() first.")

        msg = MIMEText(body, 'plain', 'utf-8')
        msg['From'] = self.mail_address
        msg['To'] = to_addresses
        msg['Subject'] = subject
        try:
            self.smtp.sendmail(self.mail_address, to_addresses.split(','), msg.as_string())
        except Exception as error:
            raise EmailManagerError("sendmail: {}".format(error))
        return True

    def send_mail_with_attachment(self, to_addresses, subject, body, attachment_string, file_name):
        """
        Send mail using SMTP with a file attachment.
        :param to_addresses: {string} Comma-separated list of addresses to send the mail to
        :param subject: {string} Subject of the mail
        :param body: {string} Body of the mail
        :param attachment_string: {string} Content of the attached file represented as a string
        :param file_name: {string} File name of the attachment, as it would be shown in the email
        :return: {boolean} Returns True on successful send.
        """
        if not self.smtp:
            raise EmailManagerError("SMTP Server is not configured yet. Try to call email_manager.login_smtp() first.")

        msg = MIMEMultipart()
        msg['From'] = self.mail_address
        msg['To'] = to_addresses
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'html', 'utf-8'))

        if attachment_string:
            part = MIMEBase('application', "octet-stream")
            part.set_payload(attachment_string)
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="{0}"'.format(file_name))

            msg.attach(part)

        try:
            self.smtp.sendmail(self.mail_address, to_addresses.split(','), msg.as_string())
        except Exception as error:
            raise EmailManagerError("sendmail: {}".format(error))
        return True

    def send_mail_html_embedded_photos(self,
                                       to_addresses,
                                       subject,
                                       html_body,
                                       cc=None,
                                       bcc=None,
                                       display_sender_name=None,
                                       attachments={},
                                       original_message=None):
        """
        Send email using SMTP with embedded photos & attachments in it according to html template (Example above in consts)
        :param to_addresses: {str} Comma-separated string of emails to whom this email should be send
        :param subject: {str} Subject of the email to be send
        :param html_body: {str} String containing email HTML body
        :param cc: {str} Comma-separated string of emails to be included to CC
        :param bcc: {str} Comma-separated string of emails to be included to BCC
        :param display_sender_name: {str} Name, which should be displayed to recipients of this email
        :param attachments: {dict} Dictionary containing mapping of attachment unicode file_name to it's content as binary
        :param original_message: {EmailModel} Original message to send reply to
        :return: {str} message_id of the email, which has been successfully sent.
        """
        if not self.smtp:
            raise EmailManagerError("Smtp Server is no configured yet, call first to self.login_smtp()")

        msg = MIMEMultipart('related')

        # if set send the mail when only the sender name appear on the inbox
        if display_sender_name:
            sender = formataddr((str(Header(display_sender_name, 'utf-8')), self.mail_address))
        else:
            sender = self.mail_address

        msg['From'] = sender
        msg['To'] = to_addresses
        msg['Subject'] = subject
        msg_id = email.utils.make_msgid()
        msg['Message-ID'] = msg_id

        if original_message:
            msg['In-Reply-To'] = original_message.message_id
            msg['References'] = original_message.message_id

        # Email headers don't matter to the SMTP server. Just add the CC and BCC recipients to the toaddrs.
        # For CC, add them to the CC header.
        if cc:
            msg['CC'] = cc
            cc = cc.split(",")
        else:
            cc = []

        # Not adding header - msg['bcc'] will just add a bcc header to your email which defeats the point of bcc!
        # The bcc recipients will all receive the email, but the email clients won't display them as recipients.
        if bcc:
            bcc = bcc.split(",")
        else:
            bcc = []

        toaddrs = to_addresses.split(',') + cc + bcc

        # Passing default parser to avoid getting a warning from BeautifulSoup
        soup = BeautifulSoup(html_body, features="html.parser")
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))

        # Extract cstimage tags images from html template
        for cst_tag in soup.findAll(HTML_IMAGE_TAG):
            image_name = cst_tag[HTML_IMAGE_TAG_NAME_ATTR]
            image_content = b64decode(cst_tag[HTML_IMAGE_TAG_BASE64_ATTR])
            img = MIMEImage(image_content, image_name)
            img.add_header('Content-ID', '<{}>'.format(image_name))
            img.add_header('Content-Disposition', 'inline', filename=image_name)
            msg.attach(img)

        for file_path, file_contents in attachments.items():
            file_name = os.path.basename(file_path)
            part = MIMEBase('application', "octet-stream")
            part.set_payload(file_contents)
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="{}"'.format(file_name))
            msg.attach(part)

        try:
            self.smtp.sendmail(msg['From'], toaddrs, msg.as_string())
        except Exception as error:
            raise EmailManagerError("sendmail: {}".format(error))
        return msg_id

