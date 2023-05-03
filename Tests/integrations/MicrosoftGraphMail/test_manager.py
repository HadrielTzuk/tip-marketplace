# Integrations.MicrosoftGraphMail.Managers.
import datetime
import re

from Integrations.MicrosoftGraphMail.Managers.MicrosoftGraphMailManager import MicrosoftGraphMailManager
from Integrations.MicrosoftGraphMail.Managers.datamodels import (
    MicrosoftGraphEmail,
    MicrosoftGraphFileAttachment,
    MicrosoftGraphFolder
)
from Integrations.MicrosoftGraphMail.Managers.constants import TIME_FORMAT
from SiemplifyConnectors import SiemplifyConnectorExecution

import pytest


@pytest.mark.parametrize(
    "folder_name",
    [
        "Inbox",
        "Sent"
    ]
)
def test_get_folder(ms_graph_mail_manager: MicrosoftGraphMailManager, folder_name: str):
    folder = ms_graph_mail_manager.get_folder_by_name(folder_name)
    assert isinstance(folder, MicrosoftGraphFolder)
    assert folder.display_name == folder_name


@pytest.mark.parametrize(
    "folder_name, datetime_str, limit, unread_only, email_exclude_pattern, expected_emails_count",
    [
        ("Inbox", "2022-09-19T16:49:27Z", 20, False, "", 20),
        ("Inbox", "2022-09-19T16:49:27Z", 20, True, "", 20),
        ("Inbox", "2022-09-19T16:49:27Z", 10, False, 'Siemplify Test', 10),
    ]
)
def test_get_emails(ms_graph_mail_manager: MicrosoftGraphMailManager,
                    class_mocker,
                    folder_name: str,
                    datetime_str: str,
                    limit: int,
                    unread_only: bool,
                    email_exclude_pattern: str,
                    expected_emails_count: int):
    class_mocker.patch('test_manager.SiemplifyConnectorExecution')
    ms_graph_mail_manager.siemplify = SiemplifyConnectorExecution()
    existing_ids = []
    for _ in range(2):
        emails = ms_graph_mail_manager.get_emails(
            folder_name=folder_name,
            datetime_from=datetime.datetime.strptime(datetime_str, TIME_FORMAT),
            max_email_per_cycle=limit,
            existing_ids=existing_ids,
            unread_only=unread_only,
            email_exclude_pattern=email_exclude_pattern,
        )
        assert len(emails) == expected_emails_count
        for email in emails:
            assert isinstance(email, MicrosoftGraphEmail)
            if email.has_attachments:
                print(email.id)
            assert email.id not in existing_ids
            existing_ids.append(email.id)
            if unread_only:
                assert not email.raw_data.get('isRead')
            if email_exclude_pattern:
                assert not re.match(re.compile(email_exclude_pattern), email.subject)
                assert not re.match(re.compile(email_exclude_pattern), email.body.get('content'))
    assert len(existing_ids) == expected_emails_count * 2


@pytest.mark.parametrize(
    "folder_name, email_id",
    [
        ("Inbox", "AAMkADU0MDJjNjJkLTc3MzAtNGM5My04ZjM0LTZiYzVjMDI4ZTZlNQBGAAAAAADLc0XF-C8kRJTduC5WOJE-BwDby9ZjVdTJTJRS8jxrcA_oAAAAAAEMAADby9ZjVdTJTJRS8jxrcA_oAALEE3T3AAA="),
        ("Inbox", "AAMkADU0MDJjNjJkLTc3MzAtNGM5My04ZjM0LTZiYzVjMDI4ZTZlNQBGAAAAAADLc0XF-C8kRJTduC5WOJE-BwDby9ZjVdTJTJRS8jxrcA_oAAAAAAEMAADby9ZjVdTJTJRS8jxrcA_oAALEE3T5AAA=")
    ]
)
def test_get_attachments(ms_graph_mail_manager: MicrosoftGraphMailManager,
                         folder_name: str,
                         email_id: str):
    folder = ms_graph_mail_manager.get_folder_by_name(folder_name)
    attachments = ms_graph_mail_manager.load_attachments_for_email(folder.id, email_id)
    for attachment in attachments:
        assert isinstance(attachment, MicrosoftGraphFileAttachment)
        assert attachment.id
        assert attachment.size
        assert attachment.name
        assert attachment.content_type
        if not attachment.is_to_large:
            assert ms_graph_mail_manager.load_attachment_content(folder.id, email_id, attachment.id)
    assert len(attachments) > 0
