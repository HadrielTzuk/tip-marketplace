from datamodels import (
    MicrosoftGraphEmail,
    MicrosoftGraphFileAttachment,
    MicrosoftGraphFolder,
)
from typing import List, Dict


class MicrosoftGraphMailParser:
    """
   Microsoft Graph Mail Transformation Layer.
    """

    @staticmethod
    def build_mg_mail_objs(alerts_data: List[Dict], mailbox_name: str, folder_name: str) -> List[MicrosoftGraphEmail]:
        return [
            MicrosoftGraphEmail(raw_data=alert_data,
                                mailbox_name=mailbox_name,
                                folder_name=folder_name,
                                **alert_data)
            for alert_data in alerts_data
        ]

    @staticmethod
    def build_mg_file_attachments(attachments_data: List[Dict]) -> List[MicrosoftGraphFileAttachment]:
        return [
            MicrosoftGraphFileAttachment(raw_data=attachment_data, **attachment_data)
            for attachment_data in attachments_data
        ]

    @staticmethod
    def build_mg_folder(folder_data) -> MicrosoftGraphFolder:
        return MicrosoftGraphFolder(**folder_data)
