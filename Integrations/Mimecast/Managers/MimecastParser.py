from datamodels import *
from typing import Iterable, Any
import re


class MimecastParser:
    def build_base_model(self, raw_data):

        items = raw_data.get("data")[0].get("items")

        return [BaseModel(
            raw_data=item
        ) for item in items]

    def build_list_of_base_objects(self, raw_data):
        return [BaseModel(raw_data=item) for item in raw_data]

    def build_messages_list(self, raw_data):
        data = raw_data.get("data", [])
        emails_data = data[0].get("trackedEmails", []) if data else []
        return [self.build_message_object(item) for item in emails_data]

    def build_message_object(self, raw_data):
        return Message(
            raw_data=raw_data,
            tracking_id=raw_data.get('id'),
            status=raw_data.get('status'),
            received=raw_data.get('received'),
            route=raw_data.get('route'),
            info=raw_data.get('info')
        )

    def build_message_details_object(self, raw_data):
        data = raw_data.get("data", [])
        message_data = data[0] if data else {}
        return MessageDetails(
            raw_data=message_data,
            tracking_id=message_data.get('id'),
            message_id=self.__parse_message_id(payload=message_data),
            reason=self.__traverse_json_path_safe(payload=message_data,
                                                  path=("queueInfo", "reason"),
                                                  result_default=""),
            risk=self.__traverse_json_path_safe(payload=message_data,
                                                path=("spamInfo", "spamProcessingDetail", "verdict", "risk"),
                                                result_default=""),
            queue_detail_status=self.__traverse_json_path_safe(payload=message_data,
                                                               path=("recipientInfo", "txInfo", "queueDetailStatus"),
                                                               result_default=""),
            transmission_components=self.__traverse_json_path_safe(payload=message_data,
                                                                   path=("recipientInfo", "txInfo",
                                                                         "transmissionComponents"),
                                                                   result_default=[]),
            components=self.__traverse_json_path_safe(payload=message_data,
                                                      path=("recipientInfo", "recipientMetaInfo", "components"),
                                                      result_default=[])
        )

    # Recursively traverse through payload by specified key path, without breaking if some key isn't there
    @staticmethod
    def __traverse_json_path_safe(payload: dict, path: Iterable[str], result_default: Any) -> Any:
        result = payload
        for key in path:
            result = result.get(key, {})
        return result or result_default

    # Parse internal message_id for the email from the transmissionInfo
    # As a fallback use id from the queueInfo
    def __parse_message_id(self, payload: dict,
                           path: Iterable[str] = ("recipientInfo", "messageInfo", "transmissionInfo")) -> Any:
        transmission_info = self.__traverse_json_path_safe(payload, path, result_default=None)

        if transmission_info is not None:
            message_id_match = re.search(r"(?i)message-id: &lt;(.+)&gt;", transmission_info)
            if message_id_match is not None:
                return message_id_match.group(1)

        return self.__traverse_json_path_safe(payload, ("queueInfo", "id"), result_default=None)
