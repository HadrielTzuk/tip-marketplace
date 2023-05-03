from datamodels import *


class ExchangeParser():
    def get_mail_data(self, raw_json):
        return MailData(
            raw_data=raw_json,
            message_id=raw_json.message_id,
            sent_date=raw_json.datetime_sent
        )

    def get_message_data(self, raw_json, set_account):
        return MessageData(
            raw_data=raw_json,
            message_id=raw_json.get('message_id', ''),
            datetime_received=raw_json.get('datetime_received', ''),
            author=raw_json.get('author', ''),
            to_recipients=raw_json.get('to_recipients', []),
            subject=raw_json.get('subject', ''),
            body=raw_json.get('body', ''),
            attachments_list=raw_json.get('attachments_list', {}),
            account=raw_json.get('account', ''),
            set_account=set_account,
            sender=raw_json.get('sender', '')
        )

    def get_messages_data(self, raw_json, set_account):
        return MessagesData(
            raw_data=raw_json,
            results=[self.get_message_data(result, set_account) for result in raw_json.get("results", [])],
        )

    def get_attachment_data(self, name, path):
        return AttachmentData(
            attachment_name=name,
            downloaded_path=path,
        )

    def get_oof_data(self, raw_json):
        return SiemplifyOOF(
            raw_data=raw_json,
            end=raw_json.end,
            external_audience=raw_json.external_audience,
            external_reply=raw_json.external_reply,
            internal_reply=raw_json.internal_reply,
            start=raw_json.start,
            state=raw_json.state
        )

    def build_rule_object(self, rule_object):
        return Rule(
            raw_data=rule_object,
            id=rule_object.rule_id,
            name=rule_object.display_name,
            priority=rule_object.priority,
            is_enabled=rule_object.is_enabled,
            conditions=self.build_conditions_object(rule_object.conditions),
            actions=self.build_actions_object(rule_object.actions)
        )

    def build_conditions_object(self, conditions_object):
        return Conditions(
            raw_data=conditions_object,
            domains=conditions_object.contains_sender_strings if conditions_object.contains_sender_strings else [],
            addresses=self.build_addresses_objects(
                conditions_object.from_addresses) if conditions_object.from_addresses else [],
        )

    def build_addresses_objects(self, addresses_objects):
        return [
            Address(
                raw_data=address,
                name=address.name,
                email_address=address.email_address,
                routing_type=address.routing_type,
                mailbox_type=address.mailbox_type,
                item_id=address.item_id,
            ) for address in addresses_objects]

    def build_actions_object(self, actions_object):
        return Actions(
            raw_data=actions_object,
            move_to_folder=actions_object.move_to_folder.folder_id.id if actions_object.move_to_folder else None,
            delete=actions_object.delete,
            permanent_delete=actions_object.permanent_delete,
        )
