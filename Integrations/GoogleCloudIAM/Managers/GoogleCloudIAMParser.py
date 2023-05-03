from typing import List, Optional

from datamodels import (
    Policy,
    Role,
    ServiceAccount
)


class GoogleCloudIAMParser(object):
    """
    Google Cloud IAM Transformation Layer
    """

    @staticmethod
    def build_service_account_iam_policy(raw_data) -> Policy:
        return Policy(
            raw_data=raw_data,
            etag=raw_data.get("etag"),
            version=raw_data.get("version"),
            bindings=[GoogleCloudIAMParser.build_policy_binding_obj(binding) for binding in raw_data.get("bindings", [])]
        )

    @staticmethod
    def build_policy_binding_obj(raw_binding):
        return Policy.Binding(
            raw_data=raw_binding,
            role=raw_binding.get("role"),
            members=raw_binding.get("members", [])
        )

    @staticmethod
    def build_role_obj_list(raw_data) -> List[Role]:
        return [GoogleCloudIAMParser.build_role_obj(raw_role) for raw_role in raw_data.get("roles", [])]

    @staticmethod
    def build_role_obj(raw_role):
        return Role(
            raw_data=raw_role,
            name=raw_role.get("name"),
            title=raw_role.get("title"),
            stage=raw_role.get("stage"),
            description=raw_role.get("description"),
            etag=raw_role.get("etag"),
            permissions=raw_role.get("includedPermissions")
        )

    @staticmethod
    def get_next_page_token_from_listed_roles(raw_data):
        return raw_data.get("nextPageToken")

    @staticmethod
    def get_next_page_token_from_listed_service_accounts(raw_data):
        return raw_data.get("nextPageToken")

    @staticmethod
    def build_service_account_obj_list(raw_data, project_id: Optional[str] = None):
        return [GoogleCloudIAMParser.build_service_account_obj(raw_service_account, project_id=project_id) for raw_service_account in
                raw_data.get("accounts", [])]

    @staticmethod
    def build_service_account_obj(raw_data, project_id: Optional[str] = None):
        return ServiceAccount(
            raw_data=raw_data,
            name=raw_data.get("name"),
            unique_id=raw_data.get("uniqueId"),
            email=raw_data.get("email"),
            display_name=raw_data.get("displayName"),
            description=raw_data.get("description"),
            oath_2_client_id=raw_data.get("oauth2ClientId"),
            project_id=project_id
        )
