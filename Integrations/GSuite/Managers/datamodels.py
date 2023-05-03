from TIPCommon import dict_to_flat, add_prefix_to_dict

from consts import ENRICHMENT_PREFIX


class OrgUnit(object):
    """
    GSuite Organization unit datamodel
    """

    def __init__(self, raw_data, kind=None, name=None, description=None, etag=None, blockInheritance=None, orgUnitId=None, orgUnitPath=None,
                 parentOrgUnitId=None, parentOrgUnitPath=None, **kwargs):
        self.raw_data = raw_data
        self.kind = kind
        self.name = name
        self.description = description
        self.etag = etag
        self.block_inheritance = blockInheritance
        self.org_unit_id = orgUnitId
        self.org_unit_path = orgUnitPath
        self.parent_org_unit_id = parentOrgUnitId
        self.parent_org_unit_path = parentOrgUnitPath

    def as_json(self):
        return self.raw_data

    def as_csv(self):
        return {
            "Kind": self.kind,
            "Name": self.name,
            "Description": self.description,
            "Etag": self.etag,
            "Block Inheritance": self.block_inheritance,
            "Org Unit Id": self.org_unit_id,
            "Org Unit Path": self.org_unit_path,
            "Parent Org Unit Id": self.parent_org_unit_id,
            "Parent Org Unit Path": self.parent_org_unit_path
        }


class Group(object):
    """
    GSuite Group data model
    """

    def __init__(self, raw_data, id=None, email=None, name=None, description=None, adminCreated=None, directMembersCount=None,
                 kind=None, etag=None, aliases=None, nonEditableAliases=None, **kwargs):
        self.raw_data = raw_data
        self.id = id
        self.email = email
        self.name = name
        self.description = description
        self.admin_created = adminCreated
        self.direct_member_count = directMembersCount
        self.kind = kind
        self.etag = etag
        self.aliases = aliases or []
        self.non_editable_aliases = nonEditableAliases or []

    def as_json(self):
        return self.raw_data


class User(object):
    """
    GSuite user data model.
    """

    class Phone(object):
        """
        GSuite phone data model
        """

        def __init__(self, value=None, type=None, is_primary=None):
            self.value = value
            self.type = type
            self.is_primary = is_primary

    def __init__(self, raw_data, id=None, kind=None, etag=None, primaryEmail=None, given_name=None, family_name=None, isAdmin=None,
                 creationTime=None, lastLoginTime=None, suspended=None, archived=None, phones_objs=None, gender_type=None,
                 changePasswordAtNextLogin=None, isDelegatedAdmin=None, customerId=None, orgUnitPath=None, isMailboxSetup=None,
                 recoveryEmail=None, **kwargs):
        self.raw_data = raw_data
        self.id = id
        self.kind = kind
        self.etag = etag
        self.email = primaryEmail
        self.given_name = given_name
        self.family_name = family_name
        self.is_admin = isAdmin
        self.creation_time = creationTime
        self.phones = phones_objs or []
        self.gender = gender_type
        self.is_delegated_admin = isDelegatedAdmin
        self.last_login_time = lastLoginTime
        self.is_account_suspended = suspended
        self.is_account_archived = archived
        self.change_password_at_next_login = changePasswordAtNextLogin
        self.customer_id = customerId
        self.org_unit_path = orgUnitPath
        self.is_mailbox_setup = isMailboxSetup
        self.recovery_email = recoveryEmail

    def as_json(self):
        return self.raw_data

    def as_enriched(self):
        return add_prefix_to_dict(dict_to_flat(self.raw_data), ENRICHMENT_PREFIX)

    def as_csv(self):
        return {
            'Id': self.id,
            'Email': self.email,
            'Given Name': self.given_name,
            'Family Name': self.family_name,
            'Is Admin?': self.is_admin,
            'Is Delegated Admin?': self.is_delegated_admin,
            'Creation Time': self.creation_time,
            'Last Login Time': self.last_login_time,
            'Suspended?': self.is_account_suspended,
            'Archived?': self.is_account_archived,
            'Change Password At Next Login?': self.change_password_at_next_login,
            'Customer ID': self.customer_id,
            'Org Unit Path': self.org_unit_path,
            'Is Mailbox set?': self.is_mailbox_setup,
            'Recovery Email': self.recovery_email
        }


class Member(object):
    """
    GSuite group member data model
    """

    def __init__(self, raw_data=None, kind=None, email=None, role=None, etag=None, type=None, status=None, delivery_settings=None, id=None,
                 **kwargs):
        self.raw_data = raw_data
        self.kind = kind
        self.email = email
        self.role = role
        self.etag = etag
        self.type = type
        self.status = status
        self.delivery_settings = delivery_settings
        self.id = id

    def as_json(self):
        return self.raw_data

    def as_csv(self):
        return {
            "kind": self.kind,
            "email": self.email,
            "role": self.role,
            "etag": self.etag,
            "type": self.type,
            "status": self.status,
            "delivery_settings": self.delivery_settings,
            "id": self.id
        }


class AccessToken(object):
    """
    Gsuite access token
    """

    def __init__(self, raw_data, access_token, token_type, **kwargs):
        self.raw_data = raw_data
        self.access_token = access_token
        self.token_type = token_type
