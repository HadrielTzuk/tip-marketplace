from constants import ENRICH_PREFIX
from SiemplifyUtils import add_prefix_to_dict
from constants import ALL_FIELDS_IDENTIFIER

class BaseModel(object):
    def __init__(self, raw_data):
        self.raw_data = raw_data

    def to_json(self):
        return self.raw_data


class User(BaseModel):
    def __init__(self, raw_data=None, displayName=None, userPrincipalName=None, id=None, jobTitle=None, mail=None,
                 mobilePhone=None, preferredLanguage=None, surname=None, givenName=None, businessPhones=None, officeLocation=None, **kwargs):
        super().__init__(raw_data)
        self.name = displayName
        self.username = userPrincipalName
        self.userid = id
        self.job_title = jobTitle
        self.mail = mail
        self.mobile_phone = mobilePhone
        self.preferred_language = preferredLanguage
        self.surname = surname
        self.givenname = givenName
        self.business_phones = ",".join(businessPhones) if businessPhones else ""
        self.office_location = ",".join(officeLocation) if officeLocation else ""

    def to_json(self):

        data = {
            "Name": self.name,
            "Username": self.username,
            "Id": self.userid,
            "Job_Title": self.job_title,
            "Mail": self.mail,
            "Preferred_Language": self.preferred_language,
            "Surname": self.surname,
            "Givenname": self.givenname,
            "Mobile_Phone": self.mobile_phone
        }

        data = {key: value for key, value in data.items() if value is not None}

        return data

    def to_csv(self, fields=ALL_FIELDS_IDENTIFIER):
        data = {
            "Name": self.name,
            "Username": self.username,
            "Id": self.userid,
            "Job_Title": self.job_title,
            "Mail": self.mail,
            "Preferred_Language": self.preferred_language,
            "Surname": self.surname,
            "Givenname": self.givenname,
            "Mobile_Phone": self.mobile_phone
        }
        if fields==ALL_FIELDS_IDENTIFIER:
            return data
        else:
            data = {key: value for key, value in data.items() if value is not None}
            return data
        
    def to_member_csv(self, fields=ALL_FIELDS_IDENTIFIER):
        data = {
            "Display Name": self.name,
            "User Principal Name": self.username,
            "Id": self.userid,
            "Job Title": self.job_title,
            "Mail": self.mail,
            "Preferred Language": self.preferred_language,
            "Surname": self.surname,
            "Given Name": self.givenname,
            "Mobile Phone": self.mobile_phone,
            "Business Phones":self.business_phones,
            "Office Location": self.office_location
        }
        if fields==ALL_FIELDS_IDENTIFIER:
            return data
        else:
            data = {key: value for key, value in data.items() if value is not None}
            return data       


    def as_json(self):
        return {key: val for key, val in self.raw_data.items() if val is not None}

    def to_enrichment(self):
        return add_prefix_to_dict(self.to_csv(), ENRICH_PREFIX)


class Manager(BaseModel):
    def __init__(self, raw_data=None, context=None, mobile_phone=None, name=None, **kwargs):
        super().__init__(raw_data)
        self.name = name
        self.context = context
        self.mobile_phone = mobile_phone

    def to_json(self):

        data = {key: value for key, value in self.to_csv().items() if value is not None}

        return data

    def to_csv(self):
        return {
            "@odata.context": self.context,
            "mobilePhone": self.mobile_phone,
            "displayName": self.name
        }

class Group(BaseModel):
    """
    Group datamodel represents groups's data and it's used in actions that work with group
    """
    def __init__(self, raw_data=None, name=None, description=None, id=None, created_time=None, group_type=None):
        super().__init__(raw_data)
        self.name = name
        self.description = description
        self.id = id
        self.created_time = created_time
        self.group_type = group_type

    def to_csv(self):
        """
        Function that prepares the dict containing group's data
        :return {dict} Dictionary containing group's data
        """
        return {
            "Name": self.name,
            "Description": self.description,
            "Id": self.id,
            "Created_Time": self.created_time,
            "Group_Type": ', '.join(self.group_type)
        }

    def to_json(self):
        return {key: value for key, value in self.to_csv().items() if value is not None}

    def as_json(self, detailed_information=False):
        if detailed_information:
            return self.raw_data

        return {
            "id": self.id,
            "displayName": self.name
        }

    def to_table(self, detailed_information=False):
        if detailed_information:
            return {
                "Id": self.id,
                "Display Name": self.name,
                "Description": self.description,
                "Security Enabled": self.raw_data.get("securityEnabled"),
                "Security Identifier": self.raw_data.get("securityIdentifier"),
                "Created DateTime": self.created_time,
                "Classification": self.raw_data.get("classification"),
                "Visibility": self.raw_data.get("visibility"),
                "Mail": self.raw_data.get("mail"),
                "Mail Enabled": self.raw_data.get("mailEnabled"),
                "Mail Nickname": self.raw_data.get("mailNickname")
            }

        return {
            "Id": self.id,
            "Display Name": self.name
        }


class Host(BaseModel):
    def __init__(self, raw_data=None, name=None, account_enabled=None, id=None, operating_system=None, os_version=None,
                 profile_type=None, compliant=None, last_sign_in=None):
        super().__init__(raw_data)
        self.name = name
        self.account_enabled = account_enabled
        self.id = id
        self.operating_system = operating_system
        self.os_version = os_version
        self.profile_type = profile_type
        self.compliant = compliant
        self.last_sign_in = last_sign_in

    def to_json(self):
        return {key: value for key, value in self.raw_data.items() if value is not None}

    def to_csv(self):
        return {
            "Name": self.name,
            "Enabled": self.account_enabled,
            "Property Device ID": self.id,
            "OS": self.operating_system,
            "Version": self.os_version,
            "Profile Type": self.profile_type,
            "Compliant": self.compliant,
            "Last Sign In": self.last_sign_in
        }

    def to_enrichment(self):
        return add_prefix_to_dict(self.to_csv(), ENRICH_PREFIX)
