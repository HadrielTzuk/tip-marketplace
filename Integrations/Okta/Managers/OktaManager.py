# =====================================
#              IMPORTS                #
# =====================================
import re
import requests
import json
import urllib3

# =====================================
#             CONSTANTS               #
# =====================================

HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}
VERSION = 'v1'
CURRENT_USER = "/users/me" # X
LIST_USERS = "/users" # VA
LIST_USER_GROUPS = "/users/{userId}/groups" # VVA
ADD_GROUP = "/groups" # VA
RESET_PASSWORD = "/users/{userId}/lifecycle/reset_password" #VVA
SET_PASSWORD = "/users/{userId}" # VVA
SUSPEND_USER = "/users/{userId}/lifecycle/suspend" # VVA
UNSUSPEND_USER = "/users/{userId}/lifecycle/unsuspend" # VVA
DEACTIVATE_USER = "/users/{userId}/lifecycle/deactivate"
REACTIVATE_USER = "/users/{userId}/lifecycle/activate"
GET_USER = "/users/{userId}" # VA
GET_GROUP = "/groups/{groupId}" # VA
LIST_PROVIDERS = "/idps" # VA
LIST_ROLES = "/users/{userId}/roles" # VVA
ASSIGN_ROLE = "/users/{userId}/roles" # VVA
UNASSIGN_ROLE = "/users/{userId}/roles/{roleId}" # VVA

# =====================================
#              CLASSES                #
# =====================================

class OktaException(Exception):
    """
    General Exception for Okta manager
    """
    pass


class OktaManager(object):
    """
    Responsible for all Okta operations functionality
    """

    def __init__(self, api_root, api_token, version=VERSION, verify_ssl=False):
        if not api_root.endswith("/"):
            api_root += '/'
        self.api_root = api_root + 'api/' + version
        self.api_token = api_token
        self.session = requests.Session()
        self.session.verify = verify_ssl
        HEADERS.update({'Authorization': 'SSWS ' + api_token})
        self.session.headers = HEADERS

    def test_connectivity(self):
        """
        Test connection
        :return: {boolean}
        """
        r = self.session.get(self.api_root + CURRENT_USER)
        try:
            r.raise_for_status()
        except Exception as error:
            raise OktaException("Error: {0} {1}".format(error, r.text))
        return True

    def list_users(self, q="", _filter="", search="", limit="", after=""):
        """
        Get the list of users
        :param: q: Finds a user that matches by firstName or lastName or email properties - e.g. q=eric {String}
        :param: _filter: Filters users with a supported expression for a subset of properties - e.g. status eq "ACTIVE" {String}
        (https://developer.okta.com/docs/api/getting_started/design_principles#filtering)
        :param: search: Searches for users with a supported filtering expression for most properties (Early Access) {String}
        :param: limit: Specifies the number of results returned (maximum 200) {Number}
        If you don't specify a value for limit, all results are returned.
        :param: after: token for pagination. May be used, if known, to bring results starting from a different page.
        An HTTP 500 status code usually indicates that you have exceeded the request timeout. Retry your request with a smaller limit and paginate the results. For more information, see Pagination.
        Treat the after cursor as an opaque value and obtain it through the next link relation. See Pagination.
        :return: JSON data
        """
        params = {}
        if q:
            params['q'] = q
        if _filter:
            params['filter'] = _filter
        if search:
            params['search'] = search
        if limit:
            try:
                limit = int(limit)
            except:
                raise OktaException("Error: Limit must be a number")
            params['limit'] = limit
        if after:
            params['after'] = after
        url = self.api_root + LIST_USERS
        lu_request = self.session.get(url, params=params)
        '''try:
            lu_request.raise_for_status()
        except Exception as error:
            raise OktaException("Error: {0}".format(self.get_error(lu_request)))

        return lu_request.json()'''
        try:
            lu_request.raise_for_status()
        except Exception as err:
            raise OktaException("Error: {0}".format(self.get_error(lu_request)))
        try:
            res = lu_request.json()
            stop = False
            while not stop:
                if limit or limit == 0:
                    if limit < len(res):
                        res = res[:limit]
                    limit = limit - len(res)
                    if limit <= 0:
                        stop = True
                        break
                if not lu_request.headers.get('link'):
                    stop = True
                    break
                l, lu_request, url = self.pagination(lu_request, url, params)
                try:
                    lu_request.raise_for_status()
                except Exception as e:
                    raise OktaException("Error: {0}".format(self.get_error(lu_request)))
                if l:
                    res.extend(l)
                else:
                    stop = True
        except Exception as error:
                    raise OktaException("Error: {0}".format(error.message))
        return res  # lp_request.json()

    def list_user_groups(self, user_id):
        """
        Get the groups that the user is a member of
        :param: user_id: Id of user or login {String}
        :return: JSON data
        """
        params = {}
        params['id'] = user_id
        url = self.api_root + LIST_USER_GROUPS.format(userId=user_id)
        lug_request = self.session.get(url, params=params)
        try:
            lug_request.raise_for_status()
        except Exception as error:
            raise OktaException("Error: {0}".format(self.get_error(lug_request)))

        return lug_request.json()

    def add_group(self, profile):
        """
        Add a group
        :param: profile: okta:user_group profile for a new group. Containing a name and a description.
        :return: JSON data
        """
        _json = {}
        _json['profile'] = {}
        _json['profile']['name'] = profile['name']
        _json['profile']['description'] = profile['description']
        url = self.api_root + ADD_GROUP
        ag_request = self.session.post(url, json=_json)
        try:
            ag_request.raise_for_status()
        except Exception as error:
            if ag_request.status_code == 400:
                return None
            raise OktaException("Error: {0}".format(self.get_error(ag_request)))

        return ag_request.json()

    def reset_password(self, user_id, send_email_with_reset_link=False):
        """
        Generate a one-time token that can be used to reset a user's password
        User's account will be awaiting the password reset
        :param: user_id: Id of user or login {String}
        :param: send_email_with_reset_link: Sends reset password email to the user if true {Boolean}
        :return: JSON data (a link for the user to reset their password, or empty)
        """
        params = {}
        params['id'] = user_id
        params['sendEmail'] = send_email_with_reset_link
        url = self.api_root + RESET_PASSWORD.format(userId=user_id)
        rp_request = self.session.post(url, params=params)
        try:
            rp_request.raise_for_status()
        except Exception as error:
            raise OktaException("Error: {0}".format(self.get_error(rp_request)))

        return rp_request.json() or True

    def set_password(self, user_id, new_password):
        """
        Set the password of a user without validating existing credentials
        :param: user_id: Id of user or login {String}
        :param: new_password: The new password {String}
        :return: JSON data
        """
        _json = {}
        _json['credentials'] = {}
        _json['credentials']['password'] = {}
        _json['credentials']['password']['value'] = new_password
        url = self.api_root + SET_PASSWORD.format(userId=user_id)
        sp_request = self.session.post(url, json=_json)
        try:
            sp_request.raise_for_status()
        except Exception as error:
            raise OktaException("Error: {0}".format(self.get_error(sp_request)))

        return sp_request.json()

    # Suspend or Deactivate
    def disable_user(self, user_id, is_deactivate, send_email_deactivate):
        """
        Disables the specified user
        :param: user_id: Id of user or login {String}
        :param: is_deactivate: Deactivate if TRUE, else Suspend {Boolean}
        :param: send_email_deactivate: Sends remail to the administrator if true {Boolean}
        :return: Bool (Empty object from okta)
        """
        params = {}
        params['userId'] = user_id
        if is_deactivate:
            params['sendEmail'] = send_email_deactivate
            url = self.api_root + DEACTIVATE_USER.format(userId=user_id)
            du_request = self.session.post(url)
        else:
            url = self.api_root + SUSPEND_USER.format(userId=user_id)
            du_request = self.session.post(url, params=params)
        try:
            du_request.raise_for_status()
        except Exception as error:
            raise OktaException("Error: {0}".format(self.get_error(du_request)))

        return True

    # Unsuspend or Activate
    def enable_user(self, user_id, is_reactivate, send_email_reactivate):
        """
        Enables the specified user
        :param: user_id: Id of user or login {String}
        :param: is_reactivate: Activate if TRUE, else Unuspend {Boolean}
        :param: send_email_reactivate: Sends email to the administrator if true {Boolean}
        :return: JSON data
        """
        params = {}
        params['id'] = user_id
        if is_reactivate:
            params['sendEmail'] = send_email_reactivate
            url = self.api_root + REACTIVATE_USER.format(userId=user_id)
            eu_request = self.session.post(url)
        else:
            url = self.api_root + UNSUSPEND_USER.format(userId=user_id)
            eu_request = self.session.post(url, params=params)
        try:
            eu_request.raise_for_status()
        except Exception as error:
            raise OktaException("Error: {0}".format(self.get_error(eu_request)))

        return True

    def get_user(self, user_id):
        """
        Get information about a user
        :param: user_id: Id of user or login {String}
        :return: Analysis ID to later be queried
        """
        url = self.api_root + GET_USER.format(userId=user_id)
        gu_request = self.session.get(url)
        try:
            gu_request.raise_for_status()
        except Exception as error:
            if gu_request.status_code == 404:
                return None
            raise OktaException("Error: {0}".format(self.get_error(gu_request)))

        return gu_request.json()

    def get_group(self, group_id):
        """
        Get information about a group
        :param: group_id: Id of group {String}
        :return: JSON data
        """
        params = {}
        params['id'] = group_id
        url = self.api_root + GET_GROUP.format(groupId=group_id)
        gg_request = self.session.get(url)
        try:
            gg_request.raise_for_status()
        except Exception as error:
            if gg_request.status_code == 404:
                return None
            raise OktaException("Error: {0}".format(self.get_error(gg_request)))

        return gg_request.json()

    def list_providers(self, q="", _type="", limit="", after=""):
        """
        List identity providers (IdPs) in your organization
        :param: q: Searches the name property of IdPs for matching value (startswith) {String}
        :param: _type: Filters IdPs by type {String}
        :param: limit: Specifies the number of IdP results in a page (Default 20) {Number}
        :param: after: token for pagination. May be used, if known, to bring results starting from a different page.
        Search currently performs a startsWith match.
        SAML2       Enterprise IdP provider that supports the SAML 2.0 Web Browser SSO Profile
        FACEBOOK    Facebook Login
        GOOGLE      Google Sign-In with OpenID Connect
        LINKEDIN    Sign In with LinkedIn
        MICROSOFT   Microsoft Enterprise SSO
        :return: JSON data
        """
        params = {}
        if q:
            params['q'] = q
        if _type:
            params['type'] = _type
        if limit:
            try:
                limit = int(limit)
            except:
                raise OktaException("Error: Limit must be a number")
            params['limit'] = limit
        if after:
            params['after'] = after
        url = self.api_root + LIST_PROVIDERS
        lp_request = self.session.get(url, params=params)
        res = []
        try:
            lp_request.raise_for_status()
        except Exception as err:
            raise OktaException("Error: {0}".format(self.get_error(lp_request)))
        try:
            res = lp_request.json()
            stop = False
            while not stop:
                if limit or limit == 0:
                    if limit < len(res):
                        res = res[:limit]
                    limit = limit - len(res)
                    if limit <= 0:
                        stop = True
                        break
                if not lp_request.headers.get('link'):
                    stop = True
                    break
                l, lp_request, url = self.pagination(lp_request, url, params)
                try:
                    lp_request.raise_for_status()
                except Exception as e:
                    raise OktaException("Error: {0}".format(self.get_error(lp_request)))
                if l:
                    res.extend(l)
                else:
                    stop = True
        except Exception as error:
            raise OktaException("Error: {0}".format(error.message))
        return res#lp_request.json()

    def pagination(self, result, url, params):
        response_list = []
        stop_pagination = False
        #while not stop_pagination:
        #    after_count = 0
        r = {}
        if 'rel=\"next\"' in result.headers.get('link'):
            params['after'] = result.headers.get('link')
            for link in result.headers.get('link').split(','):
                link = link.strip()
                if not 'rel=\"next\"' in link:
                 continue
                # print link
                params['after'] = re.findall(r"(?<=after=)(.*)(?=&)|(?<=after=)(.*)(?=>)", link)#re.match(r"(?<=<)(.*)(?=>; rel=\"next\")", link)
                if not params['after']:
                    continue  #return None, None
                # print params['after']
            r = self.session.get(url, params=params)#.json()
            response_list.extend(r.json())
        else:
            r = result
        return response_list, r, url

    def list_roles(self, user_id):
        """
        Lists all roles assigned to a user
        :param: user_id: Id of user {String}
        :return: JSON data
        """
        params = {}
        params['userId'] = user_id
        url = self.api_root + LIST_ROLES.format(userId=user_id)
        lr_request = self.session.get(url)
        try:
            lr_request.raise_for_status()
        except Exception as error:
            raise OktaException("Error: {0}".format(self.get_error(lr_request)))

        return lr_request.json()

    def assign_role(self, user_id, _type):
        """
        Lists all roles assigned to a user
        :param: user_id: Id of user {String}
        :param: __type: type of role to assign {String}
        SUPER_ADMIN                             Super Administrator
        ORG_ADMIN                               Organizational Administrator
        API_ACCESS_MANAGEMENT_ADMIN	API          Access Management Administrator
        APP_ADMIN                               Application Administrator           (Apps)
        USER_ADMIN                              Group Administrator                 (Groups)
        MOBILE_ADMIN                            Mobile Administrator
        READ_ONLY_ADMIN	                         Read-only Administrator
        :return: JSON data
        """
        params = {}
        params['userId'] = user_id
        params['type'] = _type
        url = self.api_root + ASSIGN_ROLE.format(userId=user_id)
        ar_request = self.session.post(url, json={'type': _type})
        try:
            ar_request.raise_for_status()
        except Exception as error:
            if ar_request.status_code == 409:
                return None
            raise OktaException("Error: {0}".format(self.get_error(ar_request)))

        return ar_request.json()

    def unassign_role(self, user_id, role_id):
        """
        Unassign a role from a user
        :param: user_id: Id of user {String}
        :param: role_id: Id of role to unassign {String}
        :return: JSON data
        """
        params = {}
        params['userId'] = user_id
        params['roleId'] = role_id
        url = self.api_root + UNASSIGN_ROLE.format(userId=user_id, roleId=role_id)
        ur_request = self.session.delete(url)
        try:
            ur_request.raise_for_status()
        except Exception as error:
            if ur_request.status_code == 404:
                return None
            raise OktaException("Error: {0}".format(self.get_error(ur_request)))

        return True

    def list_groups(self, q="", _filter="", search="", limit="", after=""):
        """
        Get the list of groups - not an action
        :param: q: Searches the name property of groups for matching value {String}
        :param: _filter: Filter expression for groups {String}
        :param: search: Searches for users with a supported filtering expression for most properties (Early Access) {String}
        :param: limit: Specifies the number of group results in a page (Default 10000) {Number}
        :param: after: token for pagination. May be used, if known, to bring results starting from a different page.
        :return: JSON data
        """
        params = {}
        if q:
            params['q'] = q
        if _filter:
            params['filter'] = _filter
        if search:
            params['search'] = search
        if limit:
            try:
                limit = int(limit)
            except:
                raise OktaException("Error: Limit must be a number")
            params['limit'] = limit
        if after:
            params['after'] = after
        url = self.api_root + ADD_GROUP
        lg_request = self.session.get(url, params=params)
        '''try:
            lg_request.raise_for_status()
        except Exception as error:
            raise OktaException("Error: {0}".format(self.get_error(lg_request)))'''
        res = []
        try:
            lg_request.raise_for_status()
        except Exception as err:
            raise OktaException("Error: {0}".format(self.get_error(lg_request)))
        try:
            res = lg_request.json()
            stop = False
            while not stop:
                if limit or limit == 0:
                    if limit < len(res):
                        res = res[:limit]
                    limit = limit - len(res)
                    if limit <= 0:
                        stop = True
                        break
                if not lg_request.headers.get('link'):
                    stop = True
                    break
                l, lg_request, url = self.pagination(lg_request, url, params)
                try:
                    lg_request.raise_for_status()
                except Exception as e:
                    raise OktaException("Error: {0}".format(self.get_error(lg_request)))
                if l:
                    res.extend(l)
                else:
                    stop = True
        except Exception as error:
            raise OktaException("Error: {0}".format(error.message))
        #return lg_request.json() #res
        return res  # lp_request.json()

    def login_to_id(self, login):
        """
        Transform user login into id - not an action
        :return: String
        """
        user = self.get_user(login)
        if user:
            return user['id']
        else:
            return None

    def find_role_id_by_name(self, user_id, role_name):
        """
        Find role name -> id for a user - not an action
        :return: String
        """
        roles = self.list_roles(user_id)
        if roles:
            for role in roles:
                if role['type'] == role_name:
                    return role['id']
                else:
                    continue
        else:
            return None

    def get_error(self, response):
        """
        Handle errors' messages - not an action
        :return: String
        """
        m = ""
        try:
            j = json.loads(response.text)
            if "errorCauses" in j:
                if j['errorCauses']:
                    for i in j['errorCauses']:
                        if "errorSummary" in i:
                            m += i['errorSummary'] + "\n"
                else:
                    if "errorSummary" in j:
                        m = j['errorSummary']
            else:
                if "errorSummary" in j:
                    m = j['errorSummary']
        except:
            m = response.text
            pass
        if not m:
            m = response.text
        return m

def main():
    pass

if __name__ == "__main__":
    main()