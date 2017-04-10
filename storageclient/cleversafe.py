"""
Connection manager for the Cleversafe storage system
Since it is compatible with S3, we will be using boto.
"""
from boto import connect_s3
from boto.s3 import connection
from boto.s3.acl import Grant
import requests
import logging
from urllib import urlencode
import json
from base import StorageClient, User
from errors import RequestError


logging.basicConfig()
LOGGER = logging.getLogger(__name__)

def handle_request(fun):
    """
    Exception treatment for the REST API calls
    """
    def wrapper(*args, **kwargs):
        """
        We raise an internal error when
        """
        try:
            return fun(*args, **kwargs)
        except Exception as req_exception:
            LOGGER.exception("internal error")
            raise RequestError(req_exception.msg)
    return wrapper


class CleversafeManager(StorageClient):
    """
    Connection manager for Cleversafe.
    Isolates differences from other connectors
    """
    def __init__(self, config):
        """
        Creation of the manager. Since it is only s3 compatible
        we need to specify the endpoint in the config
        """
        self.__config = config
        self._host = config['host']
        self._public_host = config['public-host']
        self._access_key = config['aws_access_key_id']
        self._secret_key = config['aws_secret_access_key']
        self._port = config['port']
        self.__username = config['username']
        self.__password = config['password']
        self.__auth = requests.auth.HTTPBasicAuth(self.__username,
                                                  self.__password)
        self._conn = connect_s3(
            aws_access_key_id=self._access_key,
            aws_secret_access_key=self._secret_key,
            host=self._public_host,
            calling_format=connection.OrdinaryCallingFormat())

    def provider(self):
        """
        Returns the type of storage
        """
        return "Cleversafe"

    #@handle_request
    def _request(self, method, operation, payload=None, **kwargs):
        """
        Compose the request and send it
        """
        base_url = "https://{host}/manager/api/json/1.0/{oper}".format(
            host=self._host, oper=operation)
        url = base_url + '?' + urlencode(dict(**kwargs))
        print url
        return requests.request(method, url,
                                auth=self.__auth,
                                data=payload,
                                verify=False)#self-signed certificate

    def list_users(self):
        """
        Returns a list with all the users, in User objects
        """
        response = self._request('GET', 'listAccounts.adm')
        if response.status_code == 200:
            jsn = json.loads(response.text)
            user_list = []
            for user in jsn['responseData']['accounts']:
                new_user = self.__populate_user(user)
                user_list.append(new_user)
            return user_list
        else:
            LOGGER.error("List buckets failed with code {0}".format(response.code))
            raise RequestException(response.text, response.status_code)

    def has_bucket_access(self, bucket, user_id):
        """
        Find if a user is in the grants list of the acl for
        a certain bucket.
        Please keep in mind that buckets must be all lowercase
        """
        try:
            bucket = self._conn.get_bucket(bucket)
            for acl in bucket.get_acl().acl.grants:
                if acl.display_name == user_id:
                    return True
            return False
        except S3ResponseError as exce:
            LOGGER.error("Bucket {bucket_name} not found".format(bucket_name=bucket))
            raise RequestError(exce.message, exce.error_code)

    def __populate_user(self, data):
        """
        Populates a new user with the data provided
        in a jsonreponse
        """
        try:
            new_user = User(data['name'])
            new_user.id = data['id']
            for key in data['accessKeys']:
                new_user.keys.append(key['accessKeyId'])
            vault_roles = []
            for role in data['roles']:
                if role['role'] == 'vaultUser':
                    vault_roles = role['vaultPermissions']
            for vault_permission in vault_roles:
                vault_response = self.get_bucket_by_id(vault_permission['vault'])
                vault = json.loads(vault_response.text)
                new_user.permissions[vault['responseData']['vaults'][0]['name']] = vault_permission['permission']
            return new_user
        except KeyError as key_e:
            LOGGER.error("Failed to parse the user data. Check user fields inside the accounts section")
            raise RequestError(key_e.message, "200")

    def get_user(self, uid):
        """
        Gets the information from the user including
        but not limited to:
        - username
        - name
        - roles
        - permissions
        - access_keys
        - emailxs
        """
        response = self._request('GET',
                             'viewSystem.adm',
                             itemType='account',
                             id=uid)
        if response.status_code == 200:
            user = json.loads(response.text)
            try:
                return self.__populate_user(user['responseData']['accounts'][0])
            except:
                #Request OK but User not found
                return None
        else:
            LOGGER.error("get_user failed with code: {code}".format(code=response.status_code))
            raise RequestError(response.text, response.status_code)

    def list_buckets(self):
        """
        Lists all the vaults(buckets) and their information
        """
        response = self._request('GET', 'listVaults.adm')
        if response.status_code == 200:
            return response
        else:
            LOGGER.error("List buckets failed with code: {code}".format(code=response.status_code))
            raise RequestError(response.text, response.status_code)

    def create_user(self, **kwargs):
        """
        Creates a user
        TODO Input sanitazion for parameters
        """
        response =  self._request('POST', 'createAccount.adm', payload=kwargs)
        if response.status_code == 200:
            parsed_reply = json.loads(response.text)
            user_id = parsed_reply['responseData']['id']
            return self.get_user(user_id)
        else:
            LOGGER.error("User creation failed with code: {0}".format(response.status_code))
            raise RequestError(response.text, response.status_code)

    def delete_user(self, uid):
        """
        Eliminate a user account
        Requires the password from the account requesting the deletion
        """
        data = {'id': uid, 'password': self.__config['password']}
        response = self._request('POST', 'deleteAccount.adm', payload=data)
        if response.status_code == 200:
            return None
        else:
            LOGGER.error("Delete user failed with code: {0}".format(response.status_code))
            raise RequestError(response.text, response.status_code)

    def remove_key(self, uid, access_key):
        """
        Remove the give key/secret that match the key id
        """
        data = {'id':uid, 'accessKeyId': access_key, 'action': 'remove'}
        response = self._request('POST', 'editAccountAccessKey.adm', payload=data)
        if response.status_code == 200:
            return None
        else:
            LOGGER.error("Remove key failed with code: {0}".format(response.status_code))
            raise RequestError(response.text, response.status_code)

    def remove_all_keys(self, name):
        """
        Remove all keys from a give user
        TODO Make this robust against possible errors so most of the keys are deleted
        or retried
        """
        user = self.get_user(name)
        exception = False
        responses_list = []
        responses_codes = []
        for key in user.keys:
            response = self.remove_key(user.id, key)
            if response.status_code != 200:
                exception = True
                msg = "Remove all keys failed for one key with code: {0}"
                LOGGER.error(msg.format(response.status_code))
                responses_list.append(response.text)
                responses_codes.append(response.status_code)
        if exception:
            raise RequestError(responses_list, responses_codes)
        else:
            return None

    def create_key(self, uid):
        """
        Add a new key/secret pair
        """
        data = {'id':uid, 'action': 'add'}
        response = self._request('POST', 'editAccountAccessKey.adm', payload=data)
        if response.status_code == 200:
            return None
        else:
            msg = "Create key failed with error code: {0}"
            LOGGER.error(msg.format(response.status_code))
            raise RequestError(response.text)


    def get_bucket_by_id(self, vid):
        """
        Get bucket by id
        """
        response = self._request('GET', 'viewSystem.adm', itemType='vault', id=vid)
        if response.status_code == 200:
            return response
        else:
            msg = "Get bucket by id failed with code: {0}"
            LOGGER.error(msg.format(response.status_code))
            raise RequestError(response.text, response.status_code)

    def get_bucket(self, bucket):
        """
        Retrieves the information from the bucket matching the name
        """
        try:
            return self._conn.get_bucket(bucket)
        except S3ResponseError as exce:
            msg = "Get bucket failed on the boto call"
            LOGGER.error(msg.format(response.status_code))
            raise RequestError(exce.message, exce.error_code)

    def get_or_create_user(self, name):
        """
        Tries to get a user and if it doesn't exist, creates a new one
        """
        user = self.get_user(name)
        if user != None:
            return user
        else:
            return self.create_user()

    def get_or_create_bucket(
            self, access_key, secret_key, bucket_name):
        """
        Tries to retrieve a bucket and if it doesn't exist, creates a new one
        """
        bucket = self.get_bucket(bucket_name)
        if bucket != None:
            return bucket
        else:
            return self.create_bucket(access_key, secret_key, bucket_name)

    def create_bucket(self, access_key, secret_key, bucket_name):
        """
        Requires a default template created on cleversafe
        """
        creds = {'host':self._public_host}
        creds['aws_access_key_id'] = access_key
        creds['aws_secret_access_key'] = secret_key
        conn = connect_s3(calling_format=connection.OrdinaryCallingFormat(),
                          **creds)
        try:
            return conn.create_bucket(bucket_name)
        except S3ResponseError as exce:
            msg = "Create bucket failed with error code: {0}"
            LOGGER.error(msg.format(exce.error_code))
            raise RequestError(exce.message, exce.error_code)
            

    def edit_bucket_template(self, default_template_id, **kwargs):
        """
        Change the desired parameters of the default template
        This will affect every new bucket creation
        The idea is to have only one template, the default one, and
        modify it accordingly
        """
        data = kwargs
        data['id'] = default_template_id
        response = self._request('POST', 'editVaultTemplate.adm',
                             payload=data)
        if response.status_code == 200:
            return response
        else:
            msg = "Edit bucket template failed with code: {0}"
            LOGGER.error(msg.format(response.status_code))
            raise RequestError(response.text, response.status_code)
                         
    def update_bucket_acl(self, bucket, new_grants):
        """
        Get an acl object and add the missing credentials
        to the one retrieved from the target bucket
        new_grants contains a list of users and permissions
        """

        try:
            bucket = self._conn.get_bucket(bucket)
            policy = bucket.get_acl()
            prev_policy = policy.to_xml()
            grants = []
            for grant in policy.acl.grants:
                if grant.permission != "READ":
                    grants.append(grant)
            for userid in new_grants:
                grant = Grant(
                    id=userid, display_name=userid,
                    permission='READ', type='CanonicalUser')
                grants.append(grant)
            policy.acl.grants = grants
            new_policy = policy.to_xml()
            if prev_policy != new_policy:
                bucket.set_xml_acl(new_policy)
                for key in bucket.get_all_keys():
                    if key.get_acl().to_xml() != new_policy:
                        key.set_xml_acl(new_policy)
        except S3ResponseError as exce:
            msg = "Update bucket ACL failed {0}"
            LOGGER.error(msg.format(exce.error_code))
            raise RequestError(exce.message, exce.error_code)

    def set_bucket_quota(self, bucket, quota_unit, quota):
        """
        Set qouta for the enetire bucket/vault
        """
        data = {'hardQuotaSize': quota, 'hardQuotaUnit': quota_unit, 'id': bucket}
        response = self._request('POST', 'editVault.adm', payload=data)
        if response.status_code == 200:
            return response
        else:
            msg = "Set bucket quota failed with code: {0}"
            LOGGER.error(msg.format(response.status_code))
            raise RequestError(response.text, response.status_code)
