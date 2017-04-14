"""
Connection manager for the Cleversafe storage system
Since it is compatible with S3, we will be using boto.
"""
from boto import connect_s3
from boto.s3 import connection
from boto.exception import S3ResponseError
from boto.s3.acl import Grant
import requests
from urllib import urlencode
import json
from base import StorageClient, User, Bucket
from errors import RequestError, NotFoundError


class CleversafeClient(StorageClient):
    """
    Connection manager for Cleversafe.
    Isolates differences from other connectors
    """

    def __init__(self, config):
        """
        Creation of the manager. Since it is only s3 compatible
        we need to specify the endpoint in the config
        """
        super(CleversafeClient, self).__init__(__name__)
        self.__config = config
        self._host = config['host']
        self._public_host = config['public_host']
        self._access_key = config['aws_access_key_id']
        self._secret_key = config['aws_secret_access_key']
        self._port = config['port']
        self.__username = config['username']
        self.__password = config['password']
        self.__permissions = {
            'read-storage': 'readOnly',
            'write-storage': 'readWrite',
            'create-storage': 'owner',
            'delete-storage': 'owner',
            'disable': 'disable'
        }
        self.__auth = requests.auth.HTTPBasicAuth(self.__username,
                                                  self.__password)
        self._conn = connect_s3(
            aws_access_key_id=self._access_key,
            aws_secret_access_key=self._secret_key,
            host=self._public_host,
            calling_format=connection.OrdinaryCallingFormat())
        self.__bucket_name_id_table = {}
        self.__update__bucket_name_id_table()
        self.__user_name_id_table = {}
        self.__user_id_name_table = {}
        self.__update__user_name_id_table()

    def __update__user_name_id_table(self):
        """
        Update the name-id translation table for users
        """
        response = self.__request('GET', 'listAccounts.adm')
        if response.status_code == 200:
            jsn = json.loads(response.text)
            self.__user_name_id_table = {}
            for user in jsn['responseData']['accounts']:
                self.__user_name_id_table[user['name']] = user['id']
                self.__user_id_name_table[user['id']] = user['name']
            self.logger.debug(self.__user_name_id_table)
            self.logger.debug(self.__user_id_name_table)
        else:
            msg = "List users failed on update cache with code {0}"
            self.logger.error(msg.format(response.status_code))
            raise RequestError(response.text, response.status_code)

    def __update__bucket_name_id_table(self):
        """
        Update the name-id translation table for buckets
        """
        response = self.__request('GET', 'listVaults.adm')
        if response.status_code == 200:
            jsn = json.loads(response.text)
            self.__bucket_name_id_table = {}
            for user in jsn['responseData']['vaults']:
                self.__bucket_name_id_table[user['name']] = user['id']
            self.logger.debug(self.__bucket_name_id_table)
        else:
            msg = "List vaults failed on update cache with code {0}"
            self.logger.error(msg.format(response.status_code))
            raise RequestError(response.text, response.status_code)

    def __get_bucket_id(self, name):
        """
        Tries to return the id from the table
        If the cache misses, it updates it and
        tries again
        TODO OPTIMIZATION get the user information
        from the update itself
        """
        try:
            return self.__bucket_name_id_table[name]
        except KeyError:
            self.__update__bucket_name_id_table()
            return self.__bucket_name_id_table[name]

    def __get_user_id(self, name):
        """
        Tries to return the id from the table
        If the cache misses, it updates it and
        tries again
        """
        try:
            return self.__user_name_id_table[name]
        except KeyError:
            self.__update__user_name_id_table()
            return self.__user_name_id_table[name]

    def __get_user_by_id(self, uid):
        """
        Fetches the user by id from the REST API
        """
        response = self.__request('GET',
                                  'viewSystem.adm',
                                  itemType='account',
                                  id=uid)
        if response.status_code == 200:
            user = json.loads(response.text)
            try:
                return self.__populate_user(user['responseData']['accounts'][0])
            except:
                # Request OK but User not found
                return None
        else:
            self.logger.error("get_user failed with code: {code}".format(code=response.status_code))
            raise RequestError(response.text, response.status_code)

    def __populate_user(self, data):
        """
        Populates a new user with the data provided
        in a jsonreponse
        """
        try:
            new_user = User(data['name'])
            new_user.id = data['id']
            for key in data['accessKeys']:
                new_key = {'accessKeyId': key['accessKeyId'],
                           'secretAccessKey': key['secretAccessKey']}
                new_user.keys.append(new_key)
            vault_roles = []
            for role in data['roles']:
                if role['role'] == 'vaultUser':
                    vault_roles = role['vaultPermissions']
            for vault_permission in vault_roles:
                vault_response = self.__get_bucket_by_id(vault_permission['vault'])
                vault = json.loads(vault_response.text)
                new_user.permissions[vault['responseData']['vaults'][0]['name']] = vault_permission['permission']
            return new_user
        except KeyError as key_e:
            msg = "Failed to parse the user data. Check user fields inside the accounts section"
            self.logger.error(msg)
            raise RequestError(key_e.message, "200")

    def __get_bucket_by_id(self, vid):
        """
        Get bucket by id
        """
        response = self.__request('GET', 'viewSystem.adm', itemType='vault', id=vid)
        if response.status_code == 200:
            return response
        else:
            msg = "Get bucket by id failed with code: {0}"
            self.logger.error(msg.format(response.status_code))
            raise RequestError(response.text, response.status_code)

    # @handle_request
    def __request(self, method, operation, payload=None, **kwargs):
        """
        Compose the request and send it
        """
        base_url = "https://{host}/manager/api/json/1.0/{oper}".format(
            host=self._host, oper=operation)
        url = base_url + '?' + urlencode(dict(**kwargs))
        return requests.request(method, url,
                                auth=self.__auth,
                                data=payload,
                                verify=False)  # self-signed certificate

    def provider(self):
        """
        Returns the type of storage
        """
        return "Cleversafe"

    def list_users(self):
        """
        Returns a list with all the users, in User objects
        """
        response = self.__request('GET', 'listAccounts.adm')
        if response.status_code == 200:
            jsn = json.loads(response.text)
            user_list = []
            for user in jsn['responseData']['accounts']:
                new_user = self.__populate_user(user)
                user_list.append(new_user)
            return user_list
        else:
            msg = "List buckets failed with code {0}"
            self.logger.error(msg.format(response.status_code))
            raise RequestError(response.text, response.status_code)

    def has_bucket_access(self, bucket, username):
        """
        Find if a user is in the grants list of the acl for
        a certain bucket.
        Please keep in mind that buckets must be all lowercase
        """
        #try:
        vault_id = self.__get_bucket_id(bucket)
        vault = json.loads(self.__get_bucket_by_id(vault_id).text)
        user_id = self.__get_user_id(username)
        for permission in vault['responseData']['vaults'][0]['accessPermissions']:
            if permission['principal']['id'] == user_id:
                return True
        return False

    def get_user(self, name):
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
        try:
            uid = self.__get_user_id(name)
        except KeyError:
            return None
        return self.__get_user_by_id(uid)

    def list_buckets(self):
        """
        Lists all the vaults(buckets) and their information
        """
        response = self.__request('GET', 'listVaults.adm')
        if response.status_code == 200:
            return response
        else:
            self.logger.error("List buckets failed with code: {code}".format(code=response.status_code))
            raise RequestError(response.text, response.status_code)

    def create_user(self, name):
        """
        Creates a user
        TODO Input sanitazion for parameters
        """
        data = {'name': name, 'usingPassword': 'false', 'rolesMap[operator]': 'true'}
        response = self.__request('POST', 'createAccount.adm', payload=data)
        if response.status_code == 200:
            parsed_reply = json.loads(response.text)
            user_id = parsed_reply['responseData']['id']
            self.__update__user_name_id_table()
            return self.__get_user_by_id(user_id)
        else:
            self.logger.error("User creation failed with code: {0}".format(response.status_code))
            raise RequestError(response.text, response.status_code)

    def delete_user(self, name):
        """
        Eliminate a user account
        Requires the password from the account requesting the deletion
        """
        uid = self.__get_user_id(name)
        data = {'id': uid, 'password': self.__config['password']}
        response = self.__request('POST', 'deleteAccount.adm', payload=data)
        if response.status_code == 200:
            self.__update__user_name_id_table()
            return None
        else:
            self.logger.error("Delete user failed with code: {0}".format(response.status_code))
            raise RequestError(response.text, response.status_code)

    def delete_keypair(self, name, access_key):
        """
        Remove the give key/secret that match the key id
        """
        uid = self.__get_user_id(name)
        data = {'id': uid, 'accessKeyId': access_key, 'action': 'remove'}
        response = self.__request('POST', 'editAccountAccessKey.adm', payload=data)
        if response.status_code == 200:
            return None
        else:
            self.logger.error("Delete keypair failed with code: {0}".format(response.status_code))
            raise RequestError(response.text, response.status_code)

    def delete_all_keypairs(self, name):
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
            try:
                self.delete_keypair(user.username, key['accessKeyId'])
            except RequestError as exce:
                exception = True
                msg = "Remove all keys failed for one key"
                self.logger.error(msg.format(exce.code))
                responses_list.append(exce.message)
                responses_codes.append(exce.code)
        if exception:
            raise RequestError(responses_list, responses_codes)
        else:
            return None

    def create_keypair(self, name):
        """
        Add a new key/secret pair
        """
        uid = self.__get_user_id(name)
        data = {'id': uid, 'action': 'add'}
        response = self.__request('POST', 'editAccountAccessKey.adm', payload=data)
        if response.status_code == 200:
            return None
        else:
            msg = "Create keypair failed with error code: {0}"
            self.logger.error(msg.format(response.status_code))
            raise RequestError(response.text, response.status_code)

    def get_bucket(self, bucket):
        """
        Retrieves the information from the bucket matching the name
        """
        try:
            bucket_id = self.__get_bucket_id(bucket)
            """at this point we have all we need for the initial
            Bucket object, but for coherence, we keep this last call.
            Feel free to get more information from response.text"""
            response = self.__get_bucket_by_id(bucket_id)
            return Bucket(bucket, bucket_id)
        except KeyError as exce:
            self.logger.error("Get bucket not found on cache")
            raise RequestError(exce.message, "NA")
        except RequestError as exce:
            self.logger.error("Get bucket failed retrieving bucket info")
            raise exce

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
        creds = {'host': self._public_host}
        creds['aws_access_key_id'] = access_key
        creds['aws_secret_access_key'] = secret_key
        conn = connect_s3(calling_format=connection.OrdinaryCallingFormat(),
                          **creds)
        try:
            bucket = conn.create_bucket(bucket_name)
            self.__update__bucket_name_id_table()
            return bucket
        except S3ResponseError as exce:
            msg = "Create bucket failed with error code: {0}"
            self.logger.error(msg.format(exce.error_code))
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
        response = self.__request('POST', 'editVaultTemplate.adm',
                                  payload=data)
        if response.status_code == 200:
            return response
        else:
            msg = "Edit bucket template failed with code: {0}"
            self.logger.error(msg.format(response.status_code))
            raise RequestError(response.text, response.status_code)

    def update_bucket_acl(self, bucket, new_grants):
        """
        Get an acl object and add the missing credentials
        to the one retrieved from the target bucket
        new_grants contains a list of users and permissions
        """
        user_id_list = []
        for user in new_grants:
            user_id_list.append(self.__get_user_id(user[0]))
        bucket_id = self.__get_bucket_id(bucket)
        response = self.__get_bucket_by_id(bucket_id)
        vault = json.loads(response.text)['responseData']['vaults'][0]
        disable = []
        for permission in vault['accessPermissions']:
            uid = permission['principal']['id']
            permit_type = permission['permission']
            if uid not in user_id_list or\
               permit_type == "owner":
                disable.append((self.__user_id_name_table[uid],["disable"]))
        for user in disable:
            self.add_bucket_acl(bucket, user[0], user[1])
        for user in new_grants:
            self.add_bucket_acl(bucket, user[0], user[1])

    def set_bucket_quota(self, bucket, quota_unit, quota):
        """
        Set qouta for the entire bucket/vault
        """
        bid = self.__get_bucket_id(bucket)
        data = {'hardQuotaSize': quota, 'hardQuotaUnit': quota_unit, 'id': bid}
        response = self.__request('POST', 'editVault.adm', payload=data)
        if response.status_code == 200:
            return response
        else:
            msg = "Set bucket quota failed with code: {0}"
            self.logger.error(msg.format(response.status_code))
            raise RequestError(response.text, response.status_code)

    def add_bucket_acl(self, bucket, username, access=[]):
        """
        Add permissions to a user on the bucket ACL
        """
        try:
            bucket_param = 'vaultUserPermissions[{0}]'.format(
                self.__get_bucket_id(bucket))
        except KeyError:
            msg = "Bucket {0} wasn't found on the database"
            self.logger.error(msg.format(bucket))
            raise NotFoundError(msg.format(bucket))
        try:
            data = {'id': self.__get_user_id(username), bucket_param: self.__permissions[access[0]]}
        except KeyError:
            msg = "User {0} wasn't found on the database"
            self.logger.error(msg.format(username))
            raise NotFoundError(msg.format(username))
        data['rolesMap[vaultProvisioner]'] = 'true'
        response = self.__request('POST', 'editAccount.adm', payload=data)
        if response.status_code != 200:
            msg = "Error trying to change buket permissions for user {0}"
            self.logger.error(msg.format(username))
            raise RequestError(msg.format(username), response.status_code)
