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
        TODO integrate class InternalError in our repo
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
        TODO
        - Reactivate the exception handling on the wrapper when this is tested
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
        jsn = json.loads(response.text)
        user_list = []
        for user in jsn['responseData']['accounts']:
            new_user = User(user['name'])
            user_list.append(new_user)
        return user_list

    def has_bucket_access(self, bucket, user_id):
        """
        Find if a user is in the grants list of the acl for
        a certain bucket.
        Please keep in mind that buckets must be all lowercase
        """
        bucket = self._conn.get_bucket(bucket)
        for acl in bucket.get_acl().acl.grants:
            if acl.display_name == user_id:
                return True
        return False

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
        return self._request('GET',
                             'viewSystem.adm',
                             itemType='account',
                             id=uid)

    def list_buckets(self):
        """
        Lists all the vaults(buckets) and their information
        """
        return self._request('GET', 'listVaults.adm')

    def create_user(self, **kwargs):
        """
        Creates a user
        TODO
        Input sanitazion for parameters
        """
        return self._request('POST', 'createAccount.adm', payload=kwargs)

    def delete_user(self, uid):
        """
        Eliminate a user account
        Requires the password from the account requesting the deletion
        """
        data = {'id': uid, 'password': self.__config['password']}
        return self._request('POST', 'deleteAccount.adm', payload=data)

    def remove_key(self, uid, access_key):
        """
        Remove the give key/secret that match the key id
        """
        data = {'id':uid, 'accessKeyId': access_key, 'action': 'remove'}
        return self._request('POST', 'editAccountAccessKey.adm', payload=data)

    def remove_all_keys(self, uid):
        """
        Remove all keys from a give user
        TODO
        Make this robust against possible errors so most of the keys are deleted
        or retried
        """
        req = self.get_user(uid)
        jsn = json.loads(req.text)
        for key in jsn['responseData']['accounts'][0]['accessKeys']:
            self.remove_key(uid, key['accessKeyId'])

    def create_key(self, uid):
        """
        Add a new key/secret pair
        """
        data = {'id':uid, 'action': 'add'}
        return self._request('POST', 'editAccountAccessKey.adm', payload=data)


    def get_bucket_by_id(self, vid):
        """
        Get bucket by id
        """
        return self._request('GET', 'viewSystem.adm', itemType='vault', id=vid)

    def get_bucket(self, bucket):
        """
        Retrieves the information from the bucket matching the name
        """
        return self._conn.get_bucket(bucket)

    def get_or_create_user(self, uid):
        """
        Tries to get a user and if it doesn't exist, creates a new one
        """
        user = self.get_user(uid)
        if user.status_code == 200:
            return user
        else:
            return self.create_user()

    def get_or_create_bucket(
            self, access_key, secret_key, bucket_name):
        """
        Tries to retrieve a bucket and if it doesn't exist, creates a new one
        TODO
        - Make sure it is a bucket name issue and not a permissions issue
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
        return conn.create_bucket(bucket_name)

    def edit_bucket_template(self, default_template_id, **kwargs):
        """
        Change the desired parameters of the default template
        This will affect every new bucket creation
        The idea is to have only one template, the default one, and
        modify it accordingly
        """
        data = kwargs
        data['id'] = default_template_id
        return self._request('POST', 'editVaultTemplate.adm',
                             payload=data)

    def update_bucket_acl(self, bucket, new_grants):
        """
        Get an acl object and add the missing credentials
        to the one retrieved from the target bucket
        new_grants contains a list of users and permissions
        """
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

    def set_bucket_quota(self, bucket, quota_unit, quota):
        """
        Set qouta for the enetire bucket/vault
        """
        data={'hardQuotaSize': quota, 'hardQuotaUnit': quota_unit, 'id': bucket}
        return self._request('POST', 'editVault.adm', payload=data)
