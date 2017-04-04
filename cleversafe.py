"""
Connection manager for the Cleversafe storage system
Since it is compatible with S3, we will be using boto.
"""
from boto import connect_s3
import requests
import logging
from urllib import urlencode
import json

logging.basicConfig()
logger = logging.getLogger(__name__)

def handle_request(f):
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.exception("internal error")
            #raise InternalError(e)
    return wrapper


class CleversafeManager(object):
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
        self._access_key = config['aws_access_key_id']
        self._secret_key = config['aws_secret_access_key']
        self._port = config['port']
        self.__username = config['username']
        self.__password = config['password']
        self.__auth = requests.auth.HTTPBasicAuth(self.__username, self.__password)
        self._conn = connect_s3(self._access_key, self._secret_key)

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


    def has_bucket_access(self, bucket, user_id):
        """
        Find if a user is in the grants list of the acl for
        a certain bucket.
        Please keep in mind that buckets must be all lowercase
        TODO
        Make sure whther we are using the id or the canonical id to
        identify the user
        Also get to know whether the permission type has to be checked too
        """
        r = self.get_bucket(bucket)
        jsn = json.loads(r.text)
        for accs in jsn['responseData']['vaults'][0]['accessPermissions']:
            if accs['principal']['id'] == user_id:
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
        return self._request('POST','deleteAccount.adm', payload=data) 

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
        req = cm.get_user(uid)
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
        Sadly there seems to be no way of getting a bucket the name,
        so in order to do it we get all of them and them we use
        get_bucket_by_id to retrieve the specific bucket
        """
        r = self.list_buckets()
        jsn = json.loads(r.text)
        for i in jsn['responseData']['vaults']:
            if i['name'] == bucket:
                return self.get_bucket_by_id(i['id'])

    def get_or_create_user(self, uid):
        """
        Tries to get a user and if it doesn't exist, creates a new one
        """
        r = self.get_user(uid)
        if r.status_code == 200:
            return r
        else:
            return self.create_user()

    def get_or_create_bucket(
            self, access_key, secret_key, bucket_name, **kwargs):
        """
        Tries to retrieve a bucket and if it doesn't exist, creates a new one
        TODO
        - Implement create bucket
        - Make sure it is a bucket name issue and not a permissions issue
        """
        r = self.get_bucket(bucket_name)
        if r.status_code == 200:
            return r
        else:
            return self.create_bucket(access_key, secret_key, bucket_name)
    
    def create_bucket(self, access_key, secret_key, bucket_name):
        """
        Requires the following parameters
        name - segmentSize - segmentSizeUnit - vaultWidth - threshold 
        - storagePoolId - privacyEnabled
        """
        pass

    def set_quota(self, uid, quota):
        pass

    def update_bucket_acl(self, bucket, read_acl):
        pass
