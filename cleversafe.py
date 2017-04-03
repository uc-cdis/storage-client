"""
Connection manager for the Cleversafe storage system
Since it is compatible with S3, we will be using boto.
"""
from boto import connect_s3
import requests
import logging
from urllib import urlencode

#logging.basicConfig()
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
        base_url = "https://{host}/manager/api/json/1.0/{oper}".format(host=self._host, oper=operation)
        url = base_url + '?' + urlencode(dict(**kwargs))
        print url
        return requests.request(method, url, auth=self.__auth, data=payload, verify=False)#self-signed certificate




    def update_bucket_acl(self, bucket, read_acl):
        pass

    def has_bucket_access(self, bucket, user_id):
        """
        Find if a user is in the grants list of the acl for
        a certain bucket.
        Please keep in mind that buckets must be all lowercase
        """
        bucket = self._conn.get_bucket(bucket,validate=False)
        for acl in bucket.get_acl().acl.grants:
            if acl.id == user_id:
                return True
        return False

    def get_user(self, uid):
        """
        Gets the information from the user including
        but not limited to:
        - username
        - name
        - roles
        - permissinos
        - access_keys
        - emailxs
        """
        return self._request('GET', 'viewSystem.adm', itemType='account', id=uid)

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

    def set_quota(self, uid, quota):
        pass

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
        pass

    def create_key(self, uid):
        """
        Add a new key/secret pair
        """
        data = {'id':uid, 'action': 'add'}
        return self._request('POST', 'editAccountAccessKey.adm', payload=data)

    def create_bucket(self, access_key, secret_key, bucket_name):
        pass

    def get_bucket(self, bucket):
        """
        Retrieves the information from the bucket matching the name
        """
        return self._request('GET', 'listVaults.adm',name=bucket)
