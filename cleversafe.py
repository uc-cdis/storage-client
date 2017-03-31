"""
Connection manager for the Cleversafe storage system
Since it is compatible with S3, we will be using boto.
"""
#from boto.s3 import connection
from boto import connect_s3
from awsauth import S3Auth
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
        self.__auth = S3Auth(self._access_key, self._secret_key,
                             self._host+':'+self._port)
        self._conn = connect_s3(**self.__config)

    #@handle_request
    def _request(self, method, operation, **kwargs):
        """
        Compose the request and send it
        """
        base_url = "https://{host}:{port}/manager/api/json/1.0/{oper}".format(host=self._host, port=self._port,oper=operation)
        url = base_url + '?' + urlencode(dict(**kwargs))
        print url
        return requests.request(method, url, auth=self.__auth, verify=False)


    def update_bucket_acl(self, bucket, read_acl):
        pass

    def has_bucket_access(self, bucket, user_id):
        pass

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
        return self._request('GET', 'viewSystem.adm',itemType='account',id=uid)

    def list_buckets(self):
        pass

    def create_user(self, uid, **kwargs):
        pass

    def set_quota(self, uid, quota):
        pass

    def delete_user(self, uid):
        pass

    def remove_key(self, uid, access_key):
        pass

    def remove_all_keys(self, uid):
        pass

    def create_key(self, uid, **kwargs):
        pass

    def create_bucket(self, access_key, secret_key, bucket_name):
        pass

    def get_bucket(self, bucket):
        pass

