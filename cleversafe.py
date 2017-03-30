"""
Connection manager for the Cleversafe storage system
Since it is compatible with S3, we will be using boto.
"""
from boto.s3 import connection
from boto import connect_s3
from awsauth import S3Auth
import requests

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
        self.__host = config['host']
        self.__access_key = config['access_key']
        self.__secret_key = config['secret_key']
        self.__port = config['port']
        self.__auth = S3Auth(self.__access_key, self.__secret_key,
                             self.__host+':'+self.__port)
        self.__conn = connect_s3(
            self.__access_key,
            self.__secret_key,
            host=self.__host,
            is_secure=True,
            calling_format=connection.OrdinaryCallingFormat())

    def request(self):
        """
        Compose the request and send it
        """
        base_url = "https:///bionimbus-objstore-cs.opensciencedatacloud.org/s3testsss-random-72"
        return requests.request(method, base_url, self.__auth)


    def update_bucket_acl(self, bucket, read_acl):
        pass

    def has_bucket_access(self, bucket, user_id):
        pass

    def get_user(self, uid):
        pass

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

    def get_or_create_user(self, uid):
        pass

    def get_bucket(self, bucket):
        pass

    def get_or_create_bucket(
            self, access_key, secret_key, bucket_name, **kwargs):
        pass
