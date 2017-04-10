"""
This is the ceph manager. It inherits from a
base abstract class also used for other connectors.
It retrieves a mixture objects and json response.
"""
from boto import connect_s3, connect_sts
from urllib import urlencode
from userapi.errors import InternalError
from boto.s3.acl import Grant
from boto.exception import S3ResponseError
import json
from awsauth import S3Auth
import logging
from dateutil import parser
import requests
from flask import current_app as capp
from errors import RequestError

LOGGER = logging.getLogger(__name__)


def handle_request(f):
    """
    Wrapper for the REST API requests
    """
    def wrapper(*args, **kwargs):
        """
        Wraps the request call and transforms exceptiosn
        into a custom exception object
        """
        try:
            return f(*args, **kwargs)
        except Exception as e:
            LOGGER.exception("internal error")
            raise RequestError(e)
    return wrapper


class CephManager(StorageObject):
    """
    Manager for the Ceph database
    Contains boto and rest API calls
    as well as the connection and authentication
    setup
    """
    def __init__(self, config):
        """
        Setup authentication. Ceph is compatible with S3Auth
        """
        self.config = config
        self.server = self.config['host']
        self.port = self.config['port']
        self.auth = S3Auth(
            self.config['aws_access_key_id'],
            self.config['aws_secret_access_key'],
            self.server+':'+str(self.port))
        self.conn = connect_s3(**self.config)

    def update_bucket_acl(self, bucket, read_acl):
        """
        Update the read permissions on a bucket.
        Other permissions like OWNER and WRITE
        stay the same
        """
        bucket = self.conn.get_bucket(bucket)
        policy = bucket.get_acl()
        prev_policy = policy.to_xml()
        grants = []
        for grant in policy.acl.grants:
            if grant.permission != "READ":
                grants.append(grant)
        for userid in read_acl:
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

    def has_bucket_access(self, bucket, user_id):
        """
        Check if there is any permission granted to
        this user. Minimum is READ
        """
        bucket = self.conn.get_bucket(bucket)
        for acl in bucket.get_acl().acl.grants:
            if acl.id == user_id:
                return True
        return False

    @handle_request
    def request(self, subject, method, payload=None, **kwargs):
        """
        Build the request with the appropriate paramters and endpoints
        """
        url = ('https://{server}:{port}'
               '/admin/{subject}'
               .format(server=self.server, subject=subject, port=self.port)
               )
        url = url + '?' + urlencode(dict(format='json', **kwargs))
        return requests.request(method, url, auth=self.auth, data=payload)

    def get_user(self, uid):
        """
        Constructs and returns a User object
        """
        return self.request('user', 'GET', uid=uid)

    def list_buckets(self):
        """
        Returns a list with all the buckets in json format
        """
        return self.request('bucket', 'GET')

    def create_user(self, uid, **kwargs):
        """
        Creates a new user and returns it in user format
        """
        kwargs.update({'uid': uid, 'display-name': uid})
        return self.request('user', 'PUT', **kwargs)

    def set_quota(self, uid, quota):
        """
        Set quota for a specific user, returns the json response
        """
        return self.request(
            'user', 'PUT', quota=None,
            payload=json.dumps(quota), uid=uid)

    def delete_user(self, uid):
        """
        Deletes a user, returns the json response
        """
        return self.request('user', 'DELETE', uid=uid)

    def remove_key(self, uid, access_key):
        """
        For a given user, it removes the specified key
        """
        params = {'uid': uid, 'access-key': access_key, 'key': None}
        return self.request('user', 'DELETE', **params)

    def remove_all_keys(self, uid):
        """
        For a specific user, removes all keys
        """
        for key in self.get_user(uid).json()['keys']:
            self.remove_key(uid, key['access_key'])

    def create_key(self, uid, **kwargs):
        """
        Creates one new key for the specified user
        """
        params = {'uid': uid, 'key': None}
        return self.request('user', 'PUT', **params)

    def create_bucket(self, access_key, secret_key, bucket_name):
        """
        Creates s bucket with a default configuration
        """
        creds = dict(self.config)
        creds['aws_access_key_id'] = access_key
        creds['aws_secret_access_key'] = secret_key
        conn = connect_s3(**creds)
        return conn.create_bucket(bucket_name)

    def get_or_create_user(self, uid):
        """
        Tries to get a user and if it fails,
        creates a new one and returns it as a
        User object
        """
        r = self.get_user(uid)
        if r.status_code == 200:
            return r
        else:
            return self.create_user(uid)

    def get_bucket(self, bucket):
        """
        Returns a json response with a bucket
        """
        return self.request('bucket', 'GET', bucket=bucket)

    def get_or_create_bucket(
            self, access_key, secret_key, bucket_name, **kwargs):
        """
        Tries to retrieve a bucket and if it fails,
        creates a new bcuket and returns the json reponse
        """
        r = self.get_bucket(bucket_name)
        if r.status_code == 404:
            return self.create_bucket(access_key, secret_key, bucket_name)
        else:
            return r
