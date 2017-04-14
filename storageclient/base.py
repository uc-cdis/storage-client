from abc import abstractmethod, abstractproperty, ABCMeta
from errors import RequestError
import logging


def handle_request(fun):
    """
    Exception treatment for the REST API calls
    """

    def wrapper(self, *args, **kwargs):
        """
        We raise an internal error when
        """
        try:
            return fun(self, *args, **kwargs)
        except Exception as req_exception:
            self.logger.exception("internal error")
            raise RequestError(req_exception.message)

    return wrapper


class StorageClient(object):
    """Abstract storage client class"""
    __metaclass__ = ABCMeta

    def __init__(self, cls_name):
        self.logger = logging.getLogger(cls_name)
        self.logger.setLevel(logging.DEBUG)

    @abstractproperty
    def provider(self):
        """
        Name of the storage provider. eg: ceph
        """
        raise NotImplementedError()

    @abstractmethod
    def get_user(self, username):
        """
        Get a user
        :returns: a User object if the user exists, else None
        """
        raise NotImplementedError()

    @abstractmethod
    def delete_user(self, username):
        """
        Delete a user
        :returns: None
        :raise:
            :NotFound: the user is not found
        """
        raise NotImplementedError()

    @abstractmethod
    def create_user(self, username):
        """
        Create a user
        :returns: User object
        """
        raise NotImplementedError()

    @abstractmethod
    def list_users(self):
        """
        List users
        :returns: a list of User objects
        """
        raise NotImplementedError()

    @abstractmethod
    def get_or_create_user(self, username):
        """
        Tries to retrieve a user.
        If the user is not found, a new one
        is created and returned
        """
        raise NotImplementedError()

    @abstractmethod
    def create_keypair(self, username):
        """
        Creates a keypair for the user, and
        returns it
        """
        raise NotImplemented()

    @abstractmethod
    def delete_keypair(self, username, access_key):
        """
        Deletes a keypair from the user and
        doesn't return anything
        """
        raise NotImplemented()

    @abstractmethod
    def add_bucket_acl(self, bucket, username, access=None):
        """
        Tries to grant a user access to a bucket
        """
        raise NotImplemented()

    @abstractmethod
    def has_bucket_access(self, bucket, user_id):
        """
        Check if the user appears in the acl
        : returns Bool
        """
        raise NotImplemented()

    @abstractmethod
    def list_buckets(self):
        """
        Return a list of bucket names
        : ['bucket1', bucket2'...]
        """
        raise NotImplemented()

    @abstractmethod
    def delete_all_keypairs(self, user):
        """
        Remove all the keys from a user
        : returns None
        """
        raise NotImplemented()

    @abstractmethod
    def get_bucket(self, bucket):
        """
        Return a bucket from the storage
        """
        raise NotImplemented()

    @abstractmethod
    def get_or_create_bucket(self, access_key, secret_key, bucket):
        """
        Tries to retrieve a bucket and if fit fails,
        creates and returns one
        """
        raise NotImplemented()

    @abstractmethod
    def edit_bucket_template(self, template_id, **kwargs):
        """
        Change the parameters for the template used to create
        the buckets
        """
        raise NotImplemented()

    @abstractmethod
    def update_bucket_acl(self, bucket, user_list):
        """
        Add acl's for the list of users
        """
        raise NotImplemented()

    @abstractmethod
    def set_bucket_quota(self, bucket, quota_unit, quota):
        """
        Set quota for the entire bucket
        """
        raise NotImplemented


class User(object):
    def __init__(self, username):
        """
        - permissions {'bucketname': 'PERMISSION'}
        - keys [{'access_key': abc,'secret_key': 'def'}]
        """
        self.username = username
        self.permissions = {}
        self.keys = []
        self.id = None

class Bucket(object):
    def __init__(self, name, bucket_id):
        """
        Simple bucket representation
        """
        self.name = name 
        self.id = bucket_id

