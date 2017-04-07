from abc import abstractmethod, abstractproperty, ABCMeta


class StorageClient(object):
    """Abstract storage client class"""
    __metaclass__ = ABCMeta

    def __init__(self):
        pass

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


class User(object):
    def __init__(self, username):
        """
        - permissions {'bucketname': 'PERMISSION'}
        - keys ['key_id']
        """
        self.username = username
        self.permissions = {}
        self.keys = []
        self.id = None
