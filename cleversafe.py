"""
Connection manager for the Cleversafe storage system
Since it is compatible with S3, we will be using boto.
"""
from boto.s3 import connection
from boto import connect_s3

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
        self.__conn = connect_s3(
            config['access_key'],
            config['secret_key'],
            host=config['host'],
            is_secure=True,
            calling_format=connection.OrdinaryCallingFormat())

