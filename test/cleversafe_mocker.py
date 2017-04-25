"""
Module for mocking and testing of the
cleversafe API client
"""

from os import path, sys
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
import unittest
from urlparse import urlparse
from storageclient.cleversafe import CleversafeClient
import json
from mock import patch
from urllib import urlencode
from storageclient.errors import RequestError, NotFoundError

def fake_request(method, url, auth, data, verify):
    """
    Allows us to mock the calls to the REST API
    The url will be used as path to the resource file
    From there, if necessary, the appropriate response data
    will be collected from a different entry in the json file
    """
    parsed_url = urlparse(url)
    resource_file = parsed_url.path.split('1.0')[-1]
    if data != None:
        parsed_data = urlencode(data)
    else:
        parsed_data = None
    parsed_query = parsed_url.query
    file_path = './test/data/{request}'.format(request=resource_file)
    resource_file = path.normpath(file_path)
    with open(resource_file, 'r') as f:
        resp_dict = json.load(f)
    if parsed_data != None:
        response = Response(int(resp_dict[parsed_data]['status_code']), json.dumps(resp_dict[parsed_data]['text']))
    elif parsed_query != '':
        response = Response(int(resp_dict[parsed_query]['status_code']), json.dumps(resp_dict[parsed_query]['text']))
    else:
        response = Response(int(resp_dict['status_code']), json.dumps(resp_dict['text']))
    return response

def fake_request_only_failure(method, url, auth, data, verify):
    """                                                                                                                                                                                                            
    Used for functions without parameters, since those
    cannot be distinguished inside the file
    """ 
    return Response(404, json.dumps("Error"))

class Response(object):
    """
    Mocks a request response
    """
    def __init__(self, status_code=0, text=None):
        self.text = text
        self.status_code = status_code

class CleversafeManagerTests(unittest.TestCase):
    """
    The tests will use a fake response
    contructed from data stored in files
    on the data folder.
    """
    def setUp(self):
        self.patcher = patch('requests.request', fake_request)
        self.patcher.start()
        with open('test/data/cred.json', 'r') as f:
            creds = json.load(f)
        self.cm = CleversafeClient(creds)

    def tearDown(self):
        self.patcher.stop()

    def test_get_user_success(self):
        """
        Successful retrieval of a user
        """
        user = self.cm.get_user("ResponseSuccess")
        self.assertEqual(user.username, 'ResponseSuccess')
        self.assertEqual(user.permissions, {'testVaultName': 'owner'})
        self.assertEqual(user.keys[0]['access_key'], 'XXXXXXXXXXXXXXXXXXXXXX')
        self.assertEqual(user.keys[0]['secret_key'], 'YYYYYYYYYYYYYYYYYYYYYYYYYYYYY')
        self.assertEqual(user.id, 72)

    def test_get_user_inexistent_user(self):
        """
        Retrieval of a nonexistent user
        """
        user = self.cm.get_user("NonExistent")
        self.assertEquals(user, None)

    def test_get_bucket_by_id_success(self):
        """
        Successful retrieval of a vault
        """
        response = self.cm._CleversafeClient__get_bucket_by_id(274)
        vault = json.loads(response.text)
        self.assertEqual(vault['responseData']['vaults'][0]['id'], 274)

    def test_list_buckets_success(self):
        """
        Successful retrieval of all buckets
        """
        response = self.cm.list_buckets()
        vault_list = json.loads(response.text)['responseData']['vaults']
        self.assertEqual(vault_list[0]['id'], 1)
        self.assertEqual(vault_list[1]['id'], 2)
        self.assertEqual(vault_list[2]['id'], 274)
        self.assertEqual(vault_list[3]['id'], 3)

    def test_list_users_success(self):
        """
        Successful retrieval of all users from the database
        in the form of a list of User objects
        """
        user_list = self.cm.list_users()
        self.assertEquals(user_list[0].id, 72)
        self.assertEquals(user_list[1].id, 1)
        self.assertEquals(user_list[2].id, 95)

    def test_create_user_success(self):
        """
        Successful creation of a user
        """
        user = self.cm.create_user('testUserToBeDeleted')
        self.assertEqual(user.id, 72)
        self.assertEqual(user.keys[0]['access_key'], 'XXXXXXXXXXXXXXXXXXXXXX')

    def test_delete_user_success(self):
        """
        Successful deletion of a user
        """
        response = self.cm.delete_user("ResponseSuccess")
        self.assertEqual(response, None)

    def test_create_keypair_success(self):
        """
        Successful creation of a key for a specific user
        """
        keypair = self.cm.create_keypair("KeyPairUser")
        self.assertEqual(keypair,
                         {'access_key': u'XXXXXXXXXXXXXX',
                          'secret_key': u'AAAAAAAAAAAAAHHHHHHHHHHHHHHHHHHHNNNNNN'})

    def test_delete_keypair_success(self):
        """
        Successful deletion of a key
        """
        response = self.cm.delete_keypair("KeyPairUser", 'XXXXXXXXXXXXXX')
        self.assertEqual(response, None)

    def test_delete_keypair_inexistent_key(self):
        """
        Removal of an inexistent key
        """
        with self.assertRaises(RequestError):
            self.cm.delete_keypair("KeyPairUser",'YYYYYYYYYYYYYYY')

    def test_set_bucket_quota_succes(self):
        """
        Successful change of a bucket quota
        """
        response = self.cm.set_bucket_quota("Testforreal", "TB", "1")
        self.assertEquals(response.status_code, 200)

    def test_set_bucket_quota_error_response(self):
        """
        Set bucket quota with error response
        """
        with self.assertRaises(RequestError):
            self.cm.set_bucket_quota("whateverName", "TB", "1")

    def test_list_users_error_response(self):
        """
        List users with error response
        """
        self.patcher.stop()
        self.patcher = patch('requests.request', fake_request_only_failure)
        self.patcher.start()
        with self.assertRaises(RequestError):
            self.cm.get_user("ResponseError")

    def test_get_user_error_response(self):
        """
        Get user with error response
        """
        with self.assertRaises(RequestError):
            self.cm.get_user("ResponseError")

    def test_delete_keypair_error_response(self):
        """
        Remove key with error response
        """
        with self.assertRaises(RequestError):
            self.cm.delete_keypair("KeyPairUser",'YYYYYYYYYYYYYYY')

    def test_delete_all_keypairs_success(self):
        """
        Remove all keys success
        """
        response = self.cm.delete_all_keypairs("KeyPairUser")
        self.assertEqual(response, None)

    def test_delete_all_keypairs_response_error(self):
        """
        Remove all keys with response error
        """
        with self.assertRaises(RequestError):
            self.cm.delete_all_keypairs("KeyPairErrorUser")

    def test_create_keypair_response_error(self):
        """
        Key creation with response error
        """
        with self.assertRaises(RequestError):
            self.cm.create_keypair("KeyPairCreationUser")

    def test_edit_bucket_template_error_response(self):
        """
        Edit bucket template with error response
        """
        with self.assertRaises(RequestError):
            self.cm.edit_bucket_template("0")

    def test_edit_bucket_template_success(self):
        """
        Successful modification of the default template
        """
        response = self.cm.edit_bucket_template("5")
        self.assertEqual(response.status_code, 200)

    def test_delete_user_inexistent_user(self):
        """
        Deletion of a inexistent user
        WARNING the curl command does not print
        anything
        """
        response = self.cm.delete_user("KeyPairUser")
        self.assertEqual(response, None)

    def test_list_buckets_response_error(self):
        """
        List buckets with response error
        """
        self.patcher.stop()
        self.patcher = patch('requests.request', fake_request_only_failure)
        self.patcher.start()
        with self.assertRaises(RequestError):
            self.cm.list_buckets()

    def test_create_user_response_error(self):
        """
        Create user with response error
        """
        with self.assertRaises(RequestError):
            self.cm.create_user("ErroredUser")

    def test_add_bucket_acl_user_not_found_error(self):
        """
        ACL addition to bucket with user not found
        """
        with self.assertRaises(NotFoundError):
            self.cm.add_bucket_acl("whateverName", "NotExistentName","read-storage")

    def test_add_bucket_acl_bucket_not_found_error(self):
        """
        ACL addition to bucket with bucket not found
        """
        with self.assertRaises(NotFoundError):
            self.cm.add_bucket_acl("NonExistent", "ResponseSuccess","read-storage")

    def test_add_bucket_acl_success(self):
        """
        Successful addition of ACL to bucket
        """
        response = self.cm.add_bucket_acl("whateverName", "ResponseSuccess", ["read-storage"])
        self.assertEqual(response, None)

    def test_get_bucket_success(self):
        """
        Successful retrieval of a bucket
        """
        bucket = self.cm.get_bucket("testVaultName")
        self.assertEqual(bucket.name, "testVaultName")
        self.assertEqual(bucket.id, 274)

    def test_get_bucket_response_error(self):
        """
        Test retrieval of an inexistent bucket
        """
        with self.assertRaises(RequestError):
            self.cm.get_bucket("InexistentBucket")

    def test_update_bucket_acl_success(self):
        """
        Successful change of acl on a bucket
        """
        response = self.cm.update_bucket_acl("testVaultName", [('ResponseSuccess', ['read-storage'])])
        self.assertEqual(response, None)

    def test_update_bucket_acl_error_response(self):
        """
        Change of acl on a bucket with error response
        """
        with self.assertRaises(RequestError):
            self.cm.update_bucket_acl("testVaultName", [('KeyPairCreationUser', ['read-storage'])])
