"""
Module for mocking and testing of the
cleversafe API client
"""

from os import path, sys
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
import unittest
from urlparse import urlparse
from cleversafe import CleversafeManager
import json
from mock import patch
from urllib import urlencode

def fake_request(method, url, auth, data, verify):
    """
    Allows us to mock the calls to the REST API
    The url will be used as path to the resource file
    From there, if necessary, the appropriate response data
    will be collected from a different entry in the json file
    """
    parsed_url = urlparse(url)
    resource_file = parsed_url.path.split('1.0')[-1]
    print resource_file
    if data != None:
        parsed_data = urlencode(data)
    else:
        parsed_data = None
    parsed_query = parsed_url.query
    file_path = path.dirname(path.abspath('.'))+'/test/data/{request}'.format(request=resource_file)
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
        with open('data/cred.json', 'r') as f:
            creds = json.load(f)
        self.cm = CleversafeManager(creds)

    def tearDown(self):
        self.patcher.stop()

    def test_get_user_success(self):
        """
        Successful retrieval of a user
        """
        user = self.cm.get_user(72)
        self.assertEqual(user.username, 'testName')
        self.assertEqual(user.permissions, {'testVaultName': 'owner'})
        self.assertEqual(user.keys, ['XXXXXXXXXXXXXXXXXXXXXX'])
        self.assertEqual(user.id, 72)

    def test_get_user_inexistent_user(self):
        """
        Retrieval of a nonexistent user
        """
        user = self.cm.get_user(0)
        self.assertEquals(user, None)

    def test_get_bucket_by_id_success(self):
        """
        Successful retrieval of a vault
        """
        response = self.cm.get_bucket_by_id(274)
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
        self.assertEqual(vault_list[2]['id'], 3)

    def test_list_users_success(self):
        """
        Successful retrieval of all users from the database
        in the form of a list of User objects
        """
        user_list = self.cm.list_users()
        self.assertEquals(user_list[0].id, 42)
        self.assertEquals(user_list[1].id, 1)
        self.assertEquals(user_list[2].id, 80)
        self.assertEquals(user_list[3].id, 52)

    def test_create_user_success(self):
        """
        Successful creation of a user
        """
        args =  {'name': 'testUserToBeDeleted2',
                 'username': 'pericoDeLosPalotes2',
                 'password': 'fakepass',
                 'confirmPassword': 'fakepass',
                 'rolesMap[operator]': 'true',
                 'vaultPermissions[274]': 'readonly'}
        user = self.cm.create_user(**args)
        self.assertEqual(user.id, 72)
        self.assertEqual(user.keys, ['XXXXXXXXXXXXXXXXXXXXXX'])

    def test_delete_user_success(self):
        """
        Successful deletion of a user
        """
        response = self.cm.delete_user(0)
        self.assertEqual(response, None)

    def test_create_key_success(self):
        """
        Successful creation of a key for a specific user
        """
        response = self.cm.create_key(95)
        self.assertEqual(response, None)

    def test_remove_key_success(self):
        """
        Successful deletion of a key
        """
        response = self.cm.remove_key(95, 'XXXXXXXXXXXXXX')
        self.assertEqual(response, None)

    def test_remove_key_inexistent_key(self):
        """
        TODO IMPLEMENT Removal of an inexistent key
        """
        self.skipTest('We need a test here, really') 

    def test_edit_bucket_template_success(self):
        """
        TODO IMPLEMENT Successful modification of the default template
        """
        #response = self.cm.edit_bucket_template()
        self.skipTest('We need a test here, really')

    def test_set_bucket_quota_succes(self):
        """
        TODO IMPLEMENT Successful change of a bucket quota
        """
        self.skipTest('We need a test here, really')

    def test_delete_user_inexistent_user(self):
        """
        TODO IMPLEMENT Deletion of a inexistent user
        """
        self.skipTest('We need a test here, really')

    def test_list_users_error_response(self):
        """
        TODO IMPLEMENT List users with error response
        """
        self.skipTest('We need a test here, really')

    def test_get_user_error_response(self):
        """
        TODO IMPLEMENT Get user with error response
        """
        self.skipTest('We need a test here, really')

    def test_remove_key_error_response(self):
        """
        TODO IMPLEMENT Remove key with error response
        """
        self.skipTest('We need a test here, really')

    def test_remove_all_keys_success(self):
        """
        TODO IMPLEMENT Remove all keys success
        """
        self.skipTest('We need a test here, really')

    def test_remove_all_keys_response_error(self):
        """
        TODO IMPLEMENT Remove all keys with response error
        """
        self.skipTest('We need a test here, really')

    def test_create_key_response_error(self):
        """
        TODO IMPLEMENT Key creation with response error
        """
        self.skipTest('We need a test here, really')

    def test_get_bucket_by_id_response_error(self):
        """
        TODO IMPLEMENT Get bucket by id with response error
        """
        self.skipTest('We need a test here, really')

    def test_get_bucket_error_response(self):
        """
        TODO IMPLEMENT Get bucket with error response
        """
        self.skipTest('We need a test here, really')

    def test_edit_bucket_template_error_response(self):
        """
        TODO IMPLEMENT Edit bucket template with error response
        """
        self.skipTest('We need a test here, really')

    def test_set_bucket_quota_error_response(self):
        """
        TODO IMPLEMENT Set bucket quota with error response
        """
        self.skipTest('We need a test here, really')
