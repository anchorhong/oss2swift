# Copyright (c) 2015 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import unittest

from oss2swift.etree import fromstring
from oss2swift.test.functional import Oss2swiftFunctionalTestCase
from oss2swift.test.functional.oss_test_client import Connection, \
    get_tester2_connection
from oss2swift.test.functional.utils import get_error_code


class TestOss2swiftAcl(Oss2swiftFunctionalTestCase):
    def setUp(self):
        super(TestOss2swiftAcl, self).setUp()
        self.bucket = 'bucket'
        self.obj = 'object'
        self.conn.make_request('PUT', self.bucket)
        self.conn2 = get_tester2_connection()

    def test_acl(self):
        self.conn.make_request('PUT', self.bucket, self.obj)
        query = {'acl':''}

        # PUT Bucket ACL
        headers = {'x-oss-acl': 'public-read'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, headers=headers,
                                   query=query)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)
        self.assertEqual(headers['Content-Length'], '0')

        # GET Bucket ACL
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, query=query)

        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)
        # TODO: Fix the response that last-modified must be in the response.
        # self.assertTrue(headers['last-modified'] is not None)
        self.assertEqual(headers['Content-Length'], str(len(body)))
        self.assertTrue(headers['Content-Type'] is not None)
        elem = fromstring(body, 'AccessControlPolicy')
        owner = elem.find('Owner')
        self.assertEqual(owner.find('ID').text, self.conn.user_id)
        self.assertEqual(owner.find('DisplayName').text, self.conn.user_id)
        acl = elem.find('AccessControlList')
        self.assertTrue(acl.find('Grant') is not None)

        # GET Object ACL
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, self.obj, query=query)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)
        # TODO: Fix the response that last-modified must be in the response.
        # self.assertTrue(headers['last-modified'] is not None)
        self.assertEqual(headers['Content-Length'], str(len(body)))
        self.assertTrue(headers['Content-Type'] is not None)
        elem = fromstring(body, 'AccessControlPolicy')
        owner = elem.find('Owner')
        self.assertEqual(owner.find('ID').text, self.conn.user_id)
        self.assertEqual(owner.find('DisplayName').text, self.conn.user_id)
        acl = elem.find('AccessControlList')
        self.assertTrue(acl.find('Grant') is not None)

    def test_put_bucket_acl_error(self):
        req_headers = {'x-oss-acl': 'public-read'}
        oss_error_conn = Connection(oss_secret_key='invalid')
        status, headers, body = \
            oss_error_conn.make_request('PUT', self.bucket,
                                        headers=req_headers, query={'acl':''})
        self.assertEqual(get_error_code(body), 'SignatureDoesNotMatch')

        status, headers, body = \
            self.conn.make_request('PUT', 'nothing',
                                   headers=req_headers, query={'acl':''})
        self.assertEqual(get_error_code(body), 'NoSuchBucket')

        status, headers, body = \
            self.conn2.make_request('PUT', self.bucket,
                                    headers=req_headers, query={'acl':''})
        self.assertEqual(get_error_code(body), 'MethodNotAllowed')

    def test_get_bucket_acl_error(self):
        oss_error_conn = Connection(oss_secret_key='invalid')
        status, headers, body = \
            oss_error_conn.make_request('GET', self.bucket, query={'acl':''})
        self.assertEqual(get_error_code(body), 'SignatureDoesNotMatch')

        status, headers, body = \
            self.conn.make_request('GET', 'nothing', query={'acl':''})
        self.assertEqual(get_error_code(body), 'NoSuchBucket')

        status, headers, body = \
            self.conn2.make_request('GET', self.bucket,query={'acl':''})
        self.assertEqual(get_error_code(body), 'AccessDenied')

    def test_get_object_acl_error(self):
        self.conn.make_request('PUT', self.bucket, self.obj)

        oss_error_conn = Connection(oss_secret_key='invalid')
        status, headers, body = \
            oss_error_conn.make_request('GET', self.bucket, self.obj,
                                        query={'acl':''})
        self.assertEqual(get_error_code(body), 'SignatureDoesNotMatch')

        status, headers, body = \
            self.conn.make_request('GET', self.bucket, 'nothing', query={'acl':''})
        self.assertEqual(get_error_code(body), 'NoSuchKey')

        status, headers, body = \
            self.conn2.make_request('GET', self.bucket, self.obj, query={'acl':''})
        self.assertEqual(get_error_code(body), 'SignatureDoesNotMatch')


@unittest.skipIf(os.environ['AUTH'] == 'tempauth',
                 'v4 is supported only in keystone')
class TestOss2swiftAclSigV4(TestOss2swiftAcl):
    @classmethod
    def setUpClass(cls):
        os.environ['Oss_USE_SIGV4'] = "True"

    @classmethod
    def tearDownClass(cls):
        del os.environ['Oss_USE_SIGV4']


if __name__ == '__main__':
    unittest.main()
