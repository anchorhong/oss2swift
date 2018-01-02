# Copyright (c) 2014 OpenStack Foundation
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

from cStringIO import StringIO
import mock
import unittest

from oss2swift.acl_utils import handle_acl_header
from oss2swift.etree import fromstring, tostring, Element, SubElement, XMLNS_XSI
from oss2swift.response import InvalidArgument
from oss2swift.test.unit import Oss2swiftTestCase
from oss2swift.test.unit.test_oss_acl import ossacl
from swift.common.swob import Request, HTTPAccepted


class TestOss2swiftAcl(Oss2swiftTestCase):

    def setUp(self):
        super(TestOss2swiftAcl, self).setUp()
        # All ACL API should be called against to existing bucket.
        self.swift.register('PUT', '/v1/AUTH_test/bucket',
                            HTTPAccepted, {}, None)

    def _check_acl(self, owner, body):
        elem = fromstring(body, 'AccessControlPolicy')
        permission = elem.find('./AccessControlList/Grant/Permission').text
        self.assertEqual(permission, 'FULL_CONTROL')
        name = elem.find('./AccessControlList/Grant/Grantee/ID').text
        self.assertEqual(name, owner)

    def test_bucket_acl_GET(self):
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_oss2swift(req)
        self._check_acl('test:tester', body)

    def test_bucket_acl_PUT(self):
        elem = Element('AccessControlPolicy')
        owner = SubElement(elem, 'Owner')
        SubElement(owner, 'ID').text = 'id'
        acl = SubElement(elem, 'AccessControlList')
        grant = SubElement(acl, 'Grant')
        grantee = SubElement(grant, 'Grantee', nsmap={'xsi': XMLNS_XSI})
        grantee.set('{%s}type' % XMLNS_XSI, 'Group')
        SubElement(grantee, 'URI').text = \
            'http://acs.oss.com/groups/global/AllUsers'
        SubElement(grant, 'Permission').text = 'READ'

        xml = tostring(elem)
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=xml)
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(status.split()[0], '200')

        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT',
                                     'wsgi.input': StringIO(xml)},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'Transfer-Encoding': 'chunked'})
        self.assertIsNone(req.content_length)
        self.assertIsNone(req.message_length())
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(status.split()[0], '200')

    def test_bucket_canned_acl_PUT(self):
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'X-Oss-ACL': 'public-read'})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(status.split()[0], '200')

    @ossacl(ossacl_only=True)
    def test_bucket_canned_acl_PUT_with_ossacl(self):
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'X-Oss-ACL': 'public-read'})
        with mock.patch('oss2swift.request.handle_acl_header') as mock_handler:
            status, headers, body = self.call_oss2swift(req)
            self.assertEqual(status.split()[0], '200')
            self.assertEqual(mock_handler.call_count, 0)

    def test_bucket_fails_with_both_acl_header_and_xml_PUT(self):
        elem = Element('AccessControlPolicy')
        owner = SubElement(elem, 'Owner')
        SubElement(owner, 'ID').text = 'id'
        acl = SubElement(elem, 'AccessControlList')
        grant = SubElement(acl, 'Grant')
        grantee = SubElement(grant, 'Grantee', nsmap={'xsi': XMLNS_XSI})
        grantee.set('{%s}type' % XMLNS_XSI, 'Group')
        SubElement(grantee, 'URI').text = \
            'http://acs.oss.com/groups/global/AllUsers'
        SubElement(grant, 'Permission').text = 'READ'

        xml = tostring(elem)
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'X-Oss-ACL': 'public-read'},
                            body=xml)
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body),
                         'UnexpectedContent')

    def test_object_acl_GET(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_oss2swift(req)
        self._check_acl('test:tester', body)

    def test_invalid_xml(self):
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body='invalid')
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'MalformedACLError')

    def test_handle_acl_header(self):
        def check_generated_acl_header(acl, targets):
            req = Request.blank('/bucket',
                                headers={'X-Oss-Acl': acl})
            handle_acl_header(req)
            for target in targets:
                self.assertTrue(target[0] in req.headers)
                self.assertEqual(req.headers[target[0]], target[1])

        check_generated_acl_header('public-read',
                                   [('X-Container-Read', '.r:*,.rlistings')])
        check_generated_acl_header('public-read-write',
                                   [('X-Container-Read', '.r:*,.rlistings'),
                                    ('X-Container-Write', '.r:*')])
        check_generated_acl_header('private',
                                   [('X-Container-Read', '.'),
                                    ('X-Container-Write', '.')])

    @ossacl(ossacl_only=True)
    def test_handle_acl_header_with_ossacl(self):
        def check_generated_acl_header(acl, targets):
            req = Request.blank('/bucket',
                                headers={'X-Oss-Acl': acl})
            for target in targets:
                self.assertTrue(target not in req.headers)
            self.assertFalse('HTTP_X_Oss_ACL' in req.environ)
            # TODO: add transration and assertion for ossacl

        check_generated_acl_header('public-read',
                                   ['X-Container-Read'])
        check_generated_acl_header('public-read-write',
                                   ['X-Container-Read', 'X-Container-Write'])
        check_generated_acl_header('private',
                                   ['X-Container-Read', 'X-Container-Write'])

    def test_handle_acl_with_invalid_header_string(self):
        req = Request.blank('/bucket', headers={'X-Oss-Acl': 'invalid'})
        with self.assertRaises(InvalidArgument) as cm:
            handle_acl_header(req)
        self.assertTrue('argument_name' in cm.exception.info)
        self.assertEqual(cm.exception.info['argument_name'], 'x-oss-acl')
        self.assertTrue('argument_value' in cm.exception.info)
        self.assertEqual(cm.exception.info['argument_value'], 'invalid')


if __name__ == '__main__':
    unittest.main()
