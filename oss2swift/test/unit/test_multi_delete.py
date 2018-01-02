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

from datetime import datetime
from hashlib import md5
import unittest

from oss2swift.cfg import CONF
from oss2swift.etree import fromstring, tostring, Element, SubElement
from oss2swift.test.unit import Oss2swiftTestCase
from oss2swift.test.unit.test_oss_acl import ossacl
from six.moves import urllib
from swift.common import swob
from swift.common.swob import Request


class TestOss2swiftMultiDelete(Oss2swiftTestCase):

    def setUp(self):
        super(TestOss2swiftMultiDelete, self).setUp()
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/Key1',
                            swob.HTTPOk, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/Key2',
                            swob.HTTPNotFound, {}, None)

    @ossacl
    def test_object_multi_DELETE_to_object(self):
        elem = Element('Delete')
        obj = SubElement(elem, 'Object')
        SubElement(obj, 'Key').text = 'object'
        body = tostring(elem, use_ossns=False)
        content_md5 = md5(body).digest().encode('base64').strip()

        req = Request.blank('/bucket/object?delete',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'Content-MD5': content_md5},
                            body=body)

        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(status.split()[0], '200')

    @ossacl
    def test_object_multi_DELETE(self):
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/Key3',
                            swob.HTTPOk,
                            {'x-static-large-object': 'True'},
                            None)
        self.swift.register('DELETE', '/v1/AUTH_test/bucket/Key1',
                            swob.HTTPNoContent, {}, None)
        self.swift.register('DELETE', '/v1/AUTH_test/bucket/Key2',
                            swob.HTTPNotFound, {}, None)
        self.swift.register('DELETE', '/v1/AUTH_test/bucket/Key3',
                            swob.HTTPOk, {}, None)

        elem = Element('Delete')
        for key in ['Key1', 'Key2', 'Key3']:
            obj = SubElement(elem, 'Object')
            SubElement(obj, 'Key').text = key
        body = tostring(elem, use_ossns=False)
        content_md5 = md5(body).digest().encode('base64').strip()

        req = Request.blank('/bucket?delete',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'Content-MD5': content_md5},
                            body=body)
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(status.split()[0], '200')

        elem = fromstring(body)
        self.assertEqual(len(elem.findall('Deleted')), 3)
        _, path, _ = self.swift.calls_with_headers[-1]
        path, query_string = path.split('?', 1)
        self.assertEqual(path, '/v1/AUTH_test/bucket/Key3')
        query = dict(urllib.parse.parse_qsl(query_string))
        self.assertEqual(query['multipart-manifest'], 'delete')

    @ossacl
    def test_object_multi_DELETE_quiet(self):
        self.swift.register('DELETE', '/v1/AUTH_test/bucket/Key1',
                            swob.HTTPNoContent, {}, None)
        self.swift.register('DELETE', '/v1/AUTH_test/bucket/Key2',
                            swob.HTTPNotFound, {}, None)

        elem = Element('Delete')
        SubElement(elem, 'Quiet').text = 'true'
        for key in ['Key1', 'Key2']:
            obj = SubElement(elem, 'Object')
            SubElement(obj, 'Key').text = key
        body = tostring(elem, use_ossns=False)
        content_md5 = md5(body).digest().encode('base64').strip()

        req = Request.blank('/bucket?delete',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'Content-MD5': content_md5},
                            body=body)
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(status.split()[0], '200')

        elem = fromstring(body)
        self.assertEqual(len(elem.findall('Deleted')), 0)

    @ossacl
    def test_object_multi_DELETE_no_key(self):
        self.swift.register('DELETE', '/v1/AUTH_test/bucket/Key1',
                            swob.HTTPNoContent, {}, None)
        self.swift.register('DELETE', '/v1/AUTH_test/bucket/Key2',
                            swob.HTTPNotFound, {}, None)

        elem = Element('Delete')
        SubElement(elem, 'Quiet').text = 'true'
        for key in ['Key1', 'Key2']:
            obj = SubElement(elem, 'Object')
            SubElement(obj, 'Key')
        body = tostring(elem, use_ossns=False)
        content_md5 = md5(body).digest().encode('base64').strip()

        req = Request.blank('/bucket?delete',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'Content-MD5': content_md5},
                            body=body)
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'UserKeyMustBeSpecified')

    @ossacl
    def test_object_multi_DELETE_with_invalid_md5(self):
        elem = Element('Delete')
        for key in ['Key1', 'Key2']:
            obj = SubElement(elem, 'Object')
            SubElement(obj, 'Key').text = key
        body = tostring(elem, use_ossns=False)

        req = Request.blank('/bucket?delete',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'Content-MD5': 'XXXX'},
                            body=body)
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'InvalidDigest')

    @ossacl
    def test_object_multi_DELETE_without_md5(self):
        elem = Element('Delete')
        for key in ['Key1', 'Key2']:
            obj = SubElement(elem, 'Object')
            SubElement(obj, 'Key').text = key
        body = tostring(elem, use_ossns=False)

        req = Request.blank('/bucket?delete',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=body)
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'InvalidRequest')

    @ossacl
    def test_object_multi_DELETE_too_many_keys(self):
        elem = Element('Delete')
        for i in range(CONF.max_multi_delete_objects + 1):
            obj = SubElement(elem, 'Object')
            SubElement(obj, 'Key').text = str(i)
        body = tostring(elem, use_ossns=False)
        content_md5 = md5(body).digest().encode('base64').strip()

        req = Request.blank('/bucket?delete',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'Content-MD5': content_md5},
                            body=body)
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'MalformedXML')

    def _test_object_multi_DELETE(self, account):
        self.keys = ['Key1', 'Key2']
        self.swift.register(
            'DELETE', '/v1/AUTH_test/bucket/%s' % self.keys[0],
            swob.HTTPNoContent, {}, None)
        self.swift.register(
            'DELETE', '/v1/AUTH_test/bucket/%s' % self.keys[1],
            swob.HTTPNotFound, {}, None)

        elem = Element('Delete')
        for key in self.keys:
            obj = SubElement(elem, 'Object')
            SubElement(obj, 'Key').text = key
        body = tostring(elem, use_ossns=False)
        content_md5 = md5(body).digest().encode('base64').strip()

        req = Request.blank('/bucket?delete',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'OSS %s:hmac' % account,
                                     'Date': self.get_date_header(),
                                     'Content-MD5': content_md5},
                            body=body)
        req.date = datetime.now()
        req.content_type = 'text/plain'

        return self.call_oss2swift(req)

    @ossacl(ossacl_only=True)
    def test_object_multi_DELETE_without_permission(self):
        status, headers, body = self._test_object_multi_DELETE('test:other')
        self.assertEqual(status.split()[0], '200')
        elem = fromstring(body)
        errors = elem.findall('Error')
        self.assertEqual(len(errors), 2)
        for e in errors:
            self.assertTrue(e.find('Key').text in self.keys)
            self.assertEqual(e.find('Code').text, 'AccessDenied')
            self.assertEqual(e.find('Message').text, 'Access Denied.')

    @ossacl(ossacl_only=True)
    def test_object_multi_DELETE_with_write_permission(self):
        status, headers, body = self._test_object_multi_DELETE('test:write')
        self.assertEqual(status.split()[0], '200')
        elem = fromstring(body)
        self.assertEqual(len(elem.findall('Deleted')), len(self.keys))

    @ossacl(ossacl_only=True)
    def test_object_multi_DELETE_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_object_multi_DELETE('test:full_control')
        self.assertEqual(status.split()[0], '200')
        elem = fromstring(body)
        self.assertEqual(len(elem.findall('Deleted')), len(self.keys))

if __name__ == '__main__':
    unittest.main()
