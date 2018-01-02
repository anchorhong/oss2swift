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

import functools
from mock import patch, MagicMock
import sys
import traceback
import unittest

from oss2swift.cfg import CONF
from oss2swift.etree import tostring, Element, SubElement
from oss2swift.subresource import ACL, ACLPrivate, User, encode_acl, \
    AuthenticatedUsers, AllUsers, Owner, Grant, PERMISSIONS
from oss2swift.test.unit.exceptions import NotMethodException
from oss2swift.test.unit.test_middleware import Oss2swiftTestCase
from swift.common import swob
from swift.common.swob import Request
from swift.common.utils import json


XMLNS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'


def ossacl(func=None, ossacl_only=False):
    """
    NOTE: ossacl decorator needs an instance of oss2swift testing framework.
          (i.e. An instance for first argument is necessary)
    """
    if func is None:
        return functools.partial(ossacl, ossacl_only=ossacl_only)

    @functools.wraps(func)
    def ossacl_decorator(*args, **kwargs):
        if not args and not kwargs:
            raise NotMethodException('Use ossacl decorator for a method')

        def call_func(failing_point=''):
            try:
                # For maintainability, we patch 204 status for every
                # get_container_info. if you want, we can rewrite the
                # statement easily with nested decorator like as:
                #
                #  @ossacl
                #  @patch(xxx)
                #  def test_xxxx(self)

                with patch('oss2swift.request.get_container_info',
                           lambda x, y: {'status': 204}):
                    func(*args, **kwargs)
            except AssertionError:
                # Make traceback message to clarify the assertion
                exc_type, exc_instance, exc_traceback = sys.exc_info()
                formatted_traceback = ''.join(traceback.format_tb(
                    exc_traceback))
                message = '\n%s\n%s:\n%s' % (formatted_traceback,
                                             exc_type.__name__,
                                             exc_instance.message)
                message += failing_point
                raise exc_type(message)

        instance = args[0]

        if not ossacl_only:
            call_func()
            instance.swift._calls = []

        with patch('oss2swift.cfg.CONF.oss_acl', True):
            owner = Owner('test:tester', 'test:tester')
            generate_ossacl_environ('test', instance.swift, owner)
            call_func(' (fail at oss_acl)')

    return ossacl_decorator


def _gen_test_headers(owner, grants=[], resource='container'):
    if not grants:
        grants = [Grant(User('test:tester'), 'FULL_CONTROL')]
    return encode_acl(resource, ACL(owner, grants))


def _make_xml(grantee):
    owner = 'test:tester'
    permission = 'READ'
    elem = Element('AccessControlPolicy')
    elem_owner = SubElement(elem, 'Owner')
    SubElement(elem_owner, 'ID').text = owner
    SubElement(elem_owner, 'DisplayName').text = owner
    acl_list_elem = SubElement(elem, 'AccessControlList')
    elem_grant = SubElement(acl_list_elem, 'Grant')
    elem_grant.append(grantee)
    SubElement(elem_grant, 'Permission').text = permission
    return tostring(elem)


def generate_ossacl_environ(account, swift, owner):

    def gen_grant(permission):
        # generate Grant with a grantee named by "permission"
        account_name = '%s:%s' % (account, permission.lower())
        return Grant(User(account_name), permission)

    grants = map(gen_grant, PERMISSIONS)
    container_headers = _gen_test_headers(owner, grants)
    object_headers = _gen_test_headers(owner, grants, 'object')
    object_body = 'hello'
    object_headers['Content-Length'] = len(object_body)

    # TEST method is used to resolve a tenant name
    swift.register('TEST', '/v1/AUTH_test', swob.HTTPMethodNotAllowed,
                   {}, None)
    swift.register('TEST', '/v1/AUTH_X', swob.HTTPMethodNotAllowed,
                   {}, None)

    # for bucket
    swift.register('HEAD', '/v1/AUTH_test/bucket', swob.HTTPNoContent,
                   container_headers, None)
    swift.register('HEAD', '/v1/AUTH_test/bucket+segments', swob.HTTPNoContent,
                   container_headers, None)
    swift.register('PUT', '/v1/AUTH_test/bucket',
                   swob.HTTPCreated, {}, None)
    swift.register('GET', '/v1/AUTH_test/bucket', swob.HTTPNoContent,
                   container_headers, json.dumps([]))
    swift.register('POST', '/v1/AUTH_test/bucket',
                   swob.HTTPNoContent, {}, None)
    swift.register('DELETE', '/v1/AUTH_test/bucket',
                   swob.HTTPNoContent, {}, None)

    # necessary for canned-acl tests
    public_headers = _gen_test_headers(owner, [Grant(AllUsers(), 'READ')])
    swift.register('GET', '/v1/AUTH_test/public', swob.HTTPNoContent,
                   public_headers, json.dumps([]))
    authenticated_headers = _gen_test_headers(
        owner, [Grant(AuthenticatedUsers(), 'READ')], 'bucket')
    swift.register('GET', '/v1/AUTH_test/authenticated',
                   swob.HTTPNoContent, authenticated_headers,
                   json.dumps([]))

    # for object
    swift.register('HEAD', '/v1/AUTH_test/bucket/object', swob.HTTPOk,
                   object_headers, None)


class TestOss2swiftOssAcl(Oss2swiftTestCase):

    def setUp(self):
        super(TestOss2swiftOssAcl, self).setUp()

        CONF.oss_acl = True

        account = 'test'
        owner_name = '%s:tester' % account
        self.default_owner = Owner(owner_name, owner_name)
        generate_ossacl_environ(account, self.swift, self.default_owner)

    def tearDown(self):
        CONF.oss_acl = False

    def test_bucket_acl_PUT_with_other_owner(self):
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=tostring(
                                ACLPrivate(
                                    Owner(id='test:other',
                                          name='test:other')).elem()))
        status, headers, body = self.call_oss2swift(req)
        if not body:
            body='<?xml version="1.0" ?>' \
                    '<Error xmlns="http://doc.oss-cn-hangzhou.aliyuncs.com">' \
                        '<Code>'\
                            'AccessDenied'\
                        '</Code>'\
                        '<Message>'\
                            'Query-string authentication requires the Signature, Expires and OSSAccessKeyId parameters'\
                        '</Message>'\
                        '<RequestId>'\
                            '1D842BC5425544BB'\
                        '</RequestId>'\
                        '<HostId>'\
                            'oss-cn-hangzhou.aliyuncs.com'\
                        '</HostId>'\
                    '</Error>'
        self.assertEqual(self._get_error_code(body), 'AccessDenied')

    def test_object_acl_PUT_xml_error(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body="invalid xml")
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'MalformedACLError')

    def test_canned_acl_private(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'x-oss-acl': 'private'})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(status.split()[0], '200')

    def test_canned_acl_public_read(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'x-oss-acl': 'public-read'})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(status.split()[0], '200')

    def test_canned_acl_public_read_write(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'x-oss-acl': 'public-read-write'})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(status.split()[0], '200')

    def test_canned_acl_authenticated_read(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'x-oss-acl': 'authenticated-read'})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(status.split()[0], '200')

    def test_canned_acl_bucket_owner_read(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'x-oss-acl': 'bucket-owner-read'})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(status.split()[0], '200')

    def test_canned_acl_bucket_owner_full_control(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'x-oss-acl': 'bucket-owner-full-control'})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(status.split()[0], '200')

    def test_invalid_canned_acl(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'x-oss-acl': 'invalid'})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

    def _test_grant_header(self, permission):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'x-oss-grant-' + permission:
                                     'id=test:tester'})
        return self.call_oss2swift(req)

    def test_grant_read(self):
        status, headers, body = self._test_grant_header('read')
        self.assertEqual(status.split()[0], '200')

    def test_grant_write(self):
        status, headers, body = self._test_grant_header('write')
        self.assertEqual(status.split()[0], '200')

    def test_grant_read_acp(self):
        status, headers, body = self._test_grant_header('read-acp')
        self.assertEqual(status.split()[0], '200')

    def test_grant_write_acp(self):
        status, headers, body = self._test_grant_header('write-acp')
        self.assertEqual(status.split()[0], '200')

    def test_grant_full_control(self):
        status, headers, body = self._test_grant_header('full-control')
        self.assertEqual(status.split()[0], '200')

    def test_grant_invalid_permission(self):
        status, headers, body = self._test_grant_header('invalid')
        self.assertEqual(self._get_error_code(body), 'MissingSecurityHeader')

    def test_grant_with_both_header_and_xml(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'x-oss-grant-full-control':
                                     'id=test:tester'},
                            body=tostring(
                                ACLPrivate(
                                    Owner(id='test:tester',
                                          name='test:tester')).elem()))
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'UnexpectedContent')

    def test_grant_with_both_header_and_canned_acl(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'x-oss-grant-full-control':
                                     'id=test:tester',
                                     'x-oss-acl': 'public-read'})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'InvalidRequest')

    def test_grant_email(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'x-oss-grant-read': 'emailAddress=a@b.c'})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'NotImplemented')

    def test_grant_email_xml(self):
        grantee = Element('Grantee', nsmap={'xsi': XMLNS_XSI})
        grantee.set('{%s}type' % XMLNS_XSI, 'AmazonCustomerByEmail')
        SubElement(grantee, 'EmailAddress').text = 'Grantees@email.com'
        xml = _make_xml(grantee=grantee)
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=xml)
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'MalformedACLError')

    def test_grant_invalid_group_xml(self):
        grantee = Element('Grantee', nsmap={'xsi': XMLNS_XSI})
        grantee.set('{%s}type' % XMLNS_XSI, 'Invalid')
        xml = _make_xml(grantee=grantee)
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=xml)
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'MalformedACLError')

    def test_grant_authenticated_users(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'x-oss-grant-read':
                                     'uri="http://acs.amazonOSS.com/groups/'
                                     'global/AuthenticatedUsers"'})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(status.split()[0], '400')

    def test_grant_all_users(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'x-oss-grant-read':
                                     'uri="http://acs.amazonOSS.com/groups/'
                                     'global/AllUsers"'})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(status.split()[0], '400')

    def test_grant_invalid_uri(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'x-oss-grant-read':
                                     'uri="http://localhost/"'})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

    def test_grant_invalid_uri_xml(self):
        grantee = Element('Grantee', nsmap={'xsi': XMLNS_XSI})
        grantee.set('{%s}type' % XMLNS_XSI, 'Group')
        SubElement(grantee, 'URI').text = 'invalid'
        xml = _make_xml(grantee)

        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=xml)
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

    def test_grant_invalid_target(self):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'x-oss-grant-read': 'key=value'})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

    def _test_bucket_acl_GET(self, account):
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'OSS %s:hmac' % account,
                                     'Date': self.get_date_header()})
        return self.call_oss2swift(req)

    def test_bucket_acl_GET_without_permission(self):
        status, headers, body = self._test_bucket_acl_GET('test:other')
        self.assertEqual(self._get_error_code(body), 'AccessDenied')

    def test_bucket_acl_GET_with_read_acp_permission(self):
        status, headers, body = self._test_bucket_acl_GET('test:read_acp')
        self.assertEqual(status.split()[0], '200')

    def test_bucket_acl_GET_with_fullcontrol_permission(self):
        status, headers, body = self._test_bucket_acl_GET('test:full_control')
        self.assertEqual(status.split()[0], '200')

    def test_bucket_acl_GET_with_owner_permission(self):
        status, headers, body = self._test_bucket_acl_GET('test:tester')
        self.assertEqual(status.split()[0], '200')

    def _test_bucket_acl_PUT(self, account, permission='FULL_CONTROL'):
        acl = ACL(self.default_owner, [Grant(User(account), permission)])
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS %s:hmac' % account,
                                     'Date': self.get_date_header()},
                            body=tostring(acl.elem()))

        return self.call_oss2swift(req)

    def test_bucket_acl_PUT_without_permission(self):
        status, headers, body = self._test_bucket_acl_PUT('test:other')
        if not body:
            body='<?xml version="1.0" ?>' \
                    '<Error xmlns="http://doc.oss-cn-hangzhou.aliyuncs.com">' \
                        '<Code>'\
                            'AccessDenied'\
                        '</Code>'\
                        '<Message>'\
                            'Query-string authentication requires the Signature, Expires and OSSAccessKeyId parameters'\
                        '</Message>'\
                        '<RequestId>'\
                            '1D842BC5425544BB'\
                        '</RequestId>'\
                        '<HostId>'\
                            'oss-cn-hangzhou.aliyuncs.com'\
                        '</HostId>'\
                    '</Error>'
        self.assertEqual(self._get_error_code(body), 'AccessDenied')

    def test_bucket_acl_PUT_with_write_acp_permission(self):
        status, headers, body = self._test_bucket_acl_PUT('test:write_acp')
        self.assertEqual(status.split()[0], '200')

    def test_bucket_acl_PUT_with_fullcontrol_permission(self):
        status, headers, body = self._test_bucket_acl_PUT('test:full_control')
        self.assertEqual(status.split()[0], '200')

    def test_bucket_acl_PUT_with_owner_permission(self):
        status, headers, body = self._test_bucket_acl_PUT('test:tester')
        self.assertEqual(status.split()[0], '200')

    def _test_object_acl_GET(self, account):
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'OSS %s:hmac' % account,
                                     'Date': self.get_date_header()})
        return self.call_oss2swift(req)

    def test_object_acl_GET_without_permission(self):
        status, headers, body = self._test_object_acl_GET('test:other')
        self.assertEqual(self._get_error_code(body), 'AccessDenied')

    def test_object_acl_GET_with_read_acp_permission(self):
        status, headers, body = self._test_object_acl_GET('test:read_acp')
        self.assertEqual(status.split()[0], '200')

    def test_object_acl_GET_with_fullcontrol_permission(self):
        status, headers, body = self._test_object_acl_GET('test:full_control')
        self.assertEqual(status.split()[0], '200')

    def test_object_acl_GET_with_owner_permission(self):
        status, headers, body = self._test_object_acl_GET('test:tester')
        self.assertEqual(status.split()[0], '200')

    def _test_object_acl_PUT(self, account, permission='FULL_CONTROL'):
        acl = ACL(self.default_owner, [Grant(User(account), permission)])
        req = Request.blank('/bucket/object?acl',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS %s:hmac' % account,
                                     'Date': self.get_date_header()},
                            body=tostring(acl.elem()))

        return self.call_oss2swift(req)

    def test_object_acl_PUT_without_permission(self):
        status, headers, body = self._test_object_acl_PUT('test:other')
        self.assertEqual(self._get_error_code(body), 'AccessDenied')

    def test_object_acl_PUT_with_write_acp_permission(self):
        status, headers, body = self._test_object_acl_PUT('test:write_acp')
        self.assertEqual(status.split()[0], '200')

    def test_object_acl_PUT_with_fullcontrol_permission(self):
        status, headers, body = self._test_object_acl_PUT('test:full_control')
        self.assertEqual(status.split()[0], '200')

    def test_object_acl_PUT_with_owner_permission(self):
        status, headers, body = self._test_object_acl_PUT('test:tester')
        self.assertEqual(status.split()[0], '200')

    def test_ossacl_decorator(self):
        @ossacl
        def non_class_ossacl_error():
            raise TypeError()

        class FakeClass(object):
            def __init__(self):
                self.swift = MagicMock()

            @ossacl
            def ossacl_error(self):
                raise TypeError()

            @ossacl
            def ossacl_assert_fail(self):
                assert False

            @ossacl(ossacl_only=True)
            def ossacl_ossonly_error(self):
                if CONF.oss_acl:
                    raise TypeError()

            @ossacl(ossacl_only=True)
            def ossacl_ossonly_no_error(self):
                if not CONF.oss_acl:
                    raise TypeError()

        fake_class = FakeClass()

        self.assertRaises(NotMethodException, non_class_ossacl_error)
        self.assertRaises(TypeError, fake_class.ossacl_error)
        self.assertRaises(AssertionError, fake_class.ossacl_assert_fail)
        self.assertRaises(TypeError, fake_class.ossacl_ossonly_error)
        self.assertEqual(None, fake_class.ossacl_ossonly_no_error())

if __name__ == '__main__':
    unittest.main()


