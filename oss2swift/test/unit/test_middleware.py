# Copyright (c) 2011-2014 OpenStack Foundation.
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

import base64
from contextlib import nested
from datetime import datetime
import hashlib
from mock import patch
import unittest
from urllib import unquote, quote

import oss2swift
from oss2swift.cfg import CONF
from oss2swift.etree import fromstring
from oss2swift.middleware import filter_factory
from oss2swift.request import Request as OssRequest
from oss2swift.test.unit import Oss2swiftTestCase
from swift.common import swob, utils
from swift.common.swob import Request


class TestOss2swiftMiddleware(Oss2swiftTestCase):
    def setUp(self):
        super(TestOss2swiftMiddleware, self).setUp()

        self.swift.register('GET', '/something', swob.HTTPOk, {}, 'FAKE APP')

    def test_non_oss_request_passthrough(self):
        req = Request.blank('/something')
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(body, 'FAKE APP')

    def test_bad_format_authorization(self):
        req = Request.blank('/something',
                            headers={'Authorization': 'hoge',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'AccessDenied')

    def test_bad_method(self):
        req = Request.blank('/',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'MethodNotAllowed')

    def test_bad_method_but_method_exists_in_controller(self):
        req = Request.blank(
            '/bucket',
            environ={'REQUEST_METHOD': '_delete_segments_bucket'},
            headers={'Authorization': 'OSS test:tester:hmac',
                     'Date': self.get_date_header()})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'MethodNotAllowed')

    def test_path_info_encode(self):
        bucket_name = 'b%75cket'
        object_name = 'ob%6aect:1'
        self.swift.register('GET', '/v1/AUTH_test/bucket/object:1',
                            swob.HTTPOk, {}, None)
        req = Request.blank('/%s/%s' % (bucket_name, object_name),
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_oss2swift(req)
        raw_path_info = "/%s/%s" % (bucket_name, object_name)
        path_info = req.environ['PATH_INFO']
        self.assertEqual(path_info, unquote(raw_path_info))
        self.assertEqual(req.path, quote(path_info))

    def test_canonical_string_v2(self):
        """
        The hashes here were generated by running the same requests against
        boto.utils.canonical_string
        """
        def canonical_string(path, headers):
            if '?' in path:
                path, query_string = path.split('?', 1)
            else:
                query_string = ''

            with patch('oss2swift.request.Request._validate_headers'):
                req = OssRequest({
                    'REQUEST_METHOD': 'GET',
                    'PATH_INFO': path,
                    'QUERY_STRING': query_string,
                    'HTTP_AUTHORIZATION': 'OSS X:Y:Z',
                })
            req.headers.update(headers)
            return req._string_to_sign()

        def verify(hash, path, headers):
            s = canonical_string(path, headers)
            self.assertEqual(hash, hashlib.md5(s).hexdigest())

        verify('131f481a478f9634e764bce496ef335a', '/bucket/object',
               {'Content-Type': 'text/plain', 'X-Oss-Something': 'test',
                'Date': 'whatever'})

        verify('f6597cce8d6ebf7a549ad60c73fa4a4b', '/bucket/object',
               {'Content-Type': 'text/plain', 'X-Oss-Something': 'test'})

        verify('bf49304103a4de5c325dce6384f2a4a2', '/bucket/object',
               {'content-type': 'text/plain'})

        verify('be01bd15d8d47f9fe5e2d9248cc6f180', '/bucket/object', {})

        verify('e9ec7dca45eef3e2c7276af23135e896', '/bucket/object',
               {'Content-MD5': 'somestuff'})

        verify('a822deb31213ad09af37b5a7fe59e55e', '/bucket/object?acl', {})

        verify('8ecb58b876ec8cdb2f5e50d351cf384d', '/bucket/object',
               {'Content-Type': 'text/plain', 'X-Oss-A': 'test',
                'X-Oss-Z': 'whatever', 'X-Oss-B': 'lalala',
                'X-Oss-Y': 'lalalalalalala'})

        verify('f786ab8f6097b53230e71576cd5376cf', '/bucket/object',
               {'Content-Type': None, 'X-Oss-Something': 'test'})

        verify('97273be98ac6064e54f5a888cb8b1f36', '/bucket/object',
               {'Content-Type': None,
                'X-Oss-Date': 'Mon, 11 Jul 2011 10:52:57 +0000',
                'Date': 'Tue, 12 Jul 2011 10:52:57 +0000'})

        verify('ed6971e3eca5af4ee361f05d7c272e49', '/bucket/object',
               {'Content-Type': None,
                'Date': 'Tue, 12 Jul 2011 10:52:57 +0000'})

        verify('41ecd87e7329c33fea27826c1c9a6f91', '/bucket/object?cors', {})

        verify('d91b062f375d8fab407d6dab41fd154e', '/bucket/object?tagging',
               {})

        verify('ebab878a96814b30eb178e27efb3973f', '/bucket/object?restore',
               {})

        verify('f6bf1b2d92b054350d3679d28739fc69', '/bucket/object?'
               'response-cache-control&response-content-disposition&'
               'response-content-encoding&response-content-language&'
               'response-content-type&response-expires', {})

        str1 = canonical_string('/', headers={'Content-Type': None,
                                              'X-Oss-Something': 'test'})
        str2 = canonical_string('/', headers={'Content-Type': '',
                                              'X-Oss-Something': 'test'})
        str3 = canonical_string('/', headers={'X-Oss-Something': 'test'})

        self.assertEqual(str1, str2)
        self.assertEqual(str2, str3)

    def test_signed_urls_expired(self):
        expire = '1000000000'
        req = Request.blank('/bucket/object?Signature=X&Expires=%s&'
                            'OSSAccessKeyId=test:tester' % expire,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Date': self.get_date_header()})
        req.headers['Date'] = datetime.utcnow()
        req.content_type = 'text/plain'
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'AccessDenied')

    def test_signed_urls(self):
        # Set expire to last 32b timestamp value
        # This number can't be higher, because it breaks tests on 32b systems
        expire = '2147483647'  # 19 Jan 2038 03:14:07
        utc_date = datetime.utcnow()
        req = Request.blank('/bucket/object?Signature=X&Expires=%s&'
                            'OSSAccessKeyId=test:tester&Timestamp=%s' %
                            (expire, utc_date.isoformat().rsplit('.')[0]),
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Date': self.get_date_header()})
        req.content_type = 'text/plain'
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(status.split()[0], '200')
        for _, _, headers in self.swift.calls_with_headers:
            self.assertEqual(headers['Authorization'], 'OSS test:tester:X')

    def test_signed_urls_no_timestamp(self):
        expire = '2147483647'  # 19 Jan 2038 03:14:07
        req = Request.blank('/bucket/object?Signature=X&Expires=%s&'
                            'OSSAccessKeyId=test:tester' % expire,
                            environ={'REQUEST_METHOD': 'GET'})
        req.content_type = 'text/plain'
        status, headers, body = self.call_oss2swift(req)
        # Curious! But actually Oss doesn't verify any x-oss-date/date headers
        # for signed_url access and it also doesn't check timestamp
        self.assertEqual(status.split()[0], '200')
        for _, _, headers in self.swift.calls_with_headers:
            self.assertEqual(headers['Authorization'], 'OSS test:tester:X')

    def test_signed_urls_invalid_expire(self):
        expire = 'invalid'
        req = Request.blank('/bucket/object?Signature=X&Expires=%s&'
                            'OSSAccessKeyId=test:tester' % expire,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Date': self.get_date_header()})
        req.headers['Date'] = datetime.utcnow()
        req.content_type = 'text/plain'
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'AccessDenied')

    def test_signed_urls_no_sign(self):
        expire = '2147483647'  # 19 Jan 2038 03:14:07
        req = Request.blank('/bucket/object?Expires=%s&'
                            'OSSAccessKeyId=test:tester' % expire,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Date': self.get_date_header()})
        req.headers['Date'] = datetime.utcnow()
        req.content_type = 'text/plain'
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'AccessDenied')

    def test_signed_urls_no_access(self):
        expire = '2147483647'  # 19 Jan 2038 03:14:07
        req = Request.blank('/bucket/object?Expires=%s&'
                            'OSSAccessKeyId=' % expire,
                            environ={'REQUEST_METHOD': 'GET'})
        req.headers['Date'] = datetime.utcnow()
        req.content_type = 'text/plain'
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'AccessDenied')

    def test_bucket_virtual_hosted_style(self):
        req = Request.blank('/',
                            environ={'HTTP_HOST': 'bucket.localhost:80',
                                     'REQUEST_METHOD': 'HEAD',
                                     'HTTP_AUTHORIZATION':
                                     'OSS test:tester:hmac'},
                            headers={'Date': self.get_date_header()})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(status.split()[0], '200')

    def test_object_virtual_hosted_style(self):
        req = Request.blank('/object',
                            environ={'HTTP_HOST': 'bucket.localhost:80',
                                     'REQUEST_METHOD': 'HEAD',
                                     'HTTP_AUTHORIZATION':
                                     'OSS test:tester:hmac'},
                            headers={'Date': self.get_date_header()})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(status.split()[0], '200')

    def test_token_generation(self):
        self.swift.register('HEAD', '/v1/AUTH_test/bucket+segments/'
                                    'object/123456789abcdef',
                            swob.HTTPOk, {}, None)
        self.swift.register('PUT', '/v1/AUTH_test/bucket+segments/'
                                   'object/123456789abcdef/1',
                            swob.HTTPCreated, {}, None)
        req = Request.blank('/bucket/object?uploadId=123456789abcdef'
                            '&partNumber=1',
                            environ={'REQUEST_METHOD': 'PUT'})
        req.headers['Authorization'] = 'OSS test:tester:hmac'
        date_header = self.get_date_header()
        req.headers['Date'] = date_header
        status, headers, body = self.call_oss2swift(req)
        _, _, headers = self.swift.calls_with_headers[-1]
        self.assertEqual(base64.urlsafe_b64decode(
            headers['X-Auth-Token']),
            'PUT\n\n\n%s\n/bucket/object?partNumber=1&uploadId=123456789abcdef'
            % date_header)

    def test_invalid_uri(self):
        req = Request.blank('/bucket/invalid\xffname',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'InvalidURI')

    def test_object_create_bad_md5_unreadable(self):
        req = Request.blank('/bucket/object',
                            environ={'REQUEST_METHOD': 'PUT',
                                     'HTTP_AUTHORIZATION': 'OSS X:Y:Z',
                                     'HTTP_CONTENT_MD5': '#'},
                            headers={'Date': self.get_date_header()})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'InvalidDigest')

    def test_object_create_bad_md5_too_short(self):
        too_short_digest = hashlib.md5('hey').hexdigest()[:-1]
        md5_str = too_short_digest.encode('base64').strip()
        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT',
                     'HTTP_AUTHORIZATION': 'OSS X:Y:Z',
                     'HTTP_CONTENT_MD5': md5_str},
            headers={'Date': self.get_date_header()})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'InvalidDigest')

    def test_object_create_bad_md5_too_long(self):
        too_long_digest = hashlib.md5('hey').hexdigest() + 'suffix'
        md5_str = too_long_digest.encode('base64').strip()
        req = Request.blank(
            '/bucket/object',
            environ={'REQUEST_METHOD': 'PUT',
                     'HTTP_AUTHORIZATION': 'OSS X:Y:Z',
                     'HTTP_CONTENT_MD5': md5_str},
            headers={'Date': self.get_date_header()})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'InvalidDigest')

    def test_invalid_metadata_directive(self):
        req = Request.blank('/',
                            environ={'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'OSS X:Y:Z',
                                     'HTTP_X_oss_METADATA_DIRECTIVE':
                                     'invalid'},
                            headers={'Date': self.get_date_header()})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'InternalError')

    def test_invalid_storage_class(self):
        req = Request.blank('/',
                            environ={'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'OSS X:Y:Z',
                                     'HTTP_X_OSS_STORAGE_CLASS': 'INVALID'},
                            headers={'Date': self.get_date_header()})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'InvalidStorageClass')

    def _test_unsupported_header(self, header):
        req = Request.blank('/error',
                            environ={'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'OSS X:Y:Z'},
                            headers={'x-oss-' + header: 'value',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'NotImplemented')

    def test_mfa(self):
        self._test_unsupported_header('mfa')

    def test_server_side_encryption(self):
        self._test_unsupported_header('server-side-encryption')

    def test_website_redirect_location(self):
        self._test_unsupported_header('website-redirect-location')

    def _test_unsupported_resource(self, resource):
        req = Request.blank('/error?' + resource,
                            environ={'REQUEST_METHOD': 'GET',
                                     'HTTP_AUTHORIZATION': 'OSS X:Y:Z'},
                            headers={'Date': self.get_date_header()})
        status, headers, body = self.call_oss2swift(req)
        self.assertEqual(self._get_error_code(body), 'NotImplemented')

    def test_notification(self):
        self._test_unsupported_resource('notification')

    def test_policy(self):
        self._test_unsupported_resource('policy')

    def test_request_payment(self):
        self._test_unsupported_resource('requestPayment')

    def test_torrent(self):
        self._test_unsupported_resource('torrent')

    def test_website(self):
        self._test_unsupported_resource('website')

    def test_cors(self):
        self._test_unsupported_resource('cors')

    def test_tagging(self):
        self._test_unsupported_resource('tagging')

    def test_restore(self):
        self._test_unsupported_resource('restore')

    def test_unsupported_method(self):
        req = Request.blank('/bucket?acl',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'OSS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_oss2swift(req)
        elem = fromstring(body, 'Error')
        self.assertEqual(elem.find('./Code').text, 'MethodNotAllowed')
        self.assertEqual(elem.find('./Method').text, 'POST')
        self.assertEqual(elem.find('./ResourceType').text, 'ACL')

    def test_registered_defaults(self):
        filter_factory(CONF)
        swift_info = utils.get_swift_info()
        self.assertTrue('oss2swift' in swift_info)
        self.assertEqual(swift_info['oss2swift'].get('version'),
                         oss2swift.__version__)
        self.assertEqual(swift_info['oss2swift'].get('max_bucket_listing'),
                         CONF.max_bucket_listing)
        self.assertEqual(swift_info['oss2swift'].get('max_parts_listing'),
                         CONF.max_parts_listing)
        self.assertEqual(swift_info['oss2swift'].get('max_upload_part_num'),
                         CONF.max_upload_part_num)
        self.assertEqual(swift_info['oss2swift'].get('max_multi_delete_objects'),
                         CONF.max_multi_delete_objects)

    def test_check_pipeline(self):
        with nested(patch("oss2swift.middleware.CONF"),
                    patch("oss2swift.middleware.PipelineWrapper"),
                    patch("oss2swift.middleware.loadcontext")) as \
                (conf, pipeline, _):
            conf.auth_pipeline_check = True
            conf.__file__ = ''

            pipeline.return_value = 'oss2swift tempauth proxy-server'
            self.oss2swift.check_pipeline(conf)

            pipeline.return_value = 'oss2swift osstoken authtoken keystoneauth ' \
                'proxy-server'
            self.oss2swift.check_pipeline(conf)

            pipeline.return_value = 'oss2swift swauth proxy-server'
            self.oss2swift.check_pipeline(conf)

            pipeline.return_value = 'oss2swift authtoken osstoken keystoneauth ' \
                'proxy-server'
            with self.assertRaises(ValueError) as cm:
                self.oss2swift.check_pipeline(conf)
            self.assertIn('expected filter osstoken before authtoken before '
                          'keystoneauth', cm.exception.message)

            pipeline.return_value = 'oss2swift proxy-server'
            with self.assertRaises(ValueError) as cm:
                self.oss2swift.check_pipeline(conf)
            self.assertIn('expected auth between oss2swift and proxy-server',
                          cm.exception.message)

            pipeline.return_value = 'proxy-server'
            with self.assertRaises(ValueError) as cm:
                self.oss2swift.check_pipeline(conf)
            self.assertIn("missing filters ['oss2swift']",
                          cm.exception.message)

    def test_oss2swift_initialization_with_disabled_pipeline_check(self):
        with nested(patch("oss2swift.middleware.CONF"),
                    patch("oss2swift.middleware.PipelineWrapper"),
                    patch("oss2swift.middleware.loadcontext")) as \
                (conf, pipeline, _):
            # Disable pipeline check
            conf.auth_pipeline_check = False
            conf.__file__ = ''

            pipeline.return_value = 'oss2swift tempauth proxy-server'
            self.oss2swift.check_pipeline(conf)

            pipeline.return_value = 'oss2swift osstoken authtoken keystoneauth ' \
                'proxy-server'
            self.oss2swift.check_pipeline(conf)

            pipeline.return_value = 'oss2swift swauth proxy-server'
            self.oss2swift.check_pipeline(conf)

            pipeline.return_value = 'oss2swift authtoken osstoken keystoneauth ' \
                'proxy-server'
            self.oss2swift.check_pipeline(conf)

            pipeline.return_value = 'oss2swift proxy-server'
            self.oss2swift.check_pipeline(conf)

            pipeline.return_value = 'proxy-server'
            with self.assertRaises(ValueError):
                self.oss2swift.check_pipeline(conf)

        

if __name__ == '__main__':
    unittest.main()


