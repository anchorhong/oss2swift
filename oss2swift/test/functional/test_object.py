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

from cStringIO import StringIO
from distutils.version import StrictVersion
from email.utils import formatdate, parsedate
from hashlib import md5
from multifile import MultiFile
import os
from time import mktime
import unittest
from urllib import quote

import oss2

from oss2swift.etree import fromstring
from oss2swift.test.functional import Oss2swiftFunctionalTestCase
from oss2swift.test.functional.oss_test_client import Connection
from oss2swift.test.functional.utils import get_error_code, \
    calculate_md5


# For an issue with venv and distutils, disable pylint message here
# pylint: disable-msg=E0611,F0401
DAY = 86400.0  # 60 * 60 * 24 (sec)

class TestOss2swiftObject(Oss2swiftFunctionalTestCase):
    def setUp(self):
        super(TestOss2swiftObject, self).setUp()
        self.bucket = 'bucket'
        self.conn.make_request('PUT', self.bucket)

    def _assertObjectEtag(self, bucket, obj, etag):
        status, headers, _ = self.conn.make_request('HEAD', bucket, obj)
        self.assertEqual(status, 200)  # sanity
        self.assertCommonResponseHeaders(headers, etag)

    def test_object(self):
        obj = 'object name with %-sign'
        content = 'abc123'
        etag = md5(content).hexdigest()

        # PUT Object
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, body=content)
        self.assertEqual(status, 200)

        self.assertCommonResponseHeaders(headers)
        self.assertTrue('Content-Length' in headers)  # sanity
        self.assertEqual(headers['Content-Length'], '0')
        self._assertObjectEtag(self.bucket, obj, etag)

        # PUT Object Copy
        dst_bucket = 'dst-bucket'
        dst_obj = 'dst_obj'
        self.conn.make_request('PUT', dst_bucket)
        headers = {'x-oss-copy-source': '/%s/%s' % (self.bucket, obj)}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj,
                                   headers=headers)
        self.assertEqual(status, 200)

        # PUT Object Copy with URL-encoded Source
        dst_bucket = 'dst-bucket'
        dst_obj = 'dst_obj'
        self.conn.make_request('PUT', dst_bucket)
        headers = {'x-oss-copy-source': quote('/%s/%s' % (self.bucket, obj))}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj,
                                   headers=headers)
        self.assertEqual(status, 200)

        self.assertCommonResponseHeaders(headers)
        self.assertEqual(headers['Content-Length'], str(len(body)))

        elem = fromstring(body, 'CopyObjectResult')
        self.assertTrue(elem.find('LastModified').text is not None)
        last_modified_xml = elem.find('LastModified').text
        self.assertTrue(elem.find('ETag').text is not None)
        self.assertEqual(etag, elem.find('ETag').text.strip('"'))
        self._assertObjectEtag(dst_bucket, dst_obj, etag)

        # Check timestamp on Copy:
        status, headers, body = \
            self.conn.make_request('GET', dst_bucket)
        self.assertEqual(status, 200)
        elem = fromstring(body, 'ListBucketResult')

        # FIXME: COPY result drops milli/microseconds but GET doesn't
        self.assertEqual(
            elem.find('Contents').find("LastModified").text.rsplit('.', 1)[0],
            last_modified_xml.rsplit('.', 1)[0])

        # GET Object
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj)
        self.assertEqual(status, 200)

        self.assertCommonResponseHeaders(headers, etag)
        self.assertTrue(headers['Last-Modified'] is not None)
        self.assertTrue(headers['Content-Type'] is not None)
        self.assertEqual(headers['Content-Length'], str(len(content)))

        # HEAD Object
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj)
        self.assertEqual(status, 200)

        self.assertCommonResponseHeaders(headers, etag)
        self.assertTrue(headers['Last-Modified'] is not None)
        self.assertTrue('Content-Type' in headers)
        self.assertEqual(headers['Content-Length'], str(len(content)))

        # DELETE Object
        status, headers, body = \
            self.conn.make_request('DELETE', self.bucket, obj)
        self.assertEqual(status, 204)
        self.assertCommonResponseHeaders(headers)

    def test_put_object_error(self):
        auth_error_conn = Connection(oss_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('PUT', self.bucket, 'object')
        self.assertEqual(get_error_code(body), 'SignatureDoesNotMatch')
        self.assertEqual(headers['Content-Type'], 'application/xml')

        status, headers, body = \
            self.conn.make_request('PUT', 'bucket2', 'object')
        self.assertEqual(get_error_code(body), 'NoSuchBucket')
        self.assertEqual(headers['Content-Type'], 'application/xml')

    def test_put_object_copy_error(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)
        dst_bucket = 'dst-bucket'
        self.conn.make_request('PUT', dst_bucket)
        dst_obj = 'dst_object'

        headers = {'x-oss-copy-source': '/%s/%s' % (self.bucket, obj)}
        auth_error_conn = Connection(oss_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('PUT', dst_bucket, dst_obj, headers)
        self.assertEqual(get_error_code(body), 'SignatureDoesNotMatch')
        self.assertEqual(headers['Content-Type'], 'application/xml')

        # /src/nothing -> /dst/dst
        headers = {'X-Oss-Copy-Source': '/%s/%s' % (self.bucket, 'nothing')}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers)
        self.assertEqual(get_error_code(body), 'NoSuchKey')
        self.assertEqual(headers['Content-Type'], 'application/xml')

        # /nothing/src -> /dst/dst
        headers = {'X-Oss-Copy-Source': '/%s/%s' % ('nothing', obj)}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers)
        # TODO: source bucket is not check.
        # self.assertEqual(get_error_code(body), 'NoSuchBucket')

        # /src/src -> /nothing/dst
        headers = {'X-Oss-Copy-Source': '/%s/%s' % (self.bucket, obj)}
        status, headers, body = \
            self.conn.make_request('PUT', 'nothing', dst_obj, headers)
        self.assertEqual(get_error_code(body), 'NoSuchBucket')
        self.assertEqual(headers['Content-Type'], 'application/xml')

    def test_get_object_error(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        auth_error_conn = Connection(oss_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('GET', self.bucket, obj)
        self.assertEqual(get_error_code(body), 'SignatureDoesNotMatch')
        self.assertEqual(headers['Content-Type'], 'application/xml')

        status, headers, body = \
            self.conn.make_request('GET', self.bucket, 'invalid')
        self.assertEqual(get_error_code(body), 'NoSuchKey')
        self.assertEqual(headers['Content-Type'], 'application/xml')

        status, headers, body = self.conn.make_request('GET', 'invalid', obj)
        # TODO; requires consideration
        # self.assertEqual(get_error_code(body), 'NoSuchBucket')
        self.assertEqual(get_error_code(body), 'NoSuchKey')
        self.assertEqual(headers['Content-Type'], 'application/xml')

    def test_head_object_error(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        auth_error_conn = Connection(oss_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('HEAD', self.bucket, obj)
        self.assertEqual(status, 403)
        self.assertEqual(body, '')  # sanity
        self.assertEqual(headers['Content-Type'], 'application/xml')

        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, 'invalid')
        self.assertEqual(status, 404)
        self.assertEqual(body, '')  # sanity
        self.assertEqual(headers['Content-Type'], 'application/xml')

        status, headers, body = \
            self.conn.make_request('HEAD', 'invalid', obj)
        self.assertEqual(status, 404)
        self.assertEqual(body, '')  # sanity
        self.assertEqual(headers['Content-Type'], 'application/xml')

    def test_delete_object_error(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        auth_error_conn = Connection(oss_secret_key='invalid')
        status, headers, body = \
            auth_error_conn.make_request('DELETE', self.bucket, obj)
        self.assertEqual(get_error_code(body), 'SignatureDoesNotMatch')
        self.assertEqual(headers['Content-Type'], 'application/xml')

        status, headers, body = \
            self.conn.make_request('DELETE', self.bucket, 'invalid')
        self.assertEqual(get_error_code(body), 'NoSuchKey')
        self.assertEqual(headers['Content-Type'], 'application/xml')

        status, headers, body = \
            self.conn.make_request('DELETE', 'invalid', obj)
        self.assertEqual(get_error_code(body), 'NoSuchBucket')
        self.assertEqual(headers['Content-Type'], 'application/xml')

    def test_put_object_content_encoding(self):
        obj = 'object'
        etag = md5().hexdigest()
        headers = {'Content-Encoding': 'gzip'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, headers)
        self.assertEqual(status, 200)
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj)
        self.assertTrue('Content-Encoding' in headers)  # sanity
        self.assertEqual(headers['Content-Encoding'], 'gzip')
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, obj, etag)

    def test_put_object_content_md5(self):
        obj = 'object'
        content = 'abcdefghij'
        etag = md5(content).hexdigest()
        headers = {'Content-MD5': calculate_md5(content)}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, headers, content)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, obj, etag)

    def test_put_object_content_type(self):
        obj = 'object'
        content = 'abcdefghij'
        etag = md5(content).hexdigest()
        headers = {'Content-Type': 'text/plain'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, headers, content)
        self.assertEqual(status, 200)
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj)
        self.assertEqual(headers['Content-Type'], 'text/plain')
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, obj, etag)

    def test_put_object_conditional_requests(self):
        obj = 'object'
        content = 'abcdefghij'
        headers = {'If-None-Match': '*'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, headers, content)
        self.assertEqual(status, 501)

        headers = {'If-Match': '*'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, headers, content)
        self.assertEqual(status, 501)

        headers = {'If-Modified-Since': 'Sat, 27 Jun 2015 00:00:00 GMT'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, headers, content)
        self.assertEqual(status, 501)

        headers = {'If-Unmodified-Since': 'Sat, 27 Jun 2015 00:00:00 GMT'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, headers, content)
        self.assertEqual(status, 501)

        # None of the above should actually have created an object
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj, {}, '')
        self.assertEqual(status, 404)

    def test_put_object_expect(self):
        obj = 'object'
        content = 'abcdefghij'
        etag = md5(content).hexdigest()
        headers = {'Expect': '100-continue'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, headers, content)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, obj, etag)

    def _test_put_object_headers(self, req_headers):
        obj = 'object'
        content = 'abcdefghij'
        etag = md5(content).hexdigest()
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj,
                                   req_headers, content)
        self.assertEqual(status, 200)
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj)
        for header, value in req_headers.items():
            self.assertIn(header, headers)
            self.assertEqual(headers[header], value)
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, obj, etag)

    def test_put_object_metadata(self):
        self._test_put_object_headers({
            'X-Oss-Meta-Bar': 'foo',
            'X-Oss-Meta-Bar2': 'foo2'})

    def test_put_object_content_headers(self):
        self._test_put_object_headers({
            'Content-Type': 'foo/bar',
            'Content-Encoding': 'baz',
            'Content-Disposition': 'attachment',
            'Content-Language': 'en'})

    def test_put_object_cache_control(self):
        self._test_put_object_headers({
            'Cache-Control': 'private, some-extension'})

    def test_put_object_expires(self):
        self._test_put_object_headers({
            # We don't validate that the Expires header is a valid date
            'Expires': 'a valid HTTP-date timestamp'})

    def test_put_object_robots_tag(self):
        self._test_put_object_headers({
            'X-Robots-Tag': 'googlebot: noarchive'})

    def test_put_object_storage_class(self):
        obj = 'object'
        content = 'abcdefghij'
        etag = md5(content).hexdigest()
        headers = {'X-Oss-Storage-Class': 'STANDARD'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, headers, content)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, obj, etag)

    def test_put_object_copy_source(self):
        obj = 'object'
        content = 'abcdefghij'
        etag = md5(content).hexdigest()
        self.conn.make_request('PUT', self.bucket, obj, body=content)

        dst_bucket = 'dst-bucket'
        dst_obj = 'dst_object'
        self.conn.make_request('PUT', dst_bucket)

        # /src/src -> /dst/dst
        headers = {'X-Oss-Copy-Source': '/%s/%s' % (self.bucket, obj)}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(dst_bucket, dst_obj, etag)

        # /src/src -> /src/dst
        headers = {'X-Oss-Copy-Source': '/%s/%s' % (self.bucket, obj)}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, dst_obj, headers)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, dst_obj, etag)

        # /src/src -> /src/src
        # need changes to copy itself (e.g. metadata)
        headers = {'X-Oss-Copy-Source': '/%s/%s' % (self.bucket, obj),
                   'X-Oss-Meta-Foo': 'bar',
                   'X-Oss-Metadata-Directive': 'REPLACE'}
        status, headers, body = \
            self.conn.make_request('PUT', self.bucket, obj, headers)
        self.assertEqual(status, 200)
        self._assertObjectEtag(self.bucket, obj, etag)
        self.assertCommonResponseHeaders(headers)

    def test_put_object_copy_metadata_directive(self):
        obj = 'object'
        src_headers = {'X-Oss-Meta-Test': 'src'}
        dst_bucket = 'dst-bucket'
        dst_obj = 'dst_object'
        self.conn.make_request('PUT', self.bucket, obj, headers=src_headers)
        self.conn.make_request('PUT', dst_bucket)

        headers = {'X-Oss-Copy-Source': '/%s/%s' % (self.bucket, obj),
                   'X-Oss-Metadata-Directive': 'REPLACE',
                   'X-Oss-Meta-Test': 'dst'}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)
        status, headers, body = \
            self.conn.make_request('HEAD', dst_bucket, dst_obj)
        self.assertEqual(headers['x-oss-meta-test'], 'dst')

    def test_put_object_copy_source_if_modified_since(self):
        obj = 'object'
        dst_bucket = 'dst-bucket'
        dst_obj = 'dst_object'
        etag = md5().hexdigest()
        self.conn.make_request('PUT', self.bucket, obj)
        self.conn.make_request('PUT', dst_bucket)

        _, headers, _ = self.conn.make_request('HEAD', self.bucket, obj)
        src_datetime = mktime(parsedate(headers['Last-Modified']))
        src_datetime = src_datetime - DAY
        headers = {'X-Oss-Copy-Source': '/%s/%s' % (self.bucket, obj),
                   'X-Oss-Copy-Source-If-Modified-Since':
                   formatdate(src_datetime)}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers=headers)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, obj, etag)

    def test_put_object_copy_source_if_unmodified_since(self):
        obj = 'object'
        dst_bucket = 'dst-bucket'
        dst_obj = 'dst_object'
        etag = md5().hexdigest()
        self.conn.make_request('PUT', self.bucket, obj)
        self.conn.make_request('PUT', dst_bucket)

        _, headers, _ = self.conn.make_request('HEAD', self.bucket, obj)
        src_datetime = mktime(parsedate(headers['Last-Modified']))
        src_datetime = src_datetime + DAY
        headers = {'X-Oss-Copy-Source': '/%s/%s' % (self.bucket, obj),
                   'X-Oss-Copy-Source-If-Unmodified-Since':
                   formatdate(src_datetime)}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers=headers)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, obj, etag)

    def test_put_object_copy_source_if_match(self):
        obj = 'object'
        dst_bucket = 'dst-bucket'
        dst_obj = 'dst_object'
        etag = md5().hexdigest()
        self.conn.make_request('PUT', self.bucket, obj)
        self.conn.make_request('PUT', dst_bucket)

        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj)

        headers = {'X-Oss-Copy-Source': '/%s/%s' % (self.bucket, obj),
                   'X-Oss-Copy-Source-If-Match': etag}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers=headers)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, obj, etag)

    def test_put_object_copy_source_if_none_match(self):
        obj = 'object'
        dst_bucket = 'dst-bucket'
        dst_obj = 'dst_object'
        etag = md5().hexdigest()
        self.conn.make_request('PUT', self.bucket, obj)
        self.conn.make_request('PUT', dst_bucket)

        headers = {'X-Oss-Copy-Source': '/%s/%s' % (self.bucket, obj),
                   'X-Oss-Copy-Source-If-None-Match': 'none-match'}
        status, headers, body = \
            self.conn.make_request('PUT', dst_bucket, dst_obj, headers=headers)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)
        self._assertObjectEtag(self.bucket, obj, etag)

    def test_get_object_response_content_type(self):
        obj = 'obj'
        self.conn.make_request('PUT', self.bucket, obj)

        query = {'response-Content-Type':'application/octet-stream'}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, query=query)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)
        self.assertEqual(headers['Content-Type'], 'application/octet-stream')

    def test_get_object_response_content_language(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        query = {'response-content-language':'en'}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, query=query)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)
        self.assertEqual(headers['Content-Language'], 'en')

    def test_get_object_response_cache_control(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        query = {'response-cache-control':'private'}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, query=query)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)
        self.assertEqual(headers['Cache-Control'], 'private')

    def test_get_object_response_content_disposition(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        query = {'response-content-disposition':'inline'}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, query=query)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)
        self.assertEqual(headers['Content-Disposition'], 'inline')

    def test_get_object_response_content_encoding(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        query = {'response-content-encoding':'gzip'}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, query=query)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)
        self.assertEqual(headers['Content-Encoding'], 'gzip')

    def test_get_object_range(self):
        obj = 'object'
        content = 'abcdefghij'
        headers = {'x-oss-meta-test': 'swift'}
        self.conn.make_request(
            'PUT', self.bucket, obj, headers=headers, body=content)

        headers = {'Range': 'bytes=1-5'}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, headers=headers)
        self.assertEqual(status, 206)
        self.assertCommonResponseHeaders(headers)
        self.assertTrue('Content-Length' in headers)
        self.assertEqual(headers['Content-Length'], '5')
        self.assertTrue('x-oss-meta-test' in headers)
        self.assertEqual('swift', headers['x-oss-meta-test'])
        self.assertEqual(body, 'bcdef')

        headers = {'Range': 'bytes=5-'}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, headers=headers)
        self.assertEqual(status, 206)
        self.assertCommonResponseHeaders(headers)
        self.assertTrue('Content-Length' in headers)
        self.assertEqual(headers['Content-Length'], '5')
        self.assertTrue('x-oss-meta-test' in headers)
        self.assertEqual('swift', headers['x-oss-meta-test'])
        self.assertEqual(body, 'fghij')

        headers = {'Range': 'bytes=-5'}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, headers=headers)
        self.assertEqual(status, 206)
        self.assertCommonResponseHeaders(headers)
        self.assertTrue('Content-Length' in headers)
        self.assertEqual(headers['Content-Length'], '5')
        self.assertTrue('x-oss-meta-test' in headers)
        self.assertEqual('swift', headers['x-oss-meta-test'])
        self.assertEqual(body, 'fghij')

        ranges = ['1-2', '4-5']

        headers = {'Range': 'bytes=%s' % ','.join(ranges)}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, headers=headers)
        self.assertEqual(status, 206)
        self.assertCommonResponseHeaders(headers)
        self.assertTrue('Content-Length' in headers)

        self.assertTrue('Content-Type' in headers)  # sanity
        content_type, boundary = headers['Content-Type'].split(';')

        self.assertEqual('multipart/byteranges', content_type)
        self.assertTrue(boundary.startswith('boundary='))  # sanity
        boundary_str = boundary[len('boundary='):]

        sio = StringIO(body)
        mfile = MultiFile(sio)
        mfile.push(boundary_str)

        def check_line_header(line, expected_key, expected_value):
            key, value = line.split(':', 1)
            self.assertEqual(expected_key, key.strip())
            self.assertEqual(expected_value, value.strip())

        for range_value in ranges:
            start, end = map(int, range_value.split('-'))
            # go to next section and check sanity
            self.assertTrue(mfile.next())

            lines = mfile.readlines()
            # first line should be Content-Type which
            # includes original Content-Type
            # e.g. Content-Type: application/octet-stream
            check_line_header(
                lines[0].strip(), 'Content-Type', 'application/octet-stream')

            # second line should be byte range information
            # e.g. Content-Range: bytes 1-2/11
            expected_range = 'bytes %s/%s' % (range_value, len(content))
            check_line_header(
                lines[1].strip(), 'Content-Range', expected_range)
            # rest
            rest = [line for line in lines[2:] if line.strip()]
            self.assertEqual(1, len(rest))  # sanity
            self.assertTrue(content[start:end], rest[0])

        # no next section
        self.assertFalse(mfile.next())  # sanity

    def test_get_object_if_modified_since(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        _, headers, _ = self.conn.make_request('HEAD', self.bucket, obj)
        src_datetime = mktime(parsedate(headers['Last-Modified']))
        src_datetime = src_datetime - DAY
        headers = {'If-Modified-Since': formatdate(src_datetime)}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, headers=headers)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)

    def test_get_object_if_unmodified_since(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        _, headers, _ = self.conn.make_request('HEAD', self.bucket, obj)
        src_datetime = mktime(parsedate(headers['Last-Modified']))
        src_datetime = src_datetime + DAY
        headers = \
            {'If-Unmodified-Since': formatdate(src_datetime)}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, headers=headers)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)

    def test_get_object_if_match(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj)
        etag = headers['ETag']

        headers = {'If-Match': etag}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, headers=headers)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)

    def test_get_object_if_none_match(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        headers = {'If-None-Match': 'none-match'}
        status, headers, body = \
            self.conn.make_request('GET', self.bucket, obj, headers=headers)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)

    def test_head_object_range(self):
        obj = 'object'
        content = 'abcdefghij'
        self.conn.make_request('PUT', self.bucket, obj, body=content)

        headers = {'Range': 'bytes=1-5'}
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj, headers=headers)
        self.assertEqual(headers['Content-Length'], '5')
        self.assertCommonResponseHeaders(headers)

        headers = {'Range': 'bytes=5-'}
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj, headers=headers)
        self.assertEqual(headers['Content-Length'], '5')
        self.assertCommonResponseHeaders(headers)

        headers = {'Range': 'bytes=-5'}
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj, headers=headers)
        self.assertEqual(headers['Content-Length'], '5')
        self.assertCommonResponseHeaders(headers)

    def test_head_object_if_modified_since(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        _, headers, _ = self.conn.make_request('HEAD', self.bucket, obj)
        dt = mktime(parsedate(headers['Last-Modified']))
        dt = dt - DAY

        headers = {'If-Modified-Since': formatdate(dt)}
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj, headers=headers)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)

    def test_head_object_if_unmodified_since(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        _, headers, _ = self.conn.make_request('HEAD', self.bucket, obj)
        dt = mktime(parsedate(headers['Last-Modified']))
        dt = dt + DAY

        headers = {'If-Unmodified-Since': formatdate(dt)}
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj, headers=headers)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)

    def test_head_object_if_match(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj)
        etag = headers['ETag']

        headers = {'If-Match': etag}
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj, headers=headers)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)

    def test_head_object_if_none_match(self):
        obj = 'object'
        self.conn.make_request('PUT', self.bucket, obj)

        headers = {'If-None-Match': 'none-match'}
        status, headers, body = \
            self.conn.make_request('HEAD', self.bucket, obj, headers=headers)
        self.assertEqual(status, 200)
        self.assertCommonResponseHeaders(headers)


@unittest.skipIf(os.environ['AUTH'] == 'tempauth',
                 'v4 is supported only in keystone')
class TestOss2swiftObjectSigV4(TestOss2swiftObject):
    @classmethod
    def setUpClass(cls):
        os.environ['Oss_USE_SIGV4'] = "True"

    @classmethod
    def tearDownClass(cls):
        del os.environ['Oss_USE_SIGV4']

    @unittest.skipIf(StrictVersion(oss2.__version__) < StrictVersion('3.0'),
                     'This stuff got the signing issue of oss2<=2.x')
    def test_put_object_metadata(self):
        super(TestOss2swiftObjectSigV4, self).test_put_object_metadata()

    @unittest.skipIf(StrictVersion(oss2.__version__) < StrictVersion('3.0'),
                     'This stuff got the signing issue of oss2<=2.x')
    def test_put_object_copy_source_if_modified_since(self):
        super(TestOss2swiftObjectSigV4, self).\
            test_put_object_copy_source_if_modified_since()

    @unittest.skipIf(StrictVersion(oss2.__version__) < StrictVersion('3.0'),
                     'This stuff got the signing issue of oss2<=2.x')
    def test_put_object_copy_source_if_unmodified_since(self):
        super(TestOss2swiftObjectSigV4, self).\
            test_put_object_copy_source_if_unmodified_since()

    @unittest.skipIf(StrictVersion(oss2.__version__) < StrictVersion('3.0'),
                     'This stuff got the signing issue of oss2<=2.x')
    def test_put_object_copy_source_if_match(self):
        super(TestOss2swiftObjectSigV4,
              self).test_put_object_copy_source_if_match()

    @unittest.skipIf(StrictVersion(oss2.__version__) < StrictVersion('3.0'),
                     'This stuff got the signing issue of oss2<=2.x')
    def test_put_object_copy_source_if_none_match(self):
        super(TestOss2swiftObjectSigV4,
              self).test_put_object_copy_source_if_none_match()


if __name__ == '__main__':
    unittest.main()
