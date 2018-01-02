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

import hashlib
import hmac
from itertools import islice
import logging
import os
import socket
import time

from oss2 import utils
import oss2
from oss2.compat import urlparse, urlquote, to_bytes


RETRY_COUNT = 3
_ENDPOINT_TYPE_ALIYUN = 0
_ENDPOINT_TYPE_CNAME = 1
_ENDPOINT_TYPE_IP = 2
def get(value, default_value):
    if value is None:
        return default_value
    else:
        return value


connect_timeout = 60

request_retries = 3

multipart_threshold = 10 * 1024 * 1024

multipart_num_threads = 1

part_size = 10 * 1024 * 1024


connection_pool_size = 10


multiget_threshold = 100 * 1024 * 1024

multiget_num_threads = 4

multiget_part_size = 10 * 1024 * 1024
class Connection(object):
    _subresource_key_set = frozenset(
        ['response-content-type', 'response-content-language',
         'response-cache-control', 'logging', 'response-content-encoding',
         'acl', 'uploadId', 'uploads', 'partNumber', 'group', 'link',
         'delete', 'website', 'location', 'objectInfo', 'objectMeta',
         'response-expires', 'response-content-disposition', 'cors', 'lifecycle',
         'restore', 'qos', 'referer', 'append', 'position', 'security-token',
         'live', 'comp', 'status', 'vod', 'startTime', 'endTime', 'x-oss-process']
    )
    
    def __init__(self, is_cname=False, oss_access_key=os.environ.get('TESTER_ACCESS_KEY'),
                 oss_secret_key=os.environ.get('TESTER_SECRET_KEY'),
                 user_id='%s:%s' % (os.environ.get('TESTER_TENANT'),
                                    os.environ.get('TESTER_USER'))):
        """
        Initialize method.

        :param oss_access_key: a string of oss access key
        :param oss_secret_key: a string of oss secret key
        :param user_id: a string consists of TENANT and USER name used for
                        asserting Owner ID (not required OssConnection)

        In default, Connection class will be initialized as tester user
        behaves as:
        user_test_tester = testing .admin

        """
        self.oss_access_key = oss_access_key
        self.oss_secret_key = oss_secret_key
        self.user_id = user_id
        swift_host = os.environ.get('SWIFT_HOST').split(':')
        self.host = swift_host[0]
        self.port = int(swift_host[1]) if len(swift_host) == 2 else 80
        self.auth = \
            oss2.Auth(oss_access_key, oss_secret_key)
        self.region = self.host
        self.endpoint = _normalize_endpoint(self.region)
        self.service = oss2.Service(self.auth, self.endpoint)
        self._make_url = _UrlMaker(self.endpoint, is_cname)
        timeout = None
        self.timeout = get(timeout, connect_timeout)
        self.session = oss2.http.Session()
    def reset(self):
        for i in range(RETRY_COUNT):
            try:
                buckets = oss2.BucketIterator(self.service)
                if not buckets:
                    break

                for bucket in buckets:
                    try:
                        bucket = oss2.Bucket(self.auth, self.region, str(bucket.name))
                        for obj in islice(oss2.ObjectIterator(bucket), 10):
                            bucket.delete_object(obj.key)
                            
                        try:
                            bucket.delete_bucket()
                        except oss2.exceptions.BucketNotEmpty:
                            print('bucket is not empty.')
                        except oss2.exceptions.NoSuchBucket:
                            print('bucket does not exist')
                    except oss2.exceptions.ClientError:
                        pass  
            except oss2.exceptions.ClientError:
                        pass                      
    def make_request(self, method, bucket='', obj='', headers=None, body='',
                     query=None):
        req = oss2.http.Request(method, self._make_url(bucket, obj), data=body,
                                   params=query, headers=headers)
        self._sign_request(req, bucket, obj)
        resp = self.session.do_request(req, timeout=self.timeout)
        return resp.status, dict(resp.headers), resp.read()
    def get_request(self, method, bucket='', obj='', headers=None, body='',
                     query=None):
        req = oss2.http.Request(method, self._make_url(bucket, obj), data=body,
                                   params=query, headers=headers)
        self._sign_request(req, bucket, obj)
        return req
    def generate_url_and_headers(self, method, bucket='', obj='',
                                 expires_in=3600):
        expiration_time = int(time.time()) + expires_in
        req = self.get_request(method, bucket, obj)
        req.headers['date'] = str(expiration_time)
        signature = self.__make_signature(req, bucket, obj)

        req.params['OSSAccessKeyId'] = self.oss_access_key
        req.params['Expires'] = str(expiration_time)
        req.params['Signature'] = signature
        url=req.url + '?' + '&'.join(_param_to_quoted_query(k, v) for k, v in req.params.items())
        return url, {}
    def _sign_request(self,req, bucket_name, key):
        req.headers['date'] = oss2.utils.http_date()

        signature = self.__make_signature(req, bucket_name, key)
        req.headers['authorization'] = "OSS {0}:{1}".format(self.oss_access_key, signature)
    def __make_signature(self,req, bucket_name, key):
        string_to_sign = self.__get_string_to_sign(req, bucket_name, key)
    
        logging.debug('string_to_sign={0}'.format(string_to_sign))
    
        h = hmac.new(to_bytes(self.oss_secret_key), to_bytes(string_to_sign), hashlib.sha1)
        return utils.b64encode_as_string(h.digest())
    def __get_string_to_sign(self,req, bucket_name, key):
        resource_string = self.__get_resource_string(req, bucket_name, key)
        headers_string = self.__get_headers_string(req)
    
        content_md5 = req.headers.get('content-md5', '')
        content_type = req.headers.get('content-type', '')
        date = req.headers.get('date', '')
        return '\n'.join([req.method,
                              content_md5,
                              content_type,
                              date,
                              headers_string + resource_string])
    
    def __get_headers_string(self,req):
        headers = req.headers
        canon_headers = []
        for k, v in headers.items():
            lower_key = k.lower()
            if lower_key.startswith('x-oss-'):
                canon_headers.append((lower_key, v))
    
        canon_headers.sort(key=lambda x: x[0])
    
        if canon_headers:
            return '\n'.join(k + ':' + v for k, v in canon_headers) + '\n'
        else:
            return ''
    
    def __get_resource_string(self,req, bucket_name, key):
        if not bucket_name:
            return '/'
        else:
            print type(req.params)
            return '/{0}/{1}{2}'.format(bucket_name, key, self.__get_subresource_string(req.params))
    
    def __get_subresource_string(self,params):
        if not params:
            return ''
    
        subresource_params = []
        for key, value in params.items():
            if key in self._subresource_key_set:
                subresource_params.append((key, value))
    
        subresource_params.sort(key=lambda e: e[0])
    
        if subresource_params:
            return '?' + '&'.join(self.__param_to_query(k, v) for k, v in subresource_params)
        else:
            return ''
    
    def __param_to_query(self,k, v):
        if v:
            return k + '=' + v
        else:
            return k
def _param_to_quoted_query(k, v):
    if v:
        return urlquote(k, '') + '=' + urlquote(v, '')
    else:
        return urlquote(k, '')
def _normalize_endpoint(region):
    if not region.startswith('http://') and not region.startswith('https://'):
        return 'http://' + region
    else:
        return region
def get_admin_connection():
    """
    Return tester connection behaves as:
    user_test_admin = admin .admin
    """
    oss_access_key = os.environ.get('ADMIN_ACCESS_KEY')
    oss_secret_key = os.environ.get('ADMIN_SECRET_KEY')
    user_id = os.environ.get('ADMIN_TENANT') + ':' + \
        os.environ.get('ADMIN_USER')
    return Connection(oss_access_key, oss_secret_key, user_id)


def get_tester2_connection():
    """
    Return tester2 connection behaves as:
    user_test_tester2 = testing2
    """
    oss_access_key = os.environ.get('TESTER2_ACCESS_KEY')
    oss_secret_key = os.environ.get('TESTER2_SECRET_KEY')
    user_id = os.environ.get('TESTER2_TENANT') + ':' + \
        os.environ.get('TESTER2_USER')
    return Connection(oss_access_key, oss_secret_key, user_id)
_ALPHA_NUM = 'abcdefghijklmnopqrstuvwxyz0123456789'
_HYPHEN = '-'
_BUCKET_NAME_CHARS = set(_ALPHA_NUM + _HYPHEN)


def is_valid_bucket_name(name):
    if len(name) < 3 or len(name) > 63:
        return False

    if name[-1] == _HYPHEN:
        return False

    if name[0].lower() not in _ALPHA_NUM:
        return False

    return set(name.lower()) <= _BUCKET_NAME_CHARS

def is_ip_or_localhost(netloc):
    loc = netloc.split(':')[0]
    if loc == 'localhost':
        return True

    try:
        socket.inet_aton(loc)
    except socket.error:
        return False

    return True
def _determine_endpoint_type(netloc, is_cname, bucket_name):
    if is_ip_or_localhost(netloc):
        return _ENDPOINT_TYPE_IP

    if is_cname:
        return _ENDPOINT_TYPE_CNAME

    if is_valid_bucket_name(bucket_name):
        return _ENDPOINT_TYPE_ALIYUN
    else:
        return _ENDPOINT_TYPE_IP

class _UrlMaker(object):
    def __init__(self, endpoint, is_cname):
        p = urlparse(endpoint)

        self.scheme = p.scheme
        self.netloc = p.netloc
        self.is_cname = is_cname

    def __call__(self, bucket_name, key):
        self.type = _determine_endpoint_type(self.netloc, self.is_cname, bucket_name)

        key = urlquote(key, '')

        if self.type == _ENDPOINT_TYPE_CNAME:
            return '{0}://{1}/{2}'.format(self.scheme, self.netloc, key)

        if self.type == _ENDPOINT_TYPE_IP:
            if bucket_name:
                return '{0}://{1}/{2}/{3}'.format(self.scheme, self.netloc, bucket_name, key)
            else:
                return '{0}://{1}/{2}'.format(self.scheme, self.netloc, key)

        if not bucket_name:
            assert not key
            return '{0}://{1}'.format(self.scheme, self.netloc)

        return '{0}://{1}.{2}/{3}'.format(self.scheme, bucket_name, self.netloc, key)

