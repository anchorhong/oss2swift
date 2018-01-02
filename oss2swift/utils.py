# -*- coding: utf-8 -*-
import base64
import calendar
import datetime
import email.utils
import os
import re
import socket
import threading
import time
from urllib import unquote
import uuid

import crcmod
from exception import ClientError
from oss2swift.cfg import CONF
from swift.common import utils
from swift.common.swob import HTTPPreconditionFailed
from swift.common.utils import get_logger


# Need for check_path_header
LOGGER = get_logger(CONF, log_route='oss2swift')

MULTIUPLOAD_SUFFIX = '+segments'


def sysmeta_prefix(resource):
    """
    Returns the system metadata prefix for given resource type.
    """
    if resource == 'object':
        return 'x-object-sysmeta-oss2swift-'
    else:
        return 'x-container-sysmeta-oss2swift-'


def sysmeta_header(resource, name):
    """
    Returns the system metadata header for given resource type and name.
    """
    return sysmeta_prefix(resource) + name


def camel_to_snake(camel):
    return re.sub('(.)([A-Z])', r'\1_\2', camel).lower()


def snake_to_camel(snake):
    return snake.title().replace('_', '')

def to_string(data):
        if isinstance(data, bytes):
            return data.decode('utf-8')
        else:
            return data
def unique_id():
    return base64.urlsafe_b64encode(str(uuid.uuid4()))


def utf8encode(s):
    if isinstance(s, unicode):
        s = s.encode('utf8')
    return s


def utf8decode(s):
    if isinstance(s, str):
        s = s.decode('utf8')
    return s

def filterbadcode(s):
     #s=re.sub(r'[\x00-\x08\x0b\x0c\x0d\x0e\x1f\x7f]', '', s)
    s=re.sub(r'[\x0C\x0D\x0E\x7F]', '', s)
    return s

def check_path_header(req, name, length, error_msg):
    """
    Validate that the value of path-like header is
    well formatted. We assume the caller ensures that
    specific header is present in req.headers.

    :param req: HTTP request object
    :param name: header name
    :param length: length of path segment check
    :param error_msg: error message for client
    :returns: A tuple with path parts according to length
    :raise: HTTPPreconditionFailed if header value
            is not well formatted.
    """
    src_header = unquote(req.headers.get(name))
    if not src_header.startswith('/'):
        src_header = '/' + src_header
    try:
        return utils.split_path(src_header, length, length, True)
    except ValueError:
        raise HTTPPreconditionFailed(
            request=req,
            body=error_msg)


def is_valid_ipv6(ip):
    # FIXME: replace with swift.common.ring.utils is_valid_ipv6
    #        when oss2swift requires swift 2.3 or later
    #        --or--
    #        swift.common.utils is_valid_ipv6 when oss2swift requires swift>2.9
    """
    Returns True if the provided ip is a valid IPv6-address
    """
    try:
        socket.inet_pton(socket.AF_INET6, ip)
    except socket.error:  # not a valid IPv6 address
        return False
    return True


_ALPHA_NUM = 'abcdefghijklmnopqrstuvwxyz0123456789'
_HYPHEN = '-'
_BUCKET_NAME_CHARS = set(_ALPHA_NUM + _HYPHEN)


def validate_bucket_name(name):
    """Validates the name of the bucket against Oss criteria,True is valid, False is invalid"""
    if len(name) < 3 or len(name) > 63:
        return False
 
    if name[-1] == _HYPHEN:
        return False
 
    if name[0].lower() not in _ALPHA_NUM:
        return False
 
    return set(name) <= _BUCKET_NAME_CHARS


class OssTimestamp(utils.Timestamp):
    @property
    def ossxmlformat(self):
        # return self.isoformat[:-7] + '.000Z'
        return unixtime_to_iso8601(self)

    @property
    def oss_date_format(self):
        """
        this format should be like 'YYYYMMDDThhmmssZ'
        """
        return self.isoformat.replace(
            '-', '').replace(':', '')[:-7] + 'Z'

    @classmethod
    def now(cls):
        return cls(time.time())


def mktime(timestamp_str, time_format='%Y-%m-%dT%H:%M:%S'):
    """
    mktime creates a float instance in epoch time really like as time.mktime

    the difference from time.mktime is allowing to 2 formats string for the
    argument for the Oss testing usage.
    TODO: support

    :param timestamp_str: a string of timestamp formatted as
                          (a) RFC2822 (e.g. date header)
                          (b) %Y-%m-%dT%H:%M:%S (e.g. copy result)
    :param time_format: a string of format to parse in (b) process
    :return : a float instance in epoch time
    """
    # time_tuple is the *remote* local time
    time_tuple = email.utils.parsedate_tz(timestamp_str)
    if time_tuple is None:
        time_tuple = time.strptime(timestamp_str, time_format)
        # add timezone info as utc (no time difference)
        time_tuple += (0, )

    # We prefer calendar.gmtime and a manual adjustment over
    # email.utils.mktime_tz because older versions of Python (<2.7.4) may
    # double-adjust for timezone in some situations (such when swift changes
    # os.environ['TZ'] without calling time.tzset()).
    epoch_time = calendar.timegm(time_tuple) - time_tuple[9]

    return epoch_time


_STRPTIME_LOCK = threading.Lock()
_GMT_FORMAT = "%a, %d %b %Y %H:%M:%S GMT"
_ISO8601_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"


def unixtime_to_iso8601(timestamp):
    ISO8601_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"
    localtime = time.localtime(float(timestamp))
    return time.strftime(ISO8601_FORMAT, localtime)


def time_slow(timestring):
    ts = http_to_unixtime(timestring) - 1
    return datetime.datetime.fromtimestamp(ts).strftime(_GMT_FORMAT)


def http_to_unixtime(time_string):
    return to_unixtime(time_string, _GMT_FORMAT)


def to_unixtime(time_string, format_string):
    with _STRPTIME_LOCK:
        return int(calendar.timegm(time.strptime(time_string, format_string)))


def to_bytes(data):
        """若输入为unicode�? 则转为utf-8编码的bytes；其他则原样返回�?"""
        if isinstance(data, unicode):
            return data.encode('utf-8')
        else:
            return data


def file_object_remaining_bytes(fileobj):
    current = fileobj.tell()

    fileobj.seek(0, os.SEEK_END)
    end = fileobj.tell()
    fileobj.seek(current, os.SEEK_SET)

    return end - current


def _get_data_size(data):
    if hasattr(data, '__len__'):
        return len(data)

    if hasattr(data, 'seek') and hasattr(data, 'tell'):
        return file_object_remaining_bytes(data)

    return None


def make_crc_adapter(data, init_crc=0):
    """返回�?个�?�配器，从�?�在读取 `data` ，即调用read或�?�对其进行迭代的时�?�，能够计算CRC�?

    :param data: 可以是bytes、file object或iterable
    :param init_crc: 初始CRC值，可�??

    :return: 能够调用计算CRC函数的�?�配�?
    """
    data = to_bytes(data)

    # bytes or file object
    if hasattr(data, '__len__') or (hasattr(data, 'seek') and hasattr(data, 'tell')):
        return _BytesAndFileAdapter(data, 
                                    size=_get_data_size(data), 
                                    crc_callback=Crc64(init_crc))
    # file-like object
    elif hasattr(data, 'read'): 
        return _FileLikeAdapter(data, crc_callback=Crc64(init_crc))
    # iterator
    elif hasattr(data, '__iter__'):
        return _IterableAdapter(data, crc_callback=Crc64(init_crc))
    else:
        raise ClientError('{0} is not a file object, nor an iterator'.format(data.__class__.__name__))


def _invoke_crc_callback(crc_callback, content):
    if crc_callback:
        crc_callback(content)


_CHUNK_SIZE = 8 * 1024


class _IterableAdapter(object):
    def __init__(self, data, crc_callback=None):
        self.iter = iter(data)
        self.offset = 0
        
        self.crc_callback = crc_callback

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):            

        content = next(self.iter)
        self.offset += len(content)
                
        _invoke_crc_callback(self.crc_callback, content)

        return content
    
    @property
    def crc(self):
        return self.crc_callback.crc


class _FileLikeAdapter(object):
    """通过这个适配器，可以给无法确定内容长度的 `fileobj` 加上进度监控�?

    :param fileobj: file-like object，只要支持read即可
    :param progress_callback: 进度回调函数
    """
    def __init__(self, fileobj, progress_callback=None, crc_callback=None):
        self.fileobj = fileobj
        self.progress_callback = progress_callback
        self.offset = 0
        
        self.crc_callback = crc_callback

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        content = self.read(_CHUNK_SIZE)

        if content:
            return content
        else:
            raise StopIteration

    def read(self, amt=None):
        content = self.fileobj.read(amt)
        if not content:
            pass 
        else:
                
            self.offset += len(content)
                                   
            _invoke_crc_callback(self.crc_callback, content)

        return content
    
    @property
    def crc(self):
        return self.crc_callback.crc
    

class _BytesAndFileAdapter(object):
    """通过这个适配器，可以�? `data` 加上进度监控�?

    :param data: 可以是unicode字符串（内部会转换为UTF-8编码的bytes）�?�bytes或file object
    :param progress_callback: 用户提供的进度报告回调，形如 callback(bytes_read, total_bytes)�?
        其中bytes_read是已经读取的字节数；total_bytes是�?�的字节数�??
    :param int size: `data` 包含的字节数�?
    """
    def __init__(self, data, progress_callback=None, size=None, crc_callback=None):
        self.data = to_bytes(data)
        self.progress_callback = progress_callback
        self.size = size
        self.offset = 0
        
        self.crc_callback = crc_callback

    def __len__(self):
        return self.size
    
    # for python 2.x
    def __bool__(self):
        return True
    # for python 3.x
    __nonzero__ = __bool__

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        content = self.read(_CHUNK_SIZE)

        if content:
            return content
        else:
            raise StopIteration

    def read(self, amt=None):
        if self.offset >= self.size:
            return ''

        if amt is None or amt < 0:
            bytes_to_read = self.size - self.offset
        else:
            bytes_to_read = min(amt, self.size - self.offset)

        if isinstance(self.data, bytes):
            content = self.data[self.offset: self.offset + bytes_to_read]
        else:
            content = self.data.read(bytes_to_read)

        self.offset += bytes_to_read
            
        _invoke_crc_callback(self.crc_callback, content)

        return content
    
    @property
    def crc(self):
        return self.crc_callback.crc


class Crc64(object):

    _POLY = 0x142F0E1EBA9EA3693
    _XOROUT = 0XFFFFFFFFFFFFFFFF
    
    def __init__(self, init_crc=0):
        self.crc64 = crcmod.Crc(self._POLY, initCrc=init_crc, rev=True, xorOut=self._XOROUT)

    def __call__(self, data):
        self.update(data)
    
    def update(self, data):
        self.crc64.update(data)
    
    @property
    def crc(self):
        return self.crc64.crcValue
