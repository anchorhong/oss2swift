import sys
import zlib

import crcmod
from oss2swift.controllers.base import Controller
from oss2swift.response import OssNotImplemented, InvalidRange, NoSuchKey, \
    InvalidArgument, ObjectInvalid
from oss2swift.utils import OssTimestamp, time_slow, to_unixtime
from swift.common.http import HTTP_OK, HTTP_PARTIAL_CONTENT, HTTP_NO_CONTENT
from swift.common.swob import Range, content_range_header_value
from swift.common.utils import public


class ObjectController(Controller):
    """
    Handles requests on objects
    """
    def _gen_head_range_resp(self, req_range, resp):
        """
        Swift doesn't handle Range header for HEAD requests.
        So, this method generates HEAD range response from HEAD response.
        OSS return HEAD range response, if the value of range satisfies the
        conditions which are described in the following document.
        """
        length = long(resp.headers.get('Content-Length'))

        try:
            content_range = Range(req_range)
        except ValueError:
            return resp

        ranges = content_range.ranges_for_length(length)
        if ranges == []:
            raise InvalidRange()
        elif ranges:
            if len(ranges) == 1:
                start, end = ranges[0]
                resp.headers['Content-Range'] = \
                    content_range_header_value(start, end, length)
                resp.headers['Content-Length'] = (end - start)
                resp.status = HTTP_PARTIAL_CONTENT
                return resp
            else:
                # TODO: It is necessary to confirm whether need to respond to
                #       multi-part response.(e.g. bytes=0-10,20-30)
                pass

        return resp

    def _get_gzip_chunk(self, input_string):
        gzip_compress = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
        gzip_data = gzip_data = gzip_compress.compress(input_string) + gzip_compress.flush()
        return gzip_data

    def _gen_gzip(self, data, chunk_size=8 * 1024):
        totol_len = len(data)
        start = 0
        gzip_data = ''
        while True:
            chunk = data[start: start + chunk_size]
            gzip_chunk = self._get_gzip_chunk(chunk)
            chunk_size = len(gzip_chunk)
            chunk_pre = "%x\r\n" % chunk_size
            if start < totol_len - chunk_size:
                chunk_string = chunk_pre + gzip_chunk + "\r\n\r\n"
                gzip_data += chunk_string
                start += chunk_size
            else:
                chunk_string = chunk_pre + gzip_chunk + "\r\n\r\n" + "0\r\n"
                gzip_data += chunk_string
                break

        return gzip_data

    def _parse_lifecycle(self, headers, object_name):
        if 'rules' in headers['meta']:
            keys_string = headers['meta']['rules']
            key_lists = keys_string.split(',')
            for key in reversed(key_lists):
                rule_id = key.split(':')[0]
                rule_prefix = key.split(':')[1]
                if object_name.startswith(rule_prefix):
                    rule = headers['meta'][rule_id]
                    rule = eval(rule)
                    if rule['ruleStatus'] == 'Enabled':
                        return rule['expireDay'], rule['createDate']
                    else:
                        pass
        return '', ''

    def GETorHEAD(self, req):
        # if req.headers is not None and 'Accept-Encoding' in req.headers and req.headers['Accept-Encoding'] == 'gzip':
        #     resp = req.get_response(self.app, method='GET')
        #     resp.headers['Content-Encoding'] = 'gzip'
        #     resp.headers['Transfer-encoding'] = 'chunked'
        #     del resp.headers['Content-Length']
        #     resp.body = self._gen_gzip(resp.body)
        # else:
        resp = req.get_response(self.app, method='GET')
	if 'x-oss-index' in resp.headers:
            index=resp.headers['x-oss-index']
            resp=req.get_response(self.app, obj=index,method='GET')
        if 'x-oss-web-error' in resp.headers:
            obj=resp.headers['x-oss-web-error']
            resp=req.get_response(self.app, obj=obj,method='GET')
        if req.method == 'HEAD':
            resp.app_iter = None
        if 'x-oss-meta-validdate' in resp.headers:
            validDate = resp.headers['x-oss-meta-validdate']
            if str(validDate).isdigit() and validDate > float(OssTimestamp.now().internal):
                raise ObjectInvalid()
            else:
                pass

        for key in ('content-type', 'content-language', 'expires',
                    'cache-control', 'content-disposition',
                    'content-encoding'):
            if 'response-' + key in req.params:
                resp.headers[key] = req.params['response-' + key]
        return resp

    @public
    def HEAD(self, req):
        """
        Handle HEAD Object request
        """
        resp = self.GETorHEAD(req)

        if 'range' in req.headers:
            req_range = req.headers['range']
            resp = self._gen_head_range_resp(req_range, resp)

        return resp

    @public
    def GET(self, req):
        """
        Handle GET Object request
        """
        return self.GETorHEAD(req)

    @public
    def PUT(self, req):
        """
        Handle PUT Object and PUT Object (Copy) request
        """
        # set X-Timestamp by oss2swift to use at copy resp body
        req_timestamp = OssTimestamp.now()
        expireDay = ''
        createDate = ''
        data = req.body
        do_crc64 = crcmod.mkCrcFun(0x142F0E1EBA9EA3693L, initCrc=0L, xorOut=0xffffffffffffffffL, rev=True)
        crcValue = do_crc64(data)

        req.headers['X-Timestamp'] = req_timestamp.internal
        req.headers['x-object-meta-object-type'] = 'Normal'
        req.headers['x-object-meta-hash-crc64ecma'] = str(crcValue)

        if all(h in req.headers
               for h in ('x-oss-copy-source', 'x-oss-copy-source-range')):
            raise InvalidArgument('x-oss-copy-source-range',
                                  req.headers['x-oss-copy-source-range'],
                                  'Illegal copy header')
        req.check_copy_source(self.app)
        bucket_headers = {}
        bucket_headers = req.get_container_info(self.app)
        expireDay, createDate = self._parse_lifecycle(bucket_headers, req.object_name)
        if expireDay != '':
            try:
                days = int(expireDay)
                expire_sc = str(int(days * 2 * 3600 + float(req_timestamp.internal)))
                req.headers['X-Delete-At'] = expire_sc
            except:
                raise InvalidArgument('X-Deltete-At', days)
        elif createDate != '':
            try:
                unix_time = to_unixtime(createDate, '%Y-%m-%dT%H:%M:%S.000Z')
                if unix_time <= int(req_timestamp):
                    pass
                else:
                    req.headers['X-Object-Meta-ValidDate'] = unix_time
            except:
                raise InvalidArgument('X-Object-Meta-ValidDate', createDate)
        resp = req.get_response(self.app)

        if 'x-oss-copy-source' in req.headers:
            resp.append_copy_resp_body(req.controller_name,
                                       req_timestamp.ossxmlformat)

            # delete object metadata from response
            for key in list(resp.headers.keys()):
                if key.startswith('x-oss-meta-'):
                    del resp.headers[key]

        resp.status = HTTP_OK
        resp.headers['x-oss-hash-crc64ecma'] = crcValue
        return resp

    @public
    def POST(self, req):
        raise OssNotImplemented()

    @public
    def DELETE(self, req):
        """
        Handle DELETE Object request
        """
        try:
            query = req.gen_multipart_manifest_delete_query(self.app)
            req.headers['Content-Type'] = None  # Ignore client content-type
            resp = req.get_response(self.app, query=query)
            if query and resp.status_int == HTTP_OK:
                for chunk in resp.app_iter:
                    pass  # drain the bulk-deleter response
                resp.status = HTTP_NO_CONTENT
                resp.body = ''
        except NoSuchKey:
            # expect to raise NoSuchBucket when the bucket doesn't exist
            exc_type, exc_value, exc_traceback = sys.exc_info()
            req.get_container_info(self.app)
            raise exc_type, exc_value, exc_traceback
        return resp
