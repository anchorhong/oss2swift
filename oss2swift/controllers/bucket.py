import sys
import time
from urllib import unquote
from random import choice
from oss2swift.cfg import CONF
from oss2swift.controllers.base import Controller
from oss2swift.etree import Element, SubElement, tostring, fromstring, \
    XMLSyntaxError, DocumentInvalid
from oss2swift.response import HTTPOk, OssNotImplemented, InvalidArgument, \
    MalformedXML, InvalidLocationConstraint, NoSuchBucket, \
    BucketNotEmpty, InternalError, ServiceUnavailable, NoSuchKey
from oss2swift.utils import LOGGER, MULTIUPLOAD_SUFFIX
from swift.common.http import HTTP_OK
from swift.common.utils import json, public


MAX_PUT_BUCKET_BODY_SIZE = 10240


class BucketController(Controller):
    """
    Handles bucket request.
    """
    def _delete_segments_bucket(self, req):
        """
        Before delete bucket, delete segments bucket if existing.
        """
        container = req.container_name + MULTIUPLOAD_SUFFIX
        marker = ''
        seg = ''

        try:
            resp = req.get_response(self.app, 'HEAD')
            if int(resp.sw_headers['X-Container-Object-Count']) > 0:
                raise BucketNotEmpty()
            # FIXME: This extra HEAD saves unexpected segment deletion
            # but if a complete multipart upload happen while cleanup
            # segment container below, completed object may be missing its
            # segments unfortunately. To be safer, it might be good
            # to handle if the segments can be deleted for each object.
        except NoSuchBucket:
            pass

        try:
            while True:
                # delete all segments
                resp = req.get_response(self.app, 'GET', container,
                                        query={'format': 'json',
                                               'marker': marker})
                segments = json.loads(resp.body)
                for seg in segments:
                    try:
                        req.get_response(self.app, 'DELETE', container,
                                         seg['name'])
                    except NoSuchKey:
                        pass
                    except InternalError:
                        raise ServiceUnavailable()
                if segments:
                    marker = seg['name']
                else:
                    break
            req.get_response(self.app, 'DELETE', container)
        except NoSuchBucket:
            return
        except (BucketNotEmpty, InternalError):
            raise ServiceUnavailable()

    @public
    def HEAD(self, req):
        """
        Handle HEAD Bucket (Get Metadata) request
        """
        resp = req.get_response(self.app)

        return HTTPOk(headers=resp.headers)

    @public
    def GET(self, req):
        """
        Handle GET Bucket (List Objects) request
        """

        max_keys = req.get_validated_param('max-keys', CONF.max_bucket_listing)
        # TODO: Separate max_bucket_listing and default_bucket_listing
        tag_max_keys = max_keys
        max_keys = min(max_keys, CONF.max_bucket_listing)

        encoding_type = req.params.get('encoding-type')
        if encoding_type is not None and encoding_type != 'url':
            err_msg = 'Invalid Encoding Method specified in Request'
            raise InvalidArgument('encoding-type', encoding_type, err_msg)

        query = {
            'format': 'json',
            'limit': max_keys + 1,
        }
        if 'marker' in req.params:
            query.update({'marker': req.params['marker']})
        if 'prefix' in req.params:
            query.update({'prefix': req.params['prefix']})
        if 'delimiter' in req.params:
            query.update({'delimiter': req.params['delimiter']})

        resp = req.get_response(self.app, query=query)
        if resp.headers['x-oss-website-redirect']:
            index=resp.headers['x-oss-web-index']
            resp = req.get_response(self.app, obj=index)
            return HTTPOk(body=resp.body, content_type='application/xml')    
        objects = json.loads(resp.body)

        elem = Element('ListBucketResult')
        SubElement(elem, 'Name').text = req.container_name
        SubElement(elem, 'Prefix').text = req.params.get('prefix')
        SubElement(elem, 'Marker').text = req.params.get('marker')

        # in order to judge that truncated is valid, check whether
        # max_keys + 1 th element exists in swift.
        is_truncated = max_keys > 0 and len(objects) > max_keys
        objects = objects[:max_keys]

        if is_truncated and 'delimiter' in req.params:
            if 'name' in objects[-1]:
                SubElement(elem, 'NextMarker').text = \
                    objects[-1]['name']
            if 'subdir' in objects[-1]:
                SubElement(elem, 'NextMarker').text = \
                    objects[-1]['subdir']

        SubElement(elem, 'MaxKeys').text = str(tag_max_keys)

        if 'delimiter' in req.params:
            SubElement(elem, 'Delimiter').text = req.params['delimiter']

        if encoding_type is not None:
            SubElement(elem, 'EncodingType').text = encoding_type

        SubElement(elem, 'IsTruncated').text = \
            'true' if is_truncated else 'false'

        for o in objects:
            if 'subdir' not in o:
                contents = SubElement(elem, 'Contents')
                SubElement(contents, 'Key').text = o['name']
                SubElement(contents, 'LastModified').text = \
                    o['last_modified'][:-6] + '000Z'
                SubElement(contents, 'ETag').text = '"%s"' % o['hash']
                SubElement(contents, 'Size').text = str(o['bytes'])
                owner = SubElement(contents, 'Owner')
                SubElement(owner, 'ID').text = req.user_id
                SubElement(owner, 'DisplayName').text = req.user_id
                SubElement(contents, 'StorageClass').text = 'STANDARD'
                SubElement(contents, 'Type').text = 'Normal'

        for o in objects:
            if 'subdir' in o:
                common_prefixes = SubElement(elem, 'CommonPrefixes')
                SubElement(common_prefixes, 'Prefix').text = o['subdir']

        body = tostring(elem, encoding_type=encoding_type)

        return HTTPOk(body=body, content_type='application/xml')

    @public
    def PUT(self, req):
        """
        Handle PUT Bucket request
        """
        location = ""
        xml = req.xml(MAX_PUT_BUCKET_BODY_SIZE)
        if xml:
            # check location
            try:
                elem = fromstring(xml, 'CreateBucketConfiguration')
                location = elem.find('./LocationConstraint').text
            except (XMLSyntaxError, DocumentInvalid):
                raise MalformedXML()
            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                LOGGER.error(e)
                raise exc_type, exc_value, exc_traceback

            if location not in CONF.location:
                # Oss2swift cannot support multiple regions currently.
                raise InvalidLocationConstraint()

        if location is None or location == "":
            location = choice(CONF.location)
        req.headers['X-Container-Meta-Location'] = location
        # req.headers['X-Container-Meta-Location'] = location
        req.headers['X-Container-Meta-Create'] = time.time()
        resp = req.get_response(self.app)

        resp.status = HTTP_OK
        resp.location = '/' + location

        return resp

    @public
    def DELETE(self, req):
        """
        Handle DELETE Bucket request
        """
        if CONF.allow_multipart_uploads:
            self._delete_segments_bucket(req)
        resp = req.get_response(self.app)
        return resp

    @public
    def POST(self, req):
        """
        Handle POST Bucket request
        """
        raise OssNotImplemented()
