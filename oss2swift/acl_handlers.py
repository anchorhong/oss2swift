import sys

from oss2swift.etree import fromstring, XMLSyntaxError, DocumentInvalid
from oss2swift.response import MissingSecurityHeader, \
    MalformedACLError, UnexpectedContent
from oss2swift.subresource import ACL, Owner, encode_acl
from oss2swift.utils import LOGGER, MULTIUPLOAD_SUFFIX, sysmeta_header


def get_acl(headers, body, bucket_owner, object_owner=None):
    acl = ACL.from_headers(headers, bucket_owner, object_owner,
                           as_private=False)

    if acl is None:
        # Get acl from request body if possible.
        if not body:
            msg = 'Your request was missing a required header'
            raise MissingSecurityHeader(msg, missing_header_name='x-oss-acl')
        try:
            elem = fromstring(body, ACL.root_tag)
            acl = ACL.from_elem(elem)
        except(XMLSyntaxError, DocumentInvalid):
            raise MalformedACLError()
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            LOGGER.error(e)
            raise exc_type, exc_value, exc_traceback
    else:
        if body:
            # Specifying grant with both header and xml is not allowed.
            raise UnexpectedContent()

    return acl


def get_acl_handler(controller_name):
    for base_klass in [BaseAclHandler, MultiUploadAclHandler]:
        # pylint: disable-msg=E1101
        for handler in base_klass.__subclasses__():
            handler_suffix_len = len('AclHandler') \
                if not handler.__name__ == 'OssAclHandler' else len('Hanlder')
            if handler.__name__[:-handler_suffix_len] == controller_name:
                return handler
    return BaseAclHandler


class BaseAclHandler(object):
    """
    BaseAclHandler: Handling ACL for basic requests mapped on ACL_MAP
    """
    def __init__(self, req, container, obj, headers):
        self.req = req
        self.container = self.req.container_name if container is None \
            else container
        self.obj = self.req.object_name if obj is None else obj
        self.method = req.environ['REQUEST_METHOD']
        self.user_id = self.req.user_id
        self.headers = self.req.headers if headers is None else headers

    def handle_acl(self, app, method):
        method = method or self.method
        if hasattr(self, method):
            return getattr(self, method)(app)
        else:
            return self._handle_acl(app, method)

    def _handle_acl(self, app, sw_method, container=None, obj=None,
                    permission=None, headers=None):
        

        container = self.container if container is None else container
        obj = self.obj if obj is None else obj
        sw_method = sw_method or self.req.environ['REQUEST_METHOD']
        resource = 'object' if obj else 'container'
        headers = self.headers if headers is None else headers

        if not container:
            return
        if not permission and (self.method, sw_method, resource) in ACL_MAP:
        	acl_check = ACL_MAP[(self.method, sw_method, resource)]
        	resource = acl_check.get('Resource') or resource
        	permission = acl_check['Grant']
        if not permission:
            raise Exception('No permission to be checked exists')

        if resource == 'object':
            resp = self.req.get_acl_response(app, 'HEAD',
                                             container, obj,
                                             headers)
            acl = resp.object_acl
        elif resource == 'container':
            resp = self.req.get_acl_response(app, 'HEAD',
                                             container, '')
            acl = resp.bucket_acl
        acl.check_permission(self.user_id, permission)

        if sw_method == 'HEAD':
            return resp


class BucketAclHandler(BaseAclHandler):
    """
    BucketAclHandler: Handler for BucketController
    """
    def DELETE(self, app):
        if self.container.endswith(MULTIUPLOAD_SUFFIX):
           
            pass
        else:
            return self._handle_acl(app, 'DELETE')

    def HEAD(self, app):
        if self.method == 'DELETE':
            return self._handle_acl(app, 'DELETE')
        else:
            return self._handle_acl(app, 'HEAD')

    def GET(self, app):
        if self.method == 'DELETE' and \
                self.container.endswith(MULTIUPLOAD_SUFFIX):
            pass
        else:
            return self._handle_acl(app, 'GET')

    def PUT(self, app):
	req_acl = ACL.from_headers(self.req.headers,
                                   Owner(self.user_id, self.user_id))
        if 'X-Oss-Acl' not in self.req.headers:
	    try:
           	 resp =self.req.get_acl_response(app, 'GET')
		 if resp.bucket_acl:
		    req_acl=resp.bucket_acl
            except :
                 pass
        
        self.req.get_acl_response(app, 'PUT')

        # update metadata
        self.req.bucket_acl = req_acl
        
        # FIXME If this request is failed, there is a possibility that the
        # bucket which has no ACL is left.
        return self.req.get_acl_response(app, 'POST')


class ObjectAclHandler(BaseAclHandler):
    """
    ObjectAclHandler: Handler for ObjectController
    """
    def HEAD(self, app):
        # No check object permission needed at DELETE Object
        if self.method != 'DELETE':
            return self._handle_acl(app, 'HEAD')

    def PUT(self, app):
	OBJ_ACL='default'
        b_resp = self._handle_acl(app, 'HEAD', obj='')
        req_acl = ACL.from_headers(self.req.headers,
                                   b_resp.bucket_acl.owner,
                                   Owner(self.user_id, self.user_id))
	if 'X-Oss-Acl' not in self.req.headers:
	    if req_acl=='private':
		req_acl=='default'
            try:
                 resp =self.req.get_acl_response(app, 'GET')
                 if resp.object_acl:
                    req_acl=resp.object_acl
            except :
                 pass
        self.req.object_acl = req_acl
        

class OssAclHandler(BaseAclHandler):
    """
    OssAclHandler: Handler for OssAclController
    """
    def GET(self, app):
        self._handle_acl(app, 'HEAD', permission='READ-ACL')

    def PUT(self, app):
        if self.req.is_object_request:
            b_resp = self.req.get_acl_response(app, 'HEAD', obj='')
            o_resp = self._handle_acl(app, 'HEAD', permission='WRITE-ACL')
            req_acl = get_acl(self.req.headers,
                              self.req.xml(ACL.max_xml_length),
                              b_resp.bucket_acl.owner,
                              o_resp.object_acl.owner)

            # Don't change the owner of the resource by PUT acl request.
            o_resp.object_acl.check_owner(req_acl.owner.id)

            g = req_acl.grant
            LOGGER.debug('Grant  %s permission on the object /%s/%s' %
                         (g, self.req.container_name,
                          self.req.object_name))
	    if 'X-Oss-Acl' not in self.req.headers:
		if req_acl=='private':
           		req_acl=='default'
            	try:
                   resp =self.req.get_acl_response(app, 'GET')
                   if resp.object_acl:
                   	req_acl=resp.object_acl
            	except :
                   pass
            self.req.object_acl = req_acl
        else:
            self._handle_acl(app, self.method)

    def POST(self, app):
        if self.req.is_bucket_request:
            resp = self._handle_acl(app, 'HEAD', permission='WRITE-ACL')

            req_acl = get_acl(self.req.headers,
                              self.req.xml(ACL.max_xml_length),
                              resp.bucket_acl.owner)

            # Don't change the owner of the resource by PUT acl request.
            resp.bucket_acl.check_owner(req_acl.owner.id)

            g = req_acl.grant
            LOGGER.debug('Grant %s permission on the bucket /%s' %
                         (g,self.req.container_name))
            self.req.bucket_acl = req_acl
        else:
            self._handle_acl(app, self.method)


class MultiObjectDeleteAclHandler(BaseAclHandler):
    """
    MultiObjectDeleteAclHandler: Handler for MultiObjectDeleteController
    """
    def HEAD(self, app):
        # Only bucket write acl is required
        if not self.obj:
            return self._handle_acl(app, 'HEAD')

    def DELETE(self, app):
        # Only bucket write acl is required
        pass


class MultiUploadAclHandler(BaseAclHandler):
    def __init__(self, req, container, obj, headers):
        super(MultiUploadAclHandler, self).__init__(req, container, obj,
                                                    headers)
        self.container = self.container[:-len(MULTIUPLOAD_SUFFIX)]

    def handle_acl(self, app, method):
        method = method or self.method
        # MultiUpload stuffs don't need acl check basically.
        if hasattr(self, method):
            return getattr(self, method)(app)
        else:
            pass

    def HEAD(self, app):
        # For _check_upload_info
        self._handle_acl(app, 'HEAD', self.container, '')


class PartAclHandler(MultiUploadAclHandler):
    """
    PartAclHandler: Handler for PartController
    """
    def __init__(self, req, container, obj, headers):
        # pylint: disable-msg=E1003
        super(MultiUploadAclHandler, self).__init__(req, container, obj,
                                                    headers)
        self.check_copy_src = False
        if self.container.endswith(MULTIUPLOAD_SUFFIX):
            self.container = self.container[:-len(MULTIUPLOAD_SUFFIX)]
        else:
            self.check_copy_src = True

    def HEAD(self, app):
        if self.check_copy_src:
            # For check_copy_source
            return self._handle_acl(app, 'HEAD', self.container, self.obj)
        else:
            # For _check_upload_info
            self._handle_acl(app, 'HEAD', self.container, '')


class UploadsAclHandler(MultiUploadAclHandler):
    """
    UploadsAclHandler: Handler for UploadsController
    """
    def GET(self, app):
        # List Multipart Upload
        self._handle_acl(app, 'GET', self.container, '')

    def PUT(self, app):
        if not self.obj:
            # Initiate Multipart Uploads (put +segment container)
            resp = self._handle_acl(app, 'HEAD')
            req_acl = ACL.from_headers(self.req.headers,
                                       resp.bucket_acl.owner,
                                       Owner(self.user_id, self.user_id))
            acl_headers = encode_acl('object', req_acl)
            self.req.headers[sysmeta_header('object', 'tmpacl')] = \
                acl_headers[sysmeta_header('object', 'acl')]

        # No check needed at Initiate Multipart Uploads (put upload id object)


class UploadAclHandler(MultiUploadAclHandler):
    """
    UploadAclHandler: Handler for UploadController
    """
    def HEAD(self, app):
        # FIXME: GET HEAD case conflicts with GET service
        method = 'GET' if self.method == 'GET' else 'HEAD'
        self._handle_acl(app, method, self.container, '')

    def PUT(self, app):
        container = self.req.container_name + MULTIUPLOAD_SUFFIX
        obj = '%s/%s' % (self.obj, self.req.params['uploadId'])
        resp = self.req._get_response(app, 'HEAD', container, obj)
        self.req.headers[sysmeta_header('object', 'acl')] = \
            resp.sysmeta_headers.get(sysmeta_header('object', 'tmpacl'))
ACL_MAP = {
    # HEAD Bucket
    ('HEAD', 'HEAD', 'container'):
    {'Grant': 'PUBLIC-READ'},
    # GET Service
    ('GET', 'HEAD', 'container'):
    {'Grant': 'PUBLIC-READ'},
    # GET Bucket, List Parts, List Multipart Upload
    ('GET', 'GET', 'container'):
    {'Grant': 'PUBLIC-READ'},
    # PUT Object, PUT Object Copy
    ('PUT', 'HEAD', 'container'):
    {'Grant': 'PUBLIC-READ-WRITE'},
    ('PUT', 'PUT', 'container'):
    {'Grant': 'PUBLIC-READ-WRITE'},
    ('PUT', 'GET', 'container'):
    {'Grant': 'PUBLIC-READ-WRITE'},
    ('PUT', 'POST', 'container'):
    {'Grant': 'PUBLIC-READ-WRITE'},
    # DELETE Bucket
    ('DELETE', 'DELETE', 'container'):
    {'Grant': 'PUBLIC-READ-WRITE'},
    # HEAD Object
    ('HEAD', 'HEAD', 'object'):
    {'Grant': 'PUBLIC-READ'},
    ('HEAD', 'GET', 'object'):
    {'Grant': 'PUBLIC-READ'},
    # GET Object
    ('GET', 'GET', 'object'):
    {'Grant': 'PUBLIC-READ'},
    ('GET', 'HEAD', 'object'):
    {'Grant': 'PUBLIC-READ'},
    # PUT Object Copy, Upload Part Copy
    ('PUT', 'HEAD', 'object'):
    {'Grant': 'PUBLIC-READ'},
    ('PUT', 'GET', 'object'):
    {'Grant': 'PUBLIC-READ'},
    # Abort Multipart Upload
    ('DELETE', 'HEAD', 'container'):
    {'Grant': 'PUBLIC-READ-WRITE'},
    ('DELETE', 'GET', 'container'):
    {'Grant': 'PUBLIC-READ-WRITE'},
    ('DELETE', 'POST', 'container'):
    {'Grant': 'PUBLIC-READ-WRITE'},
    # Delete Object
    ('DELETE', 'DELETE', 'object'):
    {'Resource': 'container',
     'Grant': 'PUBLIC-READ-WRITE'},
    # Complete Multipart Upload, DELETE Multiple Objects,
    # Initiate Multipart Upload
    ('POST', 'HEAD', 'container'):
    {'Grant': 'PUBLIC-READ-WRITE'},
}


