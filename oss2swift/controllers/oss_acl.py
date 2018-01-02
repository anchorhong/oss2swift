import sys
from urllib import quote

from oss2swift.controllers.base import Controller
from oss2swift.etree import tostring
from oss2swift.response import HTTPOk, OssNotImplemented
from swift.common.utils import public


class OssAclController(Controller):
    @public
    def GET(self, req):
        resp = req.get_response(self.app)

        acl = resp.object_acl if req.is_object_request else resp.bucket_acl
	if 'cnc' in resp.sysmeta_copy_headers:
           raise OssNotImplemented
	if not acl.grant:
	   acl.grant=resp.sysmeta_copy_headers
	   acl.owner.id=resp.owner
	   acl.owner.name=resp.owner	
        resp = HTTPOk()
        resp.body = tostring(acl.elem())

        return resp

    @public
    def PUT(self, req):
        """
        Handles PUT Bucket acl and PUT Object acl.
        """
        if req.is_object_request:
            headers = {}
            src_path = '/%s/%s' % (req.container_name, req.object_name)
            headers['X-Copy-From'] = quote(src_path)
            headers['Content-Length'] = 0
            req.get_response(self.app, 'PUT', headers=headers)
        else:
            req.get_response(self.app, 'POST')

        return HTTPOk()

