from oss2swift.controllers.base import Controller, bucket_operation
from oss2swift.etree import Element, tostring
from oss2swift.response import HTTPOk, OssNotImplemented
from swift.common.utils import public


class VersioningController(Controller):
    """
    Handles the following APIs:

     - GET Bucket versioning
     - PUT Bucket versioning

    Those APIs are logged as VERSIONING operations in the Oss server log.
    """
    @public
    @bucket_operation
    def GET(self, req):
        """
        Handles GET Bucket versioning.
        """
        req.get_response(self.app, method='HEAD')

        # Just report there is no versioning configured here.
        elem = Element('VersioningConfiguration')
        body = tostring(elem)

        return HTTPOk(body=body, content_type="text/plain")

    @public
    @bucket_operation
    def PUT(self, req):
        """
        Handles PUT Bucket versioning.
        """
        raise OssNotImplemented()
