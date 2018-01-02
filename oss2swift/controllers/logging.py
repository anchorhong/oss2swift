from oss2swift.controllers.base import Controller, bucket_operation
from oss2swift.etree import Element, tostring
from oss2swift.response import HTTPOk, OssNotImplemented, NoLoggingStatusForKey
from swift.common.utils import public


class LoggingStatusController(Controller):
    """
    Handles the following APIs:

     - GET Bucket logging
     - PUT Bucket logging

    Those APIs are logged as LOGGING_STATUS operations in the Oss server log.
    """
    @public
    @bucket_operation(err_resp=NoLoggingStatusForKey)
    def GET(self, req):
        """
        Handles GET Bucket logging.
        """
        req.get_response(self.app, method='HEAD')

        # logging disabled
        elem = Element('BucketLoggingStatus')
        body = tostring(elem)

        return HTTPOk(body=body, content_type='application/xml')

    @public
    @bucket_operation(err_resp=NoLoggingStatusForKey)
    def PUT(self, req):
        """
        Handles PUT Bucket logging.
        """
        raise OssNotImplemented()
