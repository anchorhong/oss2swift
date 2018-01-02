from oss2swift.cfg import CONF
from oss2swift.controllers.base import Controller, bucket_operation
from oss2swift.etree import Element, tostring
from oss2swift.response import HTTPOk
from swift.common.utils import public


class LocationController(Controller):
    """
    Handles GET Bucket location, which is logged as a LOCATION operation in the
    OSS server log.
    """
    @public
    @bucket_operation
    def GET(self, req):
        """
        Handles GET Bucket location.
        """
        meta_location = dict(req.get_response(self.app, method='HEAD').headers)['x-oss-meta-location']

        elem = Element('LocationConstraint')
        if meta_location is not None:
            elem.text = meta_location
        else:
            elem.text = ''

        body = tostring(elem)

        return HTTPOk(body=body, content_type='application/xml')
