from oss2swift.acl_utils import swift_acl_translate
from oss2swift.controllers.base import Controller
from oss2swift.etree import Element, SubElement, tostring
from oss2swift.exception import ACLError
from oss2swift.response import HTTPOk, OssNotImplemented, MalformedACLError, \
    UnexpectedContent
from swift.common.http import HTTP_OK
from swift.common.middleware.acl import parse_acl, referrer_allowed
from swift.common.utils import public


MAX_ACL_BODY_SIZE = 200 * 1024


def get_acl(account_name, headers):
    """
    Attempts to construct an Oss ACL based on what is found in the swift headers
    """

    elem = Element('AccessControlPolicy')
    owner = SubElement(elem, 'Owner')
    SubElement(owner, 'ID').text = account_name
    SubElement(owner, 'DisplayName').text = account_name
    access_control_list = SubElement(elem, 'AccessControlList')

    # grant FULL_CONTROL to myself by default
    referrers, _ = parse_acl(headers.get('x-container-read'))
    if referrer_allowed('unknown', referrers):
        # grant public-read access
        SubElement(access_control_list, 'Grant').text = 'PUBLIC-READ'

    referrers, _ = parse_acl(headers.get('x-container-write'))
    if referrer_allowed('unknown', referrers):
        # grant public-write access
        SubElement(access_control_list, 'Grant').text = 'PUBLIC-READ-WRITE'

    body = tostring(elem)

    return HTTPOk(body=body, content_type="text/plain")


class AclController(Controller):
    @public
    def GET(self, req):
        resp = req.get_response(self.app, method='HEAD')

        return get_acl(req.user_id, resp.headers)

    @public
    def PUT(self, req):
        """
        Handles PUT Bucket acl and PUT Object acl.
        """
        if req.is_object_request:
            # Handle Object ACL
            raise OssNotImplemented()
        else:
            # Handle Bucket ACL
            xml = req.xml(MAX_ACL_BODY_SIZE)
            if 'HTTP_X_OSS_ACL' in req.environ and xml:
                # Oss doesn't allow to give ACL with both ACL header and body.
                raise UnexpectedContent()
            elif xml and 'HTTP_X_OSS_ACL' not in req.environ:
                # We very likely have an XML-based ACL request.
                try:
                    translated_acl = swift_acl_translate(xml, xml=True)
                except ACLError:
                    raise MalformedACLError()

                for header, acl in translated_acl:
                    req.headers[header] = acl

            resp = req.get_response(self.app, 'POST')
            resp.status = HTTP_OK
            resp.headers.update({'Location': req.container_name})

            return resp
