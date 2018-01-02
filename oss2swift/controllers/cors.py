import sys

from oss2swift.cfg import CONF
from oss2swift.controllers.base import Controller
from oss2swift.etree import Element, SubElement, tostring, fromstring, \
    XMLSyntaxError, DocumentInvalid
from oss2swift.response import HTTPOk, \
    MalformedXML, NoSuchCORSConfiguration,InvalidArgument
from oss2swift.utils import LOGGER
from swift.common.http import HTTP_OK
from swift.common.utils import public

MAX_PUT_BUCKET_CORERULE_SIZE = 16*1024
def _add_node_list(parent, tag, entries):
    for e in entries:
        _add_text_child(parent, tag, e)
def _add_text_child(parent, tag, text):
    SubElement(parent, tag).text = text
def _find_all_tags(parent, tag):
    return [node.text or '' for node in parent.findall(tag)]
def _str_list(cors):
    if cors is not None and cors !='':
        cor_list=[]
        for k in cors.split(','):
            cor_list.append(k)
        return cor_list
    return []
def _list_str(cors):
    str=','
    return str.join(cors)
class CorsController(Controller):
    """
    Handles bucket cors request.
    """
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
        Handle GET Bucket Core (List Bucket CoreRules) request
        """

        max_keys = req.get_validated_param('max-keys', CONF.max_corerule_listing)
        # TODO: Separate max_corerule_listing and default_corerule_listing
        max_keys = min(max_keys, CONF.max_corerule_listing)
        resp = req.get_response(self.app)
	if 'x-oss-meta-access-control-allow-origin' not in resp.headers:
	    raise NoSuchCORSConfiguration()
        allowed_origins=resp.headers['x-oss-meta-access-control-allow-origin']
        allowed_headers=resp.headers['x-oss-meta-access-control-allow-headers']
        allowed_methods=resp.headers['x-oss-meta-access-control-allow-methods']
        expose_headers=resp.headers['x-oss-meta-access-control-expose-headers']
        max_age_seconds=resp.headers['x-oss-meta-access-control-max-age']
        elem = Element('CORSConfiguration')
        rule_node =SubElement(elem, 'CORSRule')
        if rule_node is None and rule_node =='':
            raise NoSuchCORSConfiguration
        _add_node_list(rule_node, 'AllowedOrigin', _str_list(allowed_origins))
        _add_node_list(rule_node, 'AllowedMethod', _str_list(allowed_methods))
        _add_node_list(rule_node, 'AllowedHeader', _str_list(allowed_headers))
        _add_node_list(rule_node, 'ExposeHeader', _str_list(expose_headers))
        if max_age_seconds is not None:
            _add_text_child(rule_node, 'MaxAgeSeconds', str(max_age_seconds))
        body = tostring(elem)

        return HTTPOk(body=body, content_type='application/xml')

    @public
    def PUT(self, req):
        """
        Handle PUT Bucket CoreRule request
        """
        xml = req.xml(MAX_PUT_BUCKET_CORERULE_SIZE)
        if xml:
            # check location
            try:
		try:

                   elem = fromstring(xml, 'CORSConfiguration')
		except (XMLSyntaxError, DocumentInvalid):
                   raise InvalidArgument()
                for core_rule in  elem.findall('CORSRule'):
                    allowed_origins = _find_all_tags(core_rule,'AllowedOrigin')
                    allowed_methods = _find_all_tags(core_rule,'AllowedMethod')
                    allowed_headers= _find_all_tags(core_rule,'AllowedHeader')
                    expose_headers = _find_all_tags(core_rule,'ExposeHeader')
                    if core_rule.find('MaxAgeSeconds') is not None:
                       max_age_seconds = core_rule.find('MaxAgeSeconds').text
                    req.headers['X-Container-Meta-Access-Control-Allow-Origin'] = _list_str(allowed_origins)
                    req.headers['X-Container-Meta-Access-Control-Allow-Methods']=_list_str(allowed_methods)
                    req.headers['X-Container-Meta-Access-Control-Allow-Headers'] = _list_str(allowed_headers)
                    req.headers['X-Container-Meta-Access-Control-Expose-Headers'] = _list_str(expose_headers)
                    req.headers['X-Container-Meta-Access-Control-Max-Age'] = max_age_seconds
            except (XMLSyntaxError, DocumentInvalid):
                raise MalformedXML()
            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                LOGGER.error(e)
                raise exc_type, exc_value, exc_traceback
        resp = req.get_response(self.app)

        resp.status = HTTP_OK

        return resp

    @public
    def DELETE(self, req):
        """
        Handle DELETE Bucket Core request
        """
        req.headers['X-Remove-Container-Meta-Access-Control-Allow-Origin'] = 'x'
        req.headers['X-Remove-Container-Meta-Access-Control-Allow-Methods'] = 'x'
        req.headers['X-Remove-Container-Meta-Access-Control-Allow-Headers'] = 'x'
        req.headers['X-Remove-Container-Meta-Access-Control-Expose-Headers'] = 'x'
        req.headers['X-Remove-Container-Meta-Access-Control-Max-Age'] = 'x'

        resp = req.get_response(self.app, method='POST', headers=req.headers)

        return resp

    @public
    def OPTIONS(self, req):
        """
        Handle OPTIONS Object request
        """
        resp = req.get_response(self.app)
        return resp




