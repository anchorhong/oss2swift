import sys
import os

from oss2swift.controllers.base import Controller
from oss2swift.etree import Element, SubElement, tostring, fromstring, \
    XMLSyntaxError, DocumentInvalid
from oss2swift.response import HTTPOk,OssNotImplemented, \
    MalformedXML, InvalidArgument
from oss2swift.utils import LOGGER
from swift.common.http import HTTP_OK
from swift.common.utils import public

MAX_PUT_BUCKET_REFERER_SIZE = 10*1024
def get_oss_refer(swift_refer):
    if swift_refer is None:
       return ''
    oss_refer=swift_refer[3:].split(',')
    if '.rlistings' in oss_refer:
       oss_refer.remove('.rlistings')
    for ref in oss_refer:
        if ref.startswith('-'):
            raise OssNotImplemented
    if '*' in oss_refer:
        return '*'
    oss_real_refer=[]
    for ref in oss_refer:
       if ref.startswith('.'):
           ref='*'+ref
	   oss_real_refer.append(ref)
       else:
	   oss_real_refer.append(ref)
    return ','.join(oss_real_refer)
def get_real_url(urls):
    real_urls=[]
    for url in urls:
        if url.startswith('*'):
            url=url.replace('*','')
            real_urls.append(url)
        else:
            real_urls.append(url)
    return real_urls       

class RefererController(Controller):
    """
    Handles bucket referer request.
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
        Handle GET Bucket Referer  request
        """
        resp = req.get_response(self.app)
        referers=resp.headers['X-Container-Read']
	real_referers=get_oss_refer(referers)
        elem = Element('RefererConfiguration')
        SubElement(elem, 'AllowEmptyReferer').text='true'
        referer_list=SubElement(elem, 'RefererList')
	if real_referers is None:
	   SubElement(referer_list, 'Referer').text=''
	   body = tostring(elem)
	   return HTTPOk(body=body, content_type='application/xml')
	if real_referers =='*':
	   SubElement(referer_list, 'Referer').text='*'
	   body = tostring(elem)
	   return HTTPOk(body=body, content_type='application/xml')
	for refer in real_referers.split(','):
	   SubElement(referer_list, 'Referer').text=refer
        body = tostring(elem)

        return HTTPOk(body=body, content_type='application/xml')

    @public
    def PUT(self, req):
        """
        Handle PUT Bucket Referer request
        """
        xml = req.xml(MAX_PUT_BUCKET_REFERER_SIZE)
        if xml:
            # check referer
            try:
                elem = fromstring(xml, 'RefererConfiguration')
                allow_empyt_referer=elem.find('AllowEmptyReferer').text
                if allow_empyt_referer not in ['true','false']:
                    raise InvalidArgument()
                referer_list=elem.find('RefererList')
		swift_referers=[]
                for referer in  referer_list.findall('Referer'):
	            swift_referers.append(referer.text)
		if len(swift_referers)==0 :
		    req.headers['X-Container-Read']=' '
		else:
                    req.headers['X-Container-Read'] = '.r:'+','.join(get_real_url(swift_referers))
            except (XMLSyntaxError, DocumentInvalid):
                raise MalformedXML()
            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                LOGGER.error(e)
                raise exc_type, exc_value, exc_traceback
        resp = req.get_response(self.app)
        resp.status = HTTP_OK
        return resp
