import sys
from oss2swift.cfg import CONF
from oss2swift.controllers.base import Controller
from oss2swift.etree import Element, SubElement, tostring, fromstring, \
    XMLSyntaxError, DocumentInvalid
from oss2swift.response import HTTPOk, NoSuchKey,AccessDenied,\
    MalformedXML, NoSuchWebsiteConfiguration,InvalidArgument
from oss2swift.utils import LOGGER
from swift.common.http import HTTP_OK,HTTP_NOT_FOUND
from swift.common.utils import public
MAX_PUT_BUCKET_WEBSITE_SIZE=10*1024
class WebsiteController(Controller):
    """
    Handles bucket website request.
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
        Handle GET Bucket website request
        """
        resp = req.get_response(self.app)
	if resp.bucket_acl =='private':
	   raise AccessDenied()
	if 'x-oss-web-index' not in resp.headers:
	    raise NoSuchWebsiteConfiguration()
        web_index=resp.headers['x-oss-web-index']
        web_error=resp.headers['x-oss-web-error']
        elem = Element('WebsiteConfiguration')
        index =SubElement(elem, 'IndexDocument')
        SubElement(index, 'Suffix').text=web_index
        if web_error is not None:
	   error_doc =SubElement(elem, 'ErrorDocument')
	   key=SubElement(error_doc, 'Key')
	   if key is None and key=='':
		raise NoSuchKey()
	   key.text=web_error           
        body = tostring(elem)

        return HTTPOk(body=body, content_type='application/xml')

    @public
    def PUT(self, req):
        """
        Handle PUT Bucket website request
        """
        xml = req.xml(MAX_PUT_BUCKET_WEBSITE_SIZE)
        if xml:
            try:
	       elem = fromstring(xml, 'WebsiteConfiguration')
	       index=elem.find('IndexDocument')
	       sufix= index.find('Suffix').text
	       if elem.find('ErrorDocument') is not None:
		    error_doc=elem.find('ErrorDocument')
		    key=error_doc.find('Key').text
#	       resp = req.get_response(self.app, obj=sufix,method='GET')
#	       if resp.status_int==HTTP_NOT_FOUND:
#		   raise NoSuchKey(sufix)
	       req.headers['X-Container-Meta-Web-Index'] = str(sufix)
	       req.headers['X-Container-Meta-Web-Error']= str(key)
	       req.headers['X-Container-Meta-Web-Listings'] = 'true'
               req.headers['X-Container-Meta-Web-Listings-CSS'] = '*.css'
               req.headers['X-Container-Read'] = '.r:*'
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
        req.headers['X-Remove-Container-Meta-Web-Index'] = 'x'
        req.headers['X-Remove-Container-Meta-Web-Error'] = 'x'
        req.headers['X-Remove-Container-Meta-Web-Listings'] = 'x'
        req.headers['X-Remove-Container-Meta-Web-Listings-CSS'] = 'x'

        resp = req.get_response(self.app, method='POST', headers=req.headers)

        return resp

