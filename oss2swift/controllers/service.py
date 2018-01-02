from oss2swift.cfg import CONF
from oss2swift.controllers.base import Controller
from oss2swift.etree import Element, SubElement, tostring
from oss2swift.response import HTTPOk, AccessDenied, NoSuchBucket
from oss2swift.utils import unixtime_to_iso8601
from oss2swift.utils import validate_bucket_name
from swift.common.utils import json, public
from random import choice

class ServiceController(Controller):
    """
    Handles account level requests.
    """
    @public
    def GET(self, req):
        """
        Handle GET Service request
        """
        resp = req.get_response(self.app, query={'format': 'json'})

        containers = json.loads(resp.body)

        containers = filter(
            lambda item: validate_bucket_name(item['name']), containers)

        # we don't keep the creation time of a bucket (osscmd doesn't
        # work without that) so we use something bogus.
        elem = Element('ListAllMyBucketsResult')

        owner = SubElement(elem, 'Owner')
        SubElement(owner, 'ID').text = req.user_id
        SubElement(owner, 'DisplayName').text = req.user_id

        buckets = SubElement(elem, 'Buckets')
        for c in containers:
            if CONF.oss_acl and CONF.check_bucket_owner:
                try:
                    meta_headers = dict(req.get_response(
                        self.app, 'HEAD', c['name']).headers)
                except AccessDenied:
                    continue
                except NoSuchBucket:
                    continue
            meta_headers = dict(req.get_response(
                self.app, 'HEAD', c['name']).headers)
            if meta_headers.has_key('x-oss-meta-create'):
                create_time = unixtime_to_iso8601(meta_headers['x-oss-meta-create'])
            else:
                create_time = unixtime_to_iso8601(0)

            if meta_headers.has_key('x-oss-meta-location') and \
                meta_headers['x-oss-meta-location'] != '':
                location = meta_headers['x-oss-meta-location']
            else:
                location = choice(CONF.location)

            bucket = SubElement(buckets, 'Bucket')
            SubElement(bucket, 'Name').text = c['name']
            SubElement(bucket, 'CreationDate').text = create_time
            SubElement(bucket, 'Location').text = location
            SubElement(
                bucket, 'ExtranetEndpoint').text = 'oss-ostorage-'+location+'.com'
            SubElement(
                bucket, 'IntranetEndpoint').text = 'oss-ostorage-internal-'+location+'.com'
        body = tostring(elem)

        return HTTPOk(content_type='application/xml', body=body)
