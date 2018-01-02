import sys

from oss2swift.controllers.base import Controller
from oss2swift.controllers.base import bucket_operation
from oss2swift.etree import Element, SubElement, tostring, fromstring, \
    XMLSyntaxError, DocumentInvalid
from oss2swift.response import HTTPOk, MalformedXML, NoSuchLifecycle, TooManyRules, RuleIdExisted, \
    RuleDateRequired
from oss2swift.controllers.base import bucket_operation
from oss2swift.utils import LOGGER
from swift.common.http import HTTP_OK
from swift.common.utils import public


MAX_PUT_BUCKET_BODY_SIZE = 10240
MAX_RULE_SIZE = 10


class LifecycleController(Controller):
    """
    Handles bucket lifecycle.
    """
    @public
    @bucket_operation
    def HEAD(self, req):
        resp = req.get_response(self.app)
        return HTTPOk(headers=resp.headers)

    @public
    def GET(self, req):
        resp = req.get_response(self.app)
        if 'x-oss-meta-rules' in resp.headers:
            rules_string = resp.headers['x-oss-meta-rules']
            if rules_string.startswith(','):
                rules_string = rules_string[1:]
            rule_lists = rules_string.split(',')
            rule_key = rule_lists[len(rule_lists) - 1]
            rule_id = rule_key.split(':')[0]
            rule_meta_name = 'x-oss-meta-' + rule_id
            rule = resp.headers[rule_meta_name]
            rule = eval(rule)
            elem = Element('LifecycleConfiguration')
            xml_rule = SubElement(elem, 'Rule')
            SubElement(xml_rule, 'ID').text = rule['ruleId']
            SubElement(xml_rule, 'Prefix').text = rule['rulePrefix']
            SubElement(xml_rule, 'Status').text = rule['ruleStatus']
            expiration = SubElement(xml_rule, 'Expiration')
            if rule['expireDay'] != '':
                SubElement(expiration, 'Days').text = rule['expireDay']
            else:
                SubElement(expiration, 'Date').text = rule['createDate']
            body = tostring(elem)
            return HTTPOk(body=body, content_type='application/xml')
        else:
            elem = Element('Error')
            SubElement(elem, req.container_name)
            SubElement(elem, 'Code').text = 'NoSuchLifecycle'
            SubElement(elem, 'Message').text = 'No Row found in Lifecycle Table.'
            SubElement(elem, 'RequestId').text = resp.headers['x-oss-request-id']
            SubElement(elem, 'HostId').text = req.headers['Host']
            body = tostring(elem)
            return NoSuchLifecycle(req.container_name)

    @public
    def PUT(self, req):
        xml = req.xml(MAX_PUT_BUCKET_BODY_SIZE)
        if xml:
            # query bucket metadata
            resp = req.get_response(self.app, method='GET')
            if 'x-oss-meta-rules' in resp.headers:
                rules_string = resp.headers['x-oss-meta-rules']
                rules_num = len(rules_string.split(','))
                if rules_num > MAX_RULE_SIZE:
                    raise TooManyRules()
            else:
                rules_string = ''
            # get rule from request body
            try:
                elem = fromstring(xml, 'LifecycleConfiguration')
                for r in elem.findall('Rule'):
                    rule_id = r.find('ID').text
                    if rule_id in rules_string:
                        raise RuleIdExisted()
                    rule_prefix = r.find('Prefix').text
                    if rule_prefix is None:
                        rule_prefix = ''
                    rule_status = r.find('Status').text
                    expiration = r.find('Expiration')
                    if expiration.find('Days') is not None:
                        rule = LifecycleRule(rule_id, rule_prefix, status=rule_status,
                                             expiration=LifecycleExpiration(days=expiration.find('Days').text))
                    elif expiration.find('Date') is not None:
                        rule = LifecycleRule(rule_id, rule_prefix, status=rule_status,
                                             expiration=LifecycleExpiration(date=expiration.find('Date').text))
                    else:
                        raise MalformedXML()
                    if rules_string == '':
                        req.headers['X-Container-Meta-Rules'] = rule_id + ':' + rule_prefix
                    else:
                        req.headers['X-Container-Meta-Rules'] = rules_string + ',' + rule_id + ':' + rule_prefix
                    keys = ("ruleId", "rulePrefix", "ruleStatus", "expireDay", "createDate")
                    if rule.expiration.days is not None:
                        values = (rule.id, rule.prefix, rule.status, rule.expiration.days, '')
                        rule_dict = dict(zip(keys, values))
                        meta_name = 'X-Container-Meta-' + rule.id
                        req.headers[meta_name] = str(rule_dict)
                    elif rule.expiration.date is not None:
                        values = (rule.id, rule.prefix, rule.status, '', rule.expiration.date)
                        rule_dict = dict(zip(keys, values))
                        meta_name = 'X-Container-Meta-' + rule.id
                        req.headers[meta_name] = str(rule_dict)
                    else:
                        pass
            except (XMLSyntaxError, DocumentInvalid):
                raise MalformedXML()
            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                LOGGER.error(e)
                raise exc_type, exc_value, exc_traceback
        resp = req.get_response(self.app, method='POST', headers=req.headers)

        resp.Status = HTTP_OK

        return resp

    @public
    def DELETE(self, req):
        resp = req.get_response(self.app, method='GET')
        # if 'x-oss-meta-rules' is None should raise exception
        if 'x-oss-meta-rules' in resp.headers and resp.headers['x-oss-meta-rules'] != '':
            rules_string = resp.headers['x-oss-meta-rules']
            if rules_string.startswith(','):
                rules_string = rules_string[1:]
            rule_lists = rules_string.split(',')
            for rid in rule_lists:
                rule_key = rid.split(':')[0]
                rule_id = rule_key[0].upper() + rule_key[1:]
                # rule_id = rule_id.strip()
                meta_of_remove = 'X-Remove-Container-Meta-' + rule_id
                req.headers[meta_of_remove] = 'x'
            req.headers['X-Remove-Container-Meta-Rules'] = 'x'
        resp = req.get_response(self.app, method='POST', headers=req.headers)

        return resp


class LifecycleRule(object):

    ENABLED = 'Enabled'
    DISABLED = 'Disabled'

    def __init__(self, id, prefix,
                 status=ENABLED, expiration=None):
        self.id = id
        self.prefix = prefix
        self.status = status
        self.expiration = expiration


class LifecycleExpiration(object):
    def __init__(self, days=None, date=None):
        if days is not None and date is not None:
            raise RuleDateRequired()

        self.days = days
        self.date = date
