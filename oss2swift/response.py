from UserDict import DictMixin
from functools import partial
import re
import sys
from oss2swift.etree import Element, SubElement, tostring
from oss2swift.utils import snake_to_camel, sysmeta_prefix
from swift.common import swob
from swift.common.utils import config_true_value


class HeaderKey(str):
    """
    A string object that normalizes string as OSS clients expect with title().
    """
    def title(self):
        if self.lower() == 'etag':
            return 'ETag'
        if self.lower().startswith('x-oss-'):
            return self.lower()
        return str.title(self)


class HeaderKeyDict(swob.HeaderKeyDict):
    """
    Similar to the HeaderKeyDict class in Swift, but its key name is normalized
    as OSS clients expect.
    """
    def __getitem__(self, key):
        return swob.HeaderKeyDict.__getitem__(self, HeaderKey(key))

    def __setitem__(self, key, value):
        return swob.HeaderKeyDict.__setitem__(self, HeaderKey(key), value)

    def __contains__(self, key):
        return swob.HeaderKeyDict.__contains__(self, HeaderKey(key))

    def __delitem__(self, key):
        return swob.HeaderKeyDict.__delitem__(self, HeaderKey(key))

    def get(self, key, default=None):
        return swob.HeaderKeyDict.get(self, HeaderKey(key), default)

    def pop(self, key, default=None):
        return swob.HeaderKeyDict.pop(self, HeaderKey(key), default)


class ResponseBase(object):
    """
    Base class for oss2swift responses.
    """
    pass


class Response(ResponseBase, swob.Response):
    """
    Similar to the Response class in Swift, but uses our HeaderKeyDict for
    headers instead of Swift's HeaderKeyDict.  This also translates Swift
    specific headers to OSS headers.
    """
    def __init__(self, *args, **kwargs):
        swob.Response.__init__(self, *args, **kwargs)

        if self.etag:
            # add double quotes to the etag header
            self.headers['etag'] = self.etag

        sw_sysmeta_headers = swob.HeaderKeyDict()
        sw_headers = swob.HeaderKeyDict()
        headers = HeaderKeyDict()
        self.is_slo = False

        for key, val in self.headers.iteritems():
            _key = key.lower()
            if _key.startswith(sysmeta_prefix('object')) or \
                    _key.startswith(sysmeta_prefix('container')):
                sw_sysmeta_headers[key] = val
            else:
                sw_headers[key] = val

        # Handle swift headers
        for key, val in sw_headers.iteritems():
            _key = key.lower()

            if _key.startswith('x-object-meta-'):
                if any(_str in _key for _str in ('object-type', 'hash-crc64ecma')):
                    headers['x-oss-' + _key[14:]] = val
                else:
                    headers['x-oss-meta-' + _key[14:]] = val
            elif _key.startswith('x-container-meta-'):
                headers['x-oss-meta-' + _key[17:]] = val
            elif _key in ('content-length', 'content-type',
                          'content-range', 'content-encoding',
                          'content-disposition', 'content-language',
                          'etag', 'last-modified', 'x-robots-tag',
                          'cache-control', 'expires'):
                headers[key] = val
            elif _key == 'x-static-large-object':
                # for delete slo
                self.is_slo = config_true_value(val)

        if headers['x-oss-meta-location'] is None:
            headers['x-oss-meta-location'] = ''
        self.headers = headers
        # Used for pure swift header handling at the request layer
        self.sw_headers = sw_headers
        self.sysmeta_headers = sw_sysmeta_headers

    @classmethod
    def from_swift_resp(cls, sw_resp):
        """
        Create a new OSS response object based on the given Swift response.
        """
        if sw_resp.app_iter:
            body = None
            app_iter = sw_resp.app_iter
        else:
            body = sw_resp.body
            app_iter = None

        resp = Response(status=sw_resp.status, headers=sw_resp.headers,
                        request=sw_resp.request, body=body, app_iter=app_iter,
                        conditional_response=sw_resp.conditional_response)
        resp.environ.update(sw_resp.environ)

        return resp

    def append_copy_resp_body(self, controller_name, last_modified):
        elem = Element('Copy%sResult' % controller_name)
        SubElement(elem, 'LastModified').text = last_modified
        SubElement(elem, 'ETag').text = '"%s"' % self.etag
        self.headers['Content-Type'] = 'application/xml'
        self.body = tostring(elem)
#        self.etag = None


HTTPOk = partial(Response, status=200)
HTTPCreated = partial(Response, status=201)
HTTPAccepted = partial(Response, status=202)
HTTPNoContent = partial(Response, status=204)
HTTPPartialContent = partial(Response, status=206)


class ErrorResponse(ResponseBase, swob.HTTPException):
    """
    OSS error object.
    """
    _status = ''
    _msg = ''
    _code = ''

    def __init__(self, msg=None, *args, **kwargs):
        if msg:
            self._msg = msg
        if not self._code:
            self._code = self.__class__.__name__

        self.info = kwargs.copy()
        for reserved_key in ('headers', 'body'):
            if self.info.get(reserved_key):
                del(self.info[reserved_key])

        swob.HTTPException.__init__(self, status=self._status,
                                    app_iter=self._body_iter(),
                                    content_type='application/xml', *args,
                                    **kwargs)
        self.headers = HeaderKeyDict(self.headers)

    def _body_iter(self):
        error_elem = Element('Error')
        SubElement(error_elem, 'Code').text = self._code
        SubElement(error_elem, 'Message').text = self._msg
        if 'swift.trans_id' in self.environ:
            request_id = self.environ['swift.trans_id']
            SubElement(error_elem, 'RequestId').text = request_id

        self._dict_to_etree(error_elem, self.info)

        yield tostring(error_elem, use_ossns=False)

    def _dict_to_etree(self, parent, d):
        for key, value in d.items():
            tag = re.sub('\W', '', snake_to_camel(key))
            elem = SubElement(parent, tag)

            if isinstance(value, (dict, DictMixin)):
                self._dict_to_etree(elem, value)
            else:
                try:
                    elem.text = str(value)
                except ValueError:
                    # We set an invalid string for XML.
                    elem.text = '(invalid string)'


class AccessDenied(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'Access Denied.'


class AccountProblem(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'There is a problem with your OSS account that prevents the ' \
           'operation from completing successfully.'


class TooManyRules(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'There is too many rule item in this Bukcet'


class RuleIdExisted(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'The rule id already existed'


class AmbiguousGrantByEmailAddress(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The e-mail address you provided is associated with more than ' \
           'one account.'


class AuthorizationHeaderMalformed(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The authorization header is malformed; the authorization ' \
           'header requires three components: Credential, SignedHeaders, ' \
           'and Signature.'


class AuthorizationQueryParametersError(ErrorResponse):
    _status = '400 Bad Request'


class BadDigest(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The Content-MD5 you specified did not match what we received.'


class BucketAlreadyExists(ErrorResponse):
    _status = '409 Conflict'
    _msg = 'The requested bucket name is not available. The bucket ' \
           'namespace is shared by all users of the system. Please select a ' \
           'different name and try again.'

    def __init__(self, bucket, msg=None, *args, **kwargs):
        ErrorResponse.__init__(self, msg, bucket_name=bucket, *args, **kwargs)


class BucketAlreadyOwnedByYou(ErrorResponse):
    _status = '409 Conflict'
    _msg = 'Your previous request to create the named bucket succeeded and ' \
           'you already own it.'

    def __init__(self, bucket, msg=None, *args, **kwargs):
        ErrorResponse.__init__(self, msg, bucket_name=bucket, *args, **kwargs)


class BucketNotEmpty(ErrorResponse):
    _status = '409 Conflict'
    _msg = 'The bucket you tried to delete is not empty.'


class CredentialsNotSupported(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'This request does not support credentials.'


class CrossLocationLoggingProhibited(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'Cross location logging not allowed. Buckets in one geographic ' \
           'location cannot log information to a bucket in another location.'


class EntityTooSmall(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your proposed upload is smaller than the minimum allowed object ' \
           'size.'


class EntityTooLarge(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your proposed upload exceeds the maximum allowed object size.'


class ExpiredToken(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The provided token has expired.'


class IllegalVersioningConfigurationException(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The Versioning configuration specified in the request is invalid.'


class IncompleteBody(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'You did not provide the number of bytes specified by the ' \
           'Content-Length HTTP header.'


class IncorrectNumberOfFilesInPostRequest(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'POST requires exactly one file upload per request.'


class InlineDataTooLarge(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Inline data exceeds the maximum allowed size.'


class InvalidObjectName(ErrorResponse):
    _status = '400 InvalidObjectName'
    _code = 'InvalidObjectName'


class InternalError(ErrorResponse):
    _status = '500 Internal Server Error'
    _msg = 'We encountered an internal error. Please try again.'


class InvalidAccessKeyId(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'The OSS Access Key Id you provided does not exist in our records.'


class InvalidArgument(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Invalid Argument.'
#    def __init__(self, status, headers, body, details):
#        super(InvalidArgument, self).__init__(status, headers, body, details)
#        self.name = details.get('ArgumentName')
#        self.value = details.get('ArgumentValue')

#    def __init__(self, name, value, msg=None, *args, **kwargs):
#        ErrorResponse.__init__(self, msg, argument_name=name,
#                               argument_value=value, *args, **kwargs)


class ObjectInvalid(ErrorResponse):
    _status = '403 Object Invalid'
    _msg = 'The specified object is not valid now'


class InvalidBucketName(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The specified bucket is not valid.'

    def __init__(self, bucket, msg=None, *args, **kwargs):
        ErrorResponse.__init__(self, msg, bucket_name=bucket, *args, **kwargs)


class InvalidBucketState(ErrorResponse):
    _status = '409 Conflict'
    _msg = 'The request is not valid with the current state of the bucket.'


class InvalidDigest(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The Content-MD5 you specified was an invalid.'


class InvalidLocationConstraint(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The specified location constraint is not valid.'


class InvalidObjectState(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'The operation is not valid for the current state of the object.'


class InvalidPart(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'One or more of the specified parts could not be found. The part ' \
           'might not have been uploaded, or the specified entity tag might ' \
           'not have matched the part\'s entity tag.'


class InvalidPartOrder(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The list of parts was not in ascending order.Parts list must ' \
           'specified in order by part number.'


class InvalidPayer(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'All access to this object has been disabled.'


class InvalidPolicyDocument(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The content of the form does not meet the conditions specified ' \
           'in the policy document.'


class InvalidRange(ErrorResponse):
    _status = '416 Requested Range Not Satisfiable'
    _msg = 'The requested range cannot be satisfied.'


class InvalidRequest(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Invalid Request.'


class InvalidSecurity(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'The provided security credentials are not valid.'


class InvalidSOAPRequest(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The SOAP request body is invalid.'


class InvalidStorageClass(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The storage class you specified is not valid.'


class InvalidTargetBucketForLogging(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The target bucket for logging does not exist, is not owned by ' \
           'you, or does not have the appropriate grants for the ' \
           'log-delivery group.'

    def __init__(self, bucket, msg=None, *args, **kwargs):
        ErrorResponse.__init__(self, msg, target_bucket=bucket, *args,
                               **kwargs)


class InvalidToken(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The provided token is malformed or otherwise invalid.'


class InvalidURI(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Couldn\'t parse the specified URI.'

    def __init__(self, uri, msg=None, *args, **kwargs):
        ErrorResponse.__init__(self, msg, uri=uri, *args, **kwargs)


class KeyTooLong(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your key is too long.'


class MalformedACLError(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The XML you provided was not well-formed or did not validate ' \
           'against our published schema.'


class MalformedPOSTRequest(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The body of your POST request is not well-formed ' \
           'multipart/form-data.'


class MalformedXML(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The XML you provided was not well-formed or did not validate ' \
           'against our published schema.'


class MaxMessageLengthExceeded(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your request was too big.'


class MaxPostPreDataLengthExceededError(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your POST request fields preceding the upload file were too large.'


class MetadataTooLarge(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your metadata headers exceed the maximum allowed metadata size.'


class MethodNotAllowed(ErrorResponse):
    _status = '405 Method Not Allowed'
    _msg = 'The specified method is not allowed against this resource.'

    def __init__(self, method, resource_type, msg=None, *args, **kwargs):
        ErrorResponse.__init__(self, msg, method=method,
                               resource_type=resource_type, *args, **kwargs)


class MissingContentLength(ErrorResponse):
    _status = '411 Length Required'
    _msg = 'You must provide the Content-Length HTTP header.'


class MissingRequestBodyError(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Request body is empty.'


class MissingSecurityElement(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The SOAP 1.1 request is missing a security element.'


class MissingSecurityHeader(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your request was missing a required header.'


class NoLoggingStatusForKey(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'There is no such thing as a logging status sub-resource for a key.'


class NoSuchBucket(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified bucket does not exist.'

    def __init__(self, bucket, msg=None, *args, **kwargs):
        if not bucket:
            raise InternalError()
        ErrorResponse.__init__(self, msg, bucket_name=bucket, *args, **kwargs)


class NoSuchLifecycle(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The lifecycle configuration does not exist.'

    def __init__(self, bucket, msg=None, *args, **kwargs):
        if not bucket:
            raise InternalError()
        ErrorResponse.__init__(self, msg, bucket_name=bucket, *args, **kwargs)


class NoSuchKey(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified key does not exist.'

    def __init__(self, key, msg=None, *args, **kwargs):
        if key is None:
            raise InternalError()
        ErrorResponse.__init__(self, msg, key=key, *args, **kwargs)


class NoSuchCORSConfiguration(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified Cors does not exist.'
class NoSuchWebsiteConfiguration(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified Website does not exist.'

class NoSuchLifecycleConfiguration(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The lifecycle configuration does not exist. .'


class NoSuchUpload(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified multipart upload does not exist. The upload ID ' \
           'might be invalid, or the multipart upload might have been ' \
           'aborted or completed.'


class NoSuchVersion(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified version does not exist.'

    def __init__(self, key, version_id, msg=None, *args, **kwargs):
        if not key:
            raise InternalError()
        ErrorResponse.__init__(self, msg, key=key, version_id=version_id,
                               *args, **kwargs)


# NotImplemented is a python built-in constant.  Use OssNotImplemented instead.
class OssNotImplemented(ErrorResponse):
    _status = '501 Not Implemented'
    _msg = 'Not implemented.'
    _code = 'NotImplemented'


class NotSignedUp(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'Your account is not signed up for the Aliyun OSS service.'


class NotSuchBucketPolicy(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified bucket does not have a bucket policy.'


class OperationAborted(ErrorResponse):
    _status = '409 Conflict'
    _msg = 'A conflicting conditional operation is currently in progress ' \
           'against this resource. Please try again.'


class PermanentRedirect(ErrorResponse):
    _status = '301 Moved Permanently'
    _msg = 'The bucket you are attempting to access must be addressed using ' \
           'the specified endpoint. Please send all future requests to this ' \
           'endpoint.'


class PreconditionFailed(ErrorResponse):
    _status = '412 Precondition Failed'
    _msg = 'At least one of the preconditions you specified did not hold.'


class Redirect(ErrorResponse):
    _status = '307 Moved Temporarily'
    _msg = 'Temporary redirect.'


class RestoreAlreadyInProgress(ErrorResponse):
    _status = '409 Conflict'
    _msg = 'Object restore is already in progress.'


class RequestIsNotMultiPartContent(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Bucket POST must be of the enclosure-type multipart/form-data.'


class RequestTimeout(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your socket connection to the server was not read from or ' \
           'written to within the timeout period.'


class RequestTimeTooSkewed(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'The difference between the request time and the server\'s time ' \
           'is too large.'


class RequestTorrentOfBucketError(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Requesting the torrent file of a bucket is not permitted.'


class RuleDateRequired(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'days and date should not be both specified'


class SignatureDoesNotMatch(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'The request signature we calculated does not match the ' \
           'signature you provided. Check your key and signing method.'


class ServiceUnavailable(ErrorResponse):
    _status = '503 Service Unavailable'
    _msg = 'Please reduce your request rate.'


class SlowDown(ErrorResponse):
    _status = '503 Slow Down'
    _msg = 'Please reduce your request rate.'


class TemporaryRedirect(ErrorResponse):
    _status = '307 Moved Temporarily'
    _msg = 'You are being redirected to the bucket while DNS updates.'


class TokenRefreshRequired(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The provided token must be refreshed.'


class TooManyRules(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'There is too many Core rule item in this Bukcet'


class TooManyBuckets(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'You have attempted to create more buckets than allowed.'


class UnexpectedContent(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'This request does not support content.'


class UnresolvableGrantByEmailAddress(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The e-mail address you provided does not match any account on ' \
           'record.'


class UserKeyMustBeSpecified(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The bucket POST must contain the specified field name. If it is ' \
           'specified, please check the order of the fields.'
