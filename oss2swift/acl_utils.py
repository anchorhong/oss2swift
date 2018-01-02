from oss2swift.etree import fromstring, XMLSyntaxError, DocumentInvalid
from oss2swift.exception import ACLError
from oss2swift.response import OssNotImplemented, MalformedACLError, \
    InvalidArgument


def swift_acl_translate(acl, group='', user='', xml=False):
    """
    Takes an OSS style ACL and returns a list of header/value pairs that
    implement that ACL in Swift, or "NotImplemented" if there isn't a way to do
    that yet.
    """
    swift_acl = {}
    swift_acl['public-read'] = [['X-Container-Read', '.r:*,.rlistings']]
    # Swift does not support public write:
    swift_acl['public-read-write'] = [['X-Container-Write', '.r:*'],
                                      ['X-Container-Read',
                                       '.r:*,.rlistings']]

    # TODO: if there's a way to get group and user, this should work for
    # private:
    # swift_acl['private'] = \
    #     [['HTTP_X_CONTAINER_WRITE',  group + ':' + user], \
    #      ['HTTP_X_CONTAINER_READ', group + ':' + user]]
    swift_acl['private'] = [['X-Container-Write', ' '],
                            ['X-Container-Read', ' ']]
    if xml:
        # We are working with XML and need to parse it
        try:
            elem = fromstring(acl, 'AccessControlPolicy')
        except (XMLSyntaxError, DocumentInvalid):
            raise MalformedACLError()
        acl = 'unknown'
        acl = elem.find('./AccessControlList/Grant').text
    if acl not in swift_acl:
        raise ACLError()

    return swift_acl[acl]


def handle_acl_header(req):

    oss_acl = req.environ['HTTP_X_OSS_ACL']
    del req.environ['HTTP_X_OSS_ACL']
    if req.query_string:
        req.query_string = ''

    try:
        translated_acl = swift_acl_translate(oss_acl)
    except ACLError:
        raise InvalidArgument('x-oss-acl', oss_acl)

    for header, acl in translated_acl:
        req.headers[header] = acl

