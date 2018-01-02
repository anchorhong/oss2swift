from copy import deepcopy
import sys
from urllib import quote
import lxml.etree
from oss2swift.exception import OssException
from oss2swift.utils import LOGGER, camel_to_snake, utf8encode, utf8decode,filterbadcode
from pkg_resources import resource_stream  # pylint: disable-msg=E0611


XMLNS_OSS = 'http://doc.oss-cn-hangzhou.aliyuncs.com'
XMLNS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'


class XMLSyntaxError(OssException):
    pass


class DocumentInvalid(OssException):
    pass


def cleanup_namespaces(elem):
    def remove_ns(tag, ns):
        if tag.startswith('{%s}' % ns):
            tag = tag[len('{%s}' % ns):]
        return tag

    if not isinstance(elem.tag, basestring):
        # elem is a comment element.
        return

    # remove oss namespace
    elem.tag = remove_ns(elem.tag, XMLNS_OSS)

    # remove default namespace
    if elem.nsmap and None in elem.nsmap:
        elem.tag = remove_ns(elem.tag, elem.nsmap[None])

    for e in elem.iterchildren():
        cleanup_namespaces(e)


def fromstring(text, root_tag=None):
    try:
        elem = lxml.etree.fromstring(text, parser)
    except lxml.etree.XMLSyntaxError as e:
        LOGGER.debug(e)
        raise XMLSyntaxError(e)

    cleanup_namespaces(elem)

    if root_tag is not None:
        # validate XML
        try:
            path = 'schema/%s.rng' % camel_to_snake(root_tag)
            with resource_stream(__name__, path) as rng:
                lxml.etree.RelaxNG(file=rng).assertValid(elem)
        except IOError as e:
            # Probably, the schema file doesn't exist.
            exc_type, exc_value, exc_traceback = sys.exc_info()
            LOGGER.error(e)
            raise exc_type, exc_value, exc_traceback
        except lxml.etree.DocumentInvalid as e:
            LOGGER.debug(e)
            raise DocumentInvalid(e)

    return elem


def tostring(tree, encoding_type=None, use_ossns=False):

    if encoding_type == 'url':
        tree = deepcopy(tree)
        for e in tree.iter():
            # Some elements are not url-encoded even when we specify
            # encoding_type=url.
            blacklist = ['LastModified', 'ID', 'DisplayName', 'Initiated']
            if e.tag not in blacklist:
                if isinstance(e.text, basestring):
                    e.text = quote(e.text)

    return lxml.etree.tostring(tree, xml_declaration=True, encoding='UTF-8')


class _Element(lxml.etree.ElementBase):
    """
    Wrapper Element class of lxml.etree.Element to support
    a utf-8 encoded non-ascii string as a text.

    Why we need this?:
    Original lxml.etree.Element supports only unicode for the text.
    It declines maintainability because we have to call a lot of encode/decode
    methods to apply account/container/object name (i.e. PATH_INFO) to each
    Element instance. When using this class, we can remove such a redundant
    codes from oss2swift middleware.
    """
    def __init__(self, *args, **kwargs):
        # pylint: disable-msg=E1002
        super(_Element, self).__init__(*args, **kwargs)

    @property
    def text(self):
        """
        utf-8 wrapper property of lxml.etree.Element.text
        """
        return utf8encode(lxml.etree.ElementBase.text.__get__(self))

    @text.setter
    def text(self, value):
        #lxml.etree.ElementBase.text.__set__(self, filterbadcode(utf8decode(value)))
        if value is not None:
            lxml.etree.ElementBase.text.__set__(self, filterbadcode(utf8decode(value)))

parser_lookup = lxml.etree.ElementDefaultClassLookup(element=_Element)
parser = lxml.etree.XMLParser()
parser.set_element_class_lookup(parser_lookup)

Element = parser.makeelement
SubElement = lxml.etree.SubElement
