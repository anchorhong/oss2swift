from functools import partial
import sys
import time

from oss2swift.cfg import CONF
from oss2swift.etree import Element, SubElement
from oss2swift.exception import InvalidSubresource
from oss2swift.response import InvalidArgument, MalformedACLError, \
    OssNotImplemented, InvalidRequest, AccessDenied
from oss2swift.utils import LOGGER, sysmeta_header
from swift.common.utils import json


XMLNS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'
PERMISSIONS = ['PRIVATE', 'PUBLIC-READ', 'PUBLIC-READ-WRITE']

def encode_acl(resource, acl):
    header_value = {"Owner": acl.owner.id}
    header_value.update({"Grant": acl.grant})
    headers = {}
    key = sysmeta_header(resource, 'acl')
    headers[key] = header_value['Grant']
    return headers


def decode_acl(resource, headers,owner):
    value = ''

    key = sysmeta_header(resource, 'acl')
    if key in headers:
        value = headers[key]
    if value == '':
      
        return ACL(Owner(None, None), [])
    try:

        id = None
        name = None
        if owner is not None:
	   id=owner
	   name=owner
	if id is not None and name is not None:
           return ACL(Owner(id, name), value)
    except Exception as e:
        LOGGER.debug(e)
        pass

    raise InvalidSubresource((resource, 'acl', value))





class Owner(object):
    """
    Owner class for Oss accounts
    """
    def __init__(self, id, name):
        self.id = id
        self.name = name


class AccessControlList(object):
    

    def __init__(self, grant):
        if grant.upper() not in PERMISSIONS:
	        raise OssNotImplemented
        self.grant = grant
    @classmethod
    def from_elem(cls, elem):
        
        grant = elem.find('./AccessControlList/Grant').text
        return cls(grant)
    def elem(self):
        """
        Create an etree element.
        """
        elem = Element('AccessControlList')
        SubElement(elem, 'Grant').text = self.grant

        return elem

    def allow(self, grant):
        return grant in self.grant


class ACL(object):
    """
    Oss ACL class.
    """
    metadata_name = 'acl'
    root_tag = 'AccessControlPolicy'
    max_xml_length = 200 * 1024

    def __init__(self, owner, grant):
    
        self.owner = owner
        self.grant = grant

    @classmethod
    def from_elem(cls, elem):
        """
        Convert an ElementTree to an ACL instance
        """
        id = elem.find('./Owner/ID').text
        try:
            name = elem.find('./Owner/DisplayName').text
        except AttributeError:
            name = id
         
        grant = elem.find('./AccessControlList/Grant').text
        
        return cls(Owner(id, name), grant)

    def elem(self):
        """
        Decode the value to an ACL instance.
        """
        elem = Element(self.root_tag)

        owner = SubElement(elem, 'Owner')
        SubElement(owner, 'ID').text = self.owner.id
        SubElement(owner, 'DisplayName').text = self.owner.name

        grant = SubElement(elem, 'AccessControlList')
        
        SubElement(grant, 'Grant').text = str(self.grant)
        return elem

    def check_owner(self, user_id):
        """
        Check that the user is an owner.
        """
        if not CONF.oss_acl:
            # Ignore Oss2Swift ACL.
            return

        if not self.owner.id:
            if CONF.allow_no_owner:
                # No owner means public.
                return
            raise AccessDenied()

        if user_id != self.owner.id:
            raise AccessDenied()

    def check_permission(self, user_id, grant):
        """
        Check that the user has a permission.
        """
        if not CONF.oss_acl:
            # Ignore Oss2Swift ACL.
            return

        try:
            # owners have full control permission
            self.check_owner(user_id)
            return
        except AccessDenied:
            pass

        if grant.upper in PERMISSIONS:
                g = self.grant
                if g.allow(user_id, 'public-read-write') or \
                        g.allow(user_id, grant):
                    return

        raise AccessDenied()

    @classmethod
    def from_headers(cls, headers, bucket_owner, object_owner=None,
                     as_private=True):
        grant=[]
        try:
            for key, value in headers.items():
                if key.lower().startswith('x-oss-acl'):
                    if value.upper() not in PERMISSIONS:
                        raise OssNotImplemented
                    grant.append(value)
            #===================================================================
            # if 'x-oss-acl' in headers:
            #     try:
            #         acl = headers['x-oss-acl']
            #         if len(grant) > 0:
            #             err_msg = 'Specifying both Canned ACLs and Header ' \
            #                 'Grants is not allowed'
            #             raise InvalidRequest(err_msg)
            #             grant.append(AccessControlList(grant[0]))
            #     except KeyError:
            #         # expects canned_acl_grantees()[] raises KeyError
            #         raise InvalidArgument('x-oss-acl', headers['x-oss-acl'])
            #===================================================================
        except (KeyError, ValueError):
            # TODO: think about we really catch this except sequence
            raise InvalidRequest()

        if len(grant) == 0:
            # No ACL headers
            if as_private:
                return ACLPrivate(bucket_owner, object_owner)
            else:
                return None

        return cls(object_owner or bucket_owner, grant[0])
def canned_acl_grant(bucket_owner, object_owner=None):
    owner = object_owner or bucket_owner

    return {
        'private': [
            ('private', User(owner.name)),
        ],
        'public-read': [
            ('public-read', AllUsers(owner.name)),
        ],
        'public-read-write': [
            ('public-read-write', AllUsers(owner.name)),
        ],
    }
class AllUsers(Owner):
    def __init__(self,name):
        super(AllUsers,self).__init__(id, name)
    uri = ''

    def __contains__(self, key):
        return True

class User(Owner):

    def __init__(self,name):
        
        super(User, self).__init__(id, name)
    def __contains__(self, key):
        return key == self.id

    def elem(self):
        elem = Element('Owner')
        SubElement(elem, 'ID').text = self.id
        SubElement(elem, 'DisplayName').text = self.display_name
        return elem

    def __str__(self):
        return self.display_name

class CannedACL(object):
    def __getitem__(self, key):
        def acl(key, bucket_owner, object_owner=None):
            grant= canned_acl_grant(bucket_owner, object_owner)[key]
            if str(grant[0]).upper in PERMISSIONS:
                grant.append(AccessControlList(grant[0]))
            
            return ACL(object_owner or bucket_owner, grant[0][0])

        return partial(acl, key)


canned_acl = CannedACL()

ACLPrivate = canned_acl['private']
ACLPublicRead = canned_acl['public-read']
ACLPublicReadWrite = canned_acl['public-read-write']


