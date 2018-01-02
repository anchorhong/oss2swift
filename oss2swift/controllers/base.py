import functools

from oss2swift.response import OssNotImplemented, InvalidRequest
from oss2swift.utils import LOGGER, camel_to_snake


def bucket_operation(func=None, err_resp=None, err_msg=None):
    """
    A decorator to ensure that the request is a bucket operation.  If the
    target resource is an object, this decorator updates the request by default
    so that the controller handles it as a bucket operation.  If 'err_resp' is
    specified, this raises it on error instead.
    """
    def _bucket_operation(func):
        @functools.wraps(func)
        def wrapped(self, req):
            if not req.is_bucket_request:
                if err_resp:
                    raise err_resp(msg=err_msg)

                LOGGER.debug('A key is specified for bucket API.')
                req.object_name = None

            return func(self, req)

        return wrapped

    if func:
        return _bucket_operation(func)
    else:
        return _bucket_operation


def object_operation(func):
    """
    A decorator to ensure that the request is an object operation.  If the
    target resource is not an object, this raises an error response.
    """
    @functools.wraps(func)
    def wrapped(self, req):
        if not req.is_object_request:
            raise InvalidRequest('A key must be specified')

        return func(self, req)

    return wrapped


def check_container_existence(func):
    """
    A decorator to ensure the container existence.
    """
    @functools.wraps(func)
    def check_container(self, req):
        req.get_container_info(self.app)
        return func(self, req)

    return check_container


class Controller(object):
    """
    Base WSGI controller class for the middleware
    """
    def __init__(self, app, **kwargs):
        self.app = app

    @classmethod
    def resource_type(cls):
        """
        Returns the target resource type of this controller.
        """
        name = cls.__name__[:-len('Controller')]
        return camel_to_snake(name).upper()


class UnsupportedController(Controller):
    """
    Handles unsupported requests.
    """
    def __init__(self, app, **kwargs):
        raise OssNotImplemented('The requested resource is not implemented')
