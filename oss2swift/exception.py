class OssException(Exception):
    pass


class NotOssRequest(OssException):
    pass


class BadSwiftRequest(OssException):
    pass


class ACLError(OssException):
    pass


class InvalidSubresource(OssException):
    pass


OSS_CLIENT_ERROR_STATUS = -1


class OssError(Exception):
    def __init__(self, status, headers, body, details):
        self.status = status
        self.request_id = headers.get('x-oss-request-id', '')
        self.body = body
        self.details = details
        self.code = self.details.get('Code', '')
        self.message = self.details.get('Message', '')

    def __str__(self):
        error = {'status': self.status,
                 'details': self.details}
        return str(error)


class ClientError(OssError):
    def __init__(self, message):
        OssError.__init__(self, OSS_CLIENT_ERROR_STATUS, {}, 'ClientError: ' + message, {})

    def __str__(self):
        error = {'status': self.status,
                 'details': self.body}
        return str(error)


class ServerError(OssError):
    pass


class NotFound(ServerError):
    status = 40


class NoSuchLifecycle(NotFound):
    status = 404
    code = 'NoSuchLifecycle'
