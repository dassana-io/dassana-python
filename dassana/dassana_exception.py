import ujson as json


class DassanaException(Exception):
    """Exception Raised when something bad happened within dassana and could not auto recover"""
    is_internal = True
    is_auto_recoverable = False
    error_type = "internal_error"
    message = "Something went wrong"

    def __init__(self, message, error_details=None):
        super().__init__()
        self.message = message
        self.error_details = error_details

    def __str__(self):
        error_msg = f"[{self.error_type}] {self.message}"
        if self.error_details is not None:
            error_msg += f" : {self.error_details}"

    def to_json(self):
        return json.dumps(self.__dict__)


class ApiRequest:
    url = None
    body = None

    def __init__(self, url, body=None):
        self.url = url
        if body is not None:
            self.body = str(body)

    @classmethod
    def fromRequest(cls, request):
        return cls(request.url, request.body)

    def __str__(self):
        request_str = f"URL: {self.url} "
        if self.body is not None:
            request_str += f"Body: {self.body} "
        return request_str


class ApiResponse:
    status_code = 0
    status_message = None
    headers = None
    body = None

    def __init__(self, status_code=0, status_message=None, headers=None, body=None):
        if status_code is not None:
            self.status_code = status_code
        if status_message is not None:
            self.status_message = status_message
        if headers is not None:
            self.headers = headers
        if body is not None:
            self.body = str(body)

    @classmethod
    def fromResponse(cls, response):
        return cls(response.status_code, response.reason, response.headers, response.text)

    def __str__(self):
        response_str = f"Status code: {self.status_code} "
        if self.status_message is not None:
            response_str += f"Reason: {self.status_message} "
        if self.body is not None:
            response_str += f"Body: {self.body} "
        if self.headers is not None:
            response_str += f"Headers: {self.headers}"
        return response_str


class ApiError(DassanaException):
    """Exception Raised when api request failed"""
    httpResponse = None

    def __init__(self, http_request: ApiRequest, http_response: ApiResponse, is_internal, error_type="internal_error",
                 message="Something went wrong", error_details=None, is_auto_recoverable=False):
        super().__init__(message, error_details)
        self.httpRequest = http_request
        if http_response is not None:
            self.httpResponse = http_response
        self.error_type = error_type
        self.is_internal = is_internal
        self.is_auto_recoverable = is_auto_recoverable

    def __str__(self):
        error_str = f"[{self.error_type}] {self.message} : API Request failed - {self.httpRequest} "
        if self.httpResponse is not None:
            error_str += f"Response - {self.httpResponse} "
        if self.error_details is not None:
            error_str += f"due to {self.error_details} "
        return error_str


class AuthError(ApiError):
    """Exception Raised when credentials in configuration are invalid"""
    error_type = "auth_error"
    message = "Authorization Failure"

    def __init__(self, request, response, is_internal):
        super().__init__(request, response, error_type=self.error_type, message=self.message,
                         is_auto_recoverable=False, is_internal=is_internal)


class NetworkError(ApiError):
    """Exception Raised when api request failed to connection failure due to network issue or server not responding"""
    error_type = "network_error"
    message = "Connection/Network Failure"

    def __init__(self, request, error_msg, is_internal):
        super().__init__(request, ApiResponse(), error_type=self.error_type, message=self.message,
                         error_details=error_msg, is_auto_recoverable=True, is_internal=is_internal)


class ServerError(ApiError):
    """Exception Raised when server responded with 5xx failure"""
    error_type = "server_error"
    message = "Server Failure"

    def __init__(self, request, response, is_internal):
        super().__init__(request, response, error_type=self.error_type, message=self.message, is_auto_recoverable=True,
                         is_internal=is_internal)


class RateLimitError(ApiError):
    """Exception Raised when api request is rate limited by server"""
    error_type = "rate_limit_error"
    message = "Rate limit exceeded"

    def __init__(self, request, response, is_internal):
        super().__init__(request, response, error_type=self.error_type, message=self.message, is_auto_recoverable=True,
                         is_internal=is_internal)


class ExternalError(DassanaException):
    """Exception Raised when an unexpected exception occurred in an external service"""
    is_internal = False
    is_auto_recoverable = False
    error_type = "external_error"
    message = "Something went wrong"

    def __init__(self, message, error_details=None):
        super().__init__(message, error_details)


class InternalError(DassanaException):
    """Exception Raised when something bad happened within dassana and could not auto recover"""


class StageWriteFailure(DassanaException):
    """Exception for StageWriteFailure"""
    is_internal = True
    is_auto_recoverable = False
    error_type = "stage_write_failure"
    message = "Failed to write to external stage"

    def __init__(self, message, error_details=None):
        super().__init__(message, error_details)
