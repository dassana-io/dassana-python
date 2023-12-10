import timeit
import requests
import logging
from tenacity import retry, stop_after_attempt, before_sleep_log, retry_if_exception, wait_exponential
from typing import Final
from requests.exceptions import Timeout, HTTPError, ConnectionError, RequestException
from .dassana_exception import ApiRequest, ApiResponse, ApiError, NetworkError, ServerError, RateLimitError, AuthError

logger: Final = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class Api:
    http_response = None
    api_start_ts = None
    api_end_ts = None

    def __init__(self, method, url, data=None, json=None, auth=None, headers=None, params=None, cookies=None,
                 timeout=300, verify=True, is_internal=False, ignore_not_found_error=False):
        self.method = method.upper()  # supported method GET/POST/PUT/PATCH/DELETE
        self.url = url
        self.auth = auth
        self.headers = headers
        self.data = data
        self.json = json
        self.params = params
        self.cookies = cookies
        self.timeout = timeout
        self.verify = verify
        self.is_internal = is_internal
        self.ignore_not_found_error = ignore_not_found_error
        if data is not None:
            self.http_request = ApiRequest(url, data)
        elif json is not None:
            self.http_request = ApiRequest(url, json)
        else:
            self.http_request = ApiRequest(url)

    def call_api(self):
        try:
            response = self.api_request()
            logging.debug(f"API request successful (url - {self.http_request.url} body - {self.http_request.body})")
            return response
        except ApiError as e:
            logging.error(f"{str(e)}")
            raise e

    @retry(
        retry=retry_if_exception(lambda e: isinstance(e, ApiError) and e.is_auto_recoverable),
        wait=wait_exponential(multiplier=5, min=30, max=60),
        stop=stop_after_attempt(3),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True)
    def api_request(self):
        try:
            self.api_start_ts = timeit.default_timer()
            response = requests.request(self.method, self.url, headers=self.headers, data=self.data, json=self.json,
                                        params=self.params, auth=self.auth,
                                        timeout=self.timeout, cookies=self.cookies, verify=self.verify)
            self.http_response = ApiResponse().fromResponse(response)
            self.statusValidator()
            return response
        except (ConnectionError, Timeout) as exp:
            raise NetworkError(self.http_request, exp, is_internal=self.is_internal)
        except HTTPError as httpError:
            raise ApiError(self.http_request, ApiResponse().fromResponse(httpError.response),
                           is_internal=self.is_internal, is_auto_recoverable=True)
        except RequestException as requestError:
            raise ApiError(self.http_request, ApiResponse().fromResponse(requestError.response),
                           error_details=requestError, is_internal=self.is_internal, is_auto_recoverable=True)
        except ApiError as apiError:
            raise apiError
        finally:
            self.api_end_ts = timeit.default_timer()

    def statusValidator(self):
        if self.http_response.status_code == 200:
            return
        elif self.http_response.status_code == 400:
            raise ApiError(self.http_request, self.http_response, is_internal=self.is_internal,
                           is_auto_recoverable=False)
        elif not self.ignore_not_found_error and self.http_response.status_code == 404:
            raise ApiError(self.http_request, self.http_response, is_internal=self.is_internal,
                           is_auto_recoverable=False)
        elif self.http_response.status_code in (401, 403):
            raise AuthError(self.http_request, self.http_response, self.is_internal)
        elif self.http_response.status_code == 408:
            raise NetworkError(self.http_request, self.http_response, is_internal=self.is_internal)
        elif self.http_response.status_code == 429:
            raise RateLimitError(self.http_request, self.http_response, is_internal=self.is_internal)
        elif 500 <= self.http_response.status_code < 599:
            raise ServerError(self.http_request, self.http_response, is_internal=self.is_internal)
        else:
            raise ApiError(self.http_request, self.http_response, is_internal=self.is_internal,
                           is_auto_recoverable=True)
