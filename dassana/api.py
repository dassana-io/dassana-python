import timeit
import requests
from requests.models import Response
import logging
from tenacity import retry, stop_after_attempt, before_sleep_log, retry_if_exception, wait_exponential
from typing import Final
from requests.exceptions import Timeout, HTTPError, ConnectionError, RequestException
from .dassana_exception import ApiRequest, ApiResponse, ApiError, NetworkError, ServerError, RateLimitError, AuthError
from requests.compat import (
    basestring,
    urlencode
)
from requests.utils import to_key_val_list
from json import dumps as json_dumps

logger: Final = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def encode_params(data):
    """Encode parameters in a piece of data.

    Will successfully encode parameters when passed as a dict or a list of
    2-tuples. Order is retained if data is a list of 2-tuples but arbitrary
    if parameters are supplied as a dict.
    """

    if data is None:
        return None
    if isinstance(data, (str, bytes)):
        return data
    elif hasattr(data, "read"):
        return data
    elif hasattr(data, "__iter__"):
        result = []
        for k, vs in to_key_val_list(data):
            if isinstance(vs, basestring) or not hasattr(vs, "__iter__"):
                vs = [vs]
            for v in vs:
                if v is not None:
                    result.append(
                        (
                            k.encode("utf-8") if isinstance(k, str) else k,
                            v.encode("utf-8") if isinstance(v, str) else v,
                        )
                    )
        return urlencode(result, doseq=True)
    else:
        return data


def call_api(method, url, data=None, json=None, auth=None, headers=None, params=None, cookies=None, timeout=300,
             verify=True, is_internal=False, ignore_not_found_error=False, new_status_validator=None,
             do_not_track_request_body=False) -> Response:
    api_start_ts = timeit.default_timer()
    try:
        response = api_request(method, url, data, json, auth, headers, params, cookies, timeout, verify, is_internal,
                               ignore_not_found_error, new_status_validator, do_not_track_request_body)
        api_end_ts = timeit.default_timer()
        logging.debug(f"API request successful (url - {url} body - {data or json})")
        return response
    except ApiError as e:
        api_end_ts = timeit.default_timer()
        logging.error(f"{str(e)}")
        raise e


@retry(
    retry=retry_if_exception(lambda e: isinstance(e, ApiError) and e.is_auto_recoverable),
    wait=wait_exponential(multiplier=5, min=30, max=60),
    stop=stop_after_attempt(3),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=True)
def api_request(method, url, data=None, json=None, auth=None, headers=None, params=None, cookies=None, timeout=300,
                verify=True, is_internal=False, ignore_not_found_error=False, new_status_validator=None,
                do_not_track_request_body=False) -> Response:
    global status_validator
    http_request = ApiRequest(method, url,
                              (json_dumps(json) if json is not None else encode_params(data))
                              if not do_not_track_request_body else None)
    try:
        response = requests.request(method, url, headers=headers, data=data, json=json, params=params, auth=auth,
                                    timeout=timeout, cookies=cookies, verify=verify)
        http_response = ApiResponse().from_response(response)
        status_validator = new_status_validator or status_validator
        status_validator(http_request, http_response, is_internal, ignore_not_found_error)
        return response
    except (ConnectionError, Timeout) as exp:
        raise NetworkError(http_request, exp, is_internal=is_internal)
    except HTTPError as httpError:
        raise ApiError(http_request, ApiResponse().from_response(httpError.response), is_internal=is_internal,
                       is_auto_recoverable=True)
    except RequestException as requestError:
        raise ApiError(http_request, ApiResponse().from_response(requestError.response), error_details=requestError,
                       is_internal=is_internal, is_auto_recoverable=True)
    except ApiError as apiError:
        raise apiError


def status_validator(http_request, http_response, is_internal, ignore_not_found_error):
    if int(http_response.status_code / 100) == 2:
        return
    elif http_response.status_code == 400:
        raise ApiError(http_request, http_response, is_internal=is_internal, is_auto_recoverable=False)
    elif not ignore_not_found_error and http_response.status_code == 404:
        raise ApiError(http_request, http_response, is_internal=is_internal, is_auto_recoverable=False)
    elif http_response.status_code in (401, 403):
        raise AuthError(http_request, http_response, is_internal)
    elif http_response.status_code == 408:
        raise NetworkError(http_request, http_response, is_internal=is_internal)
    elif http_response.status_code == 429:
        raise RateLimitError(http_request, http_response, is_internal=is_internal)
    elif int(http_response.status_code / 100) == 5:
        raise ServerError(http_request, http_response, is_internal=is_internal)
    else:
        raise ApiError(http_request, http_response, is_internal=is_internal, is_auto_recoverable=True)
