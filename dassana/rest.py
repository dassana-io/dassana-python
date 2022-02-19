import requests
import gzip
from .dassana_env import *
from json import dumps
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from urllib3.exceptions import MaxRetryError


def forward_logs(
    log_data,
    endpoint=get_endpoint(),
    token=get_token(),
    app_id=get_app_id(),
    use_ssl=get_ssl(),
):

    headers = {
        "x-dassana-token": token,
        "x-dassana-app-id": app_id,
        "Content-type": "application/x-ndjson",
        "Content-encoding": "gzip",
    }

    retry = Retry(
        total=3,
        status_forcelist=[429, 500, 502, 503, 504],
        backoff_factor=1,
        method_whitelist=["POST"],
    )

    http = requests.Session()
    adapter = HTTPAdapter(max_retries=retry)
    http.mount("http://", adapter)
    http.mount("https://", adapter)

    payload = "\n".join(dumps(log) for log in log_data) + "\n"
    payload_compressed = gzip.compress(payload.encode("utf-8"))

    response = http.post(
        endpoint, headers=headers, data=payload_compressed, verify=use_ssl
    )
    return response
