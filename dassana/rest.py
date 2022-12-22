import requests
import gzip
from .dassana_env import *
from json import dumps
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from urllib3.exceptions import MaxRetryError
from google.cloud import pubsub_v1


def datetime_handler(val):
    if isinstance(val, datetime.datetime):
        return val.isoformat()
    return str(val)

def forward_logs(
    log_data
):

    endpoint=get_endpoint()
    app_id=get_app_id()
    use_ssl=get_ssl()
    token = get_token()
    magic_word = get_magic_word()

    headers = {
        "x-dassana-token": token,
        "x-dassana-app-id": app_id,
        "Content-type": "application/x-ndjson",
        "Content-encoding": "gzip",
    }

    if magic_word:
        headers['x-dassana-magic-word'] = magic_word

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

    bytes_so_far = 0
    payload = ""
    responses = []
    batch_size = get_batch_size()

    for log in log_data:
        payload_line = dumps(log, default=datetime_handler)
        payload += payload_line + "\n"
        bytes_so_far += len(payload_line)
        if bytes_so_far > batch_size * 1048576:
            payload_compressed = gzip.compress(payload.encode("utf-8"))
            response = requests.post(
                endpoint, headers=headers, data=payload_compressed, verify=use_ssl
            )
            print(response.text)
            bytes_so_far = 0
            payload = ""
            responses.append(response)

    if bytes_so_far > 0:
        payload_compressed = gzip.compress(payload.encode("utf-8"))
        response = requests.post(
            endpoint, headers=headers, data=payload_compressed, verify=use_ssl
        )
        print(response.text)
        responses.append(response)

    all_ok = True
    total_docs = 0
    res_objs = []
    for response in responses:
        resp_ok = response.status_code == 200
        all_ok = all_ok & resp_ok
        if resp_ok:
            res_objs.append(response.json())
            total_docs += response.get("docCount", 0)

    return {
        "batches": len(responses),
        "success": all_ok,
        "total_docs": total_docs,
        "responses": res_objs,
    }

def acknowledge_delivery():
    try:
        ack_id = get_ackID()
    except:
        return

    subscriber = pubsub_v1.SubscriberClient()
    subscription_path = subscriber.subscription_path(get_gcp_project_id(), get_gcp_subscription_id())

    ack_ids = [ack_id]
    subscriber.acknowledge(
        request={"subscription": subscription_path, "ack_ids": ack_ids}
    )

