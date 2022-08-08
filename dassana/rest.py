import requests
import gzip
from .dassana_env import *
from json import dumps
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from urllib3.exceptions import MaxRetryError
from google.api_core import retry
from google.cloud import pubsub_v1


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

    bytes_so_far = 0
    payload = ""
    responses = []
    batch_size = get_batch_size()

    for log in log_data:
        payload += dumps(log) + "\n"
        bytes_so_far += len(dumps(log))
        if bytes_so_far > batch_size * 1048576:
            payload_compressed = gzip.compress(payload.encode("utf-8"))
            response = http.post(
                endpoint, headers=headers, data=payload_compressed, verify=use_ssl
            )
            bytes_so_far = 0
            payload = ""
            responses.append(response)

    if bytes_so_far > 0:
        payload_compressed = gzip.compress(payload.encode("utf-8"))
        response = http.post(
            endpoint, headers=headers, data=payload_compressed, verify=use_ssl
        )
        responses.append(response)

    res_objs = [response.json() for response in responses]
    all_ok = all(response.status_code == 200 for response in responses)
    total_docs = sum(response.get("docCount", 0) for response in res_objs)

    ack = get_ackID()
    if ack['ack_exists'] and all_ok:
        acknowledge_delivery(ack['gcp_config'])   

    return {
        "batches": len(responses),
        "success": all_ok,
        "total_docs": total_docs,
        "responses": res_objs,
    }

def acknowledge_delivery(gcp_config):
    subscriber = pubsub_v1.SubscriberClient()
    subscription_path = subscriber.subscription_path(gcp_config['project_id'], gcp_config['subscription_id'])

    ack_ids = [gcp_config['ack_id']]
    subscriber.acknowledge(
        request={"subscription": subscription_path, "ack_ids": ack_ids}
    )
