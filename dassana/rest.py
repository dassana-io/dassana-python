import requests
import json
import base64
import gzip
import datetime
import logging
import sys, os
from .dassana_env import *
from json import dumps
from requests.adapters import HTTPAdapter
from kubernetes import client, config
from requests.packages.urllib3.util.retry import Retry
from urllib3.exceptions import MaxRetryError
from google.cloud import pubsub_v1
import jwt
import time

logging.basicConfig(level=logging.INFO)

auth_url = os.environ.get("DASSANA_JWT_ISSUER")
app_url = os.environ.get("DASSANA_APP_SERVICE_HOST")
service_client_id = os.environ.get("DASSANA_CLIENT_ID")
tenant_id = os.environ.get("DASSANA_TENANT_ID")
debug = int(os.environ.get("DASSANA_DEBUG", 0))

class AuthenticationError(Exception):
    """Exception Raised when credentials in configuration are invalid"""

    def __init__(self, message):
        super().__init__()
        self.source = 'snyk-api'
        self.message = message

    def __str__(self):
        return f"Source authentication failure: {self.message}"


class InternalError(Exception):
    """Exception Raised for AppServices, Ingestion, or Upstream
    Attributes:
        source -- error origin
        message -- upstream response
    """

    def __init__(self, source, message=""):
        self.source = source
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return json.dumps({"source": self.source, "message": self.message})

class TimeRange:

    def __new__(self, timeRangeType):

        class AbsoluteTimeRange:

            def __init__(self):
                pass

            startTime = None
            endTime = None

            def setStartTime(self, startTime: int):
                self.startTime = startTime
                return self

            def setEndTime(self, endTime: int):
                self.endTime = endTime
                return self

            def getStartTime(self):
                return self.startTime

            def getEndTime(self):
                return self.endTime

            def getTimeRangeDict(self):
                timeDict = dict()
                timeDict["type"] = timeRangeType
                timeDict["startTime"]= self.startTime
                timeDict["endTime"] = self.endTime
                return timeDict

            def __str__(self) -> str:
                return (f"Range Type : {timeRangeType},\nStart Time : {self.startTime},\nEnd Time : {self.endTime}")

        class RelativeTimeRange:

            unit = None
            amount = None

            def __init__(self):
                pass

            def setAmount(self, amount: int):
                self.amount = amount
                return self

            def setUnit(self, unit: str):
                self.unit = unit
                return self

            def getAmount(self):
                return self.amount

            def getUnit(self):
                return self.unit

            def getTimeRangeDict(self):
                timeDict = dict()
                timeDict["type"] = timeRangeType
                timeDict["amount"]= self.amount
                timeDict["unit"] = self.unit
                return timeDict

            def __str__(self) -> str:
                return (f"Range Type : {timeRangeType},\nAmount : {self.amount},\nUnit : {self.unit}")

            # return RelativeTimeRange()

        if timeRangeType=='absolute':
            return AbsoluteTimeRange()
        elif timeRangeType=='relative':
            return RelativeTimeRange()

    def getTimeRangeDict(self):
        pass

def get_client_secret():
    if os.getenv("KUBERNETES_SERVICE_HOST"):
        config.load_incluster_config()
    else:
        config.load_kube_config()
        if debug:
            return os.getenv("DASSANA_SERVICE_CLIENT_SECRET")
    v1 = client.CoreV1Api()
    secret_res = v1.read_namespaced_secret("ingestion-secrets", "ingestion")
    secret_b64 = secret_res.data["security.clientSecret"]
    secret = base64.b64decode(secret_b64)
    return secret

def get_access_token():
    url = f"{auth_url}/oauth/token"
    if auth_url.endswith("svc.cluster.local"):
        response = requests.post(
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": service_client_id,
                "client_secret": get_client_secret(),
            },
            verify=False
        )  
    else:
        response = requests.post(
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": service_client_id,
                "client_secret": get_client_secret(),
            }
        )
    try:
        access_token = response.json()["access_token"]
    except:
        raise InternalError(url, response.json())
    return access_token

app_id = get_app_id()
ingestion_config_id = get_ingestion_config_id()

def get_ingestion_config(ingestion_config_id):
    url = f"https://{app_url}/app/{app_id}/ingestionConfig/{ingestion_config_id}"
    access_token = get_access_token()
    headers = {
        "x-dassana-tenant-id": tenant_id,
        "Authorization": f"Bearer {access_token}", 
    }
    if app_url.endswith("svc.cluster.local:443"):
        response = requests.request("GET", url, headers=headers, verify=False)
    else:
        response = requests.request("GET", url, headers=headers)
    try:
        ingestion_config = response.json() 
    except:
        raise InternalError(url, response.json())
    return ingestion_config

def patch_ingestion_config(payload, ingestion_config_id):
    url = f"https://{app_url}/app/{app_id}/ingestionConfig/{ingestion_config_id}"
    access_token = get_access_token()
    headers = {
        "x-dassana-tenant-id": tenant_id,
        "Authorization": f"Bearer {access_token}",
    }
    if app_url.endswith("svc.cluster.local:443"):
        response = requests.request("PATCH", url, headers=headers, json=payload, verify=False)
    else:
        response = requests.request("PATCH", url, headers=headers, json=payload)
    snyk_token=response.json()
    return snyk_token

def get_dassana_token():
    access_token = get_access_token()
    url = f"https://{app_url}/token"

    headers = {
        "x-dassana-tenant-id": tenant_id,
        "Authorization": f"Bearer {access_token}",
    }
    if app_url.endswith("svc.cluster.local:443"):
        response = requests.request("GET", url, headers=headers, verify=False)
    else:
        response = requests.request("GET", url, headers=headers)
    try:
        token = response.json()[0]["value"]
    except:
        raise InternalError(url, response.json())
    return token

dassana_token = get_dassana_token()
os.environ["DASSANA_TOKEN"] = dassana_token

def report_status(status, additionalContext, timeTakenInSec, recordsIngested, ingestion_config_id):
    reportingURL = f"https://{app_url}/app/v1/{app_id}/status"

    headers = {
        "x-dassana-tenant-id": tenant_id,
        "Authorization": f"Bearer {get_access_token()}",
    }

    payload = {
        "status": status,
        "timeTakenInSec": int(timeTakenInSec),
        "recordsIngested": recordsIngested,
        "ingestionConfigId": ingestion_config_id
    }

    if additionalContext:
        payload['additionalContext'] = additionalContext

    # logging.info(f"Reporting headers: {json.dumps(headers)}")
    logging.info(f"Reporting status: {json.dumps(payload)}")
    if app_url.endswith("svc.cluster.local:443"):
        resp = requests.Session().post(reportingURL, headers=headers, json=payload, verify=False)
        logging.info(f"Report request status: {resp.status_code}")
    else:
        resp = requests.Session().post(reportingURL, headers=headers, json=payload)
        logging.info(f"Report request status: {resp.status_code}")

def datetime_handler(val):
    if isinstance(val, datetime.datetime):
        return val.isoformat()
    return str(val)

endpoint = get_endpoint()

def create_snapshot(ingestion_type,metadata):

    if ingestion_type == 'assets':
        snapshotId = get_asset_snapshot_id()
        if snapshotId is not None:
            return snapshotId
        
    elif ingestion_type == 'findings':
        snapshotId = get_finding_snapshot_id()
        if snapshotId is not None:
            return snapshotId

    headers = {
        "x-dassana-app-id":f"{app_id}",
        "x-dassana-token":f"{dassana_token}",
        "x-dassana-ingestion-type":f"{ingestion_type}"
    }
    
    resp = requests.post(f"{endpoint}/snapshot", headers=headers,json=metadata)
    snapshot = resp.json()

    currentTs = round(time.time() * 1000)
    timeRange = currentTs - 3600000
    if snapshot['status'] == "IN_PROGRESS":
        if timeRange <= snapshot['lastUpdatedTs'] <= currentTs:
            logging.info("wait for previous snapshot to end")
            return None
        else:
            snapshot_id = snapshot.get('id')
            end_snapshot(ingestion_type,snapshot_id,'cancel',False)
            result = create_snapshot(ingestion_type,metadata)
            return result['id']
    else:
        return snapshot['id']
    
def update_snapshot(ingestion_type,snapshot_id,payload):
    headers = {
        "x-dassana-app-id":f"{app_id}",
        "x-dassana-token":f"{dassana_token}",
        "x-dassana-ingestion-type":f"{ingestion_type}",
        "x-dassana-snapshot-id":f"{snapshot_id}"
    }

    retry = Retry(
    total=3,
    status_forcelist=[429, 500, 502, 503, 504],
    backoff_factor=2,
    method_whitelist=["PUT"]
    )

    http = requests.Session()
    adapter = HTTPAdapter(max_retries=retry)
    http.mount("http://", adapter)
    http.mount("https://", adapter)

    resp = http.put(f"{endpoint}/snapshot", headers=headers,json=payload)
    updated_snapshot = resp.json()
    return updated_snapshot
    
def end_snapshot(ingestion_type,snapshot_id,status,is_recon):
    headers = {
        "x-dassana-app-id":f"{app_id}",
        "x-dassana-token":f"{dassana_token}",
        "x-dassana-ingestion-type":f"{ingestion_type}",
        "x-dassana-snapshot-id":f"{snapshot_id}"
    }
    resp = requests.post(f"{endpoint}/snapshot/{status}?isReconJob={is_recon}", headers=headers)
    return resp.status_code

def forward_logs(log_data,type="findings",snapshot_id=None):    
    if type == 'findings':
        endpoint = f"{os.environ['DASSANA_ENDPOINT']}/findings"
    elif type == 'assets':
        endpoint = f"{os.environ['DASSANA_ENDPOINT']}/assets"
    elif type == 'events':
        endpoint = f"{os.environ['DASSANA_ENDPOINT']}/events"

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
    
    if snapshot_id:
        headers['x-dassana-snapshot-id'] = snapshot_id

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
            resp_obj = response.json()
            res_objs.append(resp_obj)
            total_docs = total_docs + resp_obj.get("docCount", 0)

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

def refreshDassanaToken(token):
    decoded_token = jwt.decode(token, key=None, options={"verify_signature":False})

    # Less than 3 minutes to expiry, refresh
    if decoded_token.get('exp') - int(time.time()) < 180:
        return get_access_token()
    return token

def post_dassana_query(query: str, timeRange: TimeRange) -> list:
    try:
        token = get_access_token()
        #refresh
        token = refreshDassanaToken(token)
        decoded = jwt.decode(token, key=None, options={"verify_signature":False})
        domain = (str(decoded["aud"]).split(".")[2])

        requestHeader = {
            "content-type" : "application/json",
            "Authorization" : "Bearer"+" "+token,
            "Accept" : "application/json",
            "x-dassana-tenant-id" : tenant_id
        }

        requestBody = dict()
        requestBody["query"] = query
        requestBody["timeRange"] = timeRange.getTimeRangeDict()

        response = requests.request("POST", f"https://dquery.dassana.{domain}/query", headers=requestHeader, json=requestBody).text
        responseDict = json.loads(response)
        return responseDict

    except KeyError as e:
        logging.error(f"No such key '{e}' found while triggering dassana query")
    except Exception as e:
        logging.error(f"An exception occurred while triggering dassana query {e}")
