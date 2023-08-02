import ujson as json
import time
from google.cloud import storage
import boto3
import os
import gzip
import requests
import logging
from .dassana_env import *
import datetime

logging.basicConfig(level=logging.INFO)

auth_url = get_auth_url()
app_url = get_app_url()
debug = get_if_debug()
ingestion_service_url = get_ingestion_srv_url()
client_id = get_client_id()
client_secret = get_client_secret()

class AuthenticationError(Exception):
    """Exception Raised when credentials in configuration are invalid"""

    def __init__(self, message):
        super().__init__()
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

class StageWriteFailure(Exception):
    """Exception for StageWriteFailure"""
    def __init__(self, message):
        super().__init__()
        self.message = message

    def __str__(self):
        return f"Stage Write Failure: {self.message}"

def datetime_handler(val):
    if isinstance(val, datetime.datetime):
        return val.isoformat()
    return str(val)

def get_ingestion_config(ingestion_config_id, app_id, tenant_id):
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

def patch_ingestion_config(payload, ingestion_config_id, app_id, tenant_id):
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
    
    return response.status_code

def get_access_token():
    url = f"{auth_url}/oauth/token"
    if auth_url.endswith("svc.cluster.local"):
        response = requests.post(
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
            verify=False
        )  
    else:
        response = requests.post(
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            }
        )
    try:
        access_token = response.json()["access_token"]
    except:
        raise InternalError(url, response.json())
    return access_token

def update_ingestion_to_done(job_id, tenant_id, metadata = {}):
    
    access_token = get_access_token()
    headers = {
        "x-dassana-tenant-id": tenant_id,
        "Authorization": f"Bearer {access_token}", 
    }
    res = requests.post(ingestion_service_url +"/job/"+job_id+"/"+"done", headers=headers, json={
        "metadata": metadata
    })
    print("Ingestion status updated to done")
    return res.json()

def cancel_ingestion_job(job_id, tenant_id, metadata, fail_type):
    
    access_token = get_access_token()
    headers = {
        "x-dassana-tenant-id": tenant_id,
        "Authorization": f"Bearer {access_token}", 
    }
    res = requests.post(ingestion_service_url +"/job/"+job_id+"/"+fail_type, headers=headers, json={
        "metadata": metadata
    })
    print("Ingestion status updated to failed")
    return res.json()

def get_ingestion_details(tenant_id, source, record_type, config_id, metadata, priority, is_snapshot):
    access_token = get_access_token()

    headers = {
        "x-dassana-tenant-id": tenant_id,
        "Authorization": f"Bearer {access_token}", 
    }
    json_body = {
        "source": str(source),
        "recordType": str(record_type),
        "configId": str(config_id),
        "is_snapshot": is_snapshot,
        "priority": priority,
        "metadata": metadata
        }
    
    if json_body["priority"] is None:
        del json_body["priority"]
    
    res = requests.post(ingestion_service_url +"/job/", headers=headers, json=json_body)
    if(res.status_code == 200):
        return res.json()

    return 0

def report_status(status, additionalContext, timeTakenInSec, recordsIngested, ingestion_config_id, app_id, tenant_id):
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

    logging.info(f"Reporting status: {json.dumps(payload)}")
    if app_url.endswith("svc.cluster.local:443"):
        resp = requests.Session().post(reportingURL, headers=headers, json=payload, verify=False)
        logging.info(f"Report request status: {resp.status_code}")
    else:
        resp = requests.Session().post(reportingURL, headers=headers, json=payload)
        logging.info(f"Report request status: {resp.status_code}")

class DassanaWriter:
    def __init__(self, tenant_id, source, record_type, config_id, metadata = {}, priority = None, is_snapshot = False):
        print("Initialized common utility")

        self.source = source
        self.record_type = record_type
        self.config_id = config_id
        self.metadata = metadata
        self.priority = priority
        self.is_snapshot = is_snapshot
        self.tenant_id = tenant_id
        self.bytes_written = 0
        self.client = None
        self.bucket_name = None
        self.blob = None
        self.full_file_path = None
        self.file_path = self.get_file_path()
        self.job_id = None
        self.initialize_client(self.tenant_id, self.source, self.record_type, self.config_id, self.metadata, self.priority, self.is_snapshot)
        self.file = open(self.file_path, 'a')
        

    def get_file_path(self):
        epoch_ts = int(time.time())
        return f"{epoch_ts}.ndjson"

    def compress_file(self):
        with open(self.file_path, 'rb') as file_in:
            with gzip.open(f"{self.file_path}.gz", 'wb') as file_out:
                file_out.writelines(file_in)
        print("Compressed file completed")
    
    def initialize_client(self, tenant_id, source, record_type, config_id,  metadata, priority, is_snapshot):
        try:
            response = get_ingestion_details(tenant_id, source, record_type, config_id, metadata, priority, is_snapshot)
            service = response['stageDetails']['cloud']
            self.job_id = response["jobId"]
        except Exception as e:
            raise InternalError("Failed to create ingestion job",e)


        if service == 'gcp':
            self.bucket_name = response['stageDetails']['bucket']
            credentials = response['stageDetails']['serviceAccountCredentialsJson']
            self.full_file_path = response['stageDetails']['filePath']
        
            with open('service_account.json', 'w') as f:
                json.dump(json.loads(credentials), f, indent=4)
                f.close()
            
            os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = 'service_account.json'
            self.client = storage.Client()

        elif service == 'aws':
            self.client = boto3.client('s3')
        else:
            raise ValueError()

    def write_json(self, json_object):
        self.file.flush()
        json.dump(json_object, self.file)
        self.file.write('\n')
        self.bytes_written = self.file.tell()
        if self.bytes_written >= 99 * 1000 * 1000:
            self.file.close()
            self.compress_file()
            self.upload_to_cloud()
            self.file_path = self.get_file_path()
            self.file = open(self.file_path, 'a')
            print(f"Ingested data: {self.bytes_written} bytes")
            self.bytes_written = 0
        
            

    def upload_to_cloud(self):
        if self.client is None:
            raise ValueError("Client not initialized.")

        if isinstance(self.client, storage.Client):
            self.upload_to_gcp()
        elif isinstance(self.client, boto3.client('s3')):
            self.upload_to_aws()
        else:
            raise ValueError()

    def upload_to_gcp(self):
        if self.client is None:
            raise ValueError("GCP client not initialized.")
        
        self.blob = self.client.bucket(self.bucket_name).blob(str(self.full_file_path) + "/" + str(self.file_path)+".gz")
        self.blob.upload_from_filename(self.file_path + ".gz")

    def upload_to_aws(self):
        if self.client is None:
            raise ValueError()

        self.client.upload_file(self.file_path, self.bucket_name, self.file_path)

    def cancel_job(self, error_code, failure_reason, debug_log, pass_counter = 0, fail_counter = 0, fail_type = "failed"):
        metadata = {}
        job_result = {"failure_reason": failure_reason, "status": str(fail_type), "debug_log": debug_log, "pass": pass_counter, "fail": fail_counter, "error_code": error_code}
        metadata["job_result"] = job_result
        cancel_ingestion_job(self.job_id, self.tenant_id, metadata, fail_type)
        if os.path.exists("service_account.json"):
            os.remove("service_account.json")

    def close(self):
        self.file.close()
        if self.bytes_written > 0:
            self.compress_file()
            self.upload_to_cloud()
            print(f"Ingested remaining data: {self.bytes_written} bytes")
            self.bytes_written = 0
        update_ingestion_to_done(self.job_id, self.tenant_id)
        if os.path.exists("service_account.json"):
            os.remove("service_account.json")

