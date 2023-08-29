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
from tenacity import retry, wait_fixed, stop_after_attempt

logging.basicConfig(level=logging.INFO)

auth_url = get_auth_url()
app_url = get_app_url()
debug = get_if_debug()
ingestion_service_url = get_ingestion_srv_url()
client_id = get_client_id()
client_secret = get_client_secret()

class AuthenticationError(Exception):
    """Exception Raised when credentials in configuration are invalid"""

    def __init__(self, message, response):
        super().__init__()
        self.message = message
        self.response = response

    def __str__(self):
        return f"AuthenticationError: {self.message} (Response: {self.response})"

class ExternalError(Exception):
    """Exception Raised when credentials in configuration are invalid"""

    def __init__(self, message):
        super().__init__()
        self.message = message

    def __str__(self):
        return f"ExternalError: {self.message}"

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
        return f"InternalError from {self.source}: {self.message}"
        

class StageWriteFailure(Exception):
    """Exception for StageWriteFailure"""
    def __init__(self, message):
        super().__init__()
        self.message = message

    def __str__(self):
        return f"StageWriteFailure: {self.message}"

def datetime_handler(val):
    if isinstance(val, datetime.datetime):
        return val.isoformat()
    return str(val)

@retry(wait=wait_fixed(30), stop=stop_after_attempt(3))
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
    except Exception as e:
        raise InternalError("Failed to get ingestion config", "Error getting response from app-manager with response body: " + str(response.text) + " and response header: " + str(response.headers) + " and stack trace: " +  str(e))
    return ingestion_config

@retry(wait=wait_fixed(30), stop=stop_after_attempt(3))
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

@retry(wait=wait_fixed(30), stop=stop_after_attempt(3))
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
    except Exception as e:
        raise InternalError("Failed to get access token", "Error getting response from app-manager with response body: " + str(response.text) + " and response header: " + str(response.headers) + " and stack trace: " +  str(e))

    return access_token

@retry(wait=wait_fixed(30), stop=stop_after_attempt(3))
def update_ingestion_to_done(job_id, tenant_id, metadata):
    
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

@retry(wait=wait_fixed(30), stop=stop_after_attempt(3))
def cancel_ingestion_job(job_id, tenant_id, metadata, fail_type):
    
    access_token = get_access_token()
    headers = {
        "x-dassana-tenant-id": tenant_id,
        "Authorization": f"Bearer {access_token}", 
    }
    res = requests.post(ingestion_service_url +"/job/"+job_id+"/"+fail_type, headers=headers, json={
        "metadata": metadata
    })
    print("Ingestion status updated to " + str(fail_type))
    return res.json()

@retry(wait=wait_fixed(30), stop=stop_after_attempt(3))
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

@retry(wait=wait_fixed(30), stop=stop_after_attempt(3))
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
        self.storage_service = None
        self.client = None
        self.aws_iam_role_arn = None
        self.aws_iam_external_id = None
        self.aws_sts_client = None
        self.aws_session_token_expiration = None
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
            
            self.storage_service = response['stageDetails']['cloud']
            self.job_id = response["jobId"]
        except Exception as e:
            raise InternalError("Failed to create ingestion job", "Error getting response from ingestion-srv with response body: " + str(response.text) + " and response header: " + str(response.headers) + " and stack trace: " +  str(e))


        if self.storage_service == 'gcp':
            self.bucket_name = response['stageDetails']['bucket']
            credentials = response['stageDetails']['serviceAccountCredentialsJson']
            self.full_file_path = response['stageDetails']['filePath']
        
            with open('service_account.json', 'w') as f:
                json.dump(json.loads(credentials), f, indent=4)
                f.close()
            
            os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = 'service_account.json'
            self.client = storage.Client()

        elif self.storage_service == 'aws':
            stage_details = response['stageDetails']
            if "awsIamRoleArn" in stage_details:
                self.aws_sts_client = boto3.client('sts', aws_access_key_id=stage_details['accessKey'], aws_secret_access_key=stage_details['secretKey'])
                self.aws_iam_role_arn = stage_details['awsIamRoleArn']
                self.aws_iam_external_id = stage_details['awsIamExternalId']
            else:
                self.client = boto3.client('s3', aws_access_key_id=stage_details['accessKey'], aws_secret_access_key=stage_details['secretKey'])
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

        if self.storage_service == 'gcp':
            self.upload_to_gcp()
        elif self.storage_service == 'aws':
            self.upload_to_aws()
        else:
            raise ValueError()

    def upload_to_gcp(self):
        if self.client is None:
            raise ValueError("GCP client not initialized.")
        
        self.blob = self.client.bucket(self.bucket_name).blob(str(self.full_file_path) + "/" + str(self.file_path)+".gz")
        self.blob.upload_from_filename(self.file_path + ".gz")

    def upload_to_aws(self):
        if self.client is None or self.aws_sts_client is None:
            raise ValueError()

        if self.aws_iam_role_arn and (not self.aws_session_token_expiration or (self.aws_session_token_expiration < datetime.datetime.now() + datetime.timedelta(minutes=2))):
            assume_role_response = self.aws_sts_client.assume_role(
                    RoleArn=self.aws_iam_role_arn,
                    RoleSessionName="DassanaIngestion",
                    ExternalId=self.aws_iam_external_id)
            temp_credentials = assume_role_response['Credentials']
            self.aws_session_token_expiration = temp_credentials['SecretAccessKey']
            self.client = boto3.client(
                's3',
                aws_access_key_id=temp_credentials['AccessKeyId'],
                aws_secret_access_key=temp_credentials['SecretAccessKey'],
                aws_session_token=temp_credentials['SessionToken'])
        
        self.client.upload_file(self.file_path, self.bucket_name, self.file_path)

    def cancel_job(self, error_code, failure_reason, debug_log, pass_counter = 0, fail_counter = 0, fail_type = "failed"):
        metadata = {}
        job_result = {"failure_reason": failure_reason, "status": str(fail_type), "debug_log": debug_log, "pass": pass_counter, "fail": fail_counter, "error_code": error_code}
        metadata["job_result"] = job_result
        cancel_ingestion_job(self.job_id, self.tenant_id, metadata, fail_type)
        if os.path.exists("service_account.json"):
            os.remove("service_account.json")

    def cancel_job(self, exception_from_src):
        if os.path.exists("service_account.json"):
            os.remove("service_account.json")
        try:
            if(type(exception_from_src).__name__ == "ExternalError"):
                metadata = {}
                job_result = {"failure_reason": exception_from_src.message, "status": "failed", "debug_log": [str(exception_from_src)], "error_code": "other_error"}
                metadata["job_result"] = job_result
                cancel_ingestion_job(self.job_id, self.tenant_id, metadata, "failed")

            elif(type(exception_from_src).__name__ == "AuthenticationError"):
                
                debug_log = ["Auth Response: " + str(exception_from_src.response) + " Stack Trace: " + str(exception_from_src)]
                metadata = {}
                job_result = {"failure_reason": exception_from_src.message, "status": "failed", "debug_log": debug_log, "error_code": "auth_error"}
                metadata["job_result"] = job_result
                cancel_ingestion_job(self.job_id, self.tenant_id, metadata, "failed")

            elif(type(exception_from_src).__name__ == "InternalError"):
                metadata = {}
                job_result = {"failure_reason": exception_from_src.message, "status": "cancel", "debug_log": [str(exception_from_src)], "error_code": "other_error"}
                metadata["job_result"] = job_result
                cancel_ingestion_job(self.job_id, self.tenant_id, metadata, "cancel")

            elif(type(exception_from_src).__name__ == "StageWriteFailure"):
                metadata = {}
                job_result = {"failure_reason": exception_from_src.message, "status": "failed", "debug_log": [str(exception_from_src)], "error_code": "stage_write_failure"}
                metadata["job_result"] = job_result
                cancel_ingestion_job(self.job_id, self.tenant_id, metadata, "failed")
            
            else:
                metadata = {}
                job_result = {"failure_reason": str(exception_from_src), "status": "cancel", "debug_log": [str(exception_from_src)], "error_code": "other_error"}
                metadata["job_result"] = job_result
                cancel_ingestion_job(self.job_id, self.tenant_id, metadata, "cancel")
        
        except Exception as e:
            metadata = {}
            job_result = {"failure_reason": str(e), "status": "cancel", "debug_log": [str(e)], "error_code": "other_error"}
            try:
                cancel_ingestion_job(self.job_id, self.tenant_id, {}, "cancel")
            except:
                raise
            
    def close(self, pass_counter, fail_counter, debug_log = set()):
        self.file.close()
        metadata = {}
        job_result = {"status": "ready_for_download", "source": {"pass" : int(pass_counter), "fail": int(fail_counter), "debug_log": list(debug_log)}}
        metadata["job_result"] = job_result
        if self.bytes_written > 0:
            self.compress_file()
            self.upload_to_cloud()
            print(f"Ingested remaining data: {self.bytes_written} bytes")
            self.bytes_written = 0
        update_ingestion_to_done(self.job_id, self.tenant_id, metadata)
        if os.path.exists("service_account.json"):
            os.remove("service_account.json")

