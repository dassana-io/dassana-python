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

class AuthenticationError(Exception):
    """Exception Raised when credentials in configuration are invalid"""

    def __init__(self, message, response):
        super().__init__()
        self.message = message
        self.response = response

    def __str__(self):
        return f"AuthenticationError: {self.message} (Response: {self.response})"

class ExternalError(Exception):
    """Exception Raised when an unexpected exception occured in an external service"""

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

class ApiResponseError(Exception):
    """Exception Raised when API response is not as expected"""

    def __init__(self, request_url, response_code, response_header, response_body, request_header):
        super().__init__()
        self.request_url = request_url
        self.response_code = response_code
        self.response_header = response_header
        self.response_body = response_body
        self.request_header = request_header
    
    def __str__(self):
        return f"ApiResponseError:\n Endpoint:{self.request_url}\n Reponse Code:{self.response_code}\n Response Header:{self.response_header}\n Response Body:{self.response_body}\n Request Header: {self.request_header}"

    def get_json(self):
        return {"request_url": self.request_url, "response_code": self.response_code, "response_header": self.response_header, "response_body": self.response_body, "request_header": self.request_header}
        
def datetime_handler(val):
    if isinstance(val, datetime.datetime):
        return val.isoformat()
    return str(val)

def get_headers():
    headers = {}
    if is_internal_auth():
        access_token = get_access_token()
        headers = {
            "x-dassana-tenant-id": get_tenant_id(),
            "Authorization": f"Bearer {access_token}", 
        }
    else:
        app_token = get_dassana_token()
        headers = {
            "Authorization": f"Dassana {app_token}"
        }
    return headers

def get_exc_str(exc):
    return str(exc.replace("\"", "").replace("'", "").replace("\n"," ").replace("\t"," "))

@retry(wait=wait_fixed(30), stop=stop_after_attempt(3))
def get_ingestion_config(ingestion_config_id, app_id):
    app_url = get_app_url()
    url = f"https://{app_url}/app/{app_id}/ingestionConfig/{ingestion_config_id}"
    headers = get_headers()
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
def patch_ingestion_config(payload, ingestion_config_id, app_id):
    app_url = get_app_url()
    url = f"https://{app_url}/app/{app_id}/ingestionConfig/{ingestion_config_id}"
    headers = get_headers()
    if app_url.endswith("svc.cluster.local:443"):
        response = requests.request("PATCH", url, headers=headers, json=payload, verify=False)
    else:
        response = requests.request("PATCH", url, headers=headers, json=payload)
    
    return response.status_code

@retry(wait=wait_fixed(30), stop=stop_after_attempt(3))
def get_access_token():
    auth_url = get_auth_url()
    url = f"{auth_url}/oauth/token"
    if auth_url.endswith("svc.cluster.local"):
        response = requests.post(
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": get_client_id(),
                "client_secret": get_client_secret(),
            },
            verify=False
        )  
    else:
        response = requests.post(
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": get_client_id(),
                "client_secret": get_client_secret(),
            }
        )
    try:
        access_token = response.json()["access_token"]
    except Exception as e:
        raise InternalError("Failed to get access token", "Error getting response from app-manager with response body: " + str(response.text) + " and response header: " + str(response.headers) + " and stack trace: " +  str(e))

    return access_token

@retry(wait=wait_fixed(30), stop=stop_after_attempt(3))
def report_status(status, additionalContext, timeTakenInSec, recordsIngested, ingestion_config_id, app_id):
    app_url = get_app_url()
    reportingURL = f"https://{app_url}/app/v1/{app_id}/status"

    headers = get_headers()

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
    def __init__(self, source, record_type, config_id, metadata = {}, priority = None, is_snapshot = False):
        logging.info("Initialized common utility")

        self.source = source
        self.record_type = record_type
        self.config_id = config_id
        self.metadata = metadata
        self.priority = priority
        self.is_snapshot = is_snapshot
        self.bytes_written = 0
        self.fail_counter = 0
        self.pass_counter = 0
        self.debug_log = set()
        self.storage_service = None
        self.client = None
        self.aws_iam_role_arn = None
        self.aws_iam_external_id = None
        self.aws_sts_client = None
        self.aws_session_token_expiration = None
        self.bucket_name = None
        self.blob = None
        self.full_file_path = None
        self.headers = get_headers()
        self.ingestion_service_url = get_ingestion_srv_url()
        self.is_internal_auth = is_internal_auth()
        self.file_path = self.get_file_path()
        self.job_id = None
        self.ingestion_metadata = None
        self.custom_file_dict = dict()
        self.initialize_client()
        self.file = open(self.file_path, 'a')

    def get_file_path(self):
        epoch_ts = int(time.time())
        if not self.is_internal_auth:
            return f"/tmp/{epoch_ts}.ndjson"
        return f"{epoch_ts}.ndjson"

    def compress_file(self, file_name):
        with open(file_name, 'rb') as file_in:
            with gzip.open(f"{file_name}.gz", 'wb') as file_out:
                file_out.writelines(file_in)
        logging.info("Compressed file completed")
    
    def initialize_client(self):
        try:
            response = self.get_ingestion_details()
            
            self.storage_service = response['stageDetails']['cloud']
            self.job_id = response["jobId"]
            logging.info(f"Ingestion job created with job id: {self.job_id}")
            self.ingestion_metadata = response["metadata"]
        except Exception as e:
            raise InternalError("Failed to create ingestion job", "Error getting response from ingestion-srv with stack trace: " +  str(e))
        
        if "bucket" in response['stageDetails']:
            self.bucket_name = response['stageDetails']['bucket']
            self.full_file_path = response['stageDetails']['filePath']

        if self.storage_service == 'gcp':
            if "bucket" in response["stageDetails"]:
                credentials = response['stageDetails']['serviceAccountCredentialsJson']
                with open('service_account.json', 'w') as f:
                    json.dump(json.loads(credentials), f, indent=4)
                    f.close()
                
                os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = 'service_account.json'
                self.client = storage.Client()
        elif self.storage_service == 'aws':
            stage_details = response['stageDetails']
            if "awsIamRoleArn" in stage_details and stage_details["awsIamRoleArn"] is not None:
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
            self.compress_file(self.file_path)
            self.upload_to_cloud(self.file_path)
            self.file_path = self.get_file_path()
            self.file = open(self.file_path, 'a')
            logging.info(f"Ingested data: {self.bytes_written} bytes")
            self.bytes_written = 0

    def write_custom_json(self, json_object, file_name):
        if file_name in self.custom_file_dict:
            custom_file = self.custom_file_dict[file_name]
        else:
            custom_file = open(file_name, 'a')
            self.custom_file_dict[file_name] = custom_file
        custom_file.flush()
        json.dump(json_object, custom_file)
        custom_file.write('\n')

    def upload_to_cloud(self, file_name):

        if not self.is_internal_auth:
            self.upload_to_signed_url()
        elif self.storage_service == 'gcp':
            self.upload_to_gcp(file_name)
        elif self.storage_service == 'aws':
            self.upload_to_aws(file_name)
        else:
            raise ValueError()

    def upload_to_gcp(self, file_name):
        if self.client is None:
            raise ValueError("GCP client not initialized.")
        
        self.blob = self.client.bucket(self.bucket_name).blob(str(self.full_file_path) + "/" + str(file_name)+".gz")
        self.blob.upload_from_filename(file_name + ".gz")

    def upload_to_aws(self, file_name):
        if self.client is None and self.aws_sts_client is None:
            raise ValueError("AWS client not initialized")

        if self.aws_iam_role_arn and (not self.aws_session_token_expiration or (self.aws_session_token_expiration.timestamp() < (datetime.datetime.now() + datetime.timedelta(minutes=2)).timestamp())):
            assume_role_response = self.aws_sts_client.assume_role(
                    RoleArn=self.aws_iam_role_arn,
                    RoleSessionName="DassanaIngestion",
                    ExternalId=self.aws_iam_external_id)
            temp_credentials = assume_role_response['Credentials']
            self.aws_session_token_expiration = temp_credentials['Expiration']
            self.client = boto3.client(
                's3',
                aws_access_key_id=temp_credentials['AccessKeyId'],
                aws_secret_access_key=temp_credentials['SecretAccessKey'],
                aws_session_token=temp_credentials['SessionToken'])

        self.client.put_object(Body=open(f"{file_name}.gz", 'rb'), Bucket=self.bucket_name, Key=f"{str(self.full_file_path)}/{str(file_name)}.gz")
        # self.client.upload_file(file_name + ".gz" , self.bucket_name, str(self.full_file_path) + "/" + str(file_name)+".gz")

    def upload_to_signed_url(self):
        signed_url = self.get_signing_url()
        if not signed_url:
            raise ValueError("The signed URL has not been received")
        
        headers = {
            'Content-Encoding': 'gzip',
            'Content-Type': 'application/octet-stream'
        }
        with open(str(self.file_path) + ".gz", "rb") as read:
            data = read.read()
            requests.put(url=signed_url, data=data, headers=headers)

    def cancel_job(self, error_code, failure_reason, fail_type = "failed"):
        metadata = {}
        fail_type_status_metadata = "canceled" if str(fail_type) == "cancel" else str(fail_type)
        self.debug_log.add(get_exc_str(str(failure_reason)))
        job_result = {"failure_reason": failure_reason, "status": fail_type_status_metadata, "debug_log": list(self.debug_log), "pass": self.pass_counter, "fail": self.fail_counter, "error_code": error_code}
        metadata["job_result"] = job_result
        self.cancel_ingestion_job(metadata, fail_type)
        if os.path.exists("service_account.json"):
            os.remove("service_account.json")

    def cancel_job(self, exception_from_src):
        if os.path.exists("service_account.json"):
            os.remove("service_account.json")
        try:
            str_exc = get_exc_str(str(exception_from_src))
            if(type(exception_from_src).__name__ == "ExternalError"):
                metadata = {}
                self.debug_log.add(str_exc)
                job_result = {"failure_reason": exception_from_src.message, "status": "failed", "debug_log": list(self.debug_log), "pass": self.pass_counter, "fail": self.fail_counter, "error_code": "other_error"}
                metadata["job_result"] = job_result
                self.cancel_ingestion_job(metadata, "failed")

            elif(type(exception_from_src).__name__ == "AuthenticationError"):
                self.debug_log.add("Auth Response: " + get_exc_str(str(exception_from_src.response)) + " Stack Trace: " + str_exc)
                metadata = {}
                job_result = {"failure_reason": exception_from_src.message, "status": "failed", "debug_log": list(self.debug_log), "pass": self.pass_counter, "fail": self.fail_counter, "error_code": "auth_error"}
                metadata["job_result"] = job_result
                self.cancel_ingestion_job(metadata, "failed")

            elif(type(exception_from_src).__name__ == "InternalError"):
                self.debug_log.add(str_exc)
                metadata = {}
                job_result = {"failure_reason": exception_from_src.message, "status": "canceled", "debug_log": list(self.debug_log), "pass": self.pass_counter, "fail": self.fail_counter, "error_code": "other_error"}
                metadata["job_result"] = job_result
                self.cancel_ingestion_job(metadata, "cancel")

            elif(type(exception_from_src).__name__ == "StageWriteFailure"):
                metadata = {}
                self.debug_log.add(str_exc)
                job_result = {"failure_reason": exception_from_src.message, "status": "failed", "debug_log": list(self.debug_log), "pass": self.pass_counter, "fail": self.fail_counter, "error_code": "stage_write_failure"}
                metadata["job_result"] = job_result
                self.cancel_ingestion_job(metadata, "failed")
            elif(type(exception_from_src).__name__ == "ApiResponseError"):
                metadata = {}
                self.debug_log.add(str_exc)
                job_result = {"failure_reason": exception_from_src.message, "status": "failed", "debug_log": list(self.debug_log), "pass": self.pass_counter, "fail": self.fail_counter, "error_code": "other_error", "api_response": exception_from_src.get_json()}
                metadata["job_result"] = job_result
                self.cancel_ingestion_job(metadata, "failed")
            
            else:
                metadata = {}
                self.debug_log.add(str_exc)
                job_result = {"failure_reason": str(exception_from_src), "status": "canceled", "debug_log": list(self.debug_log), "pass": self.pass_counter, "fail": self.fail_counter, "error_code": "other_error"}
                metadata["job_result"] = job_result
                self.cancel_ingestion_job(metadata, "cancel")
        
        except Exception as e:
            metadata = {}
            job_result = {"failure_reason": str(e), "status": "canceled", "debug_log": [str(e)], "pass": self.pass_counter, "fail": self.fail_counter, "error_code": "other_error"}
            try:
                self.cancel_ingestion_job({}, "cancel")
            except:
                raise
            
    def close(self, metadata={}):
        self.file.close()
        job_result = {"status": "ready_for_loading", "source": {"pass" : int(self.pass_counter), "fail": int(self.fail_counter), "debug_log": list(self.debug_log)}}
        metadata["job_result"] = job_result
        if self.bytes_written > 0:
            self.compress_file(self.file_path)
            self.upload_to_cloud(self.file_path)
            logging.info(f"Ingested remaining data: {self.bytes_written} bytes")
            self.bytes_written = 0
        for custom_file in self.custom_file_dict:
            self.custom_file_dict[custom_file].close()
            self.compress_file(custom_file)
            self.upload_to_cloud(custom_file)
        self.update_ingestion_to_done(metadata)
        if os.path.exists("service_account.json"):
            os.remove("service_account.json")

    @retry(wait=wait_fixed(30), stop=stop_after_attempt(3))
    def update_ingestion_to_done(self, metadata):
        
        res = requests.post(self.ingestion_service_url +"/job/"+self.job_id+"/"+"done", headers=self.headers, json={
            "metadata": metadata
        })
        logging.info("Ingestion status updated to done")
        return res.json()

    @retry(wait=wait_fixed(30), stop=stop_after_attempt(3))
    def get_ingestion_details(self):
        
        json_body = {
            "source": str(self.source),
            "recordType": str(self.record_type),
            "configId": str(self.config_id),
            "is_snapshot": self.is_snapshot,
            "priority": self.priority,
            "metadata": self.metadata
            }
        
        if json_body["priority"] is None:
            del json_body["priority"]
        
        res = requests.post(self.ingestion_service_url +"/job/", headers=self.headers, json=json_body)
        if(res.status_code == 200):
            return res.json()
        else:
            logging.error(f"Failed to create ingestion job with response body: {res.text} and headers: {res.headers}")
            raise Exception()


    @retry(wait=wait_fixed(30), stop=stop_after_attempt(3))
    def cancel_ingestion_job(self, metadata, fail_type):
        
        res = requests.post(self.ingestion_service_url +"/job/"+ self.job_id +"/"+fail_type, headers=self.headers, json={
            "metadata": metadata
        })
        logging.info("Ingestion status updated to " + str(fail_type))
        return res.json()

    @retry(wait=wait_fixed(30), stop=stop_after_attempt(3))
    def get_signing_url(self):
        res = requests.get(self.ingestion_service_url +"/job/"+self.job_id+"/"+"signing-url", headers=self.headers)
        signed_url = res.json()["url"]
        return signed_url
