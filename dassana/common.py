import datetime
import gzip
import logging
import threading
import time
from typing import Final

import boto3
import requests
from google.cloud import storage

from .api import call_api
from .dassana_env import *
from .dassana_exception import *
from .dassana_logging import log

logger: Final = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

job_list = set()


def datetime_handler(val):
    if isinstance(val, datetime.datetime):
        return val.isoformat()
    return str(val)


def compress_file(file_name):
    with open(file_name, 'rb') as file_in:
        with gzip.open(f"{file_name}.gz", 'wb') as file_out:
            file_out.writelines(file_in)
    logger.info("Compressed file completed")


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
    return str(exc).replace("\"", "").replace("'", "").replace("\n", " ").replace("\t", " ")


def patch_ingestion(job_id, metadata=None):
    if metadata is None:
        metadata = {}
    json_body = {"metadata": metadata}
    res = call_api('PATCH', get_ingestion_srv_url() + "/job/" + job_id, headers=get_headers(), json=json_body,
                   is_internal=True, verify=False if "svc.cluster.local" in get_ingestion_srv_url() else True)
    return res.json()


def every(delay, task):
    next_time = time.time() + delay
    while True:
        time.sleep(max(0, next_time - time.time()))
        task()
        next_time += (time.time() - next_time) // delay * delay + delay


def iterate_and_update_job_status():
    global job_list
    for job_id in job_list:
        try:
            patch_ingestion(job_id)
            logger.info(f"Updated job status for job id: {job_id}")
        except Exception as exp:
            logger.warning(f"Failed to update job ({job_id}) heartbeat due to {exp}")


threading.Thread(target=lambda: every(1800, iterate_and_update_job_status), daemon=True).start()


def get_ingestion_config(ingestion_config_id, app_id):
    app_url = get_app_url()
    url = f"https://{app_url}/app/{app_id}/ingestionConfig/{ingestion_config_id}"
    headers = get_headers()
    response = call_api("GET", url, headers=headers,
                        verify=False if "svc.cluster.local" in app_url else True,
                        is_internal=True)
    
    try:
        response = response.json()
        if not response.get("config"):
            raise KeyError("config  missing in the response.")
        else:
            if not response["config"].get("_selectedScopeIds"):
                raise KeyError("_selectedScopeIds are missing in the response.")            
        return response
    except:
        raise

def patch_ingestion_config(ingestion_config_id, app_id, payload):
    app_url = get_app_url()
    url = f"https://{app_url}/app/{app_id}/ingestionConfig/{ingestion_config_id}"
    headers = get_headers()
    response = call_api("PATCH", url=url, headers=headers, json=payload,
                        verify=False if "svc.cluster.local" in app_url else True,
                        is_internal=True)
    return response.text

def get_access_token():
    auth_url = get_auth_url()
    url = f"{auth_url}/oauth/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": get_client_id(),
        "client_secret": get_client_secret(),
    }
    response = call_api("POST", url, data=data, verify=False if "svc.cluster.local" in auth_url else True,
                        is_internal=True)
    return response.json()["access_token"]

class DassanaWriter:
    def __init__(self, source, record_type, config_id, metadata=None, priority=None, is_snapshot=False,
                 file_size_limit=249):
        if metadata is None:
            metadata = {}
        logger.info("Initialized common utility")

        self.file_size_limit = file_size_limit
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
        self.ingestion_service_url = get_ingestion_srv_url()
        self.is_internal_auth = is_internal_auth()
        self.file_path = self.get_file_path()
        self.job_id = None
        self.ingestion_metadata = None
        self.custom_file_dict = dict()
        self.initialize_client()
        log(scope_id=self.metadata["scope"]["scopeId"], job_id=self.job_id)
        self.file = open(self.file_path, 'a')

    def get_file_path(self):
        epoch_ts = int(time.time())
        if not self.is_internal_auth:
            return f"/tmp/{epoch_ts}.ndjson"
        return f"{epoch_ts}.ndjson"

    def initialize_client(self):
        global job_list
        response = self.get_ingestion_details()
        if "jobId" not in response or "stageDetails" not in response or "cloud" not in response["stageDetails"]:
            raise InternalError("Invalid job created with missing details")

        self.storage_service = response['stageDetails']['cloud']
        self.job_id = response["jobId"]
        logger.info(f"Ingestion job created with job id: {self.job_id}")
        if "metadata" in response:
            self.ingestion_metadata = response["metadata"]
        else:
            self.ingestion_metadata = {}
        if "creationTs" in response:
            self.ingestion_metadata["creationTs"] = response["creationTs"]
        else:
            self.ingestion_metadata["creationTs"] = int(time.time() * 1000)
        job_list.add(self.job_id)

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
                self.aws_sts_client = boto3.client('sts', aws_access_key_id=stage_details['accessKey'],
                                                   aws_secret_access_key=stage_details['secretKey'])
                self.aws_iam_role_arn = stage_details['awsIamRoleArn']
                self.aws_iam_external_id = stage_details['awsIamExternalId']
            else:
                self.client = boto3.client('s3', aws_access_key_id=stage_details['accessKey'],
                                           aws_secret_access_key=stage_details['secretKey'])

    def write_json(self, json_object):
        self.file.flush()
        json.dump(json_object, self.file)
        self.file.write('\n')
        self.bytes_written = self.file.tell()
        if self.bytes_written >= int(self.file_size_limit) * 1000 * 1000:
            self.file.close()
            compress_file(self.file_path)
            self.upload_to_cloud(self.file_path)
            self.file_path = self.get_file_path()
            self.file = open(self.file_path, 'a')
            logger.info(f"Ingested data: {self.bytes_written} bytes")
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
        try:
            if not self.is_internal_auth:
                self.upload_to_signed_url()
            elif self.storage_service == 'gcp':
                self.upload_to_gcp(file_name)
            elif self.storage_service == 'aws':
                self.upload_to_aws(file_name)
            else:
                raise StageWriteFailure("Unsupported stage")
        except Exception as exp:
            raise StageWriteFailure(str(exp))

        if os.path.exists(file_name):
            os.remove(file_name)
        if os.path.exists(file_name + ".gz"):
            os.remove(file_name + ".gz")

    def upload_to_gcp(self, file_name):
        if self.client is None:
            raise ValueError("GCP client not initialized.")

        self.blob = self.client.bucket(self.bucket_name).blob(str(self.full_file_path) + "/" + str(file_name) + ".gz")
        self.blob.upload_from_filename(file_name + ".gz")

    def upload_to_aws(self, file_name):
        if self.client is None and self.aws_sts_client is None:
            raise ValueError("AWS client not initialized")

        if self.aws_iam_role_arn and (not self.aws_session_token_expiration or (
                self.aws_session_token_expiration.timestamp() < (
                datetime.datetime.now() + datetime.timedelta(minutes=2)).timestamp())):
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

        self.client.put_object(Body=open(f"{file_name}.gz", 'rb'), Bucket=self.bucket_name,
                               Key=f"{str(self.full_file_path)}/{str(file_name)}.gz")

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
            requests.put(url=signed_url, data=data, headers=headers, verify=False if "svc.cluster.local" in signed_url else True)
            
    def cancel_job_with_error_info(self, error_code, failure_reason, fail_type="failed", error_message=None, is_internal=True, is_auto_recoverable=False):
        if not error_message:
            error_message = "Unexpected error occurred while collecting data"

        global job_list
        job_list.discard(self.job_id)
        if os.path.exists("service_account.json"):
            os.remove("service_account.json")
        metadata = {}
        fail_type_status_metadata = "canceled" if str(fail_type) == "cancel" else str(fail_type)
        self.debug_log.add(get_exc_str(str(failure_reason)))
        job_result = {"status": fail_type_status_metadata,
                      "debug_log": list(self.debug_log),
                      "pass": self.pass_counter, "fail": self.fail_counter,
                      "error_code": error_code,
                      "error_message": error_message,
                      "is_internal": is_internal,
                      "is_auto_recoverable": is_auto_recoverable}
        metadata["job_result"] = job_result
        self.cancel_ingestion_job(metadata, fail_type)
        log(status=fail_type, scope_id=self.metadata["scope"]["scopeId"], metadata=job_result)

    def cancel_job(self, exception_from_src):
        global job_list
        job_list.discard(self.job_id)
        if os.path.exists("service_account.json"):
            os.remove("service_account.json")
        str_exc = get_exc_str(str(exception_from_src))
        self.debug_log.add(str_exc)
        job_result_metadata = dict()
        job_result_metadata["status"] = "failed"
        job_result_metadata["pass"] = self.pass_counter
        job_result_metadata["fail"] = self.fail_counter
        job_result_metadata["debug_log"] = list(self.debug_log)

        if isinstance(exception_from_src, DassanaException):
            job_result_metadata["error_code"] = exception_from_src.error_type
            job_result_metadata["is_internal"] = exception_from_src.is_internal
            job_result_metadata["is_auto_recoverable"] = exception_from_src.is_auto_recoverable
            if exception_from_src.error_type == "internal_error":
                job_result_metadata["error_message"] = exception_from_src.message
            if isinstance(exception_from_src, ApiError):
                job_result_metadata["api_details"] = dict()
                job_result_metadata["api_details"]["request"] = exception_from_src.http_request.__dict__
                job_result_metadata["api_details"]["response"] = exception_from_src.http_response.__dict__
        else:
            job_result_metadata["error_code"] = "internal_error"
            job_result_metadata["error_message"] = "Unexpected error occurred while collecting data"
            job_result_metadata["is_internal"] = True
            job_result_metadata["is_auto_recoverable"] = False

        metadata = {"job_result": job_result_metadata}
        self.cancel_ingestion_job(metadata, "failed") 
        log(status=job_result_metadata["status"], scope_id=self.metadata["scope"]["scopeId"], exception=exception_from_src, metadata=job_result_metadata)

    def close(self, metadata=None):
        if metadata is None:
            metadata = {}
        global job_list
        job_list.discard(self.job_id)
        self.file.close()
        job_result = {"status": "ready_for_loading",
                      "source": {"pass": int(self.pass_counter), "fail": int(self.fail_counter),
                                 "debug_log": list(self.debug_log)}}
        metadata["job_result"] = job_result
        if self.bytes_written > 0:
            compress_file(self.file_path)
            self.upload_to_cloud(self.file_path)
            logger.info(f"Ingested remaining data: {self.bytes_written} bytes")
            self.bytes_written = 0
        for custom_file in self.custom_file_dict:
            self.custom_file_dict[custom_file].close()
            compress_file(custom_file)
            self.upload_to_cloud(custom_file)
        if os.path.exists("service_account.json"):
            os.remove("service_account.json")
        self.update_ingestion_to_done(metadata)
        log(status=job_result["status"], scope_id=self.metadata["scope"]["scopeId"],  metadata=job_result,job_id=self.job_id)

    def update_ingestion_to_done(self, metadata):
        json_body = {
            "metadata": metadata
        }
        res = call_api("POST", self.ingestion_service_url + "/job/" + self.job_id + "/" + "done", headers=get_headers(),
                       json=json_body, is_internal=True, verify=False if "svc.cluster.local" in self.ingestion_service_url else True)
        logger.debug(f"Response Status: {res.status_code}")
        logger.debug(f"Request Body: {res.request.body}")
        logger.debug(f"Response Body: {res.text}")
        return res.json()

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

        res = call_api("POST", self.ingestion_service_url + "/job/", headers=get_headers(), json=json_body,
                       is_internal=True, verify=False if "svc.cluster.local" in self.ingestion_service_url else True,)
        return res.json()

    def cancel_ingestion_job(self, metadata, fail_type):
        json_body = {
            "metadata": metadata
        }
        res = call_api("POST", self.ingestion_service_url + "/job/" + self.job_id + "/" + fail_type,
                       headers=get_headers(), json=json_body, is_internal=True, verify=False if "svc.cluster.local" in self.ingestion_service_url else True)
        logger.debug(f"Response Status: {res.status_code}")
        logger.debug(f"Request Body: {res.request.body}")
        logger.debug(f"Response Body: {res.text}")
        return res.json()

    def get_signing_url(self):
        res = call_api("GET", self.ingestion_service_url + "/job/" + self.job_id + "/" + "signing-url",
                       headers=get_headers(), is_internal=True, verify=False if "svc.cluster.local" in self.ingestion_service_url else True)
        signed_url = res.json()["url"]
        return signed_url
