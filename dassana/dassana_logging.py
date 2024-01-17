import datetime
from uuid import uuid4

from .common import *
from .dassana_env import *

from typing import Final
import logging
import dassana.dassana_exception as exc


logger: Final = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

dassana_partner = get_partner()
dassana_partner_client_id = get_partner_client_id()
dassana_partner_tenant_id = get_partner_tenant_id()
config_id = get_ingestion_config_id()

topic_name = None
if dassana_partner:
    topic_name = dassana_partner + "_log_event_topic"

scope_id_mapping = {
    "crowdstrike_edr": "detection",
    "crowdstrike_spotlight": "vulnerability",
    "tenable_vulnerability": "vulnerability",
    "snyk_vulnerability": "vulnerability",
    "prisma_cloud_cspm": "cspm",
    "prisma_cloud_cwpp": "vulnerability",
    "qualys_vulnerability": "vulnerability",
    "wiz_cwpp": "vulnerability",
    "wiz_cspm": "cspm",
    "prisma_cloud_security_group": "asset",
    "prisma_cloud_instance": "asset",
    "carbon_black_vulnerability": "vulnerability",
    "ms_defender_endpoint_alert": "detection",
    "ms_defender_endpoint_vulnerability": "vulnerability"
}

def log(source, status=None, exception=None, locals={}, scope_id=None, metadata={}, job_id=None):
    state = build_state(source, scope_id, locals, job_id, status, exception)
    message = {}

    message["developerCtx"] = {}
    message["developerCtx"].update(state)
    message["developerCtx"].update(add_developer_context(metadata, state["status"], exception))

    message["customerCtx"] = {}
    message["customerCtx"].update(state)
    message["customerCtx"].update(add_customer_context(message["customerCtx"], exception))

    if state["status"] == "failed":
        logger.error(msg=message["developerCtx"])
    else:
        logger.info(msg=message["developerCtx"])
    
    message = message["customerCtx"]
    
    if dassana_partner:
        publish_message(message, topic_name)

def add_developer_context(metadata, status ,exception):
    state = {}

    if metadata:
        state["pass"] = metadata["source"]["pass"]
        state["fail"] = metadata["source"]["fail"]
        state["debugLog"] = metadata["source"]["debug_log"]
    
    if status == 'failed':
        state["errorDetails"] = {}

        if exception:
            if isinstance(exception, exc.DassanaException):
                state["errorDetails"]["errorCode"] = exception.error_type
                state["errorDetails"]["isInternal"] = exception.is_internal
                state["errorDetails"]["isAutoRecoverable"] = exception.is_auto_recoverable
                if exception.error_type == "internal_error":
                    if exception.error_details:
                        state["errorDetails"]["errorMessage"] = exception.error_details
                    else:
                        state["errorDetails"]["errorMessage"] = exception.message
                if isinstance(exception, exc.ApiError):
                    state["errorDetails"]["httpRequest"] = exception.http_request.__dict__
                    state["errorDetails"]["httpResonse"] = exception.http_response.__dict__ 
                return state
        
        if "error_code" in metadata:
            state["errorDetails"]["errorCode"] = metadata["error_code"]
        else:
            state["errorDetails"]["errorCode"] = "internal_error"

        if "is_internal" in metadata:
            state["errorDetails"]["isInternal"] = metadata["is_internal"]
        else:
            state["errorDetails"]["isInternal"] = True
        
        if "is_auto_recoverable" in metadata:
            state["errorDetails"]["isAutoRecoverable"] = metadata["is_auto_recoverable"]
        else:
            state["errorDetails"]["isAutoRecoverable"] = False

        state["errorDetails"]["errorMessage"] = "Unexpected error occurred while collecting data"
    return state
  
def add_customer_context(state, exception=None):


    state["status"] = "ok" if state.get("status") == "ready_for_loading" else state.get("status")
    if dassana_partner and dassana_partner_tenant_id:
        state["tenantId"] = dassana_partner_tenant_id
        raise KeyError("DASSANA_PARTNER_TENANT_ID environment variable is not set. Review configuration.")


    if dassana_partner and dassana_partner_client_id:
        state["siteId"] = dassana_partner_client_id
        raise KeyError("DASSANA_PARTNER_CLIENT_ID environment variable is not set. Review configuration.")

    if state["status"] == 'failed':
        state["errorDetails"] = {}
        if exception:
            if isinstance(exception, exc.DassanaException):
                if not exception.is_internal:
                    if isinstance(exception, exc.ApiError):
                        state["errorDetails"]["message"] = exception.message
                        state["errorDetails"]["httpRequest"] = exception.http_request.__dict__
                        state["errorDetails"]["httpResponse"] = exception.http_response.__dict__
                        return state
        state["errorDetails"]["message"] = "Job terminated due to internal error"
    return state

def build_state(source, scope_id, locals, job_id, status, exception):
    state = {}

    state["eventId"] = str(uuid4())
    state["timestamp"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    state["connector"] = source
    if exception:
        state["status"] = "failed"
    elif not exception and not status:
        state["status"] = "in_progress"
    else:
        state["status"] = status
    
    state["level"] = "info" if state["status"] in ['ready_for_loading', 'in_progress'] else "error"

    if job_id:
        state["jobId"] = job_id

    if state["status"] == "failed":
        state["message"] = "failed to finish data collection"

    elif state["status"] == "in_progress": 
        state["message"] = "starting data collection"

    else:
        state["message"] = "successfully finished data collection"

    if 'config_id' in locals:
        state["connectionId"] = locals.get("config_id")
    else:
        state["connectionId"] = config_id
        
    if scope_id:
        state["scopeId"] = scope_id_mapping.get(scope_id, scope_id)

    return state