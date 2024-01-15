import datetime
import json
from uuid import uuid4

from .common import *
from .dassana_env import *

from typing import Final
import logging
from google.cloud import pubsub_v1
from concurrent import futures
import dassana.dassana_exception as exc


logger: Final = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

dassana_partner = get_partner()
dassana_partner_client_id = get_partner_client_id()
dassana_partner_tenant_id = get_partner_tenant_id()
project_id = get_project_id()
publisher = pubsub_v1.PublisherClient()
event_topic_name = None

if dassana_partner:
    event_topic_name = dassana_partner + "_LOG_EVENT_TOPIC_NAME"

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

def log(source, status=None, exception=None, locals={}, scope_id=None, config_id=None, metadata={}):
    states = build_state(source, scope_id, config_id, locals, status, exception=exception)
    
    for state in states:
        message = {}

        message["developerCtx"] = {}
        message["developerCtx"].update(state)
        message["developerCtx"].update(add_developer_context(metadata, exception))

        message["customerCtx"] = {}
        message["customerCtx"].update(state)
        message["customerCtx"].update(add_customer_context(message["customerCtx"]))

        if state["status"] == "failed":
            logger.error(msg=message["developerCtx"])
        else:
            logger.info(msg=message["developerCtx"])
        
        message = message["customerCtx"]
        
        if dassana_partner:
            common.publish_message(message, project_id, event_topic_name)

def add_developer_context(metadata, exception):
    state = {}

    if metadata:
        state["pass"] = metadata["source"]["pass"]
        state["fail"] = metadata["source"]["fail"]
        state["debugLog"] = metadata["source"]["debug_log"]

    if exception:
        state["errorDetails"] = {}
        if isinstance(exception, exc.DassanaException):
            state["errorDetails"]["errorCode"] = exception.error_type
            state["errorDetails"]["isInternal"] = exception.is_internal
            state["errorDetails"]["isAutoRecoverable"] = exception.is_auto_recoverable
            if exception.error_type == "internal_error":
                state["errorDetails"]["errorMessage"] = exception.message
            if isinstance(exception, exc.ApiError):
                state["errorDetails"]["httpRequest"] = exception.http_request.__dict__
                state["errorDetails"]["httpResonse"] = exception.http_response.__dict__
        else:
            state["errorDetails"]["errorCode"] = "internal_error"
            state["errorDetails"]["errorMessage"] = "Unexpected error occurred while collecting data"
            state["errorDetails"]["isInternal"] = True
            state["errorDetails"]["isAutoRecoverable"] = False
    return state
  
def add_customer_context(state, exception=None):

    state["status"] = "successful" if state.get("status") == "ready_for_loading" else state.get("status")
    state["tenantId"] = dassana_partner_tenant_id
    state["siteId"] = dassana_partner_client_id
    
    if exception:
        state["errorDetails"] = {}
        if isinstance(exception, exc.DassanaException):
            if not exception.is_internal:
                if isinstance(exception, exc.ApiError):
                    state["errorDetails"]["message"] = exception.message
                    state["errorDetails"]["httpRequest"] = exception.http_request.__dict__
                    state["errorDetails"]["httpResponse"] = exception.http_response.__dict__
                    return state
        state["errorDetails"]["message"] = "Job terminated due to inactivity"
    return state

def build_state(source, scope_id, config_id, locals, status=None, exception=None):
    state = {}

    state["eventId"] = str(uuid4())
    state["timestamp"] = datetime.datetime.utcnow().isoformat()
    state["source"] = source
    state["status"] = status

    if status == "failed":
        if locals.get("selected_scope_ids") and len(locals.get("selected_scope_ids")) > 0:
            scope_id_str = ','.join(locals.get("selected_scope_ids"))
            state["message"] = f"failed to run data collection for {scope_id_str}"
        else:
            state["message"] = "failed to finish data collection"

    elif status == "in_progress":
        state["message"] = "starting data collection"
    else:
        state["message"] = "successfully finished data collection"

    if config_id:
        state["configId"] = config_id
    else:
        if locals.get("config_id"):
            state["configId"] = locals.get("config_id")
      
    if scope_id:
        state["scopeId"] = scope_id_mapping.get(scope_id, scope_id)
    else:
        results = []
        scope_ids = locals.get("selected_scope_ids")
        if isinstance(scope_ids, list):
            for scope_id in scope_ids:
                if exception and locals.get(f'{scope_id}_writer'):
                    continue
                state["eventId"] = str(uuid4())
                state["timestamp"] = datetime.datetime.utcnow().isoformat()
                state["scopeId"] = scope_id_mapping.get(scope_id, scope_id)
                results.append(state)
            return results

    return [state]
