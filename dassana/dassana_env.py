import os

def get_app_id():
    if "DASSANA_APP_ID" not in os.environ:
        raise KeyError(
            "DASSANA_APP_ID environment variable is not set. Review your Lambda configuration."
        )
    return os.environ["DASSANA_APP_ID"]

def get_auth_url():
    if "DASSANA_AUTH_URL" not in os.environ:
        return "https://auth.dassana.cloud"
    return os.environ["DASSANA_AUTH_URL"]

def get_app_url():
    if "DASSANA_APP_SERVICE_URL" not in os.environ:
        return "app-manager.dassana.cloud"
    return os.environ["DASSANA_APP_SERVICE_URL"]

def get_tenant_id():
    if not is_internal_auth():
        return ""
    if "DASSANA_TENANT_ID" not in os.environ:
        raise KeyError(
            "DASSANA_TENANT_ID environment variable is not set. Review your Lambda configuration."
        )
    return os.environ["DASSANA_TENANT_ID"]

def get_if_debug():
    return int(os.environ.get("DASSANA_DEBUG", 0))

def get_ingestion_srv_url():
    if "DASSANA_INGESTION_SERVICE_URL" not in os.environ:
        return "https://ingestion-srv.dassana.cloud"
    return os.environ["DASSANA_INGESTION_SERVICE_URL"]

def get_client_id():
    if "DASSANA_CLIENT_ID" not in os.environ:
        raise KeyError(
            "DASSANA_CLIENT_ID environment variable is not set. Review your Lambda configuration."
        )
    return os.environ["DASSANA_CLIENT_ID"]

def get_client_secret():
    if "DASSANA_CLIENT_SECRET" not in os.environ:
        raise KeyError(
            "DASSANA_CLIENT_SECRET environment variable is not set. Review your Lambda configuration."
        )
    return os.environ["DASSANA_CLIENT_SECRET"]

def get_ingestion_config_id():
    if "DASSANA_INGESTION_CONFIG_ID" not in os.environ:
        raise KeyError(
            "DASSANA_INGESTION_CONFIG_ID environment variable is not set. Review your Lambda configuration."
        )
    return str(os.environ["DASSANA_INGESTION_CONFIG_ID"])

def get_dassana_token():
    if "DASSANA_TOKEN" not in os.environ:
        raise KeyError(
            "DASSANA_TOKEN environment variable is not set. Review your Lambda configuration."
        )
    return str(os.environ["DASSANA_TOKEN"])

def is_internal_auth():
    try:
        get_dassana_token()
    except KeyError:
        return True
    return False

def get_project_id():
    if "GCP_PROJECT_ID" not in os.environ:
        raise KeyError(
            "GCP_PROJECT_ID environment variable is not set. Review your configuration."
        )
    return str(os.getenv("GCP_PROJECT_ID"))

def get_partner():
    if "DASSANA_PARTNER" not in os.environ:
        return None
    return str(os.environ["DASSANA_PARTNER"])

def get_partner_client_id():
    if "DASSANA_PARTNER_CLIENT_ID" not in os.environ:
        return None
    return str(os.environ["DASSANA_PARTNER_CLIENT_ID"])

def get_partner_tenant_id():
    if "DASSANA_PARTNER_TENANT_ID" not in os.environ:
        return None
    return str(os.environ["DASSANA_PARTNER_TENANT_ID"])

def get_scope_to_run():
    if "SCOPE_TO_RUN" not in os.environ:
        return None
    return str(os.environ["SCOPE_TO_RUN"])
