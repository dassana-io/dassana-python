import os


def get_endpoint():
    if "DASSANA_ENDPOINT" not in os.environ:
        raise KeyError(
            "DASSANA_ENDPOINT environment variable is not set. Review your Lambda configuration."
        )
    return os.environ["DASSANA_ENDPOINT"]


def get_app_id():
    if "DASSANA_APP_ID" not in os.environ:
        raise KeyError(
            "DASSANA_APP_ID environment variable is not set. Review your Lambda configuration."
        )
    return os.environ["DASSANA_APP_ID"]


def get_token():
    if "DASSANA_TOKEN" not in os.environ:
        raise KeyError(
            "DASSANA_TOKEN environment variable is not set. Review your Lambda configuration."
        )
    return os.environ["DASSANA_TOKEN"]


def get_ssl():
    return get_endpoint().startswith("https")


def get_batch_size():
    if "DASSANA_BATCH_SIZE" not in os.environ:
        raise KeyError(
            "DASSANA_BATCH_SIZE environment variable is not set. Review your Lambda configuration."
        )

    batch_size = os.environ["DASSANA_BATCH_SIZE"]
    if not batch_size.isdigit():
        raise ValueError("DASSANA_BATCH_SIZE environment variable is not an integer.")

    return int(batch_size)

def get_ackID():
    if "GCP_ACK_ID" not in os.environ:
        return {"ack_exists": False, "gcp_config": {}}
    return {"ack_exists": True, "gcp_config": {"ack_id": os.environ["GCP_ACK_ID"], "project_id": os.environ["GCP_PROJECT_ID"], "subscription_id": os.environ["GCP_SUBSCRIPTION_ID"]}}
    