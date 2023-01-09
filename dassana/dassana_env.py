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
        raise KeyError(
            "GCP_ACK_ID environment variable is not set."
        )
    return os.environ["GCP_ACK_ID"]

def get_gcp_project_id():
    if "DASSANA_GCP_PRJ_ID" not in os.environ:
        raise KeyError(
            "DASSANA_GCP_PRJ_ID environment variable is not set."
        )
    return os.environ["DASSANA_GCP_PRJ_ID"]

def get_gcp_subscription_id():
    if "GCP_SUBSCRIPTION_ID" not in os.environ:
        raise KeyError(
            "GCP_SUBSCRIPTION_ID environment variable is not set."
        )
    return os.environ["GCP_SUBSCRIPTION_ID"]

def get_magic_word():
    if "DASSANA_DEBUG_MAGIC_WORD" not in os.environ:
        return None
    return os.environ["DASSANA_DEBUG_MAGIC_WORD"]
