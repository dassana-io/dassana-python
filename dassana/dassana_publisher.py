from typing import Final, Callable
from google.cloud import pubsub_v1
from concurrent import futures
from .dassana_env import *
import json
import logging

logger: Final = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def get_callback(
    publish_future: pubsub_v1.publisher.futures.Future, data: str
) -> Callable[[pubsub_v1.publisher.futures.Future], None]:
    def callback(publish_future: pubsub_v1.publisher.futures.Future) -> None:
        pass

    return callback

def publish_message(message, topic_name):
    try:
        project_id = get_project_id()
        publisher = pubsub_v1.PublisherClient()
        publish_futures = []
        topic_path = publisher.topic_path(project_id, topic_name)
        data = json.dumps(message)
        # When you publish a message, the client returns a future.
        publish_future = publisher.publish(topic_path, data.encode("utf-8"))
        # Non-blocking. Publish failures are handled in the callback function.
        publish_future.add_done_callback(get_callback(publish_future, data))
        publish_futures.append(publish_future)
        futures.wait(publish_futures, return_when=futures.ALL_COMPLETED)

    except Exception as e:
        logger.error(f"Failed To Publish Message to topic {topic_name} Because of {e}")
