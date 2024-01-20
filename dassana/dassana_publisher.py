from typing import Final, Callable
from google.cloud import pubsub_v1
from concurrent import futures
from concurrent.futures import wait
from .dassana_env import *
import json
import logging

publisher = None
topic_path = None
logger: Final = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def publish_message(message, topic_name):
    global publisher
    global topic_path
    try:
        project_id = get_project_id()
        if not publisher:
            publisher = pubsub_v1.PublisherClient()
        publish_futures = []
        if not topic_path:
            topic_path = publisher.topic_path(project_id, topic_name)
        data = json.dumps(message)
        # When you publish a message, the client returns a future.
        publish_future = publisher.publish(topic_path, data.encode("utf-8"), timeout=180)
        publish_future.result(timeout=180)
        
        # Non-blocking. Publish failures are handled in the callback function.
        # publish_future.add_done_callback(get_callback(publish_future, data))

        # publish_futures.append(publish_future)
        # done, un_done = wait(publish_futures, return_when=futures.ALL_COMPLETED)
        # if len(un_done) > 0:
        #     logger.error(f"Failed To Publish all the messages to topic {topic_name}, Published {len(publish_futures)-len(un_done)}/{len(publish_futures)} Messages")

    except Exception as e:
        logger.error(f"Failed To Publish Message to topic {topic_name} Because of {e}")