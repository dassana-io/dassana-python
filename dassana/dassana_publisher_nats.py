from typing import Final
from .dassana_env import *
import json
import logging
import asyncio
import ssl
import nats

logger: Final = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

async def publish_message_nats(message, nats_partner_subject_name):
  try:
    data = json.dumps(message)
    
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    nats_client = await nats.connect(get_nats_url(), tls=ssl_ctx)
    jet_stream = nats_client.jetstream()

    await jet_stream.publish(nats_partner_subject_name, data.encode("utf-8"))
    
    await nats_client.flush()
    await nats_client.drain()
    await nats_client.close()

  except Exception as e:
    logger.error(f"Failed To Publish Message to nats-subject {nats_partner_subject_name} Because of {e}")