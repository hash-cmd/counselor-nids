from functools import lru_cache

import redis
from django.conf import settings

from nids.service import bus


@lru_cache(maxsize=1)
def get_redis() -> redis.Redis:
    """Shared client for the Redis instance the NIDS services use."""
    return bus.connect(settings.NIDS_REDIS_URL)
