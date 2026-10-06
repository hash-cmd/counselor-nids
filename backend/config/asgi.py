import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django_asgi_app = get_asgi_application()  # set up Django before importing anything that uses models

from channels.routing import ProtocolTypeRouter, URLRouter  # noqa: E402
from channels.security.websocket import AllowedHostsOriginValidator  # noqa: E402
from django.urls import path  # noqa: E402

from api.consumers import LiveConsumer  # noqa: E402
from api.auth.websocket import JWTAuthMiddleware  # noqa: E402

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": AllowedHostsOriginValidator(
        JWTAuthMiddleware(URLRouter([path("ws/live/", LiveConsumer.as_asgi())]))
    ),
})
