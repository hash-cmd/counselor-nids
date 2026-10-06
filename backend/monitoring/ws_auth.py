"""Authenticate WebSocket connections with a JWT access token: ws://.../ws/live/?token=<access>.

Browsers cannot set an Authorization header on a WebSocket, so the token goes in the
query string.
"""

from urllib.parse import parse_qs

from channels.db import database_sync_to_async
from channels.middleware import BaseMiddleware
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import AccessToken


@database_sync_to_async
def user_for(token: str | None):
    if not token:
        return AnonymousUser()
    try:
        user_id = AccessToken(token)["user_id"]
        return get_user_model().objects.get(pk=user_id, is_active=True)
    except (TokenError, KeyError, get_user_model().DoesNotExist):
        return AnonymousUser()


class JWTAuthMiddleware(BaseMiddleware):
    async def __call__(self, scope, receive, send):
        token = parse_qs(scope.get("query_string", b"").decode()).get("token", [None])[0]
        scope["user"] = await user_for(token)
        return await super().__call__(scope, receive, send)
