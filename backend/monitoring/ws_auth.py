"""Authenticate WebSocket connections with the JWT access token.

The browser sends the httpOnly access cookie with the handshake (see monitoring.auth).
Scripts can pass ``?token=<access>`` instead, since a WebSocket has no Authorization header.
"""

from http.cookies import SimpleCookie
from urllib.parse import parse_qs

from channels.db import database_sync_to_async
from channels.middleware import BaseMiddleware
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import AccessToken

from .authentication import ACCESS_COOKIE


@database_sync_to_async
def user_for(token: str | None):
    if not token:
        return AnonymousUser()
    try:
        user_id = AccessToken(token)["user_id"]
        return get_user_model().objects.get(pk=user_id, is_active=True)
    except (TokenError, KeyError, get_user_model().DoesNotExist):
        return AnonymousUser()


def cookie_token(scope) -> str | None:
    for name, value in scope.get("headers", []):
        if name == b"cookie":
            morsel = SimpleCookie(value.decode("latin-1")).get(ACCESS_COOKIE)
            if morsel:
                return morsel.value
    return None


class JWTAuthMiddleware(BaseMiddleware):
    async def __call__(self, scope, receive, send):
        token = parse_qs(scope.get("query_string", b"").decode()).get("token", [None])[0]
        scope["user"] = await user_for(token or cookie_token(scope))
        return await super().__call__(scope, receive, send)
