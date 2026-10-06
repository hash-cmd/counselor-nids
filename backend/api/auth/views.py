"""Login with JWTs kept in httpOnly cookies.

The browser never sees the tokens: login sets them as httpOnly, SameSite=Strict cookies
on the API's host, and every request (and the WebSocket handshake) carries them back.
The dashboard and API share a site (localhost:3000 and localhost:8000 are the same
site; ports do not count), so the cookies flow without a proxy.

CSRF: SameSite=Strict stops other sites from sending the cookies. As a second layer,
cookie-authenticated requests that change state must carry the ``X-NIDS-Client``
header, which a cross-origin page cannot add without passing CORS.

The ``Authorization: Bearer`` header still works for scripts and the command line.
"""

from django.conf import settings
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from .rest import ACCESS_COOKIE, REFRESH_COOKIE


def _set_cookie(response: Response, name: str, value: str, lifetime) -> None:
    response.set_cookie(
        name, value, max_age=int(lifetime.total_seconds()), httponly=True,
        secure=settings.AUTH_COOKIE_SECURE, samesite="Strict", path="/",
    )


def _set_tokens(response: Response, refresh: RefreshToken) -> Response:
    lifetimes = settings.SIMPLE_JWT
    _set_cookie(response, ACCESS_COOKIE, str(refresh.access_token), lifetimes["ACCESS_TOKEN_LIFETIME"])
    _set_cookie(response, REFRESH_COOKIE, str(refresh), lifetimes["REFRESH_TOKEN_LIFETIME"])
    return response


class LoginView(APIView):
    """POST {username, password} -> sets the cookies. Rate limited per client."""

    permission_classes = [AllowAny]
    authentication_classes: list = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "login"

    def post(self, request):
        serializer = TokenObtainPairSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)  # bad credentials -> 401
        refresh = RefreshToken(serializer.validated_data["refresh"])
        return _set_tokens(Response({"username": serializer.user.get_username()}), refresh)


class RefreshView(APIView):
    """POST -> new access cookie from the refresh cookie."""

    permission_classes = [AllowAny]
    authentication_classes: list = []

    def post(self, request):
        raw = request.COOKIES.get(REFRESH_COOKIE)
        if not raw:
            return Response({"detail": "not signed in"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            refresh = RefreshToken(raw)
        except TokenError:
            response = Response({"detail": "session expired"}, status=status.HTTP_401_UNAUTHORIZED)
            return _clear(response)
        response = Response({"detail": "refreshed"})
        _set_cookie(response, ACCESS_COOKIE, str(refresh.access_token), settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"])
        return response


def _clear(response: Response) -> Response:
    for name in (ACCESS_COOKIE, REFRESH_COOKIE):
        response.delete_cookie(name, path="/", samesite="Strict")
    return response


class LogoutView(APIView):
    permission_classes = [AllowAny]
    authentication_classes: list = []

    def post(self, request):
        return _clear(Response({"detail": "signed out"}))
