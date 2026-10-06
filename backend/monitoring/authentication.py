"""DRF authentication from the httpOnly access cookie (see monitoring.auth).

Kept apart from the login views: DRF imports authentication classes while it is still
loading its own views module.
"""

from rest_framework import exceptions
from rest_framework_simplejwt.authentication import JWTAuthentication

ACCESS_COOKIE = "nids_access"
REFRESH_COOKIE = "nids_refresh"
CLIENT_HEADER = "HTTP_X_NIDS_CLIENT"
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


class CookieJWTAuthentication(JWTAuthentication):
    """Bearer header first (scripts), then the access cookie (browser)."""

    def authenticate(self, request):
        if self.get_header(request) is not None:
            return super().authenticate(request)
        raw = request.COOKIES.get(ACCESS_COOKIE)
        if not raw:
            return None
        if request.method not in SAFE_METHODS and CLIENT_HEADER not in request.META:
            raise exceptions.PermissionDenied("missing X-NIDS-Client header")
        token = self.get_validated_token(raw)
        return self.get_user(token), token
