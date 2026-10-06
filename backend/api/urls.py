from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from . import views
from .auth import views as auth

urlpatterns = [
    path("auth/login/", auth.LoginView.as_view(), name="login"),
    path("auth/refresh/", auth.RefreshView.as_view(), name="refresh"),
    path("auth/logout/", auth.LogoutView.as_view(), name="logout"),
    # header-based tokens for scripts and the command line
    path("auth/token/", TokenObtainPairView.as_view(), name="token"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("auth/me/", views.MeView.as_view(), name="me"),
    path("detectors/", views.DetectorsView.as_view(), name="detectors"),
    path("alerts/", views.AlertsView.as_view(), name="alerts"),
    path("incidents/", views.IncidentsView.as_view(), name="incidents"),
    path("results/", views.ResultsView.as_view(), name="results"),
    path("snort/", views.SnortView.as_view(), name="snort"),
    path("replay/", views.ReplayView.as_view(), name="replay"),
    path("replay/start/", views.ReplayStartView.as_view(), name="replay-start"),
    path("replay/stop/", views.ReplayStopView.as_view(), name="replay-stop"),
]
