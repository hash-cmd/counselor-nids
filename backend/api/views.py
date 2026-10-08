import os
from pathlib import Path

from django.conf import settings
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from nids.services import journal, monitor

from . import replay, reputation, results
from .redis_client import get_redis


class MeView(APIView):
    def get(self, request):
        return Response({"username": request.user.get_username()})


class DetectorsView(APIView):
    """Live counters of every detector service, breakdowns, and the replay state."""

    def get(self, request):
        r = get_redis()
        return Response({"detectors": monitor.read_stats(r), "breakdown": monitor.read_breakdown(r),
                         "activity": monitor.read_activity(r), "live": monitor.read_live(r),
                         "health": monitor.read_health(r),
                         "replay": replay.manager.status()})


class ReputationView(APIView):
    """Offline reputation for up to 100 IPs: ?ips=a,b,c -> which are on local blocklists."""

    def get(self, request):
        raw = request.query_params.get("ips", "")
        ips = [ip.strip() for ip in raw.split(",") if ip.strip()][:100]
        return Response(reputation.check(ips))


class AlertsView(APIView):
    """Most recent attack decisions, newest first (?limit=, ?after=<stream id>)."""

    def get(self, request):
        limit = min(int(request.query_params.get("limit", 50)), 500)
        after = request.query_params.get("after")
        return Response({"alerts": monitor.read_alerts(get_redis(), limit, after)})


class IncidentsView(APIView):
    """Flagged flows with what the ML and Snort said: ?source=all|both|ml|snort&q=&limit=&offset="""

    def get(self, request):
        params = request.query_params
        source = params.get("source", "all")
        if source not in ("all", *monitor.SOURCES):
            return Response({"detail": f"unknown source {source!r}"}, status=status.HTTP_400_BAD_REQUEST)
        return Response(monitor.read_incidents(
            get_redis(), source, params.get("q", ""),
            limit=min(int(params.get("limit", 50)), 500), offset=max(int(params.get("offset", 0)), 0)))


class ResultsView(APIView):
    def get(self, request):
        return Response({"by_label": results.by_label()})


class SnortView(APIView):
    """Snort alerts linked to flows and ML verdicts, and how the two compare."""

    def get(self, request):
        limit = min(int(request.query_params.get("limit", 50)), 500)
        r = get_redis()
        return Response({"summary": monitor.read_snort(r),
                         "alerts": monitor.read_snort_alerts(r, limit, request.query_params.get("after"))})


class ReplayStartSerializer(serializers.Serializer):
    replay = serializers.CharField()
    cross_check = serializers.BooleanField(default=True)
    min_accuracy = serializers.FloatField(min_value=0, max_value=1, default=0.9)
    snort = serializers.BooleanField(default=True)


class ReplayView(APIView):
    def get(self, request):
        return Response({**replay.available(), "status": replay.manager.status()})


class ReplayStartView(APIView):
    def post(self, request):
        params = ReplayStartSerializer(data=request.data)
        params.is_valid(raise_exception=True)
        try:
            run = replay.manager.start(**params.validated_data)
        except replay.ReplayError as error:
            return Response({"detail": str(error)}, status=status.HTTP_409_CONFLICT)
        return Response(run, status=status.HTTP_201_CREATED)


class ReplayStopView(APIView):
    def post(self, request):
        try:
            return Response(replay.manager.stop())
        except replay.ReplayError as error:
            return Response({"detail": str(error)}, status=status.HTTP_409_CONFLICT)


def journal_dir() -> Path:
    return Path(os.environ.get("NIDS_JOURNAL_DIR", settings.NIDS_ROOT / "logs" / "journal"))


class JournalView(APIView):
    """False alarms recorded by the live alert journal over the last ?days= (default 7),
    leaving out the attack tests marked on the dashboard."""

    def get(self, request):
        try:
            days = min(max(int(request.query_params.get("days", 7)), 1), 365)
        except ValueError:
            return Response({"detail": "days must be a number"}, status=status.HTTP_400_BAD_REQUEST)
        folder = journal_dir()
        tests = journal.read_tests(folder)
        report = journal.report(journal.read(folder, days), journal.windows(tests))
        return Response({"days": days, "report": report, "tests": tests})


class JournalTestSerializer(serializers.Serializer):
    action = serializers.ChoiceField(["start", "stop", "delete"])
    note = serializers.CharField(required=False, allow_blank=True, max_length=200, default="")
    index = serializers.IntegerField(required=False, min_value=0)


class JournalTestsView(APIView):
    """Mark an attack test: {"action": "start", "note"} / {"action": "stop"} /
    {"action": "delete", "index"}. Alerts during a test are not counted as false alarms."""

    def post(self, request):
        body = JournalTestSerializer(data=request.data)
        body.is_valid(raise_exception=True)
        action, folder = body.validated_data["action"], journal_dir()
        if action == "start":
            tests = journal.start_test(body.validated_data["note"], folder)
        elif action == "stop":
            tests = journal.stop_test(folder)
        else:
            if "index" not in body.validated_data:
                return Response({"detail": "delete needs an index"}, status=status.HTTP_400_BAD_REQUEST)
            tests = journal.delete_test(body.validated_data["index"], folder)
        return Response({"tests": tests})
