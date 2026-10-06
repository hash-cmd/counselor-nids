from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from nids.service import monitor

from . import replay, results
from .redis_client import get_redis


class MeView(APIView):
    def get(self, request):
        return Response({"username": request.user.get_username()})


class DetectorsView(APIView):
    """Live counters of every detector service, breakdowns, and the replay state."""

    def get(self, request):
        r = get_redis()
        return Response({"detectors": monitor.read_stats(r), "breakdown": monitor.read_breakdown(r),
                         "activity": monitor.read_activity(r), "replay": replay.manager.status()})


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
        return Response({"comparisons": results.comparisons(),
                         "self_learning": results.self_learning(),
                         "by_label": results.by_label()})


class SnortView(APIView):
    """Snort alerts linked to flows and ML verdicts, and how the two compare."""

    def get(self, request):
        limit = min(int(request.query_params.get("limit", 50)), 500)
        r = get_redis()
        return Response({"summary": monitor.read_snort(r),
                         "alerts": monitor.read_snort_alerts(r, limit, request.query_params.get("after"))})


class ReplayStartSerializer(serializers.Serializer):
    replay = serializers.CharField()
    rate = serializers.FloatField(min_value=10, max_value=50_000, default=1000)
    cross_check = serializers.BooleanField(default=True)
    min_accuracy = serializers.FloatField(min_value=0, max_value=1, default=0.9)
    snort = serializers.BooleanField(default=True)  # pcap replays only


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
