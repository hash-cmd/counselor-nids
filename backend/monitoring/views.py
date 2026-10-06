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
    """Live counters of every detector service, plus the replay state."""

    def get(self, request):
        return Response({"detectors": monitor.read_stats(get_redis()),
                         "replay": replay.manager.status()})


class AlertsView(APIView):
    """Most recent attack decisions, newest first (?limit=, ?after=<stream id>)."""

    def get(self, request):
        limit = min(int(request.query_params.get("limit", 50)), 500)
        after = request.query_params.get("after")
        return Response({"alerts": monitor.read_alerts(get_redis(), limit, after)})


class ResultsView(APIView):
    def get(self, request):
        return Response({"comparisons": results.comparisons(),
                         "self_learning": results.self_learning()})


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
