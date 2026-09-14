#!/usr/bin/env python3

################################################################################
# Honeypot Framework - Shared attack statistics queries
#
# The three report generators (generate-reports.py, generate-pdf-report.py,
# generate-analytics-report.py) all answered the same questions of the same
# index -- how many events, which source IPs, which services, how many captured
# credentials, what the hourly shape looks like -- and each had written its own
# copy of the aggregation, its own bucket-unpacking loop, and its own
# `except Exception: print(...)` handler. Three copies meant three places to fix
# when a field name changed, and they had already drifted: one queried
# `_search` over HTTP with `requests`, the other two used the Elasticsearch
# client.
#
# The queries live here once. Connection settings come from es_client.
################################################################################

import logging
from typing import Any, Dict, List, Optional

import es_client

logger = logging.getLogger(__name__)

# Every honeypot index shares this prefix; Logstash writes honeypot-YYYY.MM.dd.
INDEX_PATTERN = "honeypot-*"


def _range(period: str) -> Dict[str, Any]:
    """A relative-time range filter. `period` is Elasticsearch date math: 24h, 7d, 30d."""
    return {"range": {"@timestamp": {"gte": f"now-{period}"}}}


def _buckets(response: Dict[str, Any], name: str) -> List[Dict[str, Any]]:
    """Aggregation buckets, or an empty list if the aggregation is absent."""
    return response.get("aggregations", {}).get(name, {}).get("buckets", [])


def _total(response: Dict[str, Any]) -> int:
    return response.get("hits", {}).get("total", {}).get("value", 0)


class HoneypotStats:
    """Read-only attack statistics for a time period.

    Each method returns a plain dict/list so callers can render it however they
    like (HTML, PDF, JSON) without depending on the Elasticsearch response
    shape. A failed query logs and returns an empty result rather than raising:
    a report with a missing section is more useful than no report, and these
    run unattended from cron.
    """

    def __init__(self, client=None, host: Optional[str] = None):
        self.es = client or es_client.build_client(host)

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _search(self, body: Dict[str, Any]) -> Dict[str, Any]:
        try:
            return self.es.search(index=INDEX_PATTERN, body=body)
        except Exception:
            logger.exception("Elasticsearch query failed against %s", INDEX_PATTERN)
            return {}

    # ------------------------------------------------------------------ #
    # Individual statistics
    # ------------------------------------------------------------------ #
    def total_events(self, period: str = "24h") -> int:
        """Number of honeypot events in the period."""
        return _total(self._search({"query": _range(period), "size": 0}))

    def top_source_ips(self, period: str = "24h", limit: int = 10) -> List[Dict[str, Any]]:
        """Most active source addresses, busiest first: [{ip, count}, ...]."""
        response = self._search({
            "query": _range(period),
            "size": 0,
            "aggs": {"top_ips": {"terms": {"field": "src_ip", "size": limit, "order": {"_count": "desc"}}}},
        })
        return [{"ip": b["key"], "count": b["doc_count"]} for b in _buckets(response, "top_ips")]

    def service_distribution(self, period: str = "24h", limit: int = 20) -> Dict[str, int]:
        """Event count per targeted service: {"ssh": 412, "http": 88, ...}."""
        response = self._search({
            "query": _range(period),
            "size": 0,
            "aggs": {"services": {"terms": {"field": "service", "size": limit}}},
        })
        return {b["key"]: b["doc_count"] for b in _buckets(response, "services")}

    def country_distribution(self, period: str = "24h", limit: int = 10) -> Dict[str, int]:
        """Event count per GeoIP country. Empty unless the GeoIP filter is enabled."""
        response = self._search({
            "query": _range(period),
            "size": 0,
            "aggs": {"countries": {"terms": {"field": "geoip.country_name", "size": limit}}},
        })
        return {b["key"]: b["doc_count"] for b in _buckets(response, "countries")}

    def credentials_captured(self, period: str = "24h") -> int:
        """Events carrying a captured password."""
        return _total(self._search({
            "query": {"bool": {"must": [_range(period), {"exists": {"field": "logdata.PASSWORD"}}]}},
            "size": 0,
        }))

    def failed_logins(self, period: str = "24h") -> int:
        """Login attempts against the honeypot services."""
        return _total(self._search({
            "query": {"bool": {"must": [_range(period), {"term": {"event_type": "login_attempt"}}]}},
            "size": 0,
        }))

    def download_attempts(self, period: str = "1h", command: str = "wget") -> int:
        """Events whose captured command looks like a payload fetch.

        A crude but useful signal: an attacker running wget/curl inside the
        honeypot shell is trying to stage something.
        """
        return _total(self._search({
            "query": {"bool": {"must": [_range(period), {"match": {"logdata.CMD": command}}]}},
            "size": 0,
        }))

    def hourly_trend(self, period: str = "24h") -> List[Dict[str, Any]]:
        """Event volume bucketed by hour: [{timestamp, count}, ...]."""
        response = self._search({
            "query": _range(period),
            "size": 0,
            "aggs": {"timeline": {"date_histogram": {"field": "@timestamp", "calendar_interval": "1h"}}},
        })
        return [
            {"timestamp": b.get("key_as_string"), "count": b["doc_count"]}
            for b in _buckets(response, "timeline")
        ]

    def threat_intelligence(self, period: str = "24h") -> Dict[str, Any]:
        """Threat-intel enrichment summary: level counts and mean confidence."""
        response = self._search({
            "query": {"bool": {"must": [_range(period), {"exists": {"field": "threat_intel"}}]}},
            "size": 0,
            "aggs": {
                "threat_levels": {"terms": {"field": "threat_intel.threat_level", "size": 10}},
                "avg_confidence": {"avg": {"field": "threat_intel.confidence_score"}},
            },
        })
        aggs = response.get("aggregations", {})
        return {
            "threat_levels": {b["key"]: b["doc_count"] for b in _buckets(response, "threat_levels")},
            "avg_confidence": aggs.get("avg_confidence", {}).get("value"),
        }

    # ------------------------------------------------------------------ #
    # Everything at once
    # ------------------------------------------------------------------ #
    def summary(self, period: str = "24h", top_n: int = 10) -> Dict[str, Any]:
        """The full picture every report generator needs, in one call.

        `services` is also returned as `service_breakdown` -- a list of
        {name, count, percentage} -- because every caller was computing those
        percentages itself.
        """
        total = self.total_events(period)
        services = self.service_distribution(period)
        countries = self.country_distribution(period, limit=top_n)
        top_ips = self.top_source_ips(period, limit=top_n)

        return {
            "period": period,
            "total_events": total,
            "unique_source_ips": len(top_ips),
            "top_ips": top_ips,
            "services": services,
            "service_breakdown": [
                {
                    "name": name,
                    "count": count,
                    "percentage": round(count / total * 100, 1) if total else 0.0,
                }
                for name, count in sorted(services.items(), key=lambda kv: kv[1], reverse=True)
            ],
            "countries": countries,
            "top_country": next(iter(countries), "N/A"),
            "credentials_captured": self.credentials_captured(period),
            "failed_logins": self.failed_logins(period),
            "hourly_trend": self.hourly_trend(period),
            "threat_intel": self.threat_intelligence(period),
        }
