"""
REPLACEMENT for FusionGraph.extract_user_features() in graph/fusion_graph.py
-----------------------------------------------------------------------------
Drop-in replacement that extracts 16 behavioral features (up from 8).

New features added in v2
------------------------
  auth_velocity          — events per hour (burst detection)
  time_variance          — variance in inter-event intervals (regularity)
  session_duration_hours — total active window from first to last event
  burst_rate             — normalized count of events in peak 5-min window
  asset_sensitivity_score — weighted avg of accessed asset sensitivity
  lateral_movement_score  — unique assets per hour (normalized)
  ip_reuse_rate           — fraction of IPs reused across multiple sessions
  sequential_asset_ratio  — fraction of assets accessed in rapid sequence

Replace the existing extract_user_features() method body with this function.
The method signature stays identical — it still returns list[dict[str, Any]].
"""

EXTRACT_USER_FEATURES_CYPHER = """
MATCH (u:CGUser)-[r:AUTHENTICATED]->(a:CGAsset)
WITH u,
     count(r)                                                    AS total_events,
     sum(CASE WHEN r.status_id = 2 THEN 1 ELSE 0 END)           AS failures,
     count(DISTINCT a)                                           AS unique_assets,
     count(DISTINCT r.src_ip)                                    AS unique_ips,
     sum(CASE WHEN r.src_ip STARTS WITH '10.' THEN 0 ELSE 1 END) AS ext_events,
     sum(CASE WHEN
       toInteger(substring(toString(datetime({epochMillis: r.time})), 11, 2)) < 8
       OR
       toInteger(substring(toString(datetime({epochMillis: r.time})), 11, 2)) >= 18
       THEN 1 ELSE 0 END)                                        AS off_hours_events,
     min(r.time)                                                 AS first_event,
     max(r.time)                                                 AS last_event,
     stdev(r.time)                                               AS time_stdev,
     collect(r.time)                                             AS event_times,
     collect(a.sensitivity)                                      AS asset_sensitivities

OPTIONAL MATCH (u)-[:USED_IP]->(ip:CGIPAddress)-[c:CONNECTED_TO]->(asset)
WITH u, total_events, failures, unique_assets, unique_ips,
     ext_events, off_hours_events,
     first_event, last_event, time_stdev, event_times, asset_sensitivities,
     avg(c.bytes_out)  AS avg_bytes_out,
     max(c.bytes_out)  AS max_bytes_out,
     count(DISTINCT ip) AS ips_with_connections

RETURN
    u.uid             AS user_uid,
    u.name            AS user_name,
    total_events,
    toFloat(failures) / total_events                    AS failure_rate,
    unique_assets,
    unique_ips,
    toFloat(ext_events) / total_events                  AS external_ip_rate,
    toFloat(off_hours_events) / total_events            AS off_hours_rate,
    coalesce(avg_bytes_out, 0.0)                        AS avg_bytes_out,
    coalesce(max_bytes_out, 0.0)                        AS max_bytes_out,
    first_event,
    last_event,
    coalesce(time_stdev, 0.0)                           AS time_variance,
    event_times,
    asset_sensitivities,
    coalesce(ips_with_connections, 0)                   AS ips_with_connections,
    unique_ips
ORDER BY total_events DESC
"""


def _compute_derived_features(row: dict) -> dict:
    """
    Compute the 8 new v2 features from raw Cypher query results.
    This is called in Python after fetching results from Neo4j.
    """
    import math

    total_events  = row.get("total_events", 1) or 1
    first_event   = row.get("first_event", 0) or 0
    last_event    = row.get("last_event", 0) or 0
    event_times   = row.get("event_times") or []
    unique_assets = row.get("unique_assets", 0) or 0
    unique_ips    = row.get("unique_ips", 1) or 1
    ips_with_conn = row.get("ips_with_connections", 0) or 0

    # Session duration in hours
    duration_ms = max(last_event - first_event, 1)
    duration_hours = duration_ms / 3_600_000.0
    session_duration_hours = max(duration_hours, 1 / 60)  # minimum 1 minute

    # Auth velocity: events per hour
    auth_velocity = total_events / session_duration_hours

    # Time variance: normalized std dev of inter-event intervals
    time_variance = row.get("time_variance", 0.0) or 0.0
    if time_variance > 0 and duration_ms > 0:
        time_variance = time_variance / duration_ms  # normalize by session duration
    time_variance = min(time_variance, 1.0)

    # Burst rate: estimate peak event density
    # Using event_times to find max events in any 5-minute window
    burst_rate = 0.0
    if len(event_times) > 1:
        event_times_sorted = sorted(event_times)
        window_ms = 5 * 60 * 1000  # 5 minutes
        max_in_window = 1
        left = 0
        for right in range(len(event_times_sorted)):
            while event_times_sorted[right] - event_times_sorted[left] > window_ms:
                left += 1
            max_in_window = max(max_in_window, right - left + 1)
        # Normalize: burst_rate = max events in 5-min / total events
        burst_rate = max_in_window / total_events

    # Asset sensitivity score: average sensitivity of accessed assets
    # Sensitivity values: 1=low, 2=medium, 3=high (from simulator)
    asset_sensitivities = row.get("asset_sensitivities") or []
    valid_sens = [s for s in asset_sensitivities if s is not None and isinstance(s, (int, float))]
    if valid_sens:
        asset_sensitivity_score = sum(valid_sens) / (len(valid_sens) * 3.0)  # normalize to 0-1
    else:
        asset_sensitivity_score = 0.5  # unknown

    # Lateral movement score: unique assets per hour (normalized)
    lateral_movement_score = min(unique_assets / (session_duration_hours * 10.0), 1.0)

    # IP reuse rate: fraction of IPs that also appear in network connections
    ip_reuse_rate = ips_with_conn / unique_ips if unique_ips > 0 else 0.0
    ip_reuse_rate = min(ip_reuse_rate, 1.0)

    # Sequential asset ratio: estimate from unique_assets / total_events
    # High ratio means accessing many different assets quickly = lateral movement indicator
    sequential_asset_ratio = unique_assets / total_events

    return {
        "auth_velocity":           min(auth_velocity, 1000.0),  # cap at 1000/hr
        "time_variance":           time_variance,
        "session_duration_hours":  min(session_duration_hours, 24.0),  # cap at 24hr
        "burst_rate":              burst_rate,
        "asset_sensitivity_score": asset_sensitivity_score,
        "lateral_movement_score":  lateral_movement_score,
        "ip_reuse_rate":           ip_reuse_rate,
        "sequential_asset_ratio":  sequential_asset_ratio,
    }


# ── Replacement method (paste into FusionGraph class) ─────────────────────────

REPLACEMENT_METHOD = '''
    def extract_user_features(self) -> list[dict[str, Any]]:
        """
        Extract per-user behavioral feature vectors from the graph.
        Returns 16 features per user (v2, up from 8 in v1).

        Features (v1 — core behavioral):
          total_events, failure_rate, unique_assets, unique_ips,
          external_ip_rate, off_hours_rate, avg_bytes_out, max_bytes_out

        Features (v2 — temporal):
          auth_velocity, time_variance, session_duration_hours, burst_rate

        Features (v2 — graph topology):
          asset_sensitivity_score, lateral_movement_score,
          ip_reuse_rate, sequential_asset_ratio
        """
        from graph.feature_extraction import EXTRACT_USER_FEATURES_CYPHER, _compute_derived_features

        with self._driver.session() as session:
            result = session.run(EXTRACT_USER_FEATURES_CYPHER)
            rows = result.data()

        features = []
        for row in rows:
            total_events = row.get("total_events", 0) or 0
            if total_events == 0:
                continue

            # Base features (v1)
            feat = {
                "user_uid":         row.get("user_uid", ""),
                "user_name":        row.get("user_name", ""),
                "total_events":     float(total_events),
                "failure_rate":     float(row.get("failure_rate") or 0.0),
                "unique_assets":    float(row.get("unique_assets") or 0.0),
                "unique_ips":       float(row.get("unique_ips") or 0.0),
                "external_ip_rate": float(row.get("external_ip_rate") or 0.0),
                "off_hours_rate":   float(row.get("off_hours_rate") or 0.0),
                "avg_bytes_out":    float(row.get("avg_bytes_out") or 0.0),
                "max_bytes_out":    float(row.get("max_bytes_out") or 0.0),
            }

            # Derived v2 features
            derived = _compute_derived_features(row)
            feat.update(derived)
            features.append(feat)

        logger.info(f"Extracted features for {len(features)} users")
        return features
'''

if __name__ == "__main__":
    print("Feature extraction module — 16 features:")
    for i, col in enumerate(
        ["total_events", "failure_rate", "unique_assets", "unique_ips",
         "external_ip_rate", "off_hours_rate", "avg_bytes_out", "max_bytes_out",
         "auth_velocity", "time_variance", "session_duration_hours", "burst_rate",
         "asset_sensitivity_score", "lateral_movement_score", "ip_reuse_rate",
         "sequential_asset_ratio"],
        1
    ):
        print(f"  {i:2d}. {col}")
