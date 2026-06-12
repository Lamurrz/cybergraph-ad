"""
graph/fusion_graph.py
---------------------
Implements the multisensor graph fusion framework from:

  Murray, L. (2019). "A Framework Towards Fusing Multisensory Cyber Security
  Data Utilizing Graph Databases." Iowa State University.

Graph schema
------------
Nodes
  User        {uid, name, dept, clearance}
  IPAddress   {ip, is_external, first_seen, last_seen}
  Asset       {asset_id, name, asset_type, sensitivity}
  Process     {name}

Edges (carry full OCSF event context)
  AUTHENTICATED   (User)-[:AUTHENTICATED {time, status_id, severity_id, service}]->(Asset)
  CONNECTED_FROM  (IPAddress)-[:CONNECTED_FROM {time, bytes_out, bytes_in, protocol}]->(Asset)
  USED_BY         (User)-[:USED_BY {time, event_count}]->(IPAddress)

Design rationale (from dissertation)
-------------------------------------
The fusion approach represents each sensor stream (auth logs, network flows,
configuration findings) as edge types in a unified property graph. Entity
resolution across streams is performed by matching on shared identifiers
(user UID, IP address, asset ID). Temporal edge weights enable detection of
behavioral drift via graph traversal rather than per-stream threshold rules.
"""

from __future__ import annotations

import logging
from typing import Any

from neo4j import GraphDatabase, Driver

from config import settings

logger = logging.getLogger("cybergraph.graph")


# ── Schema setup ──────────────────────────────────────────────────────────────

CONSTRAINTS = [
    "CREATE CONSTRAINT cg_user_uid IF NOT EXISTS FOR (n:CGUser) REQUIRE n.uid IS UNIQUE",
    "CREATE CONSTRAINT cg_ip IF NOT EXISTS FOR (n:CGIPAddress) REQUIRE n.ip IS UNIQUE",
    "CREATE CONSTRAINT cg_asset IF NOT EXISTS FOR (n:CGAsset) REQUIRE n.asset_id IS UNIQUE",
]

INDEXES = [
    "CREATE INDEX cg_user_name IF NOT EXISTS FOR (n:CGUser) ON (n.name)",
    "CREATE INDEX cg_event_time IF NOT EXISTS FOR ()-[r:AUTHENTICATED]-() ON (r.time)",
]


class FusionGraph:
    """
    Loads OCSF events into a Neo4j property graph implementing
    the dissertation's multisensor fusion architecture.

    Uses CG-prefixed labels (CGUser, CGIPAddress, CGAsset) to avoid
    collisions with the Meridian threat framework nodes in the same
    Neo4j instance.
    """

    def __init__(self, uri: str = None, user: str = None, password: str = None):
        self._driver: Driver = GraphDatabase.driver(
            uri or settings.neo4j_uri,
            auth=(user or settings.neo4j_user, password or settings.neo4j_password),
        )
        logger.info("FusionGraph connected to Neo4j")

    def close(self) -> None:
        self._driver.close()

    def ensure_schema(self) -> None:
        with self._driver.session() as session:
            for stmt in CONSTRAINTS + INDEXES:
                try:
                    session.run(stmt)
                except Exception as exc:
                    logger.debug(f"Schema stmt skipped: {exc}")
        logger.info("FusionGraph schema verified")

    def clear(self) -> None:
        """Remove all CyberGraph nodes and edges (leaves Meridian data intact)."""
        with self._driver.session() as session:
            session.run("MATCH (n:CGUser) DETACH DELETE n")
            session.run("MATCH (n:CGIPAddress) DETACH DELETE n")
            session.run("MATCH (n:CGAsset) DETACH DELETE n")
        logger.info("FusionGraph cleared")

    # ── Event ingestion ───────────────────────────────────────────────────────

    def ingest_events(self, events: list[dict[str, Any]]) -> dict[str, int]:
        """
        Ingest a list of OCSF events into the fusion graph.
        Returns counts of nodes and edges created.
        """
        counts = {"auth_edges": 0, "network_edges": 0, "user_ip_edges": 0,
                  "users": 0, "ips": 0, "assets": 0}

        with self._driver.session() as session:
            for event in events:
                class_uid = event.get("class_uid")
                if class_uid == 3002:
                    self._ingest_auth(session, event, counts)
                elif class_uid == 4001:
                    self._ingest_network(session, event, counts)

        logger.info(f"Ingested {len(events)} events: {counts}")
        return counts

    def _ingest_auth(self, session, event: dict, counts: dict) -> None:
        user = event.get("user", {})
        src = event.get("src_endpoint", {})
        dst = event.get("dst_endpoint", {})
        label = event.get("_label", {})

        if not user.get("uid") or not dst.get("uid"):
            return

        cypher = """
        MERGE (u:CGUser {uid: $user_uid})
          ON CREATE SET u.name = $user_name, u.created_at = $time
          ON MATCH  SET u.last_seen = $time

        MERGE (a:CGAsset {asset_id: $asset_id})
          ON CREATE SET a.name = $asset_name

        CREATE (u)-[r:AUTHENTICATED {
            time:        $time,
            status_id:   $status_id,
            severity_id: $severity_id,
            src_ip:      $src_ip,
            is_anomaly:  $is_anomaly,
            anomaly_type: $anomaly_type,
            event_uid:   $event_uid
        }]->(a)
        """

        session.run(cypher,
            user_uid=user.get("uid", ""),
            user_name=user.get("name", ""),
            asset_id=dst.get("uid", ""),
            asset_name=dst.get("name", ""),
            time=event.get("time", 0),
            status_id=event.get("status_id", 0),
            severity_id=event.get("severity_id", 0),
            src_ip=src.get("ip", ""),
            is_anomaly=label.get("is_anomaly", False),
            anomaly_type=label.get("anomaly_type", "none"),
            event_uid=event.get("metadata", {}).get("uid", ""),
        )
        counts["auth_edges"] += 1

        # User → IP edge
        if src.get("ip"):
            ip_cypher = """
            MERGE (ip:CGIPAddress {ip: $ip})
              ON CREATE SET ip.is_external = $is_external, ip.first_seen = $time
              ON MATCH  SET ip.last_seen = $time
            MERGE (u:CGUser {uid: $user_uid})
            MERGE (u)-[r:USED_IP]->(ip)
              ON CREATE SET r.first_seen = $time, r.event_count = 1
              ON MATCH  SET r.event_count = r.event_count + 1, r.last_seen = $time
            """
            is_external = not src["ip"].startswith("10.")
            session.run(ip_cypher,
                ip=src["ip"],
                is_external=is_external,
                time=event.get("time", 0),
                user_uid=user.get("uid", ""),
            )
            counts["user_ip_edges"] += 1

    def _ingest_network(self, session, event: dict, counts: dict) -> None:
        src = event.get("src_endpoint", {})
        dst = event.get("dst_endpoint", {})
        traffic = event.get("traffic", {})
        label = event.get("_label", {})

        if not src.get("ip") or not dst.get("uid"):
            return

        cypher = """
        MERGE (ip:CGIPAddress {ip: $src_ip})
          ON CREATE SET ip.is_external = $is_external, ip.first_seen = $time
          ON MATCH  SET ip.last_seen = $time

        MERGE (a:CGAsset {asset_id: $asset_id})
          ON CREATE SET a.name = $asset_name

        CREATE (ip)-[r:CONNECTED_TO {
            time:        $time,
            bytes_out:   $bytes_out,
            bytes_in:    $bytes_in,
            protocol:    $protocol,
            is_anomaly:  $is_anomaly,
            anomaly_type: $anomaly_type,
            event_uid:   $event_uid
        }]->(a)
        """

        session.run(cypher,
            src_ip=src.get("ip", ""),
            is_external=not src.get("ip", "10.").startswith("10."),
            asset_id=dst.get("uid", ""),
            asset_name=dst.get("name", ""),
            time=event.get("time", 0),
            bytes_out=traffic.get("bytes_out", 0),
            bytes_in=traffic.get("bytes_in", 0),
            protocol=event.get("connection_info", {}).get("protocol_name", "UNKNOWN"),
            is_anomaly=label.get("is_anomaly", False),
            anomaly_type=label.get("anomaly_type", "none"),
            event_uid=event.get("metadata", {}).get("uid", ""),
        )
        counts["network_edges"] += 1

    # ── Feature extraction ────────────────────────────────────────────────────

    def extract_user_features(self) -> list[dict[str, Any]]:
        """
        Extract per-user behavioral feature vectors from the graph.
        These feed the autoencoder for anomaly scoring.

        Features per user:
          - total_events: total authentication events
          - failure_rate: fraction of failed authentications
          - unique_assets: number of distinct assets accessed
          - unique_ips: number of distinct IPs used
          - external_ip_rate: fraction of events from external IPs
          - off_hours_rate: fraction of events outside 08:00-18:00
          - avg_bytes_out: average outbound bytes in network events
          - max_bytes_out: maximum outbound bytes in a single event
          - asset_diversity: Shannon entropy of asset access distribution
          - ip_diversity: Shannon entropy of IP usage distribution
        """
        cypher = """
        MATCH (u:CGUser)-[r:AUTHENTICATED]->(a:CGAsset)
        WITH u,
             count(r)                                          AS total_events,
             sum(CASE WHEN r.status_id = 2 THEN 1 ELSE 0 END) AS failures,
             count(DISTINCT a)                                 AS unique_assets,
             count(DISTINCT r.src_ip)                         AS unique_ips,
             sum(CASE WHEN r.src_ip STARTS WITH '10.' THEN 0 ELSE 1 END) AS ext_events,
             sum(CASE WHEN
               toInteger(substring(toString(datetime({epochMillis: r.time})), 11, 2)) < 8
               OR
               toInteger(substring(toString(datetime({epochMillis: r.time})), 11, 2)) >= 18
               THEN 1 ELSE 0 END)                             AS off_hours_events
        OPTIONAL MATCH (u)-[net_r:USED_IP]->(ip:CGIPAddress)-[c:CONNECTED_TO]->(asset)
        WITH u, total_events, failures, unique_assets, unique_ips,
             ext_events, off_hours_events,
             avg(c.bytes_out)  AS avg_bytes_out,
             max(c.bytes_out)  AS max_bytes_out
        RETURN
            u.uid             AS user_uid,
            u.name            AS user_name,
            total_events,
            toFloat(failures) / total_events               AS failure_rate,
            unique_assets,
            unique_ips,
            toFloat(ext_events) / total_events             AS external_ip_rate,
            toFloat(off_hours_events) / total_events       AS off_hours_rate,
            coalesce(avg_bytes_out, 0.0)                   AS avg_bytes_out,
            coalesce(max_bytes_out, 0.0)                   AS max_bytes_out
        ORDER BY total_events DESC
        """

        with self._driver.session() as session:
            result = session.run(cypher)
            return result.data()

    def extract_ip_features(self) -> list[dict[str, Any]]:
        """
        Extract per-IP behavioral feature vectors.

        Features per IP:
          - total_connections: total network connections
          - unique_assets_targeted: distinct assets connected to
          - unique_users: distinct users seen from this IP
          - avg_bytes_out: average outbound bytes
          - max_bytes_out: maximum outbound bytes
          - is_external: whether IP is outside 10.x.x.x range
          - connection_rate: connections per hour (temporal density)
        """
        cypher = """
        MATCH (ip:CGIPAddress)-[r:CONNECTED_TO]->(a:CGAsset)
        WITH ip,
             count(r)              AS total_connections,
             count(DISTINCT a)     AS unique_assets,
             avg(r.bytes_out)      AS avg_bytes_out,
             max(r.bytes_out)      AS max_bytes_out,
             min(r.time)           AS first_seen,
             max(r.time)           AS last_seen
        OPTIONAL MATCH (u:CGUser)-[:USED_IP]->(ip)
        WITH ip, total_connections, unique_assets, avg_bytes_out, max_bytes_out,
             first_seen, last_seen, count(DISTINCT u) AS unique_users
        RETURN
            ip.ip              AS ip_address,
            ip.is_external     AS is_external,
            total_connections,
            unique_assets,
            unique_users,
            coalesce(avg_bytes_out, 0.0)  AS avg_bytes_out,
            coalesce(max_bytes_out, 0.0)  AS max_bytes_out,
            CASE WHEN last_seen > first_seen
                 THEN toFloat(total_connections) /
                      ((last_seen - first_seen) / 3600000.0)
                 ELSE toFloat(total_connections) END AS connection_rate
        ORDER BY total_connections DESC
        """

        with self._driver.session() as session:
            result = session.run(cypher)
            return result.data()

    def get_anomaly_ground_truth(self) -> dict[str, bool]:
        """
        Return ground-truth anomaly labels per user from the graph.
        Used for benchmark evaluation.
        """
        cypher = """
        MATCH (u:CGUser)-[r:AUTHENTICATED]->()
        WITH u.uid AS uid, collect(r.is_anomaly) AS labels
        RETURN uid, any(l IN labels WHERE l = true) AS is_anomaly
        """
        with self._driver.session() as session:
            result = session.run(cypher)
            return {r["uid"]: r["is_anomaly"] for r in result.data()}
