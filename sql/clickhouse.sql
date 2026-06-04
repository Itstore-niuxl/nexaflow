CREATE DATABASE IF NOT EXISTS nexaflow;

CREATE TABLE IF NOT EXISTS nexaflow.link_traffic_5s
(
    ts DateTime,
    source_id LowCardinality(String),
    iface LowCardinality(String),
    bytes UInt64,
    packets UInt64,
    drops UInt64,
    utilization Float64
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (source_id, iface, ts)
TTL ts + INTERVAL 7 DAY;

CREATE TABLE IF NOT EXISTS nexaflow.ip_traffic_5s
(
    ts DateTime,
    source_id LowCardinality(String),
    iface LowCardinality(String),
    ip String,
    direction LowCardinality(String),
    bytes UInt64,
    packets UInt64
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (source_id, direction, ts, ip)
TTL ts + INTERVAL 7 DAY;

CREATE TABLE IF NOT EXISTS nexaflow.dimension_traffic_5s
(
    ts DateTime,
    source_id LowCardinality(String),
    iface LowCardinality(String),
    dimension LowCardinality(String),
    dim_key String,
    bytes UInt64,
    packets UInt64
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (source_id, dimension, ts, dim_key)
TTL ts + INTERVAL 7 DAY;

CREATE TABLE IF NOT EXISTS nexaflow.alert_events
(
    id String,
    severity LowCardinality(String),
    status LowCardinality(String),
    subject String,
    summary String,
    first_seen DateTime,
    last_seen DateTime
)
ENGINE = MergeTree
PARTITION BY toDate(first_seen)
ORDER BY (severity, status, first_seen, id)
TTL first_seen + INTERVAL 180 DAY;

