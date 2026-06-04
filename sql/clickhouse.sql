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

CREATE TABLE IF NOT EXISTS nexaflow.flow_sessions_5s
(
    ts DateTime,
    source_id LowCardinality(String),
    iface LowCardinality(String),
    flow_key String,
    src_ip String,
    src_port UInt16,
    dst_ip String,
    dst_port UInt16,
    protocol LowCardinality(String),
    service LowCardinality(String),
    category LowCardinality(String),
    risk LowCardinality(String),
    direction LowCardinality(String),
    server_ip String,
    server_port UInt16,
    client_ip String,
    confidence LowCardinality(String),
    bytes UInt64,
    packets UInt64
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (source_id, ts, dst_ip, dst_port, src_ip, protocol)
TTL ts + INTERVAL 7 DAY;

CREATE TABLE IF NOT EXISTS nexaflow.capture_quality_5s
(
    ts DateTime,
    source_id LowCardinality(String),
    iface LowCardinality(String),
    rx_bytes UInt64,
    rx_packets UInt64,
    rx_dropped UInt64,
    rx_errors UInt64,
    tx_bytes UInt64,
    tx_packets UInt64,
    tx_dropped UInt64,
    tx_errors UInt64
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (source_id, iface, ts)
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

CREATE TABLE IF NOT EXISTS nexaflow.operation_audit
(
    id String,
    ts DateTime,
    actor LowCardinality(String),
    action LowCardinality(String),
    target String,
    summary String,
    detail String,
    client_ip String
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (ts, action, actor)
TTL ts + INTERVAL 365 DAY;
