CREATE TABLE IF NOT EXISTS collectors (
    id VARCHAR(128) PRIMARY KEY,
    source_id VARCHAR(128) NOT NULL,
    name VARCHAR(255) NOT NULL,
    mode VARCHAR(64) NOT NULL,
    status VARCHAR(64) NOT NULL DEFAULT 'offline',
    iface VARCHAR(128),
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS alert_rules (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(64) NOT NULL,
    severity VARCHAR(64) NOT NULL,
    expression TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY,
    action VARCHAR(128) NOT NULL,
    resource_type VARCHAR(128),
    resource_id VARCHAR(255),
    detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

