-- MITRE ATT&CK Framework Tables
-- Stores tactics and techniques from the MITRE ATT&CK Enterprise Matrix
-- Data is fetched from https://github.com/mitre/cti

-- Tactics table (14 tactics in Enterprise ATT&CK)
CREATE TABLE IF NOT EXISTS mitre_tactics (
    id VARCHAR(10) PRIMARY KEY,  -- e.g., TA0001
    name VARCHAR(100) NOT NULL,
    short_name VARCHAR(50) NOT NULL,
    description TEXT,
    url VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Techniques table (hundreds of techniques)
CREATE TABLE IF NOT EXISTS mitre_techniques (
    id VARCHAR(20) PRIMARY KEY,  -- e.g., T1059, T1059.001
    name VARCHAR(200) NOT NULL,
    description TEXT,
    url VARCHAR(255),
    is_subtechnique BOOLEAN DEFAULT FALSE,
    parent_id VARCHAR(20) REFERENCES mitre_techniques(id) ON DELETE SET NULL,
    deprecated BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Junction table for technique-tactic relationships (many-to-many)
CREATE TABLE IF NOT EXISTS mitre_technique_tactics (
    technique_id VARCHAR(20) REFERENCES mitre_techniques(id) ON DELETE CASCADE,
    tactic_id VARCHAR(10) REFERENCES mitre_tactics(id) ON DELETE CASCADE,
    PRIMARY KEY (technique_id, tactic_id)
);

-- Metadata table to track when data was last synced
CREATE TABLE IF NOT EXISTS mitre_sync_metadata (
    id SERIAL PRIMARY KEY,
    last_sync_at TIMESTAMPTZ NOT NULL,
    version VARCHAR(50),
    technique_count INTEGER,
    tactic_count INTEGER
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_mitre_techniques_parent ON mitre_techniques(parent_id);
CREATE INDEX IF NOT EXISTS idx_mitre_techniques_deprecated ON mitre_techniques(deprecated);
CREATE INDEX IF NOT EXISTS idx_mitre_technique_tactics_tactic ON mitre_technique_tactics(tactic_id);
