-- Parser Deployment History
-- Tracks all deployment operations for parsers including deploys, undeploys, and rollbacks
-- Requirements: 7.3

CREATE TABLE IF NOT EXISTS parser_deployments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    parser_id UUID NOT NULL REFERENCES parsers(id) ON DELETE CASCADE,
    action VARCHAR(20) NOT NULL,           -- 'deploy', 'undeploy', 'rollback'
    status VARCHAR(20) NOT NULL,           -- 'success', 'failed', 'rolled_back'
    error_message TEXT,                    -- Error details if deployment failed
    config_snapshot TEXT,                  -- Snapshot of the config at deployment time
    deployed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_parser_deployments_parser_id ON parser_deployments(parser_id);
CREATE INDEX IF NOT EXISTS idx_parser_deployments_deployed_at ON parser_deployments(deployed_at DESC);
CREATE INDEX IF NOT EXISTS idx_parser_deployments_status ON parser_deployments(status);

-- Add comment for documentation
COMMENT ON TABLE parser_deployments IS 'Tracks deployment history for parsers including success/failure status and rollbacks';
COMMENT ON COLUMN parser_deployments.action IS 'Type of deployment action: deploy, undeploy, or rollback';
COMMENT ON COLUMN parser_deployments.status IS 'Result of the deployment: success, failed, or rolled_back';
COMMENT ON COLUMN parser_deployments.config_snapshot IS 'The Vector TOML configuration at the time of deployment';
