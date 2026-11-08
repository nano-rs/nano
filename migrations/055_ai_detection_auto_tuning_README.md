# Migration 055: AI Detection Auto-Tuning Schema

## Overview

This migration creates the complete database schema for the AI Detection Auto-Tuning feature, which provides intelligent, automated optimization of detection rules through continuous baseline monitoring, anomaly detection, AI-powered analysis, validation testing, and safe deployment with full audit trails.

## Requirements Addressed

- **1.1, 1.2**: Baseline monitoring and metrics collection
- **2.1**: Threshold breach detection
- **6.1**: Rule versioning and deployment
- **8.1**: Tuning summary and audit log
- **12.1**: Rule-specific tuning controls

## Tables Created

### 1. detection_rule_versions
Tracks all versions of detection rules for audit trails and revert capabilities.

**Key Features:**
- Version history for each rule
- Tracks who made changes and why
- Links to tuning proposals
- Supports revert operations

### 2. detection_rule_baselines
Stores statistical baselines for each detection rule to identify anomalous behavior.

**Key Features:**
- Mean and standard deviation calculations
- Percentile tracking (95th, 99th)
- Threshold breach levels
- Rolling window updates

### 3. detection_rule_metrics
Time-series metrics for detection rule performance monitoring.

**Key Features:**
- Alert counts over multiple time windows (1h, 24h, 7d)
- Unique entity counts (users, hosts, IPs)
- Pattern tracking in JSONB format
- Execution time monitoring

### 4. detection_threshold_breaches
Records when detection rules exceed their baseline thresholds.

**Key Features:**
- Tracks deviation magnitude
- Consecutive period counting
- Links to tuning proposals
- Breach history

### 5. tuning_proposals
AI-generated proposals for tuning detection rules.

**Key Features:**
- Original vs proposed query comparison
- AI confidence scoring (0.0-1.0)
- Safety validation results
- Status tracking through lifecycle

### 6. tuning_test_results
Validation test results for tuning proposals.

**Key Features:**
- Alert volume comparison
- Reduction percentage calculation
- True positive preservation verification
- Detailed comparison metrics

### 7. tuning_logs
Comprehensive audit trail of all auto-tuning activities.

**Key Features:**
- Complete activity history
- Status transitions
- Revert tracking
- Links to all related entities

### 8. tuning_notifications
Notifications for admins and detection engineers about tuning activities.

**Key Features:**
- Multiple notification types
- Read/unread tracking
- Links to tuning details
- User-specific notifications

## Columns Added to detection_rules

- `auto_tuning_enabled`: Enable/disable auto-tuning per rule (default: true)
- `auto_tuning_min_confidence`: Minimum confidence threshold (default: 0.8)
- `auto_tuning_critical`: Mark rule as critical to prevent auto-tuning (default: false)
- `auto_tuning_disabled_until`: Timestamp for temporary auto-tuning disable (e.g., 7 days after revert)

## Indexes Created

Performance indexes on:
- Rule ID and timestamp combinations
- Status fields for filtering
- User ID for notifications
- Active version lookups
- Unread notification queries

## Foreign Key Relationships

```
detection_rules
  ├─> detection_rule_versions (rule_id)
  ├─> detection_rule_baselines (rule_id)
  ├─> detection_rule_metrics (rule_id)
  ├─> detection_threshold_breaches (rule_id)
  ├─> tuning_proposals (rule_id)
  └─> tuning_logs (rule_id)

tuning_proposals
  ├─> tuning_test_results (proposal_id)
  └─> tuning_logs (proposal_id)

detection_rule_versions
  ├─> tuning_logs (applied_version_id)
  └─> tuning_logs (reverted_to_version_id)

users
  ├─> detection_rule_versions (created_by)
  ├─> tuning_logs (reverted_by)
  └─> tuning_notifications (user_id)
```

## Applying the Migration

### Using Docker (Recommended)
```bash
docker exec -i nanosiem-postgres psql -U nanosiem -d nanosiem < migrations/055_ai_detection_auto_tuning.sql
```

### Using psql directly
```bash
psql -U nanosiem -d nanosiem -f migrations/055_ai_detection_auto_tuning.sql
```

## Verification

After applying the migration, verify the tables were created:

```sql
-- Check all tuning-related tables
\dt detection_rule_*
\dt tuning_*

-- Check new columns on detection_rules
SELECT column_name, data_type, column_default 
FROM information_schema.columns 
WHERE table_name = 'detection_rules' 
  AND column_name LIKE 'auto_tuning%';

-- Check indexes
\di idx_*tuning*
\di idx_rule_versions_*

-- Check foreign keys
SELECT tc.constraint_name, tc.table_name, kcu.column_name, 
       ccu.table_name AS foreign_table_name
FROM information_schema.table_constraints AS tc 
JOIN information_schema.key_column_usage AS kcu 
  ON tc.constraint_name = kcu.constraint_name 
JOIN information_schema.constraint_column_usage AS ccu 
  ON ccu.constraint_name = tc.constraint_name 
WHERE tc.constraint_type = 'FOREIGN KEY' 
  AND tc.table_name LIKE '%tuning%';
```

## Rollback

To rollback this migration:

```sql
-- Drop tables in reverse order (respecting foreign keys)
DROP TABLE IF EXISTS tuning_notifications CASCADE;
DROP TABLE IF EXISTS tuning_logs CASCADE;
DROP TABLE IF EXISTS tuning_test_results CASCADE;
DROP TABLE IF EXISTS tuning_proposals CASCADE;
DROP TABLE IF EXISTS detection_threshold_breaches CASCADE;
DROP TABLE IF EXISTS detection_rule_metrics CASCADE;
DROP TABLE IF EXISTS detection_rule_baselines CASCADE;
DROP TABLE IF EXISTS detection_rule_versions CASCADE;

-- Remove columns from detection_rules
ALTER TABLE detection_rules 
  DROP COLUMN IF EXISTS auto_tuning_enabled,
  DROP COLUMN IF EXISTS auto_tuning_min_confidence,
  DROP COLUMN IF EXISTS auto_tuning_critical,
  DROP COLUMN IF EXISTS auto_tuning_disabled_until;
```

## Notes

- All timestamps use `TIMESTAMPTZ` for timezone awareness
- JSONB columns are used for flexible data storage (patterns, metrics, validation results)
- Cascade deletes are configured where appropriate to maintain referential integrity
- Check constraints ensure data validity (confidence scores 0.0-1.0, valid status values)
- Comments are added to tables and columns for documentation

## Next Steps

After applying this migration:

1. Implement the Rust data models in `nanosiem-core/src/tuning/types.rs`
2. Create repository layer for database operations
3. Implement the metrics collector service
4. Set up scheduled tasks for baseline monitoring
5. Implement the auto-tuner agent
6. Create API endpoints for UI integration
