-- NanoSIEM PostgreSQL Schema
-- Generated from current database state
--
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

-- TimescaleDB and pg_textsearch extensions removed
-- Logs are now stored in ClickHouse, not PostgreSQL

--
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;

--
-- Name: EXTENSION pg_trgm; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pg_trgm IS 'text similarity measurement and index searching based on trigrams';

--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;

--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';

--
-- Name: add_user_to_everyone_group(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE OR REPLACE FUNCTION public.add_user_to_everyone_group() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO user_groups (user_id, group_id)
    VALUES (NEW.id, '00000000-0000-0000-0000-000000000001')
    ON CONFLICT DO NOTHING;
    RETURN NEW;
END;
$$;

SET default_tablespace = '';

SET default_table_access_method = heap;

-- NOTE: logs table removed - logs are now stored in ClickHouse
-- NOTE: bm25_search functions removed - search uses ClickHouse

--
-- Name: cleanup_old_matched_events(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE OR REPLACE FUNCTION public.cleanup_old_matched_events() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM detection_matched_events
    WHERE matched_at < NOW() - INTERVAL '24 hours';
END;
$$;

--
-- Name: limit_search_history(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE OR REPLACE FUNCTION public.limit_search_history() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM search_history
    WHERE id IN (
        SELECT id FROM search_history
        WHERE user_id = NEW.user_id
        ORDER BY created_at DESC
        OFFSET 100
    );
    RETURN NEW;
END;
$$;

--
-- Name: lookup_ip_enrichment(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE OR REPLACE FUNCTION public.lookup_ip_enrichment(ip_addr text) RETURNS TABLE(country text, country_code text, continent text, continent_code text, asn text, as_name text, as_domain text)
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Handle NULL or empty IP
    IF ip_addr IS NULL OR ip_addr = '' THEN
        RETURN;
    END IF;
    
    RETURN QUERY
    SELECT 
        e.country,
        e.country_code,
        e.continent,
        e.continent_code,
        e.asn,
        e.as_name,
        e.as_domain
    FROM ip_enrichments e
    JOIN enrichment_sources s ON e.source_id = s.id
    WHERE ip_addr::inet <<= e.network
      AND s.enabled = true
    ORDER BY masklen(e.network) DESC  -- Most specific match first
    LIMIT 1;
END;
$$;

--
-- Name: normalize_log_content(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE OR REPLACE FUNCTION public.normalize_log_content(content text) RETURNS text
    LANGUAGE plpgsql IMMUTABLE
    AS $_$
BEGIN
    RETURN regexp_replace(
        regexp_replace(
            regexp_replace(
                regexp_replace(
                    regexp_replace(content, '[/=\[\]"''{}()<>|\\:;,]', ' ', 'g'),
                    '\s+', ' ', 'g'
                ),
                '^\s+', '', 'g'
            ),
            '\s+$', '', 'g'
        ),
        '-(?=[a-zA-Z])', ' ', 'g'
    );
END;
$_$;

--
-- Name: normalize_log_for_search(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE OR REPLACE FUNCTION public.normalize_log_for_search(content text) RETURNS text
    LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
    AS $$
BEGIN
    -- Replace common log delimiters with spaces
    -- This allows 'dashboard' to match '/dashboard', 'user=admin' to match 'admin', etc.
    -- Also split on dots to allow 'reddit' to match 'www.reddit.com'
    RETURN regexp_replace(content, '[/=\[\]"''{}()<>|\\:;,.]', ' ', 'g');
END;
$$;

--
-- Name: swap_enrichment_staging(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE OR REPLACE FUNCTION public.swap_enrichment_staging(p_source_id text) RETURNS bigint
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_count BIGINT;
BEGIN
    -- Get count from staging
    SELECT COUNT(*) INTO v_count FROM ip_enrichments_staging WHERE source_id = p_source_id;
    
    -- Delete old data for this source from production
    DELETE FROM ip_enrichments WHERE source_id = p_source_id;
    
    -- Move data from staging to production
    INSERT INTO ip_enrichments (source_id, network, country, country_code, continent, continent_code, asn, as_name, as_domain, extra, created_at)
    SELECT source_id, network, country, country_code, continent, continent_code, asn, as_name, as_domain, extra, created_at
    FROM ip_enrichments_staging
    WHERE source_id = p_source_id;
    
    -- Clear staging table for this source
    DELETE FROM ip_enrichments_staging WHERE source_id = p_source_id;
    
    RETURN v_count;
END;
$$;

--
-- Name: update_feeds_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE OR REPLACE FUNCTION public.update_feeds_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

--
-- Name: update_lookup_tables_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE OR REPLACE FUNCTION public.update_lookup_tables_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

--
-- Name: update_melod_settings_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE OR REPLACE FUNCTION public.update_melod_settings_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

--
-- Name: update_parsers_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE OR REPLACE FUNCTION public.update_parsers_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

--
-- Name: update_prevalence_settings_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE OR REPLACE FUNCTION public.update_prevalence_settings_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

--
-- Name: update_query_explanations_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE OR REPLACE FUNCTION public.update_query_explanations_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

--
-- Name: update_scheduled_jobs_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE OR REPLACE FUNCTION public.update_scheduled_jobs_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

--
-- Name: update_system_settings_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE OR REPLACE FUNCTION public.update_system_settings_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE OR REPLACE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

--
-- Name: upsert_detection_daily_stats(uuid, date, bigint, bigint); Type: FUNCTION; Schema: public; Owner: -
--

CREATE OR REPLACE FUNCTION public.upsert_detection_daily_stats(p_rule_id uuid, p_date date, p_match_count bigint, p_alert_count bigint DEFAULT 0) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO detection_daily_stats (rule_id, date, match_count, alert_count)
    VALUES (p_rule_id, p_date, p_match_count, p_alert_count)
    ON CONFLICT (rule_id, date) 
    DO UPDATE SET 
        match_count = detection_daily_stats.match_count + EXCLUDED.match_count,
        alert_count = detection_daily_stats.alert_count + EXCLUDED.alert_count,
        updated_at = NOW();
END;
$$;

--
-- Name: ingestion_errors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ingestion_errors (
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    id bigint NOT NULL,
    error_type text NOT NULL,
    source_type text,
    raw_content text,
    error_message text NOT NULL,
    error_details jsonb DEFAULT '{}'::jsonb
);

--
-- Name: alerts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alerts (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    rule_id uuid,
    severity text NOT NULL,
    status text DEFAULT 'new'::text NOT NULL,
    disposition text,
    matched_events jsonb DEFAULT '[]'::jsonb NOT NULL,
    assigned_to text,
    acknowledged_by text,
    acknowledged_at timestamp with time zone,
    closed_by text,
    closed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    event_hash text,
    CONSTRAINT alerts_disposition_check CHECK ((disposition = ANY (ARRAY['true_positive'::text, 'false_positive'::text, 'benign'::text]))),
    CONSTRAINT alerts_severity_check CHECK ((severity = ANY (ARRAY['critical'::text, 'high'::text, 'medium'::text, 'low'::text, 'informational'::text]))),
    CONSTRAINT alerts_status_check CHECK ((status = ANY (ARRAY['new'::text, 'acknowledged'::text, 'closed'::text])))
);

--
-- Name: COLUMN alerts.event_hash; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.alerts.event_hash IS 'Hash of matched events for deduplication - prevents duplicate alerts for same events';

--
-- Name: api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    key_hash character varying(255) NOT NULL,
    key_prefix character varying(10) NOT NULL,
    permissions text[] NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    expires_at timestamp with time zone,
    rate_limit integer,
    last_used_at timestamp with time zone,
    last_used_ip character varying(45),
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: audit_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    user_id uuid,
    api_key_id uuid,
    action character varying(100) NOT NULL,
    resource_type character varying(50),
    resource_id uuid,
    details jsonb,
    ip_address character varying(45),
    user_agent text,
    success boolean DEFAULT true NOT NULL
);

--
-- Name: dashboards; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dashboards (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name text NOT NULL,
    description text,
    layout jsonb DEFAULT '{}'::jsonb NOT NULL,
    panels jsonb DEFAULT '[]'::jsonb NOT NULL,
    refresh_interval integer,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

--
-- Name: detection_daily_stats; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.detection_daily_stats (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rule_id uuid NOT NULL,
    date date NOT NULL,
    match_count bigint DEFAULT 0 NOT NULL,
    alert_count bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: detection_matched_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.detection_matched_events (
    rule_id uuid NOT NULL,
    event_id text NOT NULL,
    event_timestamp timestamp with time zone NOT NULL,
    matched_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: TABLE detection_matched_events; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.detection_matched_events IS 'Tracks individual events that have been matched by detection rules to prevent re-detection in overlapping lookback windows';

--
-- Name: COLUMN detection_matched_events.event_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_matched_events.event_id IS 'Unique identifier for the event (typically log_id or computed hash)';

--
-- Name: COLUMN detection_matched_events.event_timestamp; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_matched_events.event_timestamp IS 'Original timestamp of the event for efficient cleanup';

--
-- Name: COLUMN detection_matched_events.matched_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_matched_events.matched_at IS 'When this event was first matched by this rule';

--
-- Name: detection_matches; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.detection_matches (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rule_id uuid NOT NULL,
    rule_name text NOT NULL,
    severity text NOT NULL,
    matched_events jsonb DEFAULT '[]'::jsonb NOT NULL,
    event_count integer DEFAULT 0 NOT NULL,
    detected_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    event_hash text
);

--
-- Name: TABLE detection_matches; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.detection_matches IS 'Stores individual detection matches for all rule modes (staging, live, alerting) so they can be reviewed';

--
-- Name: COLUMN detection_matches.matched_events; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_matches.matched_events IS 'JSONB array of events that triggered this detection';

--
-- Name: COLUMN detection_matches.event_count; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_matches.event_count IS 'Number of events in this match (for quick filtering)';

--
-- Name: COLUMN detection_matches.event_hash; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_matches.event_hash IS 'SHA256 hash of matched_events for deduplication';

--
-- Name: detection_rule_baselines; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.detection_rule_baselines (
    rule_id uuid NOT NULL,
    established_at timestamp with time zone NOT NULL,
    last_updated timestamp with time zone NOT NULL,
    mean_alerts_per_hour double precision NOT NULL,
    std_dev_alerts_per_hour double precision NOT NULL,
    percentile_95 double precision NOT NULL,
    percentile_99 double precision NOT NULL,
    threshold_breach_level double precision NOT NULL,
    data_points integer NOT NULL,
    baseline_data jsonb DEFAULT '{}'::jsonb NOT NULL
);

--
-- Name: TABLE detection_rule_baselines; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.detection_rule_baselines IS 'Statistical baselines for detection rules to identify anomalous behavior';

--
-- Name: COLUMN detection_rule_baselines.threshold_breach_level; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_rule_baselines.threshold_breach_level IS 'Calculated as mean + 2 * std_dev';

--
-- Name: detection_rule_metrics; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.detection_rule_metrics (
    id bigint NOT NULL,
    rule_id uuid NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    alert_count_1h bigint NOT NULL,
    alert_count_24h bigint NOT NULL,
    alert_count_7d bigint NOT NULL,
    unique_users bigint DEFAULT 0 NOT NULL,
    unique_hosts bigint DEFAULT 0 NOT NULL,
    unique_ips bigint DEFAULT 0 NOT NULL,
    avg_severity double precision DEFAULT 0.0 NOT NULL,
    execution_time_ms bigint DEFAULT 0 NOT NULL,
    patterns jsonb DEFAULT '{}'::jsonb NOT NULL
);

--
-- Name: TABLE detection_rule_metrics; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.detection_rule_metrics IS 'Time-series metrics for detection rule performance monitoring';

--
-- Name: detection_rule_metrics_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.detection_rule_metrics_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: detection_rule_metrics_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.detection_rule_metrics_id_seq OWNED BY public.detection_rule_metrics.id;

--
-- Name: detection_rule_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.detection_rule_versions (
    id integer NOT NULL,
    rule_id uuid NOT NULL,
    version_number integer NOT NULL,
    query text NOT NULL,
    name text NOT NULL,
    description text,
    severity text NOT NULL,
    mitre_tactics text[] DEFAULT '{}'::text[],
    mitre_techniques text[] DEFAULT '{}'::text[],
    enabled boolean DEFAULT true NOT NULL,
    is_active boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    change_reason text NOT NULL,
    tuning_proposal_id uuid,
    reverted_from_version integer,
    CONSTRAINT detection_rule_versions_severity_check CHECK ((severity = ANY (ARRAY['critical'::text, 'high'::text, 'medium'::text, 'low'::text, 'informational'::text])))
);

--
-- Name: TABLE detection_rule_versions; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.detection_rule_versions IS 'Version history for detection rules, enabling audit trails and reverts';

--
-- Name: COLUMN detection_rule_versions.is_active; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_rule_versions.is_active IS 'Only one version per rule should be active at a time';

--
-- Name: COLUMN detection_rule_versions.change_reason; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_rule_versions.change_reason IS 'Reason for version creation: manual_edit, auto_tuning, revert, initial_creation';

--
-- Name: detection_rule_versions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.detection_rule_versions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: detection_rule_versions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.detection_rule_versions_id_seq OWNED BY public.detection_rule_versions.id;

--
-- Name: detection_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.detection_rules (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name text NOT NULL,
    description text,
    query text NOT NULL,
    severity text NOT NULL,
    mitre_tactics text[] DEFAULT '{}'::text[],
    mitre_techniques text[] DEFAULT '{}'::text[],
    schedule_cron text,
    enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    last_run_at timestamp with time zone,
    match_count bigint DEFAULT 0,
    mode text DEFAULT 'staging'::text NOT NULL,
    live_match_count bigint DEFAULT 0 NOT NULL,
    narrative text,
    reference_url text,
    author text,
    tags text[] DEFAULT '{}'::text[] NOT NULL,
    ai_generated boolean DEFAULT false NOT NULL,
    last_match_at timestamp with time zone,
    realtime_enabled boolean DEFAULT false NOT NULL,
    risk_score integer,
    risk_entity_field text,
    risk_modifiers jsonb DEFAULT '[]'::jsonb,
    detection_mode text DEFAULT 'scheduled'::text NOT NULL,
    materialized_view_name text,
    archived boolean DEFAULT false NOT NULL,
    lookback_minutes integer,
    auto_tuning_enabled boolean DEFAULT true NOT NULL,
    auto_tuning_min_confidence double precision DEFAULT 0.8 NOT NULL,
    auto_tuning_critical boolean DEFAULT false NOT NULL,
    auto_tuning_disabled_until timestamp with time zone,
    auto_apply_enabled boolean DEFAULT false NOT NULL,
    CONSTRAINT check_detection_mode CHECK ((detection_mode = ANY (ARRAY['real-time'::text, 'near-real-time'::text, 'scheduled'::text]))),
    CONSTRAINT detection_rules_auto_tuning_min_confidence_check CHECK (((auto_tuning_min_confidence >= (0.0)::double precision) AND (auto_tuning_min_confidence <= (1.0)::double precision))),
    CONSTRAINT detection_rules_mode_check CHECK ((mode = ANY (ARRAY['staging'::text, 'live'::text, 'alerting'::text]))),
    CONSTRAINT detection_rules_risk_score_check CHECK (((risk_score >= 0) AND (risk_score <= 100))),
    CONSTRAINT detection_rules_severity_check CHECK ((severity = ANY (ARRAY['critical'::text, 'high'::text, 'medium'::text, 'low'::text, 'informational'::text])))
);

--
-- Name: COLUMN detection_rules.mode; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_rules.mode IS 'Rule mode: staging (being developed, not executed), live (testing, no alerts), alerting (production, generates alerts)';

--
-- Name: COLUMN detection_rules.live_match_count; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_rules.live_match_count IS 'Count of matches during live/bake-in mode for tuning';

--
-- Name: COLUMN detection_rules.narrative; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_rules.narrative IS 'AI-generated narrative explaining what the rule detects and why it matters';

--
-- Name: COLUMN detection_rules.reference_url; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_rules.reference_url IS 'Reference URL for more information (blog post, CVE, threat intel)';

--
-- Name: COLUMN detection_rules.author; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_rules.author IS 'Author of the detection rule';

--
-- Name: COLUMN detection_rules.tags; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_rules.tags IS 'Tags for categorization beyond MITRE (e.g., ransomware, apt, insider-threat)';

--
-- Name: COLUMN detection_rules.ai_generated; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_rules.ai_generated IS 'Whether this rule was created using AI assistance (meloD)';

--
-- Name: COLUMN detection_rules.realtime_enabled; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_rules.realtime_enabled IS 'When true, this rule is evaluated in real-time as logs are ingested';

--
-- Name: COLUMN detection_rules.risk_score; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_rules.risk_score IS 'Base risk score (0-100). If NULL, defaults based on severity: Critical=90, High=70, Medium=50, Low=30, Informational=10';

--
-- Name: COLUMN detection_rules.risk_entity_field; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_rules.risk_entity_field IS 'UDM field to extract risk entity from (e.g., src_ip, user, src_host). If NULL, infers from src_ip -> user -> src_host';

--
-- Name: COLUMN detection_rules.risk_modifiers; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_rules.risk_modifiers IS 'JSON array of conditional score modifiers: [{"condition": "expr", "score": N}, ...]';

--
-- Name: COLUMN detection_rules.detection_mode; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_rules.detection_mode IS 'Detection execution mode: real-time (materialized views, 10-30s), near-real-time (micro-batch, 1-5min), or scheduled (cron, hourly/daily)';

--
-- Name: COLUMN detection_rules.materialized_view_name; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_rules.materialized_view_name IS 'Auto-generated materialized view name for real-time detection rules (null for other modes)';

--
-- Name: COLUMN detection_rules.lookback_minutes; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_rules.lookback_minutes IS 'Custom lookback period in minutes for this rule. If NULL, uses the default from scheduler config. Useful for prevalence-based detections that need longer lookback windows (e.g., 1440 for 24 hours).';

--
-- Name: COLUMN detection_rules.auto_tuning_disabled_until; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_rules.auto_tuning_disabled_until IS 'Timestamp until which auto-tuning is disabled (e.g., 7 days after revert)';

--
-- Name: COLUMN detection_rules.auto_apply_enabled; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_rules.auto_apply_enabled IS 'When true, tuning proposals meeting the min_confidence threshold are automatically applied without manual review. Requires auto_tuning_enabled to also be true. Use with caution.';

--
-- Name: detection_threshold_breaches; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.detection_threshold_breaches (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rule_id uuid NOT NULL,
    detected_at timestamp with time zone NOT NULL,
    current_value double precision NOT NULL,
    baseline_mean double precision NOT NULL,
    baseline_threshold double precision NOT NULL,
    deviation_magnitude double precision NOT NULL,
    consecutive_periods integer NOT NULL,
    tuning_triggered boolean DEFAULT false NOT NULL,
    tuning_proposal_id uuid
);

--
-- Name: TABLE detection_threshold_breaches; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.detection_threshold_breaches IS 'Records of when detection rules exceed their baseline thresholds';

--
-- Name: COLUMN detection_threshold_breaches.consecutive_periods; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.detection_threshold_breaches.consecutive_periods IS 'Number of consecutive evaluation periods the breach has persisted';

--
-- Name: enrichment_sources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.enrichment_sources (
    id text NOT NULL,
    name text NOT NULL,
    source_type text NOT NULL,
    description text,
    download_url text,
    last_sync_at timestamp with time zone,
    last_sync_status text,
    last_sync_error text,
    record_count bigint DEFAULT 0,
    file_hash text,
    config jsonb DEFAULT '{}'::jsonb,
    enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

--
-- Name: entity_risk_scores; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.entity_risk_scores (
    id integer NOT NULL,
    entity text NOT NULL,
    entity_type text DEFAULT 'unknown'::text NOT NULL,
    risk_score integer DEFAULT 0 NOT NULL,
    signal_count integer DEFAULT 0 NOT NULL,
    last_signal_at timestamp with time zone,
    first_signal_at timestamp with time zone,
    last_rule_name text,
    last_severity text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: TABLE entity_risk_scores; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.entity_risk_scores IS 'Aggregated risk scores per entity for risk analytics dashboard';

--
-- Name: COLUMN entity_risk_scores.entity; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.entity_risk_scores.entity IS 'The entity identifier (IP, username, hostname, etc.)';

--
-- Name: COLUMN entity_risk_scores.entity_type; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.entity_risk_scores.entity_type IS 'Type of entity: src_ip, user, hostname, etc.';

--
-- Name: COLUMN entity_risk_scores.risk_score; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.entity_risk_scores.risk_score IS 'Cumulative risk score for this entity';

--
-- Name: COLUMN entity_risk_scores.signal_count; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.entity_risk_scores.signal_count IS 'Number of signals contributing to the score';

--
-- Name: COLUMN entity_risk_scores.last_signal_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.entity_risk_scores.last_signal_at IS 'Timestamp of the most recent signal';

--
-- Name: COLUMN entity_risk_scores.first_signal_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.entity_risk_scores.first_signal_at IS 'Timestamp of the first signal';

--
-- Name: COLUMN entity_risk_scores.last_rule_name; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.entity_risk_scores.last_rule_name IS 'Name of the most recent detection rule that fired';

--
-- Name: COLUMN entity_risk_scores.last_severity; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.entity_risk_scores.last_severity IS 'Severity of the most recent detection';

--
-- Name: entity_risk_scores_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.entity_risk_scores_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: entity_risk_scores_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.entity_risk_scores_id_seq OWNED BY public.entity_risk_scores.id;

--
-- Name: feeds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.feeds (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    match_field character varying(255),
    match_pattern character varying(512),
    match_values text[],
    category character varying(100),
    vendor character varying(255),
    product character varying(255),
    icon character varying(50),
    color character varying(20),
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: group_roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.group_roles (
    group_id uuid NOT NULL,
    role_id uuid NOT NULL
);

--
-- Name: groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.groups (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    is_system boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: ingestion_errors_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ingestion_errors_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: ingestion_errors_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ingestion_errors_id_seq OWNED BY public.ingestion_errors.id;

--
-- Name: ip_enrichments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ip_enrichments (
    id bigint NOT NULL,
    source_id text NOT NULL,
    network cidr NOT NULL,
    country text,
    country_code text,
    continent text,
    continent_code text,
    asn text,
    as_name text,
    as_domain text,
    extra jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now()
);

--
-- Name: ip_enrichments_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ip_enrichments_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: ip_enrichments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ip_enrichments_id_seq OWNED BY public.ip_enrichments.id;

--
-- Name: ip_enrichments_staging; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ip_enrichments_staging (
    id bigint NOT NULL,
    source_id text NOT NULL,
    network cidr NOT NULL,
    country text,
    country_code text,
    continent text,
    continent_code text,
    asn text,
    as_name text,
    as_domain text,
    extra jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now()
);

--
-- Name: ip_enrichments_staging_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ip_enrichments_staging_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: ip_enrichments_staging_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ip_enrichments_staging_id_seq OWNED BY public.ip_enrichments_staging.id;

--
-- Name: logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

--
-- Name: logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

--
-- Name: lookup_assets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lookup_assets (
    criticality text NOT NULL,
    department text NOT NULL,
    hostname text NOT NULL,
    ip text NOT NULL,
    owner text NOT NULL
);

--
-- Name: lookup_tables_registry; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lookup_tables_registry (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    table_name character varying(255) NOT NULL,
    columns jsonb NOT NULL,
    primary_key character varying(255),
    row_count bigint DEFAULT 0,
    size_bytes bigint DEFAULT 0,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: melod_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.melod_settings (
    id text DEFAULT 'default'::text NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    provider text DEFAULT 'aws_bedrock'::text NOT NULL,
    config jsonb DEFAULT '{"model_id": "us.anthropic.claude-sonnet-4-5-20250929-v1:0", "aws_region": "us-east-1", "max_tokens": 4096, "temperature": 0.7, "requests_per_minute": 60}'::jsonb NOT NULL,
    credentials_encrypted jsonb,
    connection_status jsonb DEFAULT '{"error": null, "connected": false, "last_checked": null, "model_available": false}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: oidc_group_mappings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oidc_group_mappings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    provider_id uuid NOT NULL,
    oidc_group character varying(255) NOT NULL,
    local_group_id uuid NOT NULL
);

--
-- Name: oidc_providers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oidc_providers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    slug character varying(50) NOT NULL,
    issuer character varying(500) NOT NULL,
    client_id character varying(255) NOT NULL,
    client_secret_encrypted bytea NOT NULL,
    scopes text[] DEFAULT ARRAY['openid'::text, 'profile'::text, 'email'::text] NOT NULL,
    group_claim character varying(100) DEFAULT 'groups'::character varying,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: parsers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.parsers (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    source_type character varying(100) NOT NULL,
    source_config jsonb DEFAULT '{}'::jsonb NOT NULL,
    parser_vrl text NOT NULL,
    output_fields jsonb,
    feed_id uuid,
    enabled boolean DEFAULT false NOT NULL,
    validated boolean DEFAULT false NOT NULL,
    validation_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.permissions (
    id character varying(100) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    category character varying(50) NOT NULL
);

--
-- Name: prevalence_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.prevalence_settings (
    id text DEFAULT 'default'::text NOT NULL,
    rarity_threshold integer DEFAULT 3 NOT NULL,
    enable_hash_tracking boolean DEFAULT true NOT NULL,
    enable_domain_tracking boolean DEFAULT true NOT NULL,
    retention_days integer DEFAULT 90 NOT NULL,
    cache_ttl_seconds integer DEFAULT 60 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: query_explanations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.query_explanations (
    query_hash character varying(64) NOT NULL,
    query text NOT NULL,
    query_mode character varying(10) DEFAULT 'piped'::character varying NOT NULL,
    natural_language_prompt text,
    explanation text,
    reasoning_steps jsonb,
    fields_used jsonb,
    generated_sql text,
    complexity character varying(20),
    suggested_time_range text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    access_count integer DEFAULT 0,
    last_accessed_at timestamp with time zone
);

--
-- Name: TABLE query_explanations; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.query_explanations IS 'Cache for AI-generated query explanations, enabling shared URLs to include the AI reasoning';

--
-- Name: COLUMN query_explanations.query_hash; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.query_explanations.query_hash IS 'SHA256 hash of normalized query for deduplication';

--
-- Name: COLUMN query_explanations.reasoning_steps; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.query_explanations.reasoning_steps IS 'JSON array of reasoning steps from meloD';

--
-- Name: query_library; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.query_library (
    id integer NOT NULL,
    name text NOT NULL,
    description text NOT NULL,
    query text NOT NULL,
    category text NOT NULL,
    tags text[] DEFAULT '{}'::text[] NOT NULL,
    difficulty text DEFAULT 'beginner'::text NOT NULL,
    use_case text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    is_builtin boolean DEFAULT true NOT NULL
);

--
-- Name: TABLE query_library; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.query_library IS 'Library of example queries to help users learn the query language';

--
-- Name: COLUMN query_library.category; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.query_library.category IS 'Category: basics, filtering, aggregation, risk, network, authentication, threat-hunting, reporting';

--
-- Name: COLUMN query_library.difficulty; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.query_library.difficulty IS 'Difficulty level: beginner, intermediate, advanced';

--
-- Name: COLUMN query_library.use_case; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.query_library.use_case IS 'Primary use case: detection, investigation, reporting, dashboard';

--
-- Name: COLUMN query_library.is_builtin; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.query_library.is_builtin IS 'Whether this is a built-in query (vs user-created)';

--
-- Name: query_library_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.query_library_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: query_library_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.query_library_id_seq OWNED BY public.query_library.id;

--
-- Name: role_permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.role_permissions (
    role_id uuid NOT NULL,
    permission_id character varying(100) NOT NULL
);

--
-- Name: roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.roles (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    is_system boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: saved_searches; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.saved_searches (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name text NOT NULL,
    query text NOT NULL,
    time_range jsonb,
    created_at timestamp with time zone DEFAULT now()
);

--
-- Name: scheduled_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scheduled_jobs (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    cron_expression character varying(100) NOT NULL,
    url text NOT NULL,
    auth_headers jsonb,
    destination_type character varying(50) NOT NULL,
    destination_config jsonb NOT NULL,
    parser_config jsonb NOT NULL,
    retry_max integer DEFAULT 3,
    retry_delay_secs integer DEFAULT 60,
    enabled boolean DEFAULT true,
    last_run_at timestamp with time zone,
    last_run_status character varying(50),
    last_run_error text,
    next_run_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: search_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.search_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    query text NOT NULL,
    query_mode character varying(10) DEFAULT 'piped'::character varying NOT NULL,
    time_range_type character varying(20) DEFAULT 'preset'::character varying NOT NULL,
    time_range_preset character varying(50),
    time_range_start timestamp with time zone,
    time_range_end timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    refresh_token_hash character varying(255) NOT NULL,
    ip_address character varying(45),
    user_agent text,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: shared_searches; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.shared_searches (
    id character varying(12) NOT NULL,
    query text NOT NULL,
    query_mode character varying(10) DEFAULT 'piped'::character varying NOT NULL,
    time_range_type character varying(10) DEFAULT 'preset'::character varying NOT NULL,
    time_range_preset character varying(50),
    time_range_start timestamp with time zone,
    time_range_end timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    access_count integer DEFAULT 0,
    last_accessed_at timestamp with time zone
);

--
-- Name: system_config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.system_config (
    key character varying(100) NOT NULL,
    value jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: system_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.system_settings (
    id text DEFAULT 'default'::text NOT NULL,
    retention_enabled boolean DEFAULT false NOT NULL,
    retention_days integer DEFAULT 90 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    risk_weight numeric(3,2) DEFAULT 1.0 NOT NULL,
    prevalence_rarity_threshold integer DEFAULT 3 NOT NULL,
    prevalence_enable_hash_tracking boolean DEFAULT true NOT NULL,
    prevalence_enable_domain_tracking boolean DEFAULT true NOT NULL,
    prevalence_enable_ip_tracking boolean DEFAULT true NOT NULL,
    prevalence_retention_days integer DEFAULT 90 NOT NULL,
    prevalence_cache_ttl_seconds integer DEFAULT 60 NOT NULL,
    CONSTRAINT system_settings_prevalence_cache_ttl_seconds_check CHECK (((prevalence_cache_ttl_seconds >= 0) AND (prevalence_cache_ttl_seconds <= 3600))),
    CONSTRAINT system_settings_prevalence_rarity_threshold_check CHECK (((prevalence_rarity_threshold >= 1) AND (prevalence_rarity_threshold <= 1000))),
    CONSTRAINT system_settings_prevalence_retention_days_check CHECK (((prevalence_retention_days >= 1) AND (prevalence_retention_days <= 365))),
    CONSTRAINT system_settings_risk_weight_check CHECK (((risk_weight >= 0.0) AND (risk_weight <= 1.0)))
);

--
-- Name: COLUMN system_settings.risk_weight; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.system_settings.risk_weight IS 'Global risk score multiplier (0.0-1.0). Applied to all risk scores. Default 1.0 = no change, 0.0 = disable risk scoring';

--
-- Name: COLUMN system_settings.prevalence_rarity_threshold; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.system_settings.prevalence_rarity_threshold IS 'Number of hosts below which an artifact is considered rare (default: 3)';

--
-- Name: COLUMN system_settings.prevalence_enable_hash_tracking; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.system_settings.prevalence_enable_hash_tracking IS 'Whether to track file hash prevalence (default: true)';

--
-- Name: COLUMN system_settings.prevalence_enable_domain_tracking; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.system_settings.prevalence_enable_domain_tracking IS 'Whether to track domain prevalence (default: true)';

--
-- Name: COLUMN system_settings.prevalence_enable_ip_tracking; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.system_settings.prevalence_enable_ip_tracking IS 'Whether to track IP address prevalence (default: true)';

--
-- Name: COLUMN system_settings.prevalence_retention_days; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.system_settings.prevalence_retention_days IS 'Number of days to retain prevalence data (default: 90)';

--
-- Name: COLUMN system_settings.prevalence_cache_ttl_seconds; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.system_settings.prevalence_cache_ttl_seconds IS 'Cache TTL in seconds for prevalence queries (default: 60)';

--
-- Name: test_bm25 - REMOVED (bm25 extension not available)
--

--
-- Name: tuning_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tuning_logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rule_id uuid NOT NULL,
    rule_name text NOT NULL,
    triggered_at timestamp with time zone NOT NULL,
    trigger_reason text NOT NULL,
    proposal_id uuid,
    test_results_id uuid,
    applied_version_id integer,
    status text NOT NULL,
    reverted_at timestamp with time zone,
    reverted_by uuid,
    reverted_to_version_id integer,
    revert_reason text,
    CONSTRAINT tuning_logs_status_check CHECK ((status = ANY (ARRAY['proposed'::text, 'testing'::text, 'test_passed'::text, 'test_failed'::text, 'staging'::text, 'promoted'::text, 'reverted'::text, 'manually_approved'::text, 'rejected'::text])))
);

--
-- Name: TABLE tuning_logs; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.tuning_logs IS 'Comprehensive audit trail of all auto-tuning activities';

--
-- Name: tuning_notifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tuning_notifications (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    notification_type text NOT NULL,
    title text NOT NULL,
    message text NOT NULL,
    link text,
    tuning_log_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    read_at timestamp with time zone,
    CONSTRAINT tuning_notifications_notification_type_check CHECK ((notification_type = ANY (ARRAY['tuning_triggered'::text, 'validation_complete'::text, 'staging_deployed'::text, 'promoted'::text, 'reverted'::text])))
);

--
-- Name: TABLE tuning_notifications; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.tuning_notifications IS 'Notifications for admins and detection engineers about tuning activities';

--
-- Name: tuning_proposals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tuning_proposals (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rule_id uuid NOT NULL,
    breach_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    original_query text NOT NULL,
    proposed_query text NOT NULL,
    rationale text NOT NULL,
    confidence_score double precision NOT NULL,
    changes_summary jsonb DEFAULT '[]'::jsonb NOT NULL,
    affected_patterns jsonb DEFAULT '[]'::jsonb NOT NULL,
    safety_validation jsonb DEFAULT '{}'::jsonb NOT NULL,
    status text DEFAULT 'proposed'::text NOT NULL,
    CONSTRAINT tuning_proposals_confidence_score_check CHECK (((confidence_score >= (0.0)::double precision) AND (confidence_score <= (1.0)::double precision))),
    CONSTRAINT tuning_proposals_status_check CHECK ((status = ANY (ARRAY['proposed'::text, 'testing'::text, 'test_passed'::text, 'test_failed'::text, 'staging'::text, 'promoted'::text, 'reverted'::text, 'manually_approved'::text, 'rejected'::text])))
);

--
-- Name: TABLE tuning_proposals; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.tuning_proposals IS 'AI-generated proposals for tuning detection rules';

--
-- Name: COLUMN tuning_proposals.confidence_score; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tuning_proposals.confidence_score IS 'AI confidence score from 0.0 to 1.0';

--
-- Name: COLUMN tuning_proposals.safety_validation; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tuning_proposals.safety_validation IS 'JSON object containing safety validation results';

--
-- Name: tuning_test_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tuning_test_results (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proposal_id uuid NOT NULL,
    tested_at timestamp with time zone DEFAULT now() NOT NULL,
    original_alert_count bigint NOT NULL,
    tuned_alert_count bigint NOT NULL,
    reduction_percentage double precision NOT NULL,
    true_positives_preserved boolean NOT NULL,
    validation_passed boolean NOT NULL,
    comparison_metrics jsonb DEFAULT '{}'::jsonb NOT NULL
);

--
-- Name: TABLE tuning_test_results; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.tuning_test_results IS 'Validation test results for tuning proposals';

--
-- Name: COLUMN tuning_test_results.reduction_percentage; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tuning_test_results.reduction_percentage IS 'Percentage reduction in alert volume (positive = reduction, negative = increase)';

--
-- Name: upload_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.upload_history (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    filename character varying(255) NOT NULL,
    file_size bigint NOT NULL,
    file_format character varying(50) NOT NULL,
    destination_type character varying(50) NOT NULL,
    destination_name character varying(255) NOT NULL,
    records_total bigint DEFAULT 0,
    records_success bigint DEFAULT 0,
    records_failed bigint DEFAULT 0,
    status character varying(50) DEFAULT 'processing'::character varying NOT NULL,
    error_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone
);

--
-- Name: user_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_groups (
    user_id uuid NOT NULL,
    group_id uuid NOT NULL
);

--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    password_hash character varying(255),
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    failed_login_attempts integer DEFAULT 0 NOT NULL,
    locked_until timestamp with time zone,
    password_reset_token character varying(255),
    password_reset_expires timestamp with time zone,
    oidc_provider_id uuid,
    oidc_subject character varying(255),
    last_login_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    search_history_enabled boolean DEFAULT true NOT NULL
);

--
-- Name: detection_rule_metrics id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_rule_metrics ALTER COLUMN id SET DEFAULT nextval('public.detection_rule_metrics_id_seq'::regclass);

--
-- Name: detection_rule_versions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_rule_versions ALTER COLUMN id SET DEFAULT nextval('public.detection_rule_versions_id_seq'::regclass);

--
-- Name: entity_risk_scores id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.entity_risk_scores ALTER COLUMN id SET DEFAULT nextval('public.entity_risk_scores_id_seq'::regclass);

--
-- Name: ingestion_errors id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ingestion_errors ALTER COLUMN id SET DEFAULT nextval('public.ingestion_errors_id_seq'::regclass);

--
-- Name: ip_enrichments id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ip_enrichments ALTER COLUMN id SET DEFAULT nextval('public.ip_enrichments_id_seq'::regclass);

--
-- Name: ip_enrichments_staging id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ip_enrichments_staging ALTER COLUMN id SET DEFAULT nextval('public.ip_enrichments_staging_id_seq'::regclass);

--
-- Name: logs id; Type: DEFAULT; Schema: public; Owner: -
--

--
-- Name: query_library id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.query_library ALTER COLUMN id SET DEFAULT nextval('public.query_library_id_seq'::regclass);

--
-- Name: test_bm25 id - REMOVED (bm25 extension not available)
--

--
-- Name: alerts alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_pkey PRIMARY KEY (id);

--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);

--
-- Name: audit_logs audit_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);

--
-- Name: dashboards dashboards_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dashboards
    ADD CONSTRAINT dashboards_pkey PRIMARY KEY (id);

--
-- Name: detection_daily_stats detection_daily_stats_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_daily_stats
    ADD CONSTRAINT detection_daily_stats_pkey PRIMARY KEY (id);

--
-- Name: detection_daily_stats detection_daily_stats_rule_id_date_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_daily_stats
    ADD CONSTRAINT detection_daily_stats_rule_id_date_key UNIQUE (rule_id, date);

--
-- Name: detection_matched_events detection_matched_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_matched_events
    ADD CONSTRAINT detection_matched_events_pkey PRIMARY KEY (rule_id, event_id);

--
-- Name: detection_matches detection_matches_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_matches
    ADD CONSTRAINT detection_matches_pkey PRIMARY KEY (id);

--
-- Name: detection_matches detection_matches_rule_event_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_matches
    ADD CONSTRAINT detection_matches_rule_event_unique UNIQUE (rule_id, event_hash);

--
-- Name: CONSTRAINT detection_matches_rule_event_unique ON detection_matches; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON CONSTRAINT detection_matches_rule_event_unique ON public.detection_matches IS 'Prevents storing duplicate matches for the same rule and events';

--
-- Name: detection_rule_baselines detection_rule_baselines_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_rule_baselines
    ADD CONSTRAINT detection_rule_baselines_pkey PRIMARY KEY (rule_id);

--
-- Name: detection_rule_metrics detection_rule_metrics_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_rule_metrics
    ADD CONSTRAINT detection_rule_metrics_pkey PRIMARY KEY (id);

--
-- Name: detection_rule_versions detection_rule_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_rule_versions
    ADD CONSTRAINT detection_rule_versions_pkey PRIMARY KEY (id);

--
-- Name: detection_rule_versions detection_rule_versions_rule_id_version_number_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_rule_versions
    ADD CONSTRAINT detection_rule_versions_rule_id_version_number_key UNIQUE (rule_id, version_number);

--
-- Name: detection_rules detection_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_rules
    ADD CONSTRAINT detection_rules_pkey PRIMARY KEY (id);

--
-- Name: detection_threshold_breaches detection_threshold_breaches_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_threshold_breaches
    ADD CONSTRAINT detection_threshold_breaches_pkey PRIMARY KEY (id);

--
-- Name: enrichment_sources enrichment_sources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrichment_sources
    ADD CONSTRAINT enrichment_sources_pkey PRIMARY KEY (id);

--
-- Name: entity_risk_scores entity_risk_scores_entity_entity_type_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.entity_risk_scores
    ADD CONSTRAINT entity_risk_scores_entity_entity_type_key UNIQUE (entity, entity_type);

--
-- Name: entity_risk_scores entity_risk_scores_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.entity_risk_scores
    ADD CONSTRAINT entity_risk_scores_pkey PRIMARY KEY (id);

--
-- Name: feeds feeds_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feeds
    ADD CONSTRAINT feeds_name_key UNIQUE (name);

--
-- Name: feeds feeds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feeds
    ADD CONSTRAINT feeds_pkey PRIMARY KEY (id);

--
-- Name: group_roles group_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_roles
    ADD CONSTRAINT group_roles_pkey PRIMARY KEY (group_id, role_id);

--
-- Name: groups groups_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_name_key UNIQUE (name);

--
-- Name: groups groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);

--
-- Name: ip_enrichments ip_enrichments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ip_enrichments
    ADD CONSTRAINT ip_enrichments_pkey PRIMARY KEY (id);

--
-- Name: ip_enrichments ip_enrichments_source_id_network_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ip_enrichments
    ADD CONSTRAINT ip_enrichments_source_id_network_key UNIQUE (source_id, network);

--
-- Name: ip_enrichments_staging ip_enrichments_staging_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ip_enrichments_staging
    ADD CONSTRAINT ip_enrichments_staging_pkey PRIMARY KEY (id);

--
-- Name: lookup_tables_registry lookup_tables_registry_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lookup_tables_registry
    ADD CONSTRAINT lookup_tables_registry_name_key UNIQUE (name);

--
-- Name: lookup_tables_registry lookup_tables_registry_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lookup_tables_registry
    ADD CONSTRAINT lookup_tables_registry_pkey PRIMARY KEY (id);

--
-- Name: lookup_tables_registry lookup_tables_registry_table_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lookup_tables_registry
    ADD CONSTRAINT lookup_tables_registry_table_name_key UNIQUE (table_name);

--
-- Name: melod_settings melod_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.melod_settings
    ADD CONSTRAINT melod_settings_pkey PRIMARY KEY (id);

--
-- Name: oidc_group_mappings oidc_group_mappings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_group_mappings
    ADD CONSTRAINT oidc_group_mappings_pkey PRIMARY KEY (id);

--
-- Name: oidc_group_mappings oidc_group_mappings_provider_id_oidc_group_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_group_mappings
    ADD CONSTRAINT oidc_group_mappings_provider_id_oidc_group_key UNIQUE (provider_id, oidc_group);

--
-- Name: oidc_providers oidc_providers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_providers
    ADD CONSTRAINT oidc_providers_pkey PRIMARY KEY (id);

--
-- Name: oidc_providers oidc_providers_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_providers
    ADD CONSTRAINT oidc_providers_slug_key UNIQUE (slug);

--
-- Name: parsers parsers_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.parsers
    ADD CONSTRAINT parsers_name_key UNIQUE (name);

--
-- Name: parsers parsers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.parsers
    ADD CONSTRAINT parsers_pkey PRIMARY KEY (id);

--
-- Name: permissions permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_pkey PRIMARY KEY (id);

--
-- Name: prevalence_settings prevalence_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.prevalence_settings
    ADD CONSTRAINT prevalence_settings_pkey PRIMARY KEY (id);

--
-- Name: query_explanations query_explanations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.query_explanations
    ADD CONSTRAINT query_explanations_pkey PRIMARY KEY (query_hash);

--
-- Name: query_library query_library_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.query_library
    ADD CONSTRAINT query_library_name_key UNIQUE (name);

--
-- Name: query_library query_library_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.query_library
    ADD CONSTRAINT query_library_pkey PRIMARY KEY (id);

--
-- Name: role_permissions role_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_pkey PRIMARY KEY (role_id, permission_id);

--
-- Name: roles roles_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_name_key UNIQUE (name);

--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);

--
-- Name: saved_searches saved_searches_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.saved_searches
    ADD CONSTRAINT saved_searches_pkey PRIMARY KEY (id);

--
-- Name: scheduled_jobs scheduled_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scheduled_jobs
    ADD CONSTRAINT scheduled_jobs_pkey PRIMARY KEY (id);

--
-- Name: search_history search_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.search_history
    ADD CONSTRAINT search_history_pkey PRIMARY KEY (id);

--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);

--
-- Name: shared_searches shared_searches_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shared_searches
    ADD CONSTRAINT shared_searches_pkey PRIMARY KEY (id);

--
-- Name: system_config system_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_config
    ADD CONSTRAINT system_config_pkey PRIMARY KEY (key);

--
-- Name: system_settings system_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_settings
    ADD CONSTRAINT system_settings_pkey PRIMARY KEY (id);

--
-- Name: tuning_logs tuning_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tuning_logs
    ADD CONSTRAINT tuning_logs_pkey PRIMARY KEY (id);

--
-- Name: tuning_notifications tuning_notifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tuning_notifications
    ADD CONSTRAINT tuning_notifications_pkey PRIMARY KEY (id);

--
-- Name: tuning_proposals tuning_proposals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tuning_proposals
    ADD CONSTRAINT tuning_proposals_pkey PRIMARY KEY (id);

--
-- Name: tuning_test_results tuning_test_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tuning_test_results
    ADD CONSTRAINT tuning_test_results_pkey PRIMARY KEY (id);

--
-- Name: upload_history upload_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.upload_history
    ADD CONSTRAINT upload_history_pkey PRIMARY KEY (id);

--
-- Name: user_groups user_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT user_groups_pkey PRIMARY KEY (user_id, group_id);

--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);

--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

--
-- Name: idx_alerts_assigned_to; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_assigned_to ON public.alerts USING btree (assigned_to);

--
-- Name: idx_alerts_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_created_at ON public.alerts USING btree (created_at DESC);

--
-- Name: idx_alerts_open_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_open_priority ON public.alerts USING btree (severity, created_at DESC) WHERE (status = ANY (ARRAY['new'::text, 'acknowledged'::text]));

--
-- Name: idx_alerts_rule_event_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_rule_event_hash ON public.alerts USING btree (rule_id, event_hash) WHERE (event_hash IS NOT NULL);

--
-- Name: idx_alerts_rule_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_rule_id ON public.alerts USING btree (rule_id);

--
-- Name: idx_alerts_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_severity ON public.alerts USING btree (severity);

--
-- Name: idx_alerts_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_status ON public.alerts USING btree (status);

--
-- Name: idx_api_keys_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_hash ON public.api_keys USING btree (key_hash);

--
-- Name: idx_api_keys_prefix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_prefix ON public.api_keys USING btree (key_prefix);

--
-- Name: idx_audit_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_action ON public.audit_logs USING btree (action, "timestamp" DESC);

--
-- Name: idx_audit_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_timestamp ON public.audit_logs USING btree ("timestamp" DESC);

--
-- Name: idx_audit_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_user ON public.audit_logs USING btree (user_id, "timestamp" DESC);

--
-- Name: idx_baselines_last_updated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_baselines_last_updated ON public.detection_rule_baselines USING btree (last_updated DESC);

--
-- Name: idx_breaches_detected; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_breaches_detected ON public.detection_threshold_breaches USING btree (detected_at DESC);

--
-- Name: idx_breaches_rule; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_breaches_rule ON public.detection_threshold_breaches USING btree (rule_id, detected_at DESC);

--
-- Name: idx_breaches_triggered; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_breaches_triggered ON public.detection_threshold_breaches USING btree (tuning_triggered, detected_at DESC);

--
-- Name: idx_dashboards_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dashboards_created_at ON public.dashboards USING btree (created_at DESC);

--
-- Name: idx_dashboards_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dashboards_name ON public.dashboards USING btree (name);

--
-- Name: idx_detection_daily_stats_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_daily_stats_date ON public.detection_daily_stats USING btree (date DESC);

--
-- Name: idx_detection_daily_stats_rule_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_daily_stats_rule_date ON public.detection_daily_stats USING btree (rule_id, date DESC);

--
-- Name: idx_detection_matched_events_event_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_matched_events_event_time ON public.detection_matched_events USING btree (rule_id, event_timestamp DESC);

--
-- Name: idx_detection_matched_events_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_matched_events_timestamp ON public.detection_matched_events USING btree (matched_at);

--
-- Name: idx_detection_matches_detected_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_matches_detected_at ON public.detection_matches USING btree (detected_at DESC);

--
-- Name: idx_detection_matches_event_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_matches_event_hash ON public.detection_matches USING btree (event_hash);

--
-- Name: idx_detection_matches_rule_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_matches_rule_id ON public.detection_matches USING btree (rule_id, detected_at DESC);

--
-- Name: idx_detection_matches_rule_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_matches_rule_time ON public.detection_matches USING btree (rule_id, detected_at DESC);

--
-- Name: idx_detection_rules_ai_generated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_ai_generated ON public.detection_rules USING btree (ai_generated);

--
-- Name: idx_detection_rules_archived; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_archived ON public.detection_rules USING btree (archived);

--
-- Name: idx_detection_rules_author; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_author ON public.detection_rules USING btree (author);

--
-- Name: idx_detection_rules_auto_apply; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_auto_apply ON public.detection_rules USING btree (auto_apply_enabled) WHERE (auto_apply_enabled = true);

--
-- Name: idx_detection_rules_auto_tuning; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_auto_tuning ON public.detection_rules USING btree (auto_tuning_enabled) WHERE (auto_tuning_enabled = true);

--
-- Name: idx_detection_rules_detection_mode; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_detection_mode ON public.detection_rules USING btree (detection_mode);

--
-- Name: idx_detection_rules_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_enabled ON public.detection_rules USING btree (enabled);

--
-- Name: idx_detection_rules_enabled_mode; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_enabled_mode ON public.detection_rules USING btree (enabled, mode);

--
-- Name: idx_detection_rules_last_match_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_last_match_at ON public.detection_rules USING btree (last_match_at DESC NULLS LAST);

--
-- Name: idx_detection_rules_mitre_tactics; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_mitre_tactics ON public.detection_rules USING gin (mitre_tactics);

--
-- Name: idx_detection_rules_mitre_techniques; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_mitre_techniques ON public.detection_rules USING gin (mitre_techniques);

--
-- Name: idx_detection_rules_mode; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_mode ON public.detection_rules USING btree (mode);

--
-- Name: idx_detection_rules_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_name ON public.detection_rules USING btree (name);

--
-- Name: idx_detection_rules_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_severity ON public.detection_rules USING btree (severity);

--
-- Name: idx_detection_rules_tags; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_tags ON public.detection_rules USING gin (tags);

--
-- Name: idx_entity_risk_scores_entity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_entity_risk_scores_entity ON public.entity_risk_scores USING btree (entity);

--
-- Name: idx_entity_risk_scores_score; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_entity_risk_scores_score ON public.entity_risk_scores USING btree (risk_score DESC);

--
-- Name: idx_entity_risk_scores_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_entity_risk_scores_type ON public.entity_risk_scores USING btree (entity_type);

--
-- Name: idx_entity_risk_scores_updated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_entity_risk_scores_updated ON public.entity_risk_scores USING btree (updated_at DESC);

--
-- Name: idx_feeds_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_feeds_enabled ON public.feeds USING btree (enabled);

--
-- Name: idx_feeds_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_feeds_name ON public.feeds USING btree (name);

--
-- Name: idx_ingestion_errors_source_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ingestion_errors_source_type ON public.ingestion_errors USING btree (source_type, "timestamp" DESC);

--
-- Name: idx_ingestion_errors_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ingestion_errors_timestamp ON public.ingestion_errors USING btree ("timestamp" DESC);

--
-- Name: idx_ingestion_errors_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ingestion_errors_type ON public.ingestion_errors USING btree (error_type, "timestamp" DESC);

--
-- Name: idx_ip_enrichments_asn; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ip_enrichments_asn ON public.ip_enrichments USING btree (asn);

--
-- Name: idx_ip_enrichments_country; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ip_enrichments_country ON public.ip_enrichments USING btree (country_code);

--
-- Name: idx_ip_enrichments_network; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ip_enrichments_network ON public.ip_enrichments USING gist (network inet_ops);

--
-- Name: idx_ip_enrichments_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ip_enrichments_source ON public.ip_enrichments USING btree (source_id);

--
-- Name: idx_ip_enrichments_staging_network; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ip_enrichments_staging_network ON public.ip_enrichments_staging USING gist (network inet_ops);

--
-- Name: idx_ip_enrichments_staging_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ip_enrichments_staging_source ON public.ip_enrichments_staging USING btree (source_id);

--
-- Name: idx_logs_action; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_dest_host; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_dest_ip; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_enriched_dest_asn; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_enriched_dest_country_asn; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_enriched_dest_country_code; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_enriched_src_asn; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_enriched_src_country_asn; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_enriched_src_country_code; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_file_path; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_ingest_time; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_metadata; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_process_name; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_raw_content_bm25; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_raw_content_fts; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_raw_content_search_trgm; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_signals_alert_id; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_signals_risk_entity; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_signals_risk_score; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_signals_rule_id; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_signals_rule_name; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_signals_severity; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_signals_source_type; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_signals_type; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_source_type; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_sourcetype; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_src_dest_ip; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_src_host; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_src_ip; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_status; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_timestamp; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_user; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_user_action; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_logs_user_agent; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: idx_lookup_assets_ip; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_lookup_assets_ip ON public.lookup_assets USING btree (ip);

--
-- Name: idx_lookup_tables_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_lookup_tables_created ON public.lookup_tables_registry USING btree (created_at DESC);

--
-- Name: idx_lookup_tables_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_lookup_tables_name ON public.lookup_tables_registry USING btree (name);

--
-- Name: idx_melod_settings_singleton; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_melod_settings_singleton ON public.melod_settings USING btree (((id = 'default'::text)));

--
-- Name: idx_metrics_rule_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_metrics_rule_time ON public.detection_rule_metrics USING btree (rule_id, "timestamp" DESC);

--
-- Name: idx_metrics_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_metrics_timestamp ON public.detection_rule_metrics USING btree ("timestamp" DESC);

--
-- Name: idx_notifications_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notifications_type ON public.tuning_notifications USING btree (notification_type, created_at DESC);

--
-- Name: idx_notifications_unread; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notifications_unread ON public.tuning_notifications USING btree (user_id, read_at) WHERE (read_at IS NULL);

--
-- Name: idx_notifications_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notifications_user ON public.tuning_notifications USING btree (user_id, created_at DESC);

--
-- Name: idx_parsers_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_parsers_enabled ON public.parsers USING btree (enabled);

--
-- Name: idx_parsers_feed_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_parsers_feed_id ON public.parsers USING btree (feed_id);

--
-- Name: idx_parsers_source_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_parsers_source_type ON public.parsers USING btree (source_type);

--
-- Name: idx_prevalence_settings_singleton; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_prevalence_settings_singleton ON public.prevalence_settings USING btree (((id = 'default'::text)));

--
-- Name: idx_proposals_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proposals_created ON public.tuning_proposals USING btree (created_at DESC);

--
-- Name: idx_proposals_rule; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proposals_rule ON public.tuning_proposals USING btree (rule_id, created_at DESC);

--
-- Name: idx_proposals_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proposals_status ON public.tuning_proposals USING btree (status, created_at DESC);

--
-- Name: idx_query_explanations_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_query_explanations_created_at ON public.query_explanations USING btree (created_at);

--
-- Name: idx_query_explanations_last_accessed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_query_explanations_last_accessed ON public.query_explanations USING btree (last_accessed_at);

--
-- Name: idx_query_library_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_query_library_category ON public.query_library USING btree (category);

--
-- Name: idx_query_library_tags; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_query_library_tags ON public.query_library USING gin (tags);

--
-- Name: idx_rule_versions_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rule_versions_active ON public.detection_rule_versions USING btree (rule_id, is_active) WHERE (is_active = true);

--
-- Name: idx_rule_versions_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rule_versions_created ON public.detection_rule_versions USING btree (created_at DESC);

--
-- Name: idx_rule_versions_rule; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rule_versions_rule ON public.detection_rule_versions USING btree (rule_id, version_number DESC);

--
-- Name: idx_saved_searches_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_saved_searches_created_at ON public.saved_searches USING btree (created_at DESC);

--
-- Name: idx_saved_searches_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_saved_searches_name ON public.saved_searches USING btree (name);

--
-- Name: idx_scheduled_jobs_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scheduled_jobs_created ON public.scheduled_jobs USING btree (created_at DESC);

--
-- Name: idx_scheduled_jobs_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scheduled_jobs_enabled ON public.scheduled_jobs USING btree (enabled);

--
-- Name: idx_scheduled_jobs_next_run; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scheduled_jobs_next_run ON public.scheduled_jobs USING btree (next_run_at) WHERE (enabled = true);

--
-- Name: idx_scheduled_jobs_poll; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scheduled_jobs_poll ON public.scheduled_jobs USING btree (enabled, next_run_at) WHERE (enabled = true);

--
-- Name: idx_search_history_user_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_search_history_user_created ON public.search_history USING btree (user_id, created_at DESC);

--
-- Name: idx_sessions_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sessions_expires ON public.sessions USING btree (expires_at);

--
-- Name: idx_sessions_token; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sessions_token ON public.sessions USING btree (refresh_token_hash);

--
-- Name: idx_sessions_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sessions_user ON public.sessions USING btree (user_id);

--
-- Name: idx_shared_searches_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_shared_searches_created_at ON public.shared_searches USING btree (created_at DESC);

--
-- Name: idx_system_settings_singleton; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_system_settings_singleton ON public.system_settings USING btree (((id = 'default'::text)));

--
-- Name: idx_test_results_proposal; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_test_results_proposal ON public.tuning_test_results USING btree (proposal_id);

--
-- Name: idx_test_results_tested; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_test_results_tested ON public.tuning_test_results USING btree (tested_at DESC);

--
-- Name: idx_tuning_logs_rule; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tuning_logs_rule ON public.tuning_logs USING btree (rule_id, triggered_at DESC);

--
-- Name: idx_tuning_logs_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tuning_logs_status ON public.tuning_logs USING btree (status, triggered_at DESC);

--
-- Name: idx_tuning_logs_triggered; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tuning_logs_triggered ON public.tuning_logs USING btree (triggered_at DESC);

--
-- Name: idx_upload_history_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_upload_history_created ON public.upload_history USING btree (created_at DESC);

--
-- Name: idx_upload_history_dest_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_upload_history_dest_created ON public.upload_history USING btree (destination_type, created_at DESC);

--
-- Name: idx_upload_history_destination; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_upload_history_destination ON public.upload_history USING btree (destination_type, destination_name);

--
-- Name: idx_upload_history_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_upload_history_status ON public.upload_history USING btree (status);

--
-- Name: idx_upload_history_status_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_upload_history_status_created ON public.upload_history USING btree (status, created_at DESC);

--
-- Name: idx_users_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_email ON public.users USING btree (email);

--
-- Name: idx_users_oidc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_oidc ON public.users USING btree (oidc_provider_id, oidc_subject);

--
-- Name: idx_users_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_status ON public.users USING btree (status);

--
-- Name: ingestion_errors_timestamp_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ingestion_errors_timestamp_idx ON public.ingestion_errors USING btree ("timestamp" DESC);

--
-- Name: logs_timestamp_idx; Type: INDEX; Schema: public; Owner: -
--

--
-- Name: test_bm25_idx - REMOVED (bm25 extension not available)
--

--
-- Name: feeds feeds_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER feeds_updated_at BEFORE UPDATE ON public.feeds FOR EACH ROW EXECUTE FUNCTION public.update_feeds_updated_at();

--
-- Name: lookup_tables_registry lookup_tables_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER lookup_tables_updated_at BEFORE UPDATE ON public.lookup_tables_registry FOR EACH ROW EXECUTE FUNCTION public.update_lookup_tables_updated_at();

--
-- Name: melod_settings melod_settings_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER melod_settings_updated_at BEFORE UPDATE ON public.melod_settings FOR EACH ROW EXECUTE FUNCTION public.update_melod_settings_updated_at();

--
-- Name: parsers parsers_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER parsers_updated_at BEFORE UPDATE ON public.parsers FOR EACH ROW EXECUTE FUNCTION public.update_parsers_updated_at();

--
-- Name: prevalence_settings prevalence_settings_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER prevalence_settings_updated_at BEFORE UPDATE ON public.prevalence_settings FOR EACH ROW EXECUTE FUNCTION public.update_prevalence_settings_updated_at();

--
-- Name: scheduled_jobs scheduled_jobs_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER scheduled_jobs_updated_at BEFORE UPDATE ON public.scheduled_jobs FOR EACH ROW EXECUTE FUNCTION public.update_scheduled_jobs_updated_at();

--
-- Name: system_settings system_settings_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER system_settings_updated_at BEFORE UPDATE ON public.system_settings FOR EACH ROW EXECUTE FUNCTION public.update_system_settings_updated_at();

--
-- Name: search_history trg_limit_search_history; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_limit_search_history AFTER INSERT ON public.search_history FOR EACH ROW EXECUTE FUNCTION public.limit_search_history();

--
-- Name: users trigger_add_user_to_everyone; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_add_user_to_everyone AFTER INSERT ON public.users FOR EACH ROW EXECUTE FUNCTION public.add_user_to_everyone_group();

--
-- Name: groups trigger_groups_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_groups_updated_at BEFORE UPDATE ON public.groups FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

--
-- Name: oidc_providers trigger_oidc_providers_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_oidc_providers_updated_at BEFORE UPDATE ON public.oidc_providers FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

--
-- Name: query_explanations trigger_query_explanations_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_query_explanations_updated_at BEFORE UPDATE ON public.query_explanations FOR EACH ROW EXECUTE FUNCTION public.update_query_explanations_updated_at();

--
-- Name: roles trigger_roles_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_roles_updated_at BEFORE UPDATE ON public.roles FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

--
-- Name: users trigger_users_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_users_updated_at BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

--
-- Name: dashboards update_dashboards_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_dashboards_updated_at BEFORE UPDATE ON public.dashboards FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

--
-- Name: detection_rules update_detection_rules_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_detection_rules_updated_at BEFORE UPDATE ON public.detection_rules FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

--
-- Name: alerts alerts_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES public.detection_rules(id) ON DELETE SET NULL;

--
-- Name: api_keys api_keys_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;

--
-- Name: audit_logs audit_logs_api_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_api_key_id_fkey FOREIGN KEY (api_key_id) REFERENCES public.api_keys(id) ON DELETE SET NULL;

--
-- Name: audit_logs audit_logs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;

--
-- Name: detection_daily_stats detection_daily_stats_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_daily_stats
    ADD CONSTRAINT detection_daily_stats_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES public.detection_rules(id) ON DELETE CASCADE;

--
-- Name: detection_matched_events detection_matched_events_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_matched_events
    ADD CONSTRAINT detection_matched_events_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES public.detection_rules(id) ON DELETE CASCADE;

--
-- Name: detection_matches detection_matches_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_matches
    ADD CONSTRAINT detection_matches_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES public.detection_rules(id) ON DELETE CASCADE;

--
-- Name: detection_rule_baselines detection_rule_baselines_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_rule_baselines
    ADD CONSTRAINT detection_rule_baselines_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES public.detection_rules(id) ON DELETE CASCADE;

--
-- Name: detection_rule_metrics detection_rule_metrics_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_rule_metrics
    ADD CONSTRAINT detection_rule_metrics_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES public.detection_rules(id) ON DELETE CASCADE;

--
-- Name: detection_rule_versions detection_rule_versions_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_rule_versions
    ADD CONSTRAINT detection_rule_versions_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);

--
-- Name: detection_rule_versions detection_rule_versions_reverted_from_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_rule_versions
    ADD CONSTRAINT detection_rule_versions_reverted_from_version_fkey FOREIGN KEY (reverted_from_version) REFERENCES public.detection_rule_versions(id);

--
-- Name: detection_rule_versions detection_rule_versions_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_rule_versions
    ADD CONSTRAINT detection_rule_versions_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES public.detection_rules(id) ON DELETE CASCADE;

--
-- Name: detection_threshold_breaches detection_threshold_breaches_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_threshold_breaches
    ADD CONSTRAINT detection_threshold_breaches_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES public.detection_rules(id) ON DELETE CASCADE;

--
-- Name: detection_threshold_breaches fk_breach_proposal; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_threshold_breaches
    ADD CONSTRAINT fk_breach_proposal FOREIGN KEY (tuning_proposal_id) REFERENCES public.tuning_proposals(id);

--
-- Name: group_roles group_roles_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_roles
    ADD CONSTRAINT group_roles_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;

--
-- Name: group_roles group_roles_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_roles
    ADD CONSTRAINT group_roles_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;

--
-- Name: ip_enrichments ip_enrichments_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ip_enrichments
    ADD CONSTRAINT ip_enrichments_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.enrichment_sources(id) ON DELETE CASCADE;

--
-- Name: oidc_group_mappings oidc_group_mappings_local_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_group_mappings
    ADD CONSTRAINT oidc_group_mappings_local_group_id_fkey FOREIGN KEY (local_group_id) REFERENCES public.groups(id) ON DELETE CASCADE;

--
-- Name: oidc_group_mappings oidc_group_mappings_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_group_mappings
    ADD CONSTRAINT oidc_group_mappings_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.oidc_providers(id) ON DELETE CASCADE;

--
-- Name: parsers parsers_feed_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.parsers
    ADD CONSTRAINT parsers_feed_id_fkey FOREIGN KEY (feed_id) REFERENCES public.feeds(id) ON DELETE SET NULL;

--
-- Name: role_permissions role_permissions_permission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_permission_id_fkey FOREIGN KEY (permission_id) REFERENCES public.permissions(id) ON DELETE CASCADE;

--
-- Name: role_permissions role_permissions_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;

--
-- Name: search_history search_history_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.search_history
    ADD CONSTRAINT search_history_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- Name: sessions sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- Name: tuning_logs tuning_logs_applied_version_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tuning_logs
    ADD CONSTRAINT tuning_logs_applied_version_id_fkey FOREIGN KEY (applied_version_id) REFERENCES public.detection_rule_versions(id);

--
-- Name: tuning_logs tuning_logs_proposal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tuning_logs
    ADD CONSTRAINT tuning_logs_proposal_id_fkey FOREIGN KEY (proposal_id) REFERENCES public.tuning_proposals(id);

--
-- Name: tuning_logs tuning_logs_reverted_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tuning_logs
    ADD CONSTRAINT tuning_logs_reverted_by_fkey FOREIGN KEY (reverted_by) REFERENCES public.users(id);

--
-- Name: tuning_logs tuning_logs_reverted_to_version_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tuning_logs
    ADD CONSTRAINT tuning_logs_reverted_to_version_id_fkey FOREIGN KEY (reverted_to_version_id) REFERENCES public.detection_rule_versions(id);

--
-- Name: tuning_logs tuning_logs_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tuning_logs
    ADD CONSTRAINT tuning_logs_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES public.detection_rules(id) ON DELETE CASCADE;

--
-- Name: tuning_logs tuning_logs_test_results_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tuning_logs
    ADD CONSTRAINT tuning_logs_test_results_id_fkey FOREIGN KEY (test_results_id) REFERENCES public.tuning_test_results(id);

--
-- Name: tuning_notifications tuning_notifications_tuning_log_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tuning_notifications
    ADD CONSTRAINT tuning_notifications_tuning_log_id_fkey FOREIGN KEY (tuning_log_id) REFERENCES public.tuning_logs(id);

--
-- Name: tuning_notifications tuning_notifications_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tuning_notifications
    ADD CONSTRAINT tuning_notifications_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- Name: tuning_proposals tuning_proposals_breach_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tuning_proposals
    ADD CONSTRAINT tuning_proposals_breach_id_fkey FOREIGN KEY (breach_id) REFERENCES public.detection_threshold_breaches(id);

--
-- Name: tuning_proposals tuning_proposals_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tuning_proposals
    ADD CONSTRAINT tuning_proposals_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES public.detection_rules(id) ON DELETE CASCADE;

--
-- Name: tuning_test_results tuning_test_results_proposal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tuning_test_results
    ADD CONSTRAINT tuning_test_results_proposal_id_fkey FOREIGN KEY (proposal_id) REFERENCES public.tuning_proposals(id) ON DELETE CASCADE;

--
-- Name: user_groups user_groups_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT user_groups_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;

--
-- Name: user_groups user_groups_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT user_groups_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- Name: users users_oidc_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_oidc_provider_id_fkey FOREIGN KEY (oidc_provider_id) REFERENCES public.oidc_providers(id) ON DELETE SET NULL;

--
-- PostgreSQL database dump complete
--

-- =============================================================================
-- SEED DATA
-- =============================================================================

-- Reset search_path to public for seed data (pg_dump sets it to empty)
SET search_path = public;

-- ============================================================================
-- SEED PERMISSIONS
-- ============================================================================
INSERT INTO permissions (id, name, description, category) VALUES
    -- Search permissions
    ('search:view', 'View Search', 'Access the search interface', 'search'),
    ('search:execute', 'Execute Search', 'Run search queries', 'search'),
    ('search:save', 'Save Search', 'Save search queries', 'search'),
    ('search:share', 'Share Search', 'Share search queries with others', 'search'),
    
    -- Dashboard permissions
    ('dashboards:view', 'View Dashboards', 'View dashboards', 'dashboards'),
    ('dashboards:create', 'Create Dashboards', 'Create new dashboards', 'dashboards'),
    ('dashboards:edit', 'Edit Dashboards', 'Modify existing dashboards', 'dashboards'),
    ('dashboards:delete', 'Delete Dashboards', 'Delete dashboards', 'dashboards'),
    
    -- Detection permissions
    ('detections:view', 'View Detections', 'View detection rules', 'detections'),
    ('detections:create', 'Create Detections', 'Create new detection rules', 'detections'),
    ('detections:edit', 'Edit Detections', 'Modify detection rules', 'detections'),
    ('detections:delete', 'Delete Detections', 'Delete detection rules', 'detections'),
    ('detections:enable', 'Enable/Disable Detections', 'Enable or disable detection rules', 'detections'),
    ('detections:promote', 'Promote/Demote Detections', 'Change detection rule mode', 'detections'),
    
    -- Alert permissions
    ('alerts:view', 'View Alerts', 'View alerts', 'alerts'),
    ('alerts:acknowledge', 'Acknowledge Alerts', 'Acknowledge alerts', 'alerts'),
    ('alerts:close', 'Close Alerts', 'Close alerts', 'alerts'),
    ('alerts:assign', 'Assign Alerts', 'Assign alerts to users', 'alerts'),
    
    -- Parser permissions
    ('parsers:view', 'View Parsers', 'View parser configurations', 'parsers'),
    ('parsers:create', 'Create Parsers', 'Create new parsers', 'parsers'),
    ('parsers:edit', 'Edit Parsers', 'Modify parser configurations', 'parsers'),
    ('parsers:delete', 'Delete Parsers', 'Delete parsers', 'parsers'),
    ('parsers:deploy', 'Deploy Parsers', 'Deploy parsers to Vector', 'parsers'),
    
    -- Feed permissions
    ('feeds:view', 'View Feeds', 'View data feeds', 'feeds'),
    ('feeds:create', 'Create Feeds', 'Create new feeds', 'feeds'),
    ('feeds:edit', 'Edit Feeds', 'Modify feed configurations', 'feeds'),
    ('feeds:delete', 'Delete Feeds', 'Delete feeds', 'feeds'),
    
    -- Enrichment permissions
    ('enrichments:view', 'View Enrichments', 'View enrichment sources', 'enrichments'),
    ('enrichments:configure', 'Configure Enrichments', 'Configure enrichment sources', 'enrichments'),
    
    -- Lookup table permissions
    ('lookup:view', 'View Lookup Tables', 'View lookup tables', 'lookup'),
    ('lookup:create', 'Create Lookup Tables', 'Create lookup tables', 'lookup'),
    ('lookup:edit', 'Edit Lookup Tables', 'Modify lookup tables', 'lookup'),
    ('lookup:delete', 'Delete Lookup Tables', 'Delete lookup tables', 'lookup'),
    
    -- Risk analytics permissions
    ('risk:view', 'View Risk Analytics', 'View risk scores and analytics', 'risk'),
    ('risk:configure', 'Configure Risk', 'Configure risk scoring settings', 'risk'),
    ('risk:clear', 'Clear Risk Scores', 'Clear entity risk scores', 'risk'),
    
    -- Prevalence permissions
    ('prevalence:view', 'View Prevalence', 'View prevalence tracking data', 'prevalence'),
    ('prevalence:configure', 'Configure Prevalence', 'Configure prevalence tracking settings', 'prevalence'),
    ('prevalence:export', 'Export Prevalence', 'Export prevalence data', 'prevalence'),
    
    -- Settings permissions
    ('settings:view', 'View Settings', 'View system settings', 'settings'),
    ('settings:system', 'System Settings', 'Modify system settings', 'settings'),
    ('settings:retention', 'Retention Settings', 'Modify data retention settings', 'settings'),
    ('settings:ai', 'AI Settings', 'Modify AI/meloD settings', 'settings'),
    ('settings:risk', 'Risk Settings', 'Modify risk scoring settings', 'settings'),
    
    -- User management permissions
    ('users:view', 'View Users', 'View user accounts', 'users'),
    ('users:create', 'Create Users', 'Create user accounts', 'users'),
    ('users:edit', 'Edit Users', 'Modify user accounts', 'users'),
    ('users:delete', 'Delete Users', 'Delete user accounts', 'users'),
    
    -- Group management permissions
    ('groups:view', 'View Groups', 'View groups', 'groups'),
    ('groups:create', 'Create Groups', 'Create groups', 'groups'),
    ('groups:edit', 'Edit Groups', 'Modify groups', 'groups'),
    ('groups:delete', 'Delete Groups', 'Delete groups', 'groups'),
    
    -- Role management permissions
    ('roles:view', 'View Roles', 'View roles', 'roles'),
    ('roles:create', 'Create Roles', 'Create roles', 'roles'),
    ('roles:edit', 'Edit Roles', 'Modify roles', 'roles'),
    ('roles:delete', 'Delete Roles', 'Delete roles', 'roles'),
    
    -- API key permissions
    ('apikeys:view', 'View API Keys', 'View API keys', 'apikeys'),
    ('apikeys:create', 'Create API Keys', 'Create API keys', 'apikeys'),
    ('apikeys:delete', 'Delete API Keys', 'Delete API keys', 'apikeys'),
    
    -- Audit permissions
    ('audit:view', 'View Audit Logs', 'View audit logs', 'audit')
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- SEED BUILT-IN ROLES
-- ============================================================================

-- Admin role (all permissions)
INSERT INTO roles (id, name, description, is_system) VALUES
    ('00000000-0000-0000-0000-000000000001', 'Admin', 'Full system access with all permissions', TRUE)
ON CONFLICT (name) DO NOTHING;

-- Editor role (detection engineers)
INSERT INTO roles (id, name, description, is_system) VALUES
    ('00000000-0000-0000-0000-000000000002', 'Editor', 'Create and manage detections, parsers, and dashboards', TRUE)
ON CONFLICT (name) DO NOTHING;

-- ReadOnly role (analysts)
INSERT INTO roles (id, name, description, is_system) VALUES
    ('00000000-0000-0000-0000-000000000003', 'ReadOnly', 'View-only access for search and monitoring', TRUE)
ON CONFLICT (name) DO NOTHING;

-- ============================================================================
-- CREATE DEFAULT "EVERYONE" GROUP
-- ============================================================================
INSERT INTO groups (id, name, description, is_system) VALUES
    ('00000000-0000-0000-0000-000000000001', 'Everyone', 'Default group that all users belong to', TRUE)
ON CONFLICT (name) DO NOTHING;

-- ============================================================================
-- ASSIGN PERMISSIONS TO ADMIN ROLE (all permissions)
-- ============================================================================
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000001'::uuid, id FROM permissions
ON CONFLICT DO NOTHING;

-- ============================================================================
-- ASSIGN PERMISSIONS TO EDITOR ROLE
-- ============================================================================
INSERT INTO role_permissions (role_id, permission_id) VALUES
    -- Search (all)
    ('00000000-0000-0000-0000-000000000002', 'search:view'),
    ('00000000-0000-0000-0000-000000000002', 'search:execute'),
    ('00000000-0000-0000-0000-000000000002', 'search:save'),
    ('00000000-0000-0000-0000-000000000002', 'search:share'),
    -- Dashboards (all)
    ('00000000-0000-0000-0000-000000000002', 'dashboards:view'),
    ('00000000-0000-0000-0000-000000000002', 'dashboards:create'),
    ('00000000-0000-0000-0000-000000000002', 'dashboards:edit'),
    ('00000000-0000-0000-0000-000000000002', 'dashboards:delete'),
    -- Detections (all)
    ('00000000-0000-0000-0000-000000000002', 'detections:view'),
    ('00000000-0000-0000-0000-000000000002', 'detections:create'),
    ('00000000-0000-0000-0000-000000000002', 'detections:edit'),
    ('00000000-0000-0000-0000-000000000002', 'detections:delete'),
    ('00000000-0000-0000-0000-000000000002', 'detections:enable'),
    ('00000000-0000-0000-0000-000000000002', 'detections:promote'),
    -- Alerts (view, acknowledge, close)
    ('00000000-0000-0000-0000-000000000002', 'alerts:view'),
    ('00000000-0000-0000-0000-000000000002', 'alerts:acknowledge'),
    ('00000000-0000-0000-0000-000000000002', 'alerts:close'),
    -- Parsers (all)
    ('00000000-0000-0000-0000-000000000002', 'parsers:view'),
    ('00000000-0000-0000-0000-000000000002', 'parsers:create'),
    ('00000000-0000-0000-0000-000000000002', 'parsers:edit'),
    ('00000000-0000-0000-0000-000000000002', 'parsers:delete'),
    ('00000000-0000-0000-0000-000000000002', 'parsers:deploy'),
    -- Feeds (all)
    ('00000000-0000-0000-0000-000000000002', 'feeds:view'),
    ('00000000-0000-0000-0000-000000000002', 'feeds:create'),
    ('00000000-0000-0000-0000-000000000002', 'feeds:edit'),
    ('00000000-0000-0000-0000-000000000002', 'feeds:delete'),
    -- Enrichments (view only)
    ('00000000-0000-0000-0000-000000000002', 'enrichments:view'),
    -- Lookup tables (all)
    ('00000000-0000-0000-0000-000000000002', 'lookup:view'),
    ('00000000-0000-0000-0000-000000000002', 'lookup:create'),
    ('00000000-0000-0000-0000-000000000002', 'lookup:edit'),
    ('00000000-0000-0000-0000-000000000002', 'lookup:delete'),
    -- Prevalence (view and export)
    ('00000000-0000-0000-0000-000000000002', 'prevalence:view'),
    ('00000000-0000-0000-0000-000000000002', 'prevalence:export'),
    -- Risk (view only)
    ('00000000-0000-0000-0000-000000000002', 'risk:view'),
    -- Settings (view only)
    ('00000000-0000-0000-0000-000000000002', 'settings:view')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- ASSIGN PERMISSIONS TO READONLY ROLE
-- ============================================================================
INSERT INTO role_permissions (role_id, permission_id) VALUES
    -- Search (view and execute)
    ('00000000-0000-0000-0000-000000000003', 'search:view'),
    ('00000000-0000-0000-0000-000000000003', 'search:execute'),
    -- Dashboards (view only)
    ('00000000-0000-0000-0000-000000000003', 'dashboards:view'),
    -- Detections (view only)
    ('00000000-0000-0000-0000-000000000003', 'detections:view'),
    -- Alerts (view only)
    ('00000000-0000-0000-0000-000000000003', 'alerts:view'),
    -- Parsers (view only)
    ('00000000-0000-0000-0000-000000000003', 'parsers:view'),
    -- Feeds (view only)
    ('00000000-0000-0000-0000-000000000003', 'feeds:view'),
    -- Enrichments (view only)
    ('00000000-0000-0000-0000-000000000003', 'enrichments:view'),
    -- Lookup tables (view only)
    ('00000000-0000-0000-0000-000000000003', 'lookup:view'),
    -- Prevalence (view only)
    ('00000000-0000-0000-0000-000000000003', 'prevalence:view'),
    -- Risk (view only)
    ('00000000-0000-0000-0000-000000000003', 'risk:view')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- ASSIGN EVERYONE GROUP TO READONLY ROLE BY DEFAULT
-- ============================================================================
INSERT INTO group_roles (group_id, role_id) VALUES
    ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000003')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- SEED ENRICHMENT SOURCES
-- ============================================================================
INSERT INTO enrichment_sources (id, name, source_type, description, enabled)
VALUES (
    'ipinfo_lite',
    'IPinfo Lite',
    'ipinfo_lite',
    'Free IP geolocation and ASN data from IPinfo. Provides country, continent, and ASN information for IP addresses.',
    false
) ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- SEED DEFAULT SETTINGS ROWS
-- ============================================================================
INSERT INTO melod_settings (id) VALUES ('default') ON CONFLICT (id) DO NOTHING;
INSERT INTO system_settings (id) VALUES ('default') ON CONFLICT (id) DO NOTHING;
INSERT INTO prevalence_settings (id) VALUES ('default') ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- SEED FEEDS (removed in migration 113)
-- Feeds are no longer seeded by default. Users can sync log sources from a
-- parser repository or create them manually.
-- ============================================================================

-- ============================================================================
-- SEED PARSERS (removed in migration 105)
-- Parsers are no longer seeded by default. Users can sync from a parser
-- repository or create new parsers manually.
-- ============================================================================
