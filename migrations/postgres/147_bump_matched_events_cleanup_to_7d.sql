-- Bump detection_matched_events cleanup from 24 hours to 7 days.
-- This aligns with the MAX_LOOKBACK_MINUTES (10080 = 7 days) validation
-- on detection rules, ensuring deduplication covers the full lookback window.
CREATE OR REPLACE FUNCTION public.cleanup_old_matched_events() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM detection_matched_events
    WHERE matched_at < NOW() - INTERVAL '7 days';
END;
$$;
