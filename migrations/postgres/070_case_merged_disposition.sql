-- Add "merged" disposition for cases that have been merged into another case
-- This is used when multiple cases are combined into a single target case

-- Drop and recreate the check constraint to include 'merged'
ALTER TABLE cases DROP CONSTRAINT IF EXISTS cases_disposition_check;

ALTER TABLE cases ADD CONSTRAINT cases_disposition_check
    CHECK (disposition IS NULL OR disposition = ANY (ARRAY[
        'true_positive'::text,
        'false_positive'::text,
        'benign'::text,
        'inconclusive'::text,
        'merged'::text
    ]));
