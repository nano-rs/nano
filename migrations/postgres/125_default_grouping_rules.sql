-- Disable IP and Detection Rule grouping rules by default.
-- Host and User grouping provide the best signal-to-noise for most SOC workflows.
-- IP grouping creates overly broad cases (NAT, proxies), and rule grouping
-- conflates unrelated hosts/users that trigger the same detection.
UPDATE public.case_grouping_rules SET enabled = false WHERE match_type = 'ip' AND name = 'Group by Source IP';
UPDATE public.case_grouping_rules SET enabled = false WHERE match_type = 'rule' AND name = 'Group by Detection Rule';
