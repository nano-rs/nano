-- NAN-5668: store content-channel file bodies uncompressed out of line.
--
-- ContentStore reads files over 1 MiB in 1 MiB substring() slices so nano-jobs
-- never holds a whole 53 MB bytea row plus its decode copy and grown connection
-- buffers (the MITRE ATT&CK v19.1 bundle OOM-killed nano-jobs on 8 GB hosts).
-- With the default EXTENDED storage the value is pglz-compressed, and every
-- slice makes the backend decompress the value from its start up to the slice
-- end: O(n^2) decompression and up to the whole file in backend memory per
-- slice. EXTERNAL keeps the value out of line but uncompressed, so substring()
-- fetches only the TOAST chunks it needs.
--
-- Metadata only: existing rows keep their current storage until rewritten, and
-- every install rewrites the channel's files. Forward-only and idempotent.

ALTER TABLE content_channel_files ALTER COLUMN content SET STORAGE EXTERNAL;
