// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

/**
 * Upload page - redirects to Lookup Tables
 *
 * Log file uploads have been removed. Logs should be ingested via the Vector pipeline.
 * This redirect preserves any existing bookmarks.
 */
export default function Upload() {
  const navigate = useNavigate();

  useEffect(() => {
    // NAN-998: canonical path is `/rules/lookup-tables`, not `/lookup-tables`.
    navigate('/rules/lookup-tables', { replace: true });
  }, [navigate]);

  return null;
}
