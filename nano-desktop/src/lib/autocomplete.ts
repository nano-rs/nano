import {
  setAutocompleteDataSource,
  type AutocompleteDataSource,
} from '@/lib/query-autocomplete';

import { api } from './ipc';

/**
 * Point the web app's autocomplete engine at our IPC transport.
 *
 * The suggestion logic (which commands are valid where, which fields exist,
 * which eval functions take what) is entirely the web app's — only the three
 * network calls it makes are swapped, because a webview `fetch` to the SIEM
 * would be blocked by CORS.
 */
const desktopDataSource: AutocompleteDataSource = {
  getSourceTypes: (timeRange) => api.sourceTypes(timeRange?.start, timeRange?.end),

  getSchemaFields: () => api.schemaFields(),

  // Fails soft: without descriptions autocomplete still works off the schema
  // endpoint, so a UDM deployment missing this route degrades rather than breaks.
  getLegacyUdmFields: () => api.udmFields().then((response) => response.fields ?? []),
};

export function installAutocompleteDataSource() {
  setAutocompleteDataSource(desktopDataSource);
}
