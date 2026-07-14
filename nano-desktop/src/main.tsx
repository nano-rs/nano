import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { getCurrentWindow } from '@tauri-apps/api/window';

import { App } from './App';
import { QuickSearch } from './screens/QuickSearch';
import { Widget } from './screens/Widget';
import { installAutocompleteDataSource } from './lib/autocomplete';
import './styles.css';

// Autocomplete's suggestion engine is the web app's; its network calls are not.
installAutocompleteDataSource();

// One bundle, several windows, told apart by label: the "quick" spotlight
// (declared in tauri.conf.json), any number of `widget-*` panels pinned to the
// desktop (created on demand in lib.rs), and the app itself.
const label = getCurrentWindow().label;
const isWidget = label.startsWith('widget-');

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {label === 'quick' ? <QuickSearch /> : isWidget ? <Widget /> : <App />}
  </StrictMode>
);
