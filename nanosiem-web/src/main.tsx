// SPDX-License-Identifier: AGPL-3.0-or-later

// Self-hosted Geist fonts (air-gap: no Google Fonts CDN). Family names
// 'Geist' / 'Geist Mono' match --font-sans / --font-mono in index.css.
import '@fontsource/geist/400.css';
import '@fontsource/geist/500.css';
import '@fontsource/geist/600.css';
import '@fontsource/geist/700.css';
import '@fontsource/geist-mono/400.css';
import '@fontsource/geist-mono/500.css';
import '@fontsource/geist-mono/600.css';
import '@fontsource/geist-mono/700.css';

import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import './index.css';

createRoot(document.getElementById('root')!).render(
  <App />
);
