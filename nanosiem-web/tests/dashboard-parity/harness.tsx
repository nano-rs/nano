import '@fontsource/geist/400.css';
import '@fontsource/geist/500.css';
import '@fontsource/geist/600.css';
import '@fontsource/geist/700.css';
import '@fontsource/geist-mono/400.css';
import '@fontsource/geist-mono/500.css';
import '@fontsource/geist-mono/600.css';
import '@fontsource/geist-mono/700.css';
import React from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import { Dashboards } from '../../src/pages/Dashboards';
import '../../src/index.css';
document.documentElement.classList.toggle(
  'dark',
  new URLSearchParams(location.search).get('appearance') !== 'light',
);
createRoot(document.getElementById('root')!).render(
  <MemoryRouter>
    <main className="h-screen flex bg-background">
      <Dashboards />
    </main>
  </MemoryRouter>,
);
