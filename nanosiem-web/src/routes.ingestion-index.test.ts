// NAN-5329: `/ingestion` (the rail group) redirects to Log Sources instead of 404.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('/ingestion index route (NAN-5329)', () => {
  it('redirects to /ingestion/log-sources', () => {
    const app = readFileSync(resolve(__dirname, 'App.tsx'), 'utf8');
    expect(app).toMatch(/<Route path="\/ingestion" element={<Navigate to="\/ingestion\/log-sources" replace \/>} \/>/);
  });
});
