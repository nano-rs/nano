// @vitest-environment jsdom
// NAN-5760: deleted log sources show as a quiet "removed" list, never silent.

import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, test } from 'vitest';
import { RemovedSourcesPanel } from './SiemHealth';

afterEach(cleanup);

test('lists each removed source with its deleted log source and volumes', () => {
  render(
    <RemovedSourcesPanel
      sources={[
        {
          source_type: 'aws_cloudtrail',
          log_source_name: 'AWS CloudTrail (OCSF)',
          deleted_at: '2026-11-19T12:00:00Z',
          count_24h: 0,
          count_prior_24h: 5000,
        },
      ]}
    />,
  );
  expect(screen.getByText('Removed sources')).toBeTruthy();
  expect(screen.getByText('1 deleted source · data still in window, not monitored')).toBeTruthy();
  expect(screen.getByText('aws_cloudtrail')).toBeTruthy();
  expect(screen.getByText('AWS CloudTrail (OCSF)')).toBeTruthy();
  expect(screen.getByText('prior 5,000')).toBeTruthy();
  expect(screen.getByText('removed')).toBeTruthy();
  expect(screen.queryByText('silent')).toBeNull();
});

test('renders nothing when no source was removed', () => {
  const { container } = render(<RemovedSourcesPanel sources={[]} />);
  expect(container.innerHTML).toBe('');
});
