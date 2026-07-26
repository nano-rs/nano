// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

import assert from 'node:assert/strict';
import test from 'node:test';

import { QueryClient, QueryObserver } from '@tanstack/react-query';

import {
  canViewNotifications,
  notificationCountQueryOptions,
  notificationListQueryOptions,
} from './notification-query-policy.ts';

interface ObservedQueryOptions {
  queryKey: readonly unknown[];
  enabled: boolean;
  refetchInterval?: number | false;
}

async function executionCount(options: ObservedQueryOptions): Promise<number> {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  let executions = 0;
  const observer = new QueryObserver(queryClient, {
    ...options,
    queryFn: async () => {
      executions += 1;
      return null;
    },
  });

  const unsubscribe = observer.subscribe(() => {});
  await new Promise<void>((resolve) => setImmediate(resolve));
  unsubscribe();
  queryClient.clear();

  return executions;
}

test('NAN-2138: principals without notifications:view trigger no notification queries', async () => {
  const canView = canViewNotifications(() => false);

  assert.equal(
    await executionCount(notificationCountQueryOptions(canView, async () => null)),
    0,
  );
  assert.equal(
    await executionCount(notificationListQueryOptions(canView, async () => null)),
    0,
  );
});

test('NAN-2138: notifications:view enables unread-count polling', async () => {
  const permissionsChecked: string[] = [];
  const canView = canViewNotifications((permission) => {
    permissionsChecked.push(permission);
    return true;
  });

  assert.deepEqual(permissionsChecked, ['notifications:view']);
  assert.equal(
    await executionCount(notificationCountQueryOptions(canView, async () => null)),
    1,
  );
});

test('notification list query requires both permission and an open popover', async () => {
  const canView = canViewNotifications(() => true);

  assert.equal(
    await executionCount(notificationListQueryOptions(canView && false, async () => null)),
    0,
  );
  assert.equal(
    await executionCount(notificationListQueryOptions(canView && true, async () => null)),
    1,
  );
});
