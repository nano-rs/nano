// SPDX-License-Identifier: AGPL-3.0-or-later
// Kept in parity with the backend by the native settings regression test.
export const PIPE_MAX_OPEN_GROUPS = 64;
export const PIPE_MAX_EXPIRE_SECONDS = 5;
export const PIPE_MAX_DEDUPE_EVENTS = 5000;
const SOURCE = String.raw`-- Fixed Nano group-bound gate. No customer Lua or filesystem/network access.
-- It sees only a {group_hash} control copy and emits only end-group markers;
-- events reach reduce directly, because Vector's Lua round trip drops event
-- metadata (finalizers, secrets) and rewrites null/[] values.
local groups, order, tick

function nano_pipe_init()
  groups, order, tick = {}, {}, 0
end

local function flush(key, emit)
  emit({log = {group_hash = key, nano_flush = true}})
end

function nano_pipe_process(event, emit)
  local key = event.log.group_hash
  if groups[key] == nil then
    if #order >= NANO_PIPE_MAX_GROUPS then
      local oldest = table.remove(order, 1)
      groups[oldest] = nil
      flush(oldest, emit)
    end
    table.insert(order, key)
  end
  groups[key] = tick
end

function nano_pipe_expire(emit)
  tick = tick + 1
  local remaining = {}
  for _, key in ipairs(order) do
    if tick - groups[key] >= NANO_PIPE_EXPIRE_TICKS then
      groups[key] = nil
      flush(key, emit)
    else
      table.insert(remaining, key)
    end
  end
  order = remaining
end

function nano_pipe_shutdown(emit)
  for _, key in ipairs(order) do flush(key, emit) end
  nano_pipe_init()
end
`;
export function groupBoundSource(timeout: number) {
  return `local NANO_PIPE_MAX_GROUPS = ${PIPE_MAX_OPEN_GROUPS}\nlocal NANO_PIPE_EXPIRE_TICKS = ${timeout}\n${SOURCE}`;
}
