# NAN-1540c — Edit capability for metric monitors (frontend-only)

## Summary
Metric monitors were create + delete only. Added an EDIT path that reuses the
existing `MetricMonitorDialog` (no second dialog), mirroring the create/edit
pattern in `SloEditorDialog.tsx`. Backend already supported edit
(`PUT /api/observability/metric-monitors/{id}` /
`api.observability.updateMetricMonitor(id, input)`).

## Files changed
- `nanosiem-web/src/components/observability/MetricMonitorDialog.tsx`
  - New optional props: `monitor?: MetricMonitor | null` (edit target) and made
    `seed?: MonitorQuerySeed` optional (only needed for create).
  - `const editing = monitor != null`.
  - The metric query (`querySeed`) is the explorer `seed` in create mode, or is
    **reconstructed from the monitor** in edit mode (see below). A defensive
    empty seed (`{ metric_name: '', agg: 'count', filters: [] }`) is used if both
    are absent so no field is read undefined.
  - Open-effect prefills ALL fields on edit: `name`, `comparator`, `threshold`
    (stringified), `window_secs`, `eval_interval_secs`; on create it keeps the
    prior auto-name + defaults.
  - Submit: edit calls `updateMetricMonitor(monitor.id, input)`, create calls
    `createMetricMonitor(input)`. The query fields in the payload come from
    `querySeed`. `enabled` is preserved from the existing monitor on edit
    (so editing doesn't silently re-enable a disabled monitor), `true` on create.
  - Title `Edit metric monitor` / `New metric monitor`; button
    `Save changes` / `Create monitor`.
  - `onCreated?.()` fires after both create and update.

- `nanosiem-web/src/components/observability/MetricMonitorsList.tsx`
  - Added `Pencil` (lucide-react) edit button per row, placed before the Trash2
    delete button, styled to match (hover:text-foreground).
  - New `editMonitor` state; the row's edit button sets it. Renders
    `<MetricMonitorDialog open={editMonitor != null} monitor={editMonitor}
    onOpenChange={(o) => !o && setEditMonitor(null)} onCreated={load} />`.
  - `load` (existing list refresh) is passed as `onCreated`, so the list
    refreshes on successful save. Toggle + delete unchanged.

Create call site (`MetricsExplorer.tsx`) is unchanged — it still passes `seed`
and no `monitor`, so create behavior is untouched.

## How edit reconstructs the query from the monitor
A `MetricMonitor` row carries the same query fields a `MonitorQuerySeed` needs:
`metric_name`, `agg`, `group_by`, `filters`. `seedFromMonitor(m)` maps them 1:1.
The dialog then shows that as the read-only query summary and resends those
fields in the `MetricMonitorRequest` on save, so the query is preserved verbatim
across an edit (the analyst only changes name/comparator/threshold/window/
interval, matching the original create UX where the query is read-only).

## Contract check with updateMetricMonitor
No mismatch. `updateMetricMonitor(id: string, input: MetricMonitorRequest)`
takes the same full `MetricMonitorRequest` as create (name, metric_name, agg,
group_by?, filters, comparator, threshold, window_secs, eval_interval_secs,
enabled). The dialog builds exactly that shape for both paths.

## Build
`npm run build` (tsc -b && vite build) — PASS, built clean. The only output note
is the pre-existing ">500 kB chunk" advisory, not an error.
