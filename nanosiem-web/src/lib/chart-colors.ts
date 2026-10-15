// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The one chart palette.
 *
 * Before this module, four files carried a byte-identical copy of the same
 * eight hex literals and two more carried their own variants — six private
 * palettes, none of which changed with the theme. `MetricViz` even documented
 * the intent ("Shared palette (matches ObsMetricWidget / VisualizationRenderer
 * ...)") while the other files duplicated it rather than importing it.
 *
 * Everything here is a `var()` string, so it resolves per theme at paint time.
 * That works because every consumer assigns these straight to a CSS property or
 * an SVG presentation attribute (`fill`, `stroke`, `background`, `color`) — both
 * resolve custom properties. If you ever need to MANIPULATE a series colour
 * (mix, add alpha, hand it to a canvas 2d context), do it in CSS with
 * `color-mix(in srgb, var(--chart-N) …)`; you cannot slice a `var()` string.
 */

/** Series colours, in plot order. Ten, matching the widest chart in the app. */
export const CHART_SERIES: readonly string[] = [
  'var(--chart-1)',
  'var(--chart-2)',
  'var(--chart-3)',
  'var(--chart-4)',
  'var(--chart-5)',
  'var(--chart-6)',
  'var(--chart-7)',
  'var(--chart-8)',
  'var(--chart-9)',
  'var(--chart-10)',
];

/** Series colour for the i-th plotted series, wrapping past the ramp's end. */
export function seriesColor(index: number): string {
  return CHART_SERIES[index % CHART_SERIES.length];
}

/**
 * Chart chrome. These reuse the app's text ramp rather than inventing
 * chart-only tokens: axis labels are muted text and axis rules are the faintest
 * text tone, which is what the hardcoded greys were approximating anyway
 * (`--fg-4` in dark is exactly the `#6b7280` they used).
 */
export const CHART_AXIS_TEXT = 'var(--muted-foreground)';
export const CHART_AXIS_LINE = 'var(--fg-4)';
/** Emphasised in-chart value text (gauge readouts, centre labels). */
export const CHART_VALUE_TEXT = 'var(--foreground)';
/** The rolled-up "other"/overflow bucket — deliberately not a series colour. */
export const CHART_OTHER = 'var(--fg-4)';
