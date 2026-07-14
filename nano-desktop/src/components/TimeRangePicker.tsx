import { DateTimeRangePicker } from '@/components/ui/date-time-range-picker';
import type { TimeRangeValue } from '@/lib/time-range';

/**
 * Time range — literally the main app's picker.
 *
 * Not a lookalike: this is `DateTimeRangePicker` itself, so the desktop gets the
 * same draggable timeline, the same preset chips, the same two-month calendar
 * and the same behaviour, and it cannot drift from the web app. An earlier pass
 * rebuilt the chrome by hand and immediately started diverging (tabs, one month,
 * a different layout) — reuse is the whole point.
 *
 * `.picker-scope` re-points one token: shadcn's `accent` is a neutral hover tint
 * while ours is the brand pink. Without it, every hover inside the picker would
 * fill solid pink. See styles.css.
 */
interface Props {
  value: TimeRangeValue;
  onChange: (value: TimeRangeValue) => void;
}

export function TimeRangePicker({ value, onChange }: Props) {
  return (
    <div className="picker-scope shrink-0">
      <DateTimeRangePicker value={value} onChange={onChange} align="end" />
    </div>
  );
}
