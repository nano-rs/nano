// SPDX-License-Identifier: AGPL-3.0-or-later

import * as React from 'react';
import { cn } from '@/lib/utils';

export interface NumberInputProps
  extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type' | 'onChange'> {
  value: number | string;
  onChange: (value: number) => void;
  min?: number;
  max?: number;
  step?: number;
  allowEmpty?: boolean;
  emptyValue?: number;
}

/**
 * NumberInput - A text input that only accepts numeric values
 *
 * Unlike type="number", this allows:
 * - Clearing the field completely while typing
 * - No spinner buttons
 * - Better UX for manual number entry
 *
 * On blur, empty values are converted to the min value (or emptyValue if specified)
 */
function NumberInput({
  className,
  value,
  onChange,
  min,
  max,
  step,
  allowEmpty = false,
  emptyValue,
  ref,
  ...props
}: NumberInputProps & {
  ref?: React.Ref<HTMLInputElement>;
}) {
  const [localValue, setLocalValue] = React.useState<string>(String(value));
  const isDecimal = step !== undefined && step < 1;

  // Sync local value when prop changes
  React.useEffect(() => {
    setLocalValue(String(value));
  }, [value]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const inputValue = e.target.value;

    // Allow empty string while typing
    if (inputValue === '') {
      setLocalValue('');
      return;
    }

    // Allow digits, negative sign, and decimal point if step allows decimals
    const pattern = isDecimal ? /^-?\d*\.?\d*$/ : /^-?\d*$/;
    if (!pattern.test(inputValue)) {
      return;
    }

    setLocalValue(inputValue);

    // Parse and validate
    const numValue = isDecimal ? parseFloat(inputValue) : parseInt(inputValue, 10);
    if (!isNaN(numValue)) {
      let clampedValue = numValue;
      if (min !== undefined && numValue < min) clampedValue = min;
      if (max !== undefined && numValue > max) clampedValue = max;
      onChange(clampedValue);
    }
  };

  const handleBlur = () => {
    // On blur, ensure we have a valid value
    const parsedValue = isDecimal ? parseFloat(localValue) : parseInt(localValue, 10);
    if (localValue === '' || isNaN(parsedValue)) {
      const defaultValue = emptyValue ?? min ?? 0;
      setLocalValue(String(defaultValue));
      onChange(defaultValue);
    } else {
      // Clamp to min/max on blur
      let numValue = parsedValue;
      if (min !== undefined && numValue < min) numValue = min;
      if (max !== undefined && numValue > max) numValue = max;
      setLocalValue(String(numValue));
      onChange(numValue);
    }
  };

  return (
    <input
      type="text"
      inputMode={isDecimal ? 'decimal' : 'numeric'}
      pattern={isDecimal ? '[0-9]*\\.?[0-9]*' : '[0-9]*'}
      className={cn(
        'flex h-9 w-full rounded-md border border-border bg-input px-3 py-1 text-base shadow-sm transition-colors file:border-0 file:bg-transparent file:text-sm file:font-medium file:text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm',
        className
      )}
      ref={ref}
      value={localValue}
      onChange={handleChange}
      onBlur={handleBlur}
      {...props}
    />
  );
}

export { NumberInput };
