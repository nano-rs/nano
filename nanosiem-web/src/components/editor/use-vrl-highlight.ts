// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo } from 'react';
import { highlightVrl, type VrlSegment } from './vrl-language';

/** Highlight a VRL document once; index the result by 0-based line number (NAN-3195). */
export function useVrlHighlight(src: string | null | undefined): VrlSegment[][] {
  return useMemo(() => highlightVrl(src ?? ''), [src]);
}
