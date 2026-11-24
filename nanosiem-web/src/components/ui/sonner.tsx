// SPDX-License-Identifier: AGPL-3.0-or-later

import { useTheme } from 'next-themes';
import { Toaster as Sonner } from 'sonner';

import { sonnerAppearance } from '@/lib/theme';
import { TOASTER_DEFAULTS } from '@/lib/toaster-defaults';

type ToasterProps = React.ComponentProps<typeof Sonner>;

const Toaster = ({ ...props }: ToasterProps) => {
  const { resolvedTheme } = useTheme();

  return <Sonner theme={sonnerAppearance(resolvedTheme)} {...TOASTER_DEFAULTS} {...props} />;
};

export { Toaster };
